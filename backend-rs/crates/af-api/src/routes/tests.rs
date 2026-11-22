fn assert_proxy_document_policy(response: &axum::response::Response) {
    use axum::http::header;

    let policies = response.headers().get_all(header::CONTENT_SECURITY_POLICY);
    assert_eq!(policies.iter().count(), 1);
    assert_eq!(
        policies.iter().next().unwrap(),
        "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let cache_policies = response.headers().get_all(header::CACHE_CONTROL);
    assert_eq!(cache_policies.iter().count(), 1);
    assert_eq!(cache_policies.iter().next().unwrap(), "private, no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert_eq!(response.headers()[header::EXPIRES], "0");
    for name in [
        "surrogate-control",
        "cdn-cache-control",
        "cloudflare-cdn-cache-control",
    ] {
        assert!(!response.headers().contains_key(name), "{name}");
    }
}

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
            super::security_headers_middleware,
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
            super::security_headers_middleware,
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
    let app = super::build_router()
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
            super::security_headers_middleware,
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

use super::*;

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
async fn test_dispatch_package_update_pre_stop_skips_maintainerr_and_stops_radarr() {
    use std::sync::{Arc, Mutex};

    let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let maintainerr_recorder = Arc::clone(&recorded_control_actions);

    let maintainerr_stopped = pre_stop_units_for_package_update_with(
        "update",
        "maintainerr",
        "",
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder_handle = Arc::clone(&maintainerr_recorder);
            async move {
                recorder_handle
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
    )
    .await
    .expect("maintainerr pre-stop decision should succeed");
    assert!(
        maintainerr_stopped.is_empty(),
        "maintainerr must not be pre-stopped by API update dispatcher"
    );
    assert!(
        recorded_control_actions.lock().unwrap().is_empty(),
        "control callback must not receive stop for maintainerr"
    );

    let radarr_recorder = Arc::clone(&recorded_control_actions);
    let radarr_stopped = pre_stop_units_for_package_update_with(
        "update",
        "radarr",
        "",
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder_handle = Arc::clone(&radarr_recorder);
            async move {
                recorder_handle
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
    )
    .await
    .expect("radarr pre-stop decision should succeed");

    assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
    assert_eq!(
        *recorded_control_actions.lock().unwrap(),
        vec!["stop radarr".to_string()]
    );

    recorded_control_actions.lock().unwrap().clear();
    for shared_app in ["nextcloud", "rutorrent", "organizr"] {
        let recorder = Arc::clone(&recorded_control_actions);
        let stopped = pre_stop_units_for_package_update_with(
            "update",
            shared_app,
            "",
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder_handle = Arc::clone(&recorder);
                async move {
                    recorder_handle
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
        )
        .await
        .expect("shared-vhost pre-stop decision should succeed");
        assert!(
            stopped.is_empty(),
            "{} must not pre-stop shared apache2 on update",
            shared_app
        );
    }
    assert!(
        recorded_control_actions.lock().unwrap().is_empty(),
        "shared-vhost updates must not invoke stop on apache2"
    );
}

#[tokio::test]
async fn test_dispatch_package_update_maintainerr_port_preservation_and_fail_closed() {
    use std::sync::{Arc, Mutex};

    let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded_dispatch_ports: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    let queried_apps: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    for alias_id in ["maintainerr", "af-maintainerr", "af-maintainerr.service"] {
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        queried_apps.lock().unwrap().clear();

        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let app_recorder = Arc::clone(&queried_apps);

        let (allocated_port, stopped_units, dispatch_res) =
            run_package_lifecycle_dispatch_gate_with(
                "update",
                alias_id,
                6246,
                "",
                |_app_id| 0,
                move |app_id| {
                    app_recorder.lock().unwrap().push(app_id.to_string());
                    Ok(Some(AppIngressConfig {
                        app_name: app_id.to_string(),
                        listen_port: 17420,
                        ..Default::default()
                    }))
                },
                |_app_id, _default_port| 6246,
                af_services::resolve_service_units,
                |_unit_name| "running".to_string(),
                move |unit_name, control_action| {
                    let recorder = Arc::clone(&control_recorder);
                    async move {
                        recorder
                            .lock()
                            .unwrap()
                            .push(format!("{} {}", control_action, unit_name));
                        Ok(())
                    }
                },
                move |port| {
                    let recorder = Arc::clone(&dispatch_recorder);
                    async move {
                        recorder.lock().unwrap().push(port);
                        Ok(())
                    }
                },
            )
            .await
            .expect("maintainerr update with valid non-default port should succeed");

        assert!(dispatch_res.is_ok());
        assert_eq!(allocated_port, 17420);
        assert!(stopped_units.is_empty());
        assert_eq!(
            *queried_apps.lock().unwrap(),
            vec!["maintainerr".to_string()]
        );
        assert!(
            recorded_control_actions.lock().unwrap().is_empty(),
            "maintainerr update must not invoke unit control for {}",
            alias_id
        );
        assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
    }

    // Missing ingress row must fail closed before any unit control or package dispatch
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let missing_err = run_package_lifecycle_dispatch_gate_with(
        "update",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Ok(None),
        |_app_id, _default_port| 6246,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect_err("missing ingress mapping must fail closed");
    assert!(
        missing_err.contains("missing persisted ingress port mapping for maintainerr update"),
        "unexpected missing-mapping error: {}",
        missing_err
    );
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

    // Unreadable DB / query error must fail closed without falling back to 6246
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let db_err = run_package_lifecycle_dispatch_gate_with(
        "update",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Err(anyhow::anyhow!("sqlite disk I/O error")),
        |_app_id, _default_port| 6246,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect_err("unreadable ingress DB must fail closed");
    assert!(
        db_err.contains("cannot read existing configured port for maintainerr")
            && db_err.contains("sqlite disk I/O error"),
        "unexpected DB error: {}",
        db_err
    );
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

    // Out-of-range / invalid ports must fail closed with zero control or dispatch calls
    for invalid_port in [0, -1, 80, 1023, 65536, 70000] {
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let port_err = run_package_lifecycle_dispatch_gate_with(
            "update",
            "maintainerr",
            6246,
            "",
            |_app_id| 0,
            move |app_id| {
                Ok(Some(AppIngressConfig {
                    app_name: app_id.to_string(),
                    listen_port: invalid_port,
                    ..Default::default()
                }))
            },
            |_app_id, _default_port| 6246,
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder = Arc::clone(&control_recorder);
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
            move |port| {
                let recorder = Arc::clone(&dispatch_recorder);
                async move {
                    recorder.lock().unwrap().push(port);
                    Ok(())
                }
            },
        )
        .await
        .expect_err("invalid persisted port must fail closed");
        assert!(
            port_err.contains(&format!(
                "invalid persisted listen port {} for maintainerr update",
                invalid_port
            )),
            "unexpected error for invalid port {}: {}",
            invalid_port,
            port_err
        );
        assert!(recorded_control_actions.lock().unwrap().is_empty());
        assert!(recorded_dispatch_ports.lock().unwrap().is_empty());
    }

    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let (radarr_port, radarr_stopped, radarr_res) = run_package_lifecycle_dispatch_gate_with(
        "update",
        "radarr",
        7878,
        "",
        |_app_id| 17878,
        |_app_id| Ok(None),
        |_app_id, _default_port| 7878,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect("radarr update must preserve its authoritative native port");
    assert!(radarr_res.is_ok());
    assert_eq!(radarr_port, 17878);
    assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
    assert_eq!(
        *recorded_control_actions.lock().unwrap(),
        vec!["stop radarr".to_string()]
    );
    assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17878]);

    // Fresh install of maintainerr preserves install port allocation without pre-existing ingress
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let (install_port, install_stopped, install_res) = run_package_lifecycle_dispatch_gate_with(
        "install",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Ok(None),
        |_app_id, _default_port| 17420,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect("fresh maintainerr install should allocate port");
    assert!(install_res.is_ok());
    assert_eq!(install_port, 17420);
    assert!(install_stopped.is_empty());
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
}

#[test]
fn test_single_package_update_response_flattens_contract_fields() {
    let rec = af_services::workers::PackageUpdateRecord {
        package_id: "radarr".to_string(),
        installed: true,
        installed_version: "5.14.0".to_string(),
        latest_version: "5.15.0".to_string(),
        update_available: true,
        checked_at: "2026-11-02T12:00:00Z".to_string(),
        release_url: "https://github.com/Radarr/Radarr/releases/tag/v5.15.0".to_string(),
        error: "github rate limit warning".to_string(),
        source_key: "github:Radarr/Radarr".to_string(),
    };
    let body = build_single_package_update_response("radarr", Some(rec));
    assert_eq!(body["package"], "radarr");
    assert_eq!(body["update_available"], true);
    assert_eq!(body["installed_version"], "5.14.0");
    assert_eq!(body["latest_version"], "5.15.0");
    assert_eq!(
        body["update_url"],
        "https://github.com/Radarr/Radarr/releases/tag/v5.15.0"
    );
    assert_eq!(body["checked_at"], "2026-11-02T12:00:00Z");
    assert_eq!(
        body["last_error"],
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(
        body["error"],
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(body["update"]["package_id"], "radarr");
}

#[tokio::test]
async fn test_finalize_post_script_lifecycle_restarts_and_verifies_before_saving() {
    let timeline = std::cell::RefCell::new(Vec::new());
    let stopped = ["radarr".into(), "companion".into()];
    let version = finalize_post_script_lifecycle_with(
        &stopped,
        async {
            timeline.borrow_mut().push("blueprint".to_string());
            Ok(Some(AppIngressConfig::default()))
        },
        |unit, action| {
            timeline.borrow_mut().push(format!("{action} {unit}"));
            async { Ok(()) }
        },
        |unit| {
            timeline.borrow_mut().push(format!("check {unit}"));
            "running".into()
        },
        async {
            timeline.borrow_mut().push("refresh".into());
            Some("v2".into())
        },
        |_| {
            timeline.borrow_mut().push("commit".into());
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(version.as_deref(), Some("v2"));
    assert_eq!(
        timeline.into_inner(),
        [
            "blueprint",
            "start companion",
            "start radarr",
            "refresh",
            "check radarr",
            "check companion",
            "commit",
        ]
    );
}

#[test]
fn test_resolve_patched_ingress_config_preserves_omitted_fields_and_rejects_port_change() {
    let now = Utc::now();
    let existing = AppIngressConfig {
        app_name: "radarr".to_string(),
        public_domain: "radarr.example.com".to_string(),
        external_access_enabled: true,
        listen_port: 17878,
        tls_enabled: true,
        created_at: now,
        updated_at: now,
    };

    let req_patch: UpdateIngressReq = serde_json::from_value(serde_json::json!({
        "publicDomain": "movies.example.com",
        "externalAccessEnabled": false
    }))
    .unwrap();

    let patched = resolve_patched_ingress_config("radarr", &req_patch, Some(&existing), 7878, now)
        .expect("omitted listenPort and tlsEnabled should be preserved");
    assert_eq!(patched.public_domain, "movies.example.com");
    assert!(!patched.external_access_enabled);
    assert_eq!(patched.listen_port, 17878);
    assert!(patched.tls_enabled);

    let req_port_change: UpdateIngressReq = serde_json::from_value(serde_json::json!({
        "listenPort": 18999
    }))
    .unwrap();
    let err =
        resolve_patched_ingress_config("radarr", &req_port_change, Some(&existing), 7878, now)
            .expect_err("changing listenPort via ingress config must fail closed");
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(err.1, "PORT_RECONFIGURATION_UNSUPPORTED");
}
fn control_req(action: &str, managed_by: &str, process: &str) -> ServiceControlReq {
    ServiceControlReq {
        action: action.to_string(),
        managed_by: managed_by.to_string(),
        process: process.to_string(),
    }
}

#[test]
fn test_service_control_rejects_foreign_units_and_unknown_managers() {
    let err =
        validate_service_control_request("sonarr", &control_req("stop", "systemd-unit", "sshd"))
            .expect_err("a package card must not stop an unrelated host unit");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert_eq!(err.1, "SERVICE_CONTROL_FORBIDDEN");
    let err = validate_service_control_request(
        "sonarr",
        &control_req("restart", "systemd", "aetherflow-runner"),
    )
    .expect_err("process override must stay within the card");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    let err =
        validate_service_control_request("sonarr", &control_req("restart", "shell", "sonarr"))
            .expect_err("unknown managers are rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    let err =
        validate_service_control_request("sonarr", &control_req("enable", "systemd", "sonarr"))
            .expect_err("only start/stop/restart are allowed");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    let err = validate_service_control_request(
        "AetherFlow Frontend",
        &control_req("restart", "embedded", "aetherflow-frontend"),
    )
    .expect_err("embedded frontend has no daemon");
    assert_eq!(err.1, "EMBEDDED_SERVICE_CONTROL_UNSUPPORTED");
    let err = validate_service_control_request(
        "nextcloud",
        &control_req("restart", "systemd", "nextcloud"),
    )
    .expect_err("shared vhost controls stay blocked");
    assert_eq!(err.1, "SHARED_VHOST_CONTROL_UNSUPPORTED");
    assert_eq!(
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"))
            .unwrap(),
        "sonarr"
    );
}

#[test]
fn test_service_control_is_serialized_with_active_lifecycle_job() {
    // Regression: manual restarts during an update raced the installer's
    // own stop/replace/start sequence.
    let started_at = "hillclimb-control-lock";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: started_at.to_string(),
            package_id: "lidarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 25,
            last_line: String::new(),
            started_at: started_at.into(),
            expected_target_version: None,
        }
    ));
    let err =
        validate_service_control_request("lidarr", &control_req("restart", "systemd", "lidarr"))
            .expect_err("controls must wait for the lifecycle job");
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(err.1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
    af_services::finish_package_job("lidarr", "update", true, "done", started_at);
    assert_eq!(
        validate_service_control_request("lidarr", &control_req("restart", "systemd", "lidarr"))
            .unwrap(),
        "lidarr"
    );
}

#[test]
fn test_uninstall_purge_requires_explicit_true() {
    let parse = |value: Option<&str>| {
        parse_uninstall_purge(&UninstallQuery {
            purge: value.map(str::to_string),
        })
    };
    assert_eq!(parse(None), Ok(false));
    assert_eq!(parse(Some("")), Ok(false));
    assert_eq!(parse(Some("false")), Ok(false));
    assert_eq!(parse(Some("true")), Ok(true));
    assert_eq!(parse(Some("1")), Ok(true));
    assert!(parse(Some("yes")).is_err());
    assert!(parse(Some("TRUE ; rm")).is_err());
}

#[test]
fn test_progress_reports_failed_outcome_after_job_clears_and_redacts_for_viewers() {
    let outcome = af_services::PackageJobOutcome {
        job_id: "test-job".into(),
        package_id: "sonarr".into(),
        action: "update".into(),
        status: "failed".into(),
        message: "Could not stop sonarr: exit status 5".into(),
        started_at: "2026-11-05T20:00:00.000Z".into(),
        finished_at: "2026-11-05T20:01:00Z".into(),
        ..Default::default()
    };
    let payload = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
    assert_eq!(payload["status"], "failed");
    assert_eq!(payload["action"], "update");
    assert_eq!(payload["message"], "Could not stop sonarr: exit status 5");
    assert_eq!(payload["started_at"], "2026-11-05T20:00:00.000Z");
    let idle = package_progress_payload("sonarr", None, None, false);
    assert_eq!(idle["status"], "idle");

    let ordinary = package_progress_payload("sonarr", None, Some(outcome), false);
    assert!(!ordinary.to_string().contains("exit status"));
    assert_eq!(ordinary["last_job"]["job_id"], "test-job");
}

fn lifecycle_status_fixture() -> (std::path::PathBuf, rusqlite::Connection) {
    let root = std::env::temp_dir().join(format!("af-api-status-{}", uuid::Uuid::new_v4()));
    let path = root.join("backend/data/aetherflow.sqlite");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    std::env::set_var("DB_PATH", &path);
    af_services::initialize_package_jobs(rusqlite::Connection::open(&path).unwrap()).unwrap();
    (root, rusqlite::Connection::open(path).unwrap())
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_inventory_requires_human_admin_for_lifecycle_diagnostics() {
    use tower::ServiceExt;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    let package = af_models::Package {
        name: "fixture".into(),
        label: "Fixture".into(),
        lock_file: "/install/.fixture.lock".into(),
        default_port: 12345,
        web_path: "/open".into(),
        ..Default::default()
    };
    let vhosts = root.join("etc/apache2/sites-enabled");
    std::fs::create_dir_all(&vhosts).unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.fixture.lock"), "installed").unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-fixture.conf"),
        "<VirtualHost *:80>\n    ServerName fixture.aether.local\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch(
            "INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin'), (2, 'viewer', 'user');
             INSERT INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status)
             VALUES ('inventory-reader', 1, 0, 1, 'running');",
        )
        .unwrap();
    drop(conn);
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "inventory-privilege-fixture".into(),
            package_id: "fixture".into(),
            expected_target_version: Some("2.0.0".into()),
            action: "update".into(),
            status: "updating".into(),
            progress: 42,
            started_at: chrono::Utc::now().to_rfc3339(),
            last_line: "PRIVATE_INSTALLER_DETAILS".into(),
        }
    ));
    af_services::finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(af_services::PackageJobFailure::Installer),
        "inventory-privilege-fixture",
        Some("private-fixture-stage".into()),
        Some(41),
        Some("PRIVATE_INSTALLER_DETAILS /home/fixture/internal-path".into()),
        Some("2.0.0".into()),
        Some("1.0.0".into()),
    )
    .unwrap();
    let (admin_token, admin_claims) =
        crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let (user_token, _) = crate::auth::create_standard_jwt(2, &HeaderMap::new()).unwrap();
    let mut cases = vec![
        ("human-admin".to_string(), admin_token, true, true),
        ("human-user".to_string(), user_token, true, false),
        (
            "invalid".to_string(),
            "invalid-token".to_string(),
            false,
            false,
        ),
    ];
    for (pid, permission, scope, authenticated) in [
        (
            "inventory-packages",
            "packages:read",
            "/api/v1/auth/packages",
            true,
        ),
        (
            "inventory-marketplace",
            "marketplace:read",
            "/api/v1/public/marketplace",
            true,
        ),
        (
            "inventory-metrics",
            "system:metrics:read",
            "/api/v1/auth/system/metrics",
            false,
        ),
    ] {
        let pdir = root.join("plugins").join(pid);
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(
            pdir.join("plugin.manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": pid,
                "name": pid,
                "version": "1.0.0",
                "permissions": [permission],
                "api_scopes": [format!("GET {scope}")],
                "backend": { "health_path": "/healthz" },
            }))
            .unwrap(),
        )
        .unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status) VALUES (?1, 1, 0, 1, 'running')",
                rusqlite::params![pid],
            )
            .unwrap();
        drop(conn);
        let (manifests, errs) = crate::plugins::discover_plugins();
        assert!(errs.is_empty(), "plugin discovery errors: {errs:?}");
        let manifest = manifests.into_iter().find(|m| m.id == pid).unwrap();
        let (token, _) = crate::plugins::mint_scoped_plugin_token(&manifest, Some(300)).unwrap();
        assert!(crate::plugins::decode_and_verify_plugin_token(&token).is_ok());
        cases.push((format!("dedicated {scope}"), token, authenticated, false));
        for plugin_id in [pid, ""] {
            let mut claims = admin_claims.clone();
            claims.plugin_id = plugin_id.into();
            claims.plugin_scopes = vec![scope.into()];
            claims.jti = uuid::Uuid::new_v4().to_string();
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(&crate::auth::jwt_secret_bytes()),
            )
            .unwrap();
            assert!(crate::auth::decode_session_claims(&token, false).is_ok());
            cases.push((format!("legacy {plugin_id:?} {scope}"), token, false, false));
        }
    }
    let router = build_router();
    for (label, token, authenticated, diagnostics_allowed) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(
            get_marketplace_auth_info(&headers),
            (authenticated, diagnostics_allowed),
            "{label}"
        );
        for require_auth in [false, true] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(if require_auth {
                            "/api/v1/public/marketplace?require_auth=1"
                        } else {
                            "/api/v1/public/marketplace"
                        })
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if require_auth && !authenticated {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
                continue;
            }
            assert_eq!(response.status(), StatusCode::OK, "{label}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            assert_eq!(response.headers()[header::VARY], "Authorization, Cookie");
            assert_eq!(
                response.headers()["x-aetherflow-inventory-authenticated"],
                if authenticated { "true" } else { "false" },
                "{label}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let app = &payload[0];
            assert_eq!(app["inventory_known"], authenticated, "{label}");
            if authenticated {
                assert_eq!(app["launch_scope"], "internal", "{label}");
                assert_eq!(
                    app["launch_url"], "http://fixture.aether.local/open",
                    "{label}"
                );
                assert_eq!(
                    app["last_job"]["job_id"], "inventory-privilege-fixture",
                    "{label}"
                );
                assert_eq!(app["last_job"]["status"], "failed", "{label}");
                assert_eq!(
                    app["last_job"]["expected_target_version"], "2.0.0",
                    "{label}"
                );
            }
            for field in ["failed_stage", "exit_code", "sanitized_summary"] {
                assert_eq!(
                    app["last_job"].get(field).is_some(),
                    diagnostics_allowed,
                    "{label} {field}"
                );
            }
            assert_eq!(
                payload.to_string().contains("PRIVATE_INSTALLER_DETAILS"),
                diagnostics_allowed,
                "{label}"
            );
            assert_eq!(
                payload.to_string().contains("/home/fixture/internal-path"),
                diagnostics_allowed,
                "{label}"
            );
        }
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_url_base_launch_contract_and_gateway_forwarding() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allocated_port = listener.local_addr().unwrap().port();
    let upstream = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut total = 0usize;
                while total < buf.len() {
                    let Ok(read) = stream.read(&mut buf[total..]).await else {
                        return;
                    };
                    if read == 0 {
                        break;
                    }
                    total += read;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&buf[..total]);
                let request_line = raw.lines().next().unwrap_or_default();
                let body = serde_json::json!({ "requestLine": request_line }).to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });

    let (root, connection) = lifecycle_status_fixture();
    let db_path = root.join("backend/data/aetherflow.sqlite");
    std::env::set_var("AF_DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");

    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let fake_systemctl = bin_dir.join("systemctl");
    std::fs::write(
        &fake_systemctl,
        "#!/bin/sh\ncase \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\n';; is-active) echo active;; *) exit 0;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var(
        "PATH",
        format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );

    af_db::init_db().unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch("INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin');")
        .unwrap();
    drop(conn);

    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    let packages = vec![
        af_models::Package {
            name: "sonarr".into(),
            label: "Sonarr".into(),
            lock_file: "/install/.sonarr.lock".into(),
            service_type: "systemd".into(),
            service_name: "sonarr".into(),
            default_port: 8989,
            web_path: "/".into(),
            ..Default::default()
        },
        af_models::Package {
            name: "bazarr".into(),
            label: "Bazarr".into(),
            lock_file: "/install/.bazarr.lock".into(),
            service_type: "systemd".into(),
            service_name: "bazarr".into(),
            default_port: 6767,
            web_path: "/".into(),
            ..Default::default()
        },
    ];
    std::fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);

    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.bazarr.lock"), "installed").unwrap();

    let sonarr_xml = root.join("var/lib/sonarr/config.xml");
    std::fs::create_dir_all(sonarr_xml.parent().unwrap()).unwrap();
    std::fs::write(
        &sonarr_xml,
        format!(
            "<Config><Port>{allocated_port}</Port><UrlBase> /tv/sonarr/ </UrlBase><ApiKey>fixture-key</ApiKey></Config>"
        ),
    )
    .unwrap();

    let bazarr_yaml = root.join("var/lib/bazarr/config/config.yaml");
    std::fs::create_dir_all(bazarr_yaml.parent().unwrap()).unwrap();
    std::fs::write(
        &bazarr_yaml,
        "general:\n  ip: 127.0.0.1\n  port: 16767\n  base_url: /bazarr/../admin\n",
    )
    .unwrap();

    let vhosts = root.join("etc/apache2/sites-enabled");
    std::fs::create_dir_all(&vhosts).unwrap();
    std::fs::write(
        vhosts.join("aetherflow-ext-sonarr.conf"),
        "<VirtualHost *:443>\n    ServerName sonarr.example.test\n    SSLEngine On\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-sonarr.conf"),
        "<VirtualHost *:80>\n    ServerName sonarr.aether.local\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-bazarr.conf"),
        "<VirtualHost *:80>\n    ServerName bazarr.aether.local\n</VirtualHost>\n",
    )
    .unwrap();

    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "sonarr.example.test".into(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: i32::from(allocated_port),
        ..Default::default()
    })
    .unwrap();
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "bazarr".into(),
        external_access_enabled: false,
        tls_enabled: false,
        listen_port: 16767,
        ..Default::default()
    })
    .unwrap();

    af_services::clear_service_status_cache();
    af_services::mutators::clear_app_runtime_meta_cache();
    let (admin_token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let app = build_router().layer(axum::middleware::from_fn(
        crate::middlewares::app_subdomain_proxy_middleware,
    ));

    let fetch_json = |uri: &'static str, token: Option<&str>| {
        let app = app.clone();
        let auth = token.map(|t| format!("Bearer {t}"));
        async move {
            let mut req = axum::http::Request::builder()
                .uri(uri)
                .header(header::HOST, "localhost");
            if let Some(auth) = auth {
                req = req.header(header::AUTHORIZATION, auth);
            }
            let resp = app
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let bytes = axum::body::to_bytes(resp.into_body(), 262_144)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        }
    };

    // 1. Unauthenticated marketplace stays redacted and never exposes retained url_base.
    let redacted = fetch_json("/api/v1/public/marketplace", None).await;
    let redacted_sonarr = redacted
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "sonarr")
        .unwrap();
    assert_eq!(redacted_sonarr["web_path"], "/");
    assert!(redacted_sonarr.get("launch_url").is_none());
    assert!(redacted_sonarr.get("launch_scope").is_none());

    // 2. Both authenticated inventories expose the allocated port, retained URL base,
    //    and safe root fallback for malformed input.
    let authed_market = fetch_json("/api/v1/public/marketplace", Some(&admin_token)).await;
    let market_row = |id: &str| {
        authed_market
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()
    };
    assert_eq!(market_row("sonarr")["active_port"], allocated_port);
    assert_eq!(market_row("sonarr")["web_path"], "/tv/sonarr");
    assert_eq!(market_row("sonarr")["launch_scope"], "public");
    assert_eq!(
        market_row("sonarr")["launch_url"],
        "https://sonarr.example.test/tv/sonarr"
    );
    assert_eq!(market_row("bazarr")["web_path"], "/");
    assert_eq!(market_row("bazarr")["launch_scope"], "internal");
    assert_eq!(
        market_row("bazarr")["launch_url"],
        "http://bazarr.aether.local"
    );

    let authed_services = fetch_json("/api/v1/auth/services", Some(&admin_token)).await;
    assert_eq!(authed_services["Sonarr"]["active_port"], allocated_port);
    assert_eq!(authed_services["Sonarr"]["web_path"], "/tv/sonarr");
    assert_eq!(authed_services["Sonarr"]["launch_scope"], "public");
    assert_eq!(
        authed_services["Sonarr"]["launch_url"],
        "https://sonarr.example.test/tv/sonarr"
    );
    assert_eq!(authed_services["Bazarr"]["web_path"], "/");
    assert_eq!(authed_services["Bazarr"]["launch_scope"], "internal");
    assert_eq!(
        authed_services["Bazarr"]["launch_url"],
        "http://bazarr.aether.local"
    );

    // 3. Launching the resolved URL forwards the retained path to the allocated port.
    let parsed_launch =
        url::Url::parse(market_row("sonarr")["launch_url"].as_str().unwrap()).unwrap();
    assert_eq!(parsed_launch.host_str(), Some("sonarr.example.test"));
    assert_eq!(parsed_launch.path(), "/tv/sonarr");
    for gateway_host in ["sonarr.example.test", "sonarr.aether.local"] {
        let proxied = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(parsed_launch.path())
                    .header(header::HOST, gateway_host)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proxied.status(), StatusCode::OK, "{gateway_host}");
        let bytes = axum::body::to_bytes(proxied.into_body(), 16_384)
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            observed["requestLine"], "GET /tv/sonarr HTTP/1.1",
            "{gateway_host}"
        );
    }

    // 4. Malformed retained UrlBase falls back safely to root in both inventories and forwarding.
    std::fs::write(
        &sonarr_xml,
        format!(
            "<Config><Port>{allocated_port}</Port><UrlBase>https://evil.example/hijack</UrlBase></Config>"
        ),
    )
    .unwrap();
    af_services::clear_service_status_cache();
    af_services::mutators::clear_app_runtime_meta_cache();

    let fallback_market = fetch_json("/api/v1/public/marketplace", Some(&admin_token)).await;
    let fallback_sonarr = fallback_market
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "sonarr")
        .unwrap();
    assert_eq!(fallback_sonarr["web_path"], "/");
    assert_eq!(fallback_sonarr["launch_url"], "https://sonarr.example.test");

    let fallback_services = fetch_json("/api/v1/auth/services", Some(&admin_token)).await;
    assert_eq!(fallback_services["Sonarr"]["web_path"], "/");
    assert_eq!(
        fallback_services["Sonarr"]["launch_url"],
        "https://sonarr.example.test"
    );

    let fallback_url = url::Url::parse(fallback_sonarr["launch_url"].as_str().unwrap()).unwrap();
    let proxied_root = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(fallback_url.path())
                .header(header::HOST, "sonarr.example.test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proxied_root.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(proxied_root.into_body(), 16_384)
        .await
        .unwrap();
    let observed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(observed["requestLine"], "GET / HTTP/1.1");

    upstream.abort();
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

fn progress_test_user(role: &str, plugin: Option<&str>) -> AuthUser {
    AuthUser {
        user_id: 1,
        username: "progress-fixture".into(),
        role: role.into(),
        jti: "progress-fixture".into(),
        plugin_id: plugin.map(str::to_owned),
        plugin_scopes: plugin
            .map(|_| vec!["telemetry:read".into()])
            .unwrap_or_default(),
    }
}

#[tokio::test]
async fn routine_service_control_failures_are_sanitized_and_correlated() {
    for timed_out in [false, true] {
        let detail = "SYNTHETIC_PRIVATE_DETAIL /private/review/secret.json";
        let error = if timed_out {
            anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, detail))
                .context("control failed")
        } else {
            anyhow::anyhow!(detail)
        };
        let response = service_control_failure_response(&error, "sonarr", "restart");
        assert_eq!(
            response.status(),
            if timed_out {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!body.to_string().contains("SYNTHETIC_PRIVATE_DETAIL"));
        assert!(!body.to_string().contains("/private/"));
        assert!(uuid::Uuid::parse_str(body["error_id"].as_str().unwrap()).is_ok());
        assert_eq!(
            body["code"],
            if timed_out {
                "SERVICE_CONTROL_TIMEOUT"
            } else {
                "SERVICE_CONTROL_FAILED"
            }
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_update_inventory_errors_are_unavailable_without_success_counts() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::fs::write(&automation, "{}").unwrap();
    let package = af_models::Package {
        name: "sonarr".into(),
        lock_file: "/install/.sonarr.lock".into(),
        ..Default::default()
    };
    let valid_catalog = serde_json::to_vec(&vec![package]).unwrap();
    for failure in ["catalog", "lock", "journal"] {
        std::fs::write(&catalog, &valid_catalog).unwrap();
        match failure {
            "catalog" => std::fs::write(&catalog, "{corrupt").unwrap(),
            "lock" => std::fs::create_dir_all(root.join("install/.sonarr.lock")).unwrap(),
            "journal" => blocker.execute_batch("BEGIN EXCLUSIVE").unwrap(),
            _ => unreachable!(),
        }
        let response = check_package_updates().await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{failure}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "STATUS_UNAVAILABLE");
        assert!(body.get("updates").is_none());
        assert!(body.get("updates_available").is_none());
        assert!(!body.to_string().contains(root.to_str().unwrap()));
        if failure == "lock" {
            std::fs::remove_dir(root.join("install/.sonarr.lock")).unwrap();
        }
        if failure == "journal" {
            blocker.execute_batch("ROLLBACK").unwrap();
        }
    }
    std::fs::write(&catalog, "[]").unwrap();
    let response = check_package_updates().await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["updates"], serde_json::json!([]));
    assert_eq!(body["updates_available"], 0);
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn services_credentials_require_a_human_admin_for_http_views() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
    std::fs::write(
        root.join("var/lib/sonarr/config.xml"),
        "<Config><ApiKey>synthetic-service-credential</ApiKey><Port>18989</Port></Config>",
    )
    .unwrap();
    let package = af_models::Package {
        name: "sonarr".into(),
        label: "Sonarr".into(),
        service_name: "sonarr".into(),
        lock_file: "/install/.sonarr.lock".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    for (role, plugin, allowed) in [
        ("user", None, false),
        ("plugin", Some("status-reader"), false),
        ("admin", Some("status-reader"), false),
        ("admin", None, true),
    ] {
        let response = get_services(Extension(progress_test_user(role, plugin))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["Sonarr"].get("api_key").is_some(),
            allowed,
            "{role} {plugin:?}"
        );
        assert_eq!(
            body.to_string().contains("synthetic-service-credential"),
            allowed
        );
        assert_eq!(body["Sonarr"]["id"], "sonarr");
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_sanitizes_users_and_plugins_but_keeps_admin_diagnostics() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "privileged-output-job".into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 42,
            last_line: "step_output=private-installer-output".into(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    for (role, plugin, raw_expected) in [
        ("user", None, false),
        ("plugin", Some("telemetry-client"), false),
        ("admin", Some("telemetry-client"), false),
        ("admin", None, true),
    ] {
        let user = progress_test_user(role, plugin);
        let response = package_progress(
            Path("sonarr".into()),
            Query(Default::default()),
            Extension(user.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["job_id"], "privileged-output-job");
        assert_eq!(payload["progress"], 42);
        assert_eq!(payload["status"], "updating");
        assert_eq!(
            payload.to_string().contains("private-installer-output"),
            raw_expected
        );
        if plugin.is_some() {
            assert_eq!(
                issue_ws_ticket(Extension(user), PeerIp(None), HeaderMap::new())
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    af_services::fail_package_job(
        "sonarr",
        "update",
        af_services::PackageJobFailure::Installer,
        "privileged-output-job",
    )
    .unwrap();
    let response = package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("admin", None)),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        outcome["message"],
        af_services::PackageJobFailure::Installer.summary()
    );
    assert!(!outcome.to_string().contains("private-installer-output"));
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

fn short_test_socket_path(filename: &str) -> std::path::PathBuf {
    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        if !tmpdir.is_empty() {
            let candidate = std::path::PathBuf::from(tmpdir).join(filename);
            if candidate.as_os_str().len() < 95 {
                return candidate;
            }
        }
    }
    let candidate = std::env::temp_dir().join(filename);
    if candidate.as_os_str().len() < 95 {
        candidate
    } else {
        std::path::PathBuf::from("/tmp").join(filename)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn package_admission_reconciles_dead_same_package_before_catalog_validation() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    let package_id = "lifecycle-admission-fixture";
    let package = af_models::Package {
        name: package_id.into(),
        label: "Lifecycle admission fixture".into(),
        service_name: package_id.into(),
        lock_file: "/install/.lifecycle-admission-fixture.lock".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );
    af_db::init_db().unwrap();
    let scripts = root.join("packages/package/install");
    std::fs::create_dir_all(&scripts).unwrap();
    let script_name = format!("installpackage-{package_id}");
    let script = scripts.join(&script_name);
    std::fs::write(&script, "#!/bin/sh\nexit 91\n").unwrap();
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    assert_eq!(
        af_runner::resolve_package_script_path("install", &script_name),
        Some(std::path::PathBuf::from("packages/package/install").join(&script_name))
    );
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "abandoned-install".into(),
            package_id: package_id.into(),
            action: "install".into(),
            status: "installing".into(),
            progress: 20,
            last_line: String::new(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    drop(af_services::take_package_job_lease(package_id, "abandoned-install").unwrap());
    assert_eq!(
        af_services::package_job_snapshot().unwrap().active[package_id].status,
        "installing"
    );
    let execution_blocked = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
    let response = dispatch_package_lifecycle(
        package_id.into(),
        "install",
        "installing",
        false,
        progress_test_user("admin", None),
        HeaderMap::new(),
    )
    .await;
    let response_status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_status, StatusCode::OK, "{payload}");
    let identity = payload["job_id"].as_str().unwrap();
    assert_ne!(identity, "abandoned-install");
    assert_eq!(
        af_services::package_job_snapshot().unwrap().active[package_id].job_id,
        identity
    );
    let rejected = dispatch_package_lifecycle(
        package_id.into(),
        "install",
        "installing",
        false,
        progress_test_user("admin", None),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert!(af_services::finish_package_job(
        package_id,
        "install",
        true,
        "late",
        "abandoned-install"
    )
    .is_none());
    af_services::finish_package_job(package_id, "install", true, "fixture done", identity).unwrap();
    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    drop(execution_blocked);
}

#[tokio::test(flavor = "current_thread")]
async fn finalize_post_script_lifecycle_preserves_routing_on_required_failure() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    use af_services::PackageJobFailure::{Configuration, ServiceRestore};

    let (root, conn) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let original = AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "custom.example.test".into(),
        external_access_enabled: false,
        tls_enabled: true,
        listen_port: 18989,
        ..Default::default()
    };
    af_db::set_app_ingress_config(&original).unwrap();
    af_db::archive_app_ingress_config("sonarr", false).unwrap();
    let retained = af_db::get_retained_app_ingress_config("sonarr").unwrap();
    af_db::set_app_ingress_config(&original).unwrap();
    let original = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();

    let vhost = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    std::fs::create_dir_all(vhost.parent().unwrap()).unwrap();
    std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:18989/\n").unwrap();
    let blueprint_snapshots = af_runner::package_lifecycle::snapshot_blueprint_targets(
        "sonarr",
        &af_runner::PackageExecutionEnv {
            fs_root: Some(root.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let prior_vhost = std::fs::read(&vhost).unwrap();

    let job_id = "ingress-update";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 85,
            last_line: String::new(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    conn.execute_batch(
        "CREATE TABLE ingress_writes(port INTEGER);
         CREATE TRIGGER count_ingress_update AFTER UPDATE ON app_ingress_configs
         BEGIN INSERT INTO ingress_writes VALUES (NEW.listen_port); END;
         CREATE TRIGGER fail_ingress_update AFTER UPDATE ON app_ingress_configs
         WHEN NEW.app_name = 'sonarr'
         BEGIN SELECT RAISE(ABORT, 'fixture rejected ingress update'); END;",
    )
    .unwrap();

    let units = ["sonarr".to_string()];
    let planned =
        af_db::plan_lifecycle_ingress("sonarr", 28989, "base.example.test", Some(&original))
            .unwrap()
            .unwrap();
    let writes = || {
        conn.query_row("SELECT count(*) FROM ingress_writes", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    };
    let run = |blueprint_failed, status: &'static str| {
        let planned = planned.clone();
        finalize_post_script_lifecycle_with(
            &units,
            async move {
                if blueprint_failed {
                    Err("fixture vhost synchronization failed".into())
                } else {
                    Ok(Some(planned))
                }
            },
            |_, _| async { Ok(()) },
            move |_| status.into(),
            async { None },
            |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, job_id, "update"),
        )
    };
    for (blueprint_failed, status, expected_kind, cause) in [
        (
            true,
            "running",
            Configuration,
            "fixture vhost synchronization failed",
        ),
        (false, "stopped", ServiceRestore, "failed to remain active"),
        (
            false,
            "running",
            Configuration,
            "fixture rejected ingress update",
        ),
    ] {
        std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:28989/\n").unwrap();
        let failure = run(blueprint_failed, status).await.unwrap_err();
        assert_eq!(failure.kind, expected_kind);
        assert!(failure.message.contains(cause), "{}", failure.message);
        let (_, restore_error, restart_failures) =
            marketplace::handle_post_certification_finalization_failure_ext_with(
                "update",
                failure,
                "sonarr",
                &units,
                &[],
                &blueprint_snapshots,
                false,
                None,
                None,
                |_, _| async { Ok(()) },
                |_| "running".into(),
            )
            .await;
        assert!(restore_error.is_none());
        assert!(restart_failures.is_empty());
        assert_eq!(std::fs::read(&vhost).unwrap(), prior_vhost);
        assert_eq!(
            af_db::get_app_ingress_config("sonarr").unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            af_db::get_retained_app_ingress_config("sonarr").unwrap(),
            retained
        );
        assert_eq!(writes(), 0);
    }

    conn.execute_batch("DROP TRIGGER fail_ingress_update")
        .unwrap();
    std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:28989/\n").unwrap();
    run(false, "running").await.unwrap();
    let committed = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(committed.listen_port, 28989);
    assert_eq!(committed.public_domain, original.public_domain);
    assert_eq!(
        committed.external_access_enabled,
        original.external_access_enabled
    );
    assert_eq!(committed.tls_enabled, original.tls_enabled);
    assert_eq!(writes(), 1);
    af_services::finish_package_job("sonarr", "update", true, "done", job_id).unwrap();
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_ingress_callbacks_require_the_current_lifecycle_owner() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let job = |identity: &str, action: &str, status: &str| af_services::PackageJobInfo {
        job_id: identity.into(),
        package_id: "sonarr".into(),
        action: action.into(),
        status: status.into(),
        progress: 20,
        last_line: String::new(),
        started_at: "fixture-start".into(),
        expected_target_version: None,
    };
    assert!(af_services::try_start_package_job(job(
        "ingress-install",
        "install",
        "installing"
    )));
    finalize_post_script_lifecycle_with(
        &[],
        async {
            af_db::plan_lifecycle_ingress("sonarr", 18989, "example.com", None)
                .map_err(|err| err.to_string())
        },
        |_, _| async { Ok(()) },
        |_| unreachable!(),
        async { None },
        |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, "ingress-install", "install"),
    )
    .await
    .unwrap();
    let ingress = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(ingress.listen_port, 18989);
    assert!(af_db::set_app_ingress_config(&ingress).is_err());
    assert!(
        af_db::set_app_ingress_config_for_lifecycle(&ingress, "wrong-owner", "install").is_err()
    );
    af_services::finish_package_job("sonarr", "install", true, "done", "ingress-install").unwrap();
    assert!(af_services::try_start_package_job(job(
        "ingress-remove",
        "remove",
        "uninstalling"
    )));
    assert!(af_db::archive_app_ingress_config("sonarr", false).is_err());
    assert!(
        af_db::archive_app_ingress_config_for_lifecycle("sonarr", false, "ingress-install")
            .is_err()
    );
    af_db::archive_app_ingress_config_for_lifecycle("sonarr", false, "ingress-remove").unwrap();
    assert!(af_db::get_app_ingress_config("sonarr").unwrap().is_none());
    assert_eq!(
        load_authoritative_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .listen_port,
        18989
    );
    af_services::finish_package_job("sonarr", "remove", true, "done", "ingress-remove").unwrap();
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_returns_superseded_receipt_by_job_and_package() {
    use super::marketplace::PackageProgressQuery;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    connection
        .execute_batch(
            "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at)
                 VALUES ('sonarr','new-job','update','updating','fixture');
             INSERT INTO package_lifecycle_history
                 (package_id,job_id,action,status,started_at,sanitized_summary)
                 VALUES ('sonarr','old-job','update','failed','fixture','private-fixture-detail');",
        )
        .unwrap();
    for (package, job_id, role, expected_status, expected_code) in [
        ("sonarr", Some("old-job"), "user", StatusCode::OK, "failed"),
        ("sonarr", Some("old-job"), "admin", StatusCode::OK, "failed"),
        (
            "sonarr",
            Some("new-job"),
            "user",
            StatusCode::OK,
            "updating",
        ),
        ("sonarr", None, "user", StatusCode::OK, "updating"),
        (
            "radarr",
            Some("old-job"),
            "user",
            StatusCode::NOT_FOUND,
            "PACKAGE_JOB_NOT_FOUND",
        ),
    ] {
        let response = package_progress(
            Path(package.into()),
            Query(PackageProgressQuery {
                job_id: job_id.map(str::to_owned),
            }),
            Extension(progress_test_user(role, None)),
        )
        .await;
        assert_eq!(response.status(), expected_status);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if expected_status == StatusCode::OK {
            assert_eq!(payload["status"], expected_code);
            assert_eq!(payload["job_id"], job_id.unwrap_or("new-job"));
        } else {
            assert_eq!(payload["code"], expected_code);
        }
        assert_eq!(
            payload.to_string().contains("private-fixture-detail"),
            role == "admin"
        );
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_yields_and_fails_closed_on_blocked_journal() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut response = Box::pin(package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("user", None)),
    ));
    assert!(
        futures::poll!(&mut response).is_pending(),
        "journal status must not block the async runtime or return idle on read failure"
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), response)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["code"], "STATUS_UNAVAILABLE");
    assert!(af_runner::acquire_lifecycle_admission_lock(Some(&root)).is_ok());
    let mut admission = Box::pin(dispatch_package_lifecycle(
        "sonarr".into(),
        "install",
        "installing",
        false,
        AuthUser {
            user_id: 1,
            username: "isolated-admin".into(),
            role: "admin".into(),
            jti: "isolated-session".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        },
        HeaderMap::new(),
    ));
    assert!(
        futures::poll!(&mut admission).is_pending(),
        "admission status lookup must yield before reading the journal"
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), admission)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    blocker.execute_batch("ROLLBACK").unwrap();
    blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','matching-receipt','update','completed','fixture')", []).unwrap();
    let response = package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("user", None)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["job_id"], "matching-receipt");
    assert_eq!(payload["status"], "completed");
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn service_control_fails_closed_for_unreadable_or_unknown_journal() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let unavailable =
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"));
    blocker.execute_batch("ROLLBACK").unwrap();
    blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','unknown-receipt','update','unrecognized-phase','fixture')", []).unwrap();
    let unknown =
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"));
    assert_eq!(unavailable.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unknown.unwrap_err().1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_control_contention_returns_409_without_lock_details() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    let socket = short_test_socket_path(&format!(
        "c-{}.sock",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let guard = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    let request = |name: &str| {
        control_service_handler(
            Path(name.to_string()),
            Extension(AuthUser {
                user_id: 1,
                username: "fixture".into(),
                role: "admin".into(),
                jti: "fixture".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            }),
            HeaderMap::new(),
            Json(control_req("restart", "systemd", name)),
        )
    };
    // With no runner, the fallback must fail before invoking a real command.
    let local = request("aetherflow-frontend").await;
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let fake_runner = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                continue;
            } // runner availability probe
            let request = String::from_utf8_lossy(&buffer[..count]);
            let (status, response) = if request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .ends_with("/v1/self-update/status")
            {
                ("200 OK", af_models::RunnerResponse { success: true, output: serde_json::json!({"status":"succeeded","completed":true,"success":true,"job_unit":"","error":"","exit_code":null}).to_string(), error: String::new() })
            } else {
                assert!(request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .ends_with("/v1/systemctl"));
                (
                    "409 Conflict",
                    af_models::RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: "release lock contention at /private/fixture.lock".into(),
                    },
                )
            };
            let body = serde_json::to_string(&response).unwrap();
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
    });
    let remote = request("aetherflow-frontend").await;
    let core = request("aetherflow-api").await;
    fake_runner.abort();
    for response in [local, remote, core] {
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["code"], "LIFECYCLE_BUSY");
        assert!(payload["message"].as_str().unwrap().contains("Retry"));
        assert!(!String::from_utf8_lossy(&body).contains(".lock"));
    }
    drop(guard);
    std::fs::remove_file(socket).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn test_system_update_blocks_package_lifecycle_until_terminal() {
    let status = |completed: bool| af_models::SelfUpdateJobStatus {
        status: if completed { "succeeded" } else { "running" }.to_string(),
        completed,
        success: completed,
        job_unit: "aetherflow-self-update-deploy-nightly-0123abcd.service".to_string(),
        error: String::new(),
        exit_code: if completed { Some(0) } else { None },
    };
    assert!(
        system_update_lifecycle_block_with(|| async { Ok(status(false)) })
            .await
            .is_some()
    );
    let running = system_update_lifecycle_block_with(|| async { Ok(status(false)) })
        .await
        .expect("running updater must block lifecycle jobs");
    assert!(running.to_string().contains("in progress"));
    let unavailable = system_update_lifecycle_block_with(|| async {
        Err(anyhow::anyhow!("runner socket connection refused"))
    })
    .await
    .expect("unknown status for a launched updater fails closed");
    assert!(unavailable.to_string().contains("unavailable"));
    assert!(
        system_update_lifecycle_block_with(|| async { Ok(status(true)) })
            .await
            .is_none()
    );
    assert!(system_update_lifecycle_block_with(|| async {
        Err(anyhow::anyhow!("self-update job 'x' not found"))
    })
    .await
    .is_some());
}

#[tokio::test]
async fn test_update_prestop_uses_daemon_and_timer_policy_not_jobs_or_unconfigured_mounts() {
    for (app, expected) in [
        ("recyclarr", vec!["recyclarr.timer".to_string()]),
        ("rclone", vec!["rclone".to_string()]),
    ] {
        let stopped = pre_stop_units_for_package_update_with(
            "update",
            app,
            "",
            |app_id| af_services::resolve_controllable_service_units_with(app_id, "restart", false),
            |_unit| "running".to_string(),
            |_unit, _action| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(stopped, expected);
    }
}

#[test]
fn test_installer_managed_ports_use_marketplace_fallback_range() {
    let blueprint = af_services::get_blueprint("uptimekuma").unwrap();
    assert_eq!(blueprint.fallback_port_range, [0, 0]);
    let [start, end] = af_models::MARKETPLACE_FALLBACK_PORT_RANGE;
    let port = allocate_or_resolve_app_port_with(
        &blueprint.app_name,
        blueprint.default_port,
        |_| Ok(None),
        |_| Ok([blueprint.default_port, start].into()),
    );
    assert!((start + 1..=end).contains(&port));

    let plex = af_services::get_blueprint("plex").unwrap();
    assert_eq!(
        allocate_or_resolve_app_port_with(
            &plex.app_name,
            plex.default_port,
            |_| Ok(None),
            |_| Ok([plex.default_port].into()),
        ),
        0
    );
}

#[test]
fn test_port_reservation_lookup_failure_fails_closed() {
    let port_when_reserved_err = allocate_or_resolve_app_port_with(
        "sonarr",
        8989,
        |_| Ok(None),
        |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
    );
    assert_eq!(
        port_when_reserved_err, 0,
        "reserved-port query failure must return 0 instead of handing out default port"
    );

    let port_when_existing_err = allocate_or_resolve_app_port_with(
        "sonarr",
        8989,
        |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
        |_| Ok(std::collections::BTreeSet::new()),
    );
    assert_eq!(
        port_when_existing_err, 0,
        "existing ingress lookup failure must return 0 instead of falling through"
    );

    let resolved = resolve_package_lifecycle_port_with(
        "install",
        "sonarr",
        8989,
        |_| 0,
        |_| Ok(None),
        |app, def| {
            allocate_or_resolve_app_port_with(
                app,
                def,
                |_| Ok(None),
                |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
            )
        },
    );
    assert!(
        resolved.is_err(),
        "resolve_package_lifecycle_port_with must fail closed when reserved-port lookup fails"
    );
}

#[tokio::test]
async fn test_incomplete_rollback_refuses_to_restart_pre_stopped_units_in_api() {
    let restarted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let restarted_clone = restarted.clone();
    let stopped = vec!["sonarr".to_string(), "sonarr.timer".to_string()];
    let (kind, msg) = restore_pre_stopped_units_after_installer_failure_with(
            "sonarr",
            &stopped,
            "Package update failed; incomplete rollback: recovery backup preserved at /var/lib/sonarr.bak",
            move |unit, action| {
                let restarted_clone = restarted_clone.clone();
                async move {
                    restarted_clone
                        .lock()
                        .unwrap()
                        .push(format!("{action} {unit}"));
                    Ok(())
                }
            },
        )
        .await;
    assert_eq!(kind, af_services::PackageJobFailure::ServiceRestore);
    assert!(
        msg.contains("Refusing to restart pre-stopped service after incomplete rollback"),
        "unexpected message: {msg}"
    );
    assert!(
        restarted.lock().unwrap().is_empty(),
        "pre-stopped units must NOT be started when rollback is incomplete"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_action_dispatch_does_not_block_install_reinstall_or_remove_on_update_errors_or_retirement(
) {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    async fn settle_dispatched_job(response: axum::response::Response, package: &str) {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let job_id = body["job_id"].as_str().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
            loop {
                if af_services::get_package_job_outcome(package)
                    .is_some_and(|outcome| outcome.job_id == job_id)
                {
                    break;
                }
                interval.tick().await;
            }
            // The outcome is committed before the worker drops its guard.
            // Wait for that task to release admission before the next action.
            let _finished = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        })
        .await
        .expect("the dispatched fixture job must settle before the next action");
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    let test_pkg = af_models::Package {
        name: "test-err-pkg".into(),
        label: "Test Error Pkg".into(),
        service_name: "test-err-pkg".into(),
        lock_file: "/install/.test-err-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let retired_pkg = af_models::Package {
        name: "readarr".into(),
        label: "Readarr".into(),
        service_name: "readarr".into(),
        lock_file: "/install/.readarr.lock".into(),
        status: "installed".into(),
        update_source: "retired".into(),
        ..Default::default()
    };
    let uninstalled_pkg = af_models::Package {
        name: "test-fresh-pkg".into(),
        label: "Test Fresh Pkg".into(),
        service_name: "test-fresh-pkg".into(),
        lock_file: "/install/.test-fresh-pkg.lock".into(),
        status: "not_installed".into(),
        ..Default::default()
    };

    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![
            test_pkg.clone(),
            retired_pkg.clone(),
            uninstalled_pkg.clone(),
        ])
        .unwrap(),
    )
    .unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    let install_scripts = root.join("packages/package/install");
    let remove_scripts = root.join("packages/package/remove");
    let update_scripts = root.join("packages/package/update");
    std::fs::create_dir_all(&install_scripts).unwrap();
    std::fs::create_dir_all(&remove_scripts).unwrap();
    std::fs::create_dir_all(&update_scripts).unwrap();
    for id in ["test-err-pkg", "readarr", "test-fresh-pkg"] {
        let inst_file = install_scripts.join(format!("installpackage-{id}"));
        let rem_file = remove_scripts.join(format!("removepackage-{id}"));
        let upd_file = update_scripts.join(format!("updatepackage-{id}"));
        std::fs::write(&inst_file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem_file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&upd_file, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&inst_file, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&rem_file, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&upd_file, std::fs::Permissions::from_mode(0o755));
        }
    }
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    // Seed app_updates with an upstream error for test-err-pkg
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, latest_version, last_error) VALUES ('test-err-pkg', '', 'GitHub rate limit exceeded')",
                [],
            ).unwrap();
    }

    let admin = progress_test_user("admin", None);
    // A. Verify 'remove' succeeds even when app_updates has a last_error
    let res_remove = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_remove.status(),
        StatusCode::OK,
        "remove must not be blocked by app_updates last_error"
    );
    settle_dispatched_job(res_remove, "test-err-pkg").await;

    // B. Verify 'install' succeeds on uninstalled package without app_updates record
    let res_install = dispatch_package_lifecycle_with_target(
        "test-fresh-pkg".into(),
        "install",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_install.status(),
        StatusCode::OK,
        "install must not require app_updates or confirmed target"
    );
    settle_dispatched_job(res_install, "test-fresh-pkg").await;

    // C. Verify 'reinstall' succeeds even when app_updates has last_error
    let res_reinstall = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "reinstall",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_reinstall.status(),
        StatusCode::OK,
        "reinstall must not be blocked by app_updates last_error"
    );
    settle_dispatched_job(res_reinstall, "test-err-pkg").await;

    // D. Verify 'remove' succeeds unconditionally on a retired package (readarr)
    let res_retired_remove = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_retired_remove.status(),
        StatusCode::OK,
        "remove on retired package must succeed unconditionally"
    );
    settle_dispatched_job(res_retired_remove, "readarr").await;

    // E. Verify 'update' on test-err-pkg IS blocked by app_updates last_error
    let res_update_blocked = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_update_blocked.status(),
        StatusCode::CONFLICT,
        "update MUST be blocked by app_updates error"
    );

    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_explicit_target_confirmation_and_stale_error_policy() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    let pkg = af_models::Package {
        name: "test-target-pkg".into(),
        label: "Test Target Pkg".into(),
        service_name: "test-target-pkg".into(),
        lock_file: "/install/.test-target-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let rem_pkg = af_models::Package {
        name: "test-remove-pkg".into(),
        label: "Test Remove Pkg".into(),
        service_name: "test-remove-pkg".into(),
        lock_file: "/install/.test-remove-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let reinst_pkg = af_models::Package {
        name: "test-reinstall-pkg".into(),
        label: "Test Reinstall Pkg".into(),
        service_name: "test-reinstall-pkg".into(),
        lock_file: "/install/.test-reinstall-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let inst_pkg = af_models::Package {
        name: "test-install-pkg".into(),
        label: "Test Install Pkg".into(),
        service_name: "test-install-pkg".into(),
        lock_file: "/install/.test-install-pkg.lock".into(),
        status: "not_installed".into(),
        ..Default::default()
    };
    let readarr_pkg = af_models::Package {
        name: "readarr".into(),
        label: "Readarr".into(),
        service_name: "readarr".into(),
        lock_file: "/install/.readarr.lock".into(),
        status: "installed".into(),
        update_source: "retired".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![
            pkg.clone(),
            rem_pkg.clone(),
            reinst_pkg.clone(),
            inst_pkg.clone(),
            readarr_pkg.clone(),
        ])
        .unwrap(),
    )
    .unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    let update_scripts = root.join("packages/package/update");
    let install_scripts = root.join("packages/package/install");
    let remove_scripts = root.join("packages/package/remove");
    std::fs::create_dir_all(&update_scripts).unwrap();
    std::fs::create_dir_all(&install_scripts).unwrap();
    std::fs::create_dir_all(&remove_scripts).unwrap();
    for id in [
        "test-target-pkg",
        "test-remove-pkg",
        "test-reinstall-pkg",
        "test-install-pkg",
        "readarr",
    ] {
        for dir in [&update_scripts, &install_scripts, &remove_scripts] {
            let script = dir.join(format!("updatepackage-{id}"));
            let _ = std::fs::write(&script, "#!/bin/sh\nexit 0\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
            }
        }
        let inst_script = install_scripts.join(format!("installpackage-{id}"));
        let rem_script = remove_scripts.join(format!("removepackage-{id}"));
        std::fs::write(&inst_script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem_script, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&inst_script, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&rem_script, std::fs::Permissions::from_mode(0o755));
        }
    }

    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.test-target-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.test-remove-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.test-reinstall-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.readarr.lock"), "installed").unwrap();

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    let admin = progress_test_user("admin", None);
    async fn wait_and_clear_job(pkg_name: &str) {
        for _ in 0..500 {
            let still_active = af_services::package_job_snapshot()
                .map(|snap| snap.active.contains_key(pkg_name))
                .unwrap_or(false);
            if !still_active {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        af_services::clear_package_job_info(pkg_name);
    }

    // 1. Update with explicit target when app_updates row is missing -> 409 Conflict
    let res_missing = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_missing.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    let expected_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &pkg);
    // Seed app_updates with db_latest = "v1.2.0" and last_error non-empty but WITHOUT prior confirmation provenance (checked_at = "", update_available = 0)
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
    }

    // 2a. Update with matching explicit target when app_updates has last_error and NO prior confirmation provenance -> 409 Conflict
    let res_unproven = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unproven.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // Now seed app_updates with proven prior confirmation provenance and subsequent rate limit error
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
    }

    // 2b. Implicit update (no explicit target) when last_error is present -> 409 Conflict
    let res_implicit = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_implicit.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 2c. Update with explicit unconfirmed target ("v9.9.9") when app_updates has db_latest = "v1.2.0" -> 409 Conflict
    let res_mismatch = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v9.9.9".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_mismatch.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 3. Update with explicit target matching previously confirmed db_latest = "v1.2.0" with proven provenance -> succeeds (200)
    let res_matching = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_matching.status(), StatusCode::OK);
    wait_and_clear_job("test-target-pkg").await;

    // 4. Install, reinstall, and remove still succeed when app_updates has last_error
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-remove-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-reinstall-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-install-pkg', '', '', 'Upstream repository unreachable')",
                [],
            ).unwrap();
    }

    let res_rem = dispatch_package_lifecycle_with_target(
        "test-remove-pkg".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_rem.status(), StatusCode::OK);
    wait_and_clear_job("test-remove-pkg").await;

    let res_reinst = dispatch_package_lifecycle_with_target(
        "test-reinstall-pkg".into(),
        "reinstall",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_reinst.status(), StatusCode::OK);
    wait_and_clear_job("test-reinstall-pkg").await;

    let res_inst = dispatch_package_lifecycle_with_target(
        "test-install-pkg".into(),
        "install",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_inst.status(), StatusCode::OK);
    wait_and_clear_job("test-install-pkg").await;

    // 5. Update with explicit target when last_error is present and update_available = 0 (even with valid checked_at and matching target) -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '2.0.0', '1.0.0', 0, '2026-11-08T10:00:00Z', 'Latest version could not be confirmed: 500', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unavail = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("1.0.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unavail.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 6. Update on retired package (readarr) when app_updates is missing -> 409 Conflict
    let res_retired_missing = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_missing.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    let readarr_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &readarr_pkg);
    // 7. Update on retired package (readarr) when app_updates has unconfirmed last_error -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('readarr', '0.4.17.2700', '0.4.18.2805', 0, '2026-11-08T10:00:00Z', 'Upstream repository unreachable', ?1)",
                [&readarr_source],
            ).unwrap();
    }
    let res_retired_err = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_err.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    let res_retired_err_explicit = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        Some("0.4.18.2805".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_err_explicit.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    // 8. Enforce confirmed provenance & source_key validation on EVERY update path (empty last_error)
    // 8a. Update with empty last_error and valid provenance & source_key -> 200 OK
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_clean_update = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_clean_update.status(), StatusCode::OK);
    wait_and_clear_job("test-target-pkg").await;

    // 8b. action == "update" with empty last_error and empty checked_at -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_empty_checked_at = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_empty_checked_at.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8c. action == "update" with empty last_error and empty/unknown installed_version -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_empty_installed = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_empty_installed.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'unknown', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unknown_installed = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unknown_installed.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8d. action == "update" with empty last_error and update_available = 0 -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unavail_no_err = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unavail_no_err.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8e. action == "update" with legacy empty source_key = '' or mismatched source_key -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', '')",
                [],
            ).unwrap();
    }
    let res_legacy_empty_source = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_legacy_empty_source.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', 'mismatched:source:key')",
                [],
            ).unwrap();
    }
    let res_mismatched_source = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_mismatched_source.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_progress_ingestion_and_projections_redact_secrets() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    // Test emit_package_progress ingests and stores redacted line
    let job_id = "secret-prog-job";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }
    ));

    emit_package_progress(
        "sonarr",
        "update",
        "updating",
        50,
        "Executing script with user_password=\"secret_pass_123\" and db_secret=secret_db_456",
        "test-time",
        job_id,
    );

    let info = af_services::get_package_job_info("sonarr").unwrap();
    assert!(!info.last_line.contains("secret_pass_123"));
    assert!(!info.last_line.contains("secret_db_456"));
    assert!(info.last_line.contains("[REDACTED]"));

    for line in [
        r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
        "Authorization: [REDACTED] FRAGMENT_CANARY",
    ] {
        emit_package_progress(
            "sonarr",
            "update",
            "updating",
            50,
            line,
            "test-time",
            job_id,
        );
        let current = af_services::get_package_job_info("sonarr").unwrap();
        assert!(!current.last_line.contains("FRAGMENT_CANARY"));
        let projected = package_progress_payload("sonarr", Some(current), None, true);
        assert!(!projected.to_string().contains("FRAGMENT_CANARY"));
    }

    // Test finish_package_lifecycle ingests and stores redacted message and summary
    finish_package_lifecycle(
        "sonarr",
        "update",
        Some(af_services::PackageJobFailure::TargetVerification),
        95,
        "Target mismatch with github_token=secret_gh_tok_789 and api_key=secret_api_key_000",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v1.0.0"),
        &[],
    );

    let outcome = af_services::get_package_job_outcome("sonarr").unwrap();
    assert!(!outcome.message.contains("secret_gh_tok_789"));
    assert!(!outcome.message.contains("secret_api_key_000"));
    if let Some(ref summary) = outcome.sanitized_summary {
        assert!(!summary.contains("secret_gh_tok_789"));
        assert!(!summary.contains("secret_api_key_000"));
        assert!(summary.contains("[REDACTED]"));
    }

    // Test package_progress_payload redacts secrets for admin view
    let progress_json = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
    assert!(!progress_json.to_string().contains("secret_gh_tok_789"));
    assert!(!progress_json.to_string().contains("secret_api_key_000"));

    // Test Authorization: Basic, curl -u, --pass, and JSON boundary redaction
    let job_id2 = "secret-prog-job-2";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id2.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }
    ));
    emit_package_progress(
            "sonarr",
            "update",
            "updating",
            60,
            "Running curl -u admin:mysecret123 http://target.local with --pass pass_val_456 and Authorization: Basic dXNlcjpwYXNz and password={\"raw\":\"boundary_secret_789\"}",
            "test-time",
            job_id2,
        );
    let info2 = af_services::get_package_job_info("sonarr").unwrap();
    assert!(!info2.last_line.contains("mysecret123"));
    assert!(!info2.last_line.contains("pass_val_456"));
    assert!(!info2.last_line.contains("dXNlcjpwYXNz"));
    assert!(!info2.last_line.contains("boundary_secret_789"));
    assert!(info2.last_line.contains("curl -u [REDACTED]"));
    assert!(info2.last_line.contains("--pass [REDACTED]"));
    assert!(info2.last_line.contains("Basic [REDACTED]"));
    assert!(info2.last_line.contains("[REDACTED]"));

    finish_package_lifecycle(
            "sonarr",
            "update",
            Some(af_services::PackageJobFailure::Installer),
            60,
            "Failed running curl -u admin:mysecret123 http://target with --pass pass_val_456 and Basic dXNlcjpwYXNz",
            "test-time",
            job_id2,
            Some("v2.0.0"),
            None,
            &[],
        );
    let outcome2 = af_services::get_package_job_outcome("sonarr").unwrap();
    assert!(!outcome2.message.contains("mysecret123"));
    assert!(!outcome2.message.contains("pass_val_456"));
    assert!(!outcome2.message.contains("dXNlcjpwYXNz"));
    if let Some(ref sum) = outcome2.sanitized_summary {
        assert!(!sum.contains("mysecret123"));
        assert!(!sum.contains("pass_val_456"));
        assert!(!sum.contains("dXNlcjpwYXNz"));
    }
    let progress_json2 = package_progress_payload("sonarr", None, Some(outcome2), true);
    assert!(!progress_json2.to_string().contains("mysecret123"));
    assert!(!progress_json2.to_string().contains("pass_val_456"));
    assert!(!progress_json2.to_string().contains("dXNlcjpwYXNz"));

    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_public_unauthenticated_catalog_strips_all_private_fields() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let ledger = connection.path().unwrap();
    std::fs::rename(ledger, root.join("unavailable-ledger.sqlite")).unwrap();
    assert!(af_services::package_job_snapshot().is_err());

    let response = get_marketplace_apps_blocking(HeaderMap::new(), false);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-aetherflow-inventory-mode")
            .unwrap()
            .to_str()
            .unwrap(),
        "public_redacted"
    );
    assert_eq!(
        response
            .headers()
            .get("x-aetherflow-inventory-authenticated")
            .unwrap()
            .to_str()
            .unwrap(),
        "false"
    );

    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let apps = payload
        .as_array()
        .expect("public response must be an array");
    assert!(!apps.is_empty(), "public catalog should return packages");

    for app in apps {
        let obj = app.as_object().expect("each item must be a JSON object");
        // Public fields that may be present:
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("desc"));
        assert!(obj.contains_key("category"));
        assert_eq!(obj.get("status").unwrap(), "not_installed");
        assert_eq!(obj.get("inventory_known").unwrap(), false);
        assert_eq!(obj.get("inventory_authenticated").unwrap(), false);
        assert_eq!(obj.get("inventory_mode").unwrap(), "public_redacted");

        // Private inventory and ingress fields that MUST be omitted:
        assert!(
            !obj.contains_key("internal_domain"),
            "internal_domain must be omitted"
        );
        assert!(
            !obj.contains_key("external_access_enabled"),
            "external_access_enabled must be omitted"
        );
        assert!(
            !obj.contains_key("tls_enabled"),
            "tls_enabled must be omitted"
        );
        assert!(
            !obj.contains_key("latest_version"),
            "latest_version must be omitted"
        );
        assert!(
            !obj.contains_key("installed_version"),
            "installed_version must be omitted"
        );
        assert!(
            !obj.contains_key("checked_at"),
            "checked_at must be omitted"
        );
        assert!(
            !obj.contains_key("update_checked_at"),
            "update_checked_at must be omitted"
        );
        assert!(
            !obj.contains_key("update_url"),
            "update_url must be omitted"
        );
        assert!(
            !obj.contains_key("update_error"),
            "update_error must be omitted"
        );
        assert!(
            !obj.contains_key("update_available"),
            "update_available must be omitted"
        );
        assert!(
            !obj.contains_key("active_port"),
            "active_port must be omitted"
        );
        assert!(
            !obj.contains_key("public_domain"),
            "public_domain must be omitted"
        );
        assert!(!obj.contains_key("launch_url"));
        assert!(!obj.contains_key("launch_scope"));
        assert!(
            !obj.contains_key("active_job"),
            "active_job must be omitted"
        );
        assert!(!obj.contains_key("last_job"), "last_job must be omitted");
        assert!(
            !obj.contains_key("last_job_outcome"),
            "last_job_outcome must be omitted"
        );
        assert!(!obj.contains_key("progress"), "progress must be omitted");
        assert!(!obj.contains_key("log_line"), "log_line must be omitted");
        assert!(
            !obj.contains_key("started_at"),
            "started_at must be omitted"
        );
        assert!(!obj.contains_key("job_id"), "job_id must be omitted");
    }

    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

static RECEIPT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_candidate_receipt_snapshot_and_restoration_with_target_certification_failure() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-receipt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
    let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
    std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

    let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

    // 2. Simulate installer making changes (overwriting existing, creating new)
    std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
    let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
    std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

    // 3. Target certification fails -> restore candidate receipts
    restore_candidate_receipts(&snapshots).unwrap();

    // 4. Verify previous receipt is restored and new receipt was removed
    assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
    assert!(
        !opt_syncthing.exists(),
        "uncertified new receipt must be removed"
    );

    // 5. Verify TargetVerification reports stage target_certification_after_install_commit
    let job_id = "test-target-cert-job";
    let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: "syncthing".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "init".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v3.0.0".into()),
    });
    finish_package_lifecycle(
            "syncthing",
            "update",
            Some(af_services::PackageJobFailure::TargetVerification),
            95,
            "Target certification failed after installer execution (runtime state may be partially committed): expected v3.0.0, achieved v2.0.0",
            "test-time",
            job_id,
            Some("v3.0.0"),
            Some("v2.0.0"),
            &[],
        );
    let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(outcome.status, "failed");
    assert_eq!(
        outcome.failed_stage.as_deref(),
        Some("target_certification_after_install_commit")
    );
    assert!(outcome
        .sanitized_summary
        .as_ref()
        .unwrap()
        .contains("Target certification failed after installer execution"));
    assert_eq!(
        outcome.message,
        af_services::PackageJobFailure::TargetVerification.summary()
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_symlink_swap_restoration_does_not_overwrite_victim() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-swap-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/radarr/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"1.0.0").unwrap();

    let victim_file = temp_dir.join("victim");
    std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("radarr").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &receipt_path && bytes.as_deref() == Some(b"1.0.0")));

    // 2. Attacker swaps receipt for a symlink pointing to /tmp/victim
    std::fs::remove_file(&receipt_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

    // 3. Restore candidate receipts
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration should succeed: {:?}",
        restore_res
    );

    // 4. Victim file must NOT be overwritten!
    let victim_content = std::fs::read(&victim_file).unwrap();
    assert_eq!(victim_content, b"VICTIM_INTACT_CONTENT");

    // 5. Receipt file must be restored as a regular file (not a symlink) with original bytes
    let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    assert!(
        meta.file_type().is_file(),
        "Receipt must be restored as a regular file"
    );
    assert!(
        !meta.file_type().is_symlink(),
        "Receipt must not be a symlink"
    );
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_snapshot_fails_closed_on_symlink_fifo_or_oversized() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-bad-receipt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/sonarr/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();

    // 1. Symlink at receipt path fails closed
    let dummy_target = temp_dir.join("dummy_target");
    std::fs::write(&dummy_target, b"test").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dummy_target, &receipt_path).unwrap();
    let sym_err = snapshot_candidate_receipts("sonarr");
    assert!(
        sym_err.is_err(),
        "Snapshot must fail closed on symlink receipt"
    );
    assert!(sym_err.unwrap_err().contains("symlink or non-regular file"));
    let _ = std::fs::remove_file(&receipt_path);

    // 2. FIFO at receipt path fails closed
    #[cfg(unix)]
    {
        let cstr = std::ffi::CString::new(receipt_path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::mkfifo(cstr.as_ptr(), 0o644) };
        assert_eq!(res, 0);
        let fifo_err = snapshot_candidate_receipts("sonarr");
        assert!(
            fifo_err.is_err(),
            "Snapshot must fail closed on FIFO receipt"
        );
        assert!(fifo_err
            .unwrap_err()
            .contains("symlink or non-regular file"));
        let _ = std::fs::remove_file(&receipt_path);
    }

    // 3. File > 64 KiB at receipt path fails closed
    let oversized = vec![b'X'; 64 * 1024 + 1];
    std::fs::write(&receipt_path, &oversized).unwrap();
    let size_err = snapshot_candidate_receipts("sonarr");
    assert!(
        size_err.is_err(),
        "Snapshot must fail closed on oversized receipt"
    );
    assert!(size_err.unwrap_err().contains("exceeds 64 KiB limit"));
    let _ = std::fs::remove_file(&receipt_path);

    // 4. Ancestor directory being a symlink fails closed
    let ancestor_link = temp_dir.join("var/lib/sonarr");
    let _ = std::fs::remove_dir(&ancestor_link);
    let real_dir = temp_dir.join("real_sonarr");
    std::fs::create_dir_all(&real_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, &ancestor_link).unwrap();
    std::fs::write(ancestor_link.join(".af-version"), b"1.0.0").unwrap();
    let ancestor_err = snapshot_candidate_receipts("sonarr");
    assert!(
        ancestor_err.is_err(),
        "Snapshot must fail closed on symlink ancestor"
    );
    assert!(ancestor_err.unwrap_err().contains("is a symlink"));

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_intermediate_ancestor_symlink_fails_closed() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-intermediate-symlink-{}",
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Intermediate ancestor "var/lib" is a symlink to "real_lib"
    let real_lib = temp_dir.join("real_lib");
    std::fs::create_dir_all(real_lib.join("syncthing")).unwrap();
    std::fs::write(real_lib.join("syncthing/.af-version"), b"1.0.0").unwrap();

    let var_dir = temp_dir.join("var");
    std::fs::create_dir_all(&var_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_lib, var_dir.join("lib")).unwrap();

    // 1. Snapshot must fail closed because intermediate ancestor "lib" is a symlink
    let snap_err = snapshot_candidate_receipts("syncthing");
    assert!(
        snap_err.is_err(),
        "Snapshot must fail closed when intermediate ancestor is a symlink"
    );
    assert!(snap_err.unwrap_err().contains("is a symlink"));

    // 2. Restore must also fail closed
    let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
    let fake_snapshot: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(
        receipt_path.clone(),
        Some(ReceiptSnapshotEntry::from(b"2.0.0".to_vec())),
    )];
    let restore_err = restore_candidate_receipts(&fake_snapshot);
    assert!(
        restore_err.is_err(),
        "Restore must fail closed when intermediate ancestor is a symlink"
    );
    assert!(restore_err.unwrap_err().contains("is a symlink"));

    // 3. Restore None (uncertified receipt removal) must also fail closed on symlink ancestor
    let fake_snapshot_none: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
        vec![(receipt_path, None)];
    let restore_none_err = restore_candidate_receipts(&fake_snapshot_none);
    assert!(
        restore_none_err.is_err(),
        "Restore None must fail closed when intermediate ancestor is a symlink"
    );
    assert!(restore_none_err.unwrap_err().contains("is a symlink"));

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_lifecycle_job_fails_closed_and_restores_receipts_on_service_restart_failure() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-service-restart-fail-{}",
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
    let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
    std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

    let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

    // 2. Simulate installer making changes
    std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
    let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
    std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

    // 3. Service restart failed: stopped unit is inactive
    let stopped_units = vec!["nonexistent-restart-fail.service".to_string()];

    // Receipts are rolled back
    restore_candidate_receipts(&snapshots).unwrap();
    assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
    assert!(!opt_syncthing.exists());

    // 4. Job lifecycle finishes with finish_package_lifecycle
    let job_id = "test-service-restart-fail-job";
    let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: "syncthing".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "init".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v2.0.0".into()),
    });

    // Even if the caller passed failure: None and progress: 100,
    // finish_package_lifecycle must verify stopped_units and fail closed!
    finish_package_lifecycle(
        "syncthing",
        "update",
        None,
        100,
        "Completed update for syncthing",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v2.0.0"),
        &stopped_units,
    );

    let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_ne!(
        outcome.status, "completed",
        "Job must NEVER be completed if stopped unit failed to restart"
    );
    assert_eq!(outcome.status, "failed");
    assert_eq!(outcome.failed_stage.as_deref(), Some("service_restore"));
    assert!(
        outcome.message.contains("service")
            || outcome.message.contains("stopped")
            || outcome
                .sanitized_summary
                .as_ref()
                .map(|s| s.contains("service") || s.contains("stopped"))
                .unwrap_or(false)
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_sanitize_url_or_source_key_for_api_strips_credentials() {
    let sample_url = "https://user:super_secret@git.example.com/team/App.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(sample_url),
        "https://git.example.com/team/App.git"
    );

    let url_with_query =
        "https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main";
    assert_eq!(
        sanitize_url_or_source_key_for_api(url_with_query),
        "https://git.example.com/team/App.git"
    );

    let release_url_with_query =
        "https://github.com/org/repo/releases/v1.1.0?download=true&token=xyz";
    assert_eq!(
        sanitize_url_or_source_key_for_api(release_url_with_query),
        "https://github.com/org/repo/releases/v1.1.0"
    );

    let sample_key = "git_head:https://user:super_secret@git.example.com/team/App.git|team/App";
    assert_eq!(
        sanitize_url_or_source_key_for_api(sample_key),
        "git_head:https://git.example.com/team/App.git|team/App"
    );

    let key_with_query = "git_head:https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main|team/App";
    assert_eq!(
        sanitize_url_or_source_key_for_api(key_with_query),
        "git_head:https://git.example.com/team/App.git?token=[REDACTED]&branch=main|team/App"
    );

    let ssh_url = "ssh://user:super_secret@git.example.com/team/App.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(ssh_url),
        "ssh://git.example.com/team/App.git"
    );

    let token_url = "https://ghp_supersecret12345@github.com/org/repo.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(token_url),
        "https://github.com/org/repo.git"
    );

    let err_diagnostic = "Clone failed for https://user:pass@host/repo: password=\"secret123\"";
    let sanitized_err = sanitize_url_or_source_key_for_api(err_diagnostic);
    assert!(!sanitized_err.contains("user:pass@"));
    assert!(!sanitized_err.contains("secret123"));
    assert_eq!(
        sanitized_err,
        "Clone failed for https://host/repo: password=[REDACTED]"
    );
}

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

#[test]
fn test_admin_update_response_sanitizes_credentials() {
    let rec = af_services::workers::PackageUpdateRecord {
        package_id: "testapp".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-09T10:00:00Z".to_string(),
        release_url: "https://user:secret_token@git.example.com/org/testapp/releases/v1.1.0"
            .to_string(),
        error: "connection failed with password=\"super_secret_pw\" to https://admin:pwd@host/repo"
            .to_string(),
        source_key: "git_head:https://user:secret_token@git.example.com/org/testapp.git|main"
            .to_string(),
    };

    let sanitized_rec = sanitize_package_update_record(rec.clone());
    assert_eq!(
        sanitized_rec.release_url,
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        sanitized_rec.source_key,
        "git_head:https://git.example.com/org/testapp.git|main"
    );
    assert!(!sanitized_rec.error.contains("super_secret_pw"));
    assert!(!sanitized_rec.error.contains("pwd@"));

    let body = build_single_package_update_response("testapp", Some(rec));
    let body_str = body.to_string();
    assert!(!body_str.contains("secret_token"));
    assert!(!body_str.contains("super_secret_pw"));
    assert!(!body_str.contains("pwd@"));
    assert_eq!(
        body["update_url"],
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        body["release_url"],
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        body["update_source_key"],
        "git_head:https://git.example.com/org/testapp.git|main"
    );
}

#[test]
fn test_sanitize_package_update_record_redacts_installed_version() {
    let rec = af_services::workers::PackageUpdateRecord {
            package_id: "testapp".to_string(),
            installed: true,
            installed_version: "https://user:leak_token@git.example.com/app/v1.0.0?token=leak#secret-frag".to_string(),
            latest_version: "https://user:leak_token@git.example.com/app/v2.0.0?token=leak#secret-frag".to_string(),
            update_available: true,
            checked_at: "2026-11-09T10:00:00Z".to_string(),
            release_url: "https://user:leak_token@git.example.com/org/testapp/releases/v2.0.0?token=leak#secret-frag".to_string(),
            error: "failure with password=\"leak_pw\"".to_string(),
            source_key: "git_head:https://user:leak_token@git.example.com/org/testapp.git|main".to_string(),
        };

    let sanitized_rec = sanitize_package_update_record(rec);
    assert_eq!(
        sanitized_rec.installed_version,
        "https://git.example.com/app/v1.0.0"
    );
    assert!(!sanitized_rec.installed_version.contains("leak_token"));
    assert!(!sanitized_rec.installed_version.contains("secret-frag"));
    assert!(!sanitized_rec.installed_version.contains("token=leak"));

    let rec_kv = af_services::workers::PackageUpdateRecord {
        package_id: "testapp".to_string(),
        installed: true,
        installed_version: "1.2.3 token=leak_secret_token_123".to_string(),
        latest_version: "1.2.4".to_string(),
        update_available: true,
        checked_at: "2026-11-09T10:00:00Z".to_string(),
        release_url: "https://github.com/org/repo".to_string(),
        error: String::new(),
        source_key: "github:org/repo".to_string(),
    };
    let sanitized_kv = sanitize_package_update_record(rec_kv);
    assert_eq!(sanitized_kv.installed_version, "1.2.3 token=[REDACTED]");
    assert!(!sanitized_kv
        .installed_version
        .contains("leak_secret_token_123"));
}

#[test]
fn test_sanitize_url_or_source_key_for_api_strips_fragments_and_queries() {
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "https://user:pass@github.com/org/repo?token=1#secret-frag"
        ),
        "https://github.com/org/repo"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("git@github.com:org/repo.git?token=1#secret-frag"),
        "git@github.com:org/repo.git"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("user:pass@host:path?token=1#secret-frag"),
        "user@host:path"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("https://example.com/download#hash"),
        "https://example.com/download"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        ),
        "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"
        ),
        "git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:https://user:pass@github.com/org/repo?bad_query#main"
        ),
        "git-repo:https://github.com/org/repo#main"
    );
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

#[test]
fn test_restore_candidate_receipts_creates_missing_directories_via_stepwise_mkdirat() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-mkdirat-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Nested parent directory does NOT exist initially
    let nested_receipt = temp_dir.join("var/lib/syncthing/.af-version");
    assert!(!nested_receipt.parent().unwrap().exists());

    let snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(
        nested_receipt.clone(),
        Some(ReceiptSnapshotEntry::from(b"1.5.0".to_vec())),
    )];
    // Must succeed using stepwise descriptor-relative mkdirat + openat without std::fs::create_dir_all
    let res = restore_candidate_receipts(&snapshots);
    assert!(
        res.is_ok(),
        "Restoration must create missing directories safely: {:?}",
        res
    );
    assert_eq!(std::fs::read(&nested_receipt).unwrap(), b"1.5.0");

    // None case where parent does not exist should cleanly succeed as no-op
    let non_existent_file = temp_dir.join("opt/nonexistent/.af-version");
    let none_snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
        vec![(non_existent_file.clone(), None)];
    let none_res = restore_candidate_receipts(&none_snapshots);
    assert!(
        none_res.is_ok(),
        "None restoration with ENOENT parent must succeed as no-op"
    );
    assert!(!non_existent_file.exists());

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_finish_package_lifecycle_appends_inactive_stopped_units_diagnostics_when_failure_already_present(
) {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let job_id = "test-inactive-diag-job";
    let pkg_id = "syncthing";
    af_services::clear_package_job_info(pkg_id);
    let started = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: pkg_id.into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "initial state".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v2.0.0".into()),
    });
    assert!(started, "Job must start");

    let stopped_units = vec!["nonexistent-inactive-dummy.service".to_string()];

    // Failure is already set (e.g. TargetVerification)
    finish_package_lifecycle(
        pkg_id,
        "update",
        Some(af_services::PackageJobFailure::TargetVerification),
        95,
        "Target certification failed: expected v2.0.0, achieved v1.0.0",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v1.0.0"),
        &stopped_units,
    );

    let outcome = af_services::get_package_job_outcome(pkg_id).unwrap();
    assert_eq!(outcome.status, "failed");
    let summary = outcome.sanitized_summary.as_deref().unwrap_or("");
    assert!(
        summary.contains("nonexistent-inactive-dummy.service")
            || summary.contains("stopped services failed to resume"),
        "Sanitized summary must contain inactive unit diagnostics: {summary}"
    );
}

#[test]
fn test_candidate_receipt_paths_includes_blueprint_config_and_restores_atomically() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-bp-config-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let (pkg, cfg_path) = if let Some(bp) =
        af_services::get_blueprint("radarr").filter(|b| !b.config_file_path.trim().is_empty())
    {
        ("radarr", bp.config_file_path.clone())
    } else if let Some(bp) =
        af_services::get_blueprint("sonarr").filter(|b| !b.config_file_path.trim().is_empty())
    {
        ("sonarr", bp.config_file_path.clone())
    } else {
        ("radarr", "/etc/radarr/config.xml".to_string())
    };

    let paths = marketplace::resolve_candidate_receipt_paths(pkg);
    let rel_trimmed = cfg_path.trim_start_matches(['/', '\\']);
    let expected_cfg = temp_dir.join(rel_trimmed);
    assert!(
        paths.contains(&expected_cfg),
        "Candidate receipt paths must include blueprint config {expected_cfg:?}, got: {paths:?}"
    );

    let _ = std::fs::create_dir_all(expected_cfg.parent().unwrap());
    std::fs::write(&expected_cfg, b"<Config><Port>7878</Port></Config>").unwrap();

    let snapshots = snapshot_candidate_receipts(pkg).unwrap();
    assert!(
        snapshots.iter().any(|(p, b)| p == &expected_cfg
            && b.as_deref() == Some(b"<Config><Port>7878</Port></Config>")),
        "Blueprint config must be snapshotted"
    );

    std::fs::write(
        &expected_cfg,
        b"<Config><Port>9999</Port><Corrupted/></Config>",
    )
    .unwrap();

    restore_candidate_receipts(&snapshots).unwrap();

    assert_eq!(
        std::fs::read(&expected_cfg).unwrap(),
        b"<Config><Port>7878</Port></Config>",
        "Blueprint config must be rolled back on certification or restart failure"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_preserves_mode_and_ownership_on_restoration() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-mode-restore-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"v1.0.0-secret").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let initial_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    let (initial_mode, initial_uid, initial_gid) = {
        use std::os::unix::fs::MetadataExt;
        (
            initial_meta.mode() & 0o7777,
            initial_meta.uid(),
            initial_meta.gid(),
        )
    };
    #[cfg(unix)]
    assert_eq!(initial_mode, 0o600);

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    let snap_entry = snapshots
        .iter()
        .find(|(p, _)| p == &receipt_path)
        .and_then(|(_, e)| e.as_ref())
        .expect("receipt must be snapshotted");

    assert_eq!(snap_entry.bytes, b"v1.0.0-secret");
    #[cfg(unix)]
    {
        assert_eq!(snap_entry.mode, 0o600);
        assert_eq!(snap_entry.uid, initial_uid);
        assert_eq!(snap_entry.gid, initial_gid);
    }

    // 2. Simulate installer/attacker clobbering the file: modifying bytes and changing permissions to 0o644
    std::fs::write(&receipt_path, b"v2.0.0-clobbered").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let clobbered_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(clobbered_meta.mode() & 0o7777, 0o644);
    }

    // 3. Call restore_candidate_receipts
    restore_candidate_receipts(&snapshots).unwrap();

    // 4. Verify exact bytes restored
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"v1.0.0-secret");

    // 5. Verify mode is 0600 (NEVER 0644) and uid/gid preserved
    let restored_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            restored_meta.mode() & 0o7777,
            0o600,
            "Mode must be restored to 0600, never left as 0644"
        );
        assert_eq!(restored_meta.uid(), initial_uid, "UID must be preserved");
        assert_eq!(restored_meta.gid(), initial_gid, "GID must be preserved");
    }

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave22_api_sanitize_scalar_credentials_and_filebot_receipts() {
    let paths = marketplace::resolve_candidate_receipt_paths("filebot");
    assert!(
        paths
            .iter()
            .any(|p| p.to_string_lossy().contains("filebot-node")),
        "FileBot receipt paths must include opt/filebot-node/.af-version: {paths:?}"
    );

    let cases = [
        "Cookie: session=CANARY_COOKIE",
        "session=CANARY_SESSION",
        "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
        "pass=CANARY_PASSWORD",
        "https://example.test/cb?session=CANARY_Q1&pass=CANARY_Q2&webhook_url=CANARY_Q3",
    ];
    for case in cases {
        let sanitized = sanitize_url_or_source_key_for_api(case);
        assert!(
                !sanitized.contains("CANARY_"),
                "CANARY_ leaked in sanitize_url_or_source_key_for_api for input: {case:?}, got: {sanitized:?}"
            );
    }
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

#[test]
fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
    let clean_plex = "plex";
    let mut plex_units = af_services::resolve_controllable_service_units(clean_plex, "stop");
    if let Ok(pkgs) = af_services::get_packages() {
        if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_plex) {
            let svc = p.service_name.trim().to_string();
            if !svc.is_empty()
                && !matches!(
                    svc.as_str(),
                    "apache2" | "nginx" | "apache2.service" | "nginx.service"
                )
                && !plex_units.contains(&svc)
            {
                plex_units.push(svc);
            }
        }
    }
    let clean_mcvnc = "mcvnc";
    let mut mcvnc_units = af_services::resolve_controllable_service_units(clean_mcvnc, "stop");
    if let Ok(pkgs) = af_services::get_packages() {
        if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_mcvnc) {
            let svc = p.service_name.trim().to_string();
            if !svc.is_empty()
                && !matches!(
                    svc.as_str(),
                    "apache2" | "nginx" | "apache2.service" | "nginx.service"
                )
                && !mcvnc_units.contains(&svc)
            {
                mcvnc_units.push(svc);
            }
        }
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-w23-api-footprint-{}",
        uuid::Uuid::new_v4()
    ));
    let mut env_cfg = af_runner::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sysd = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&sysd).unwrap();
    let mcvnc_file = sysd.join("af-mcvnc.service");
    std::fs::write(&mcvnc_file, b"OLD_MCVNC").unwrap();

    let mut mcvnc_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        clean_mcvnc,
        &mcvnc_units,
        &env_cfg,
        false,
    )
    .unwrap();

    std::fs::write(&mcvnc_file, b"NEW_MCVNC").unwrap();
    mcvnc_snap.restore().unwrap();
    assert_eq!(std::fs::read(&mcvnc_file).unwrap(), b"OLD_MCVNC");

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
#[tokio::test]
async fn plex_streaming_put_persists_configuration_and_audits_the_change() {
    use super::*;
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
    let app = super::build_v1_router();
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
    use super::*;
    use crate::plugins::tests::run_plugin_test_in_subprocess;
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    env::remove_var("AF_DISABLE_RATELIMIT");
    let router = super::build_v1_router();
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

#[tokio::test(flavor = "current_thread")]
async fn marketplace_enforces_threadfin_pinned_and_pihole_vendor_target_policies() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);
    std::env::remove_var("AF_THREADFIN_SHA256");
    std::env::remove_var("AF_THREADFIN_VERSION");

    let pihole_pkg = af_models::Package {
        name: "pihole".into(),
        label: "Pi-hole".into(),
        service_name: "pihole-FTL".into(),
        lock_file: "/install/.pihole.lock".into(),
        status: "installed".into(),
        update_source: "vendor".into(),
        ..Default::default()
    };
    let threadfin_pkg = af_models::Package {
        name: "threadfin".into(),
        label: "Threadfin".into(),
        service_name: "threadfin".into(),
        lock_file: "/install/.threadfin.lock".into(),
        status: "installed".into(),
        update_source: "pinned".into(),
        update_package: "1.2.37".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![pihole_pkg.clone(), threadfin_pkg.clone()]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &automation,
        serde_json::json!({
            "pihole": { "update_source": "vendor", "require_download_sha256": true },
            "threadfin": { "update_source": "pinned", "update_package": "1.2.37", "require_download_sha256": true }
        })
        .to_string(),
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    for id in ["pihole", "threadfin"] {
        std::fs::write(root.join(format!("install/.{id}.lock")), "installed\n").unwrap();
        let inst = root.join(format!("packages/package/install/installpackage-{id}"));
        let rem = root.join(format!("packages/package/remove/removepackage-{id}"));
        std::fs::write(&inst, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&rem, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        af_services::clear_package_job_info(id);
    }

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let admin = progress_test_user("admin", None);

    // 1. Pi-hole update fails closed with 409 CONFLICT (even with stale DB row or explicit target)
    let res_ph_upd = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "update",
        "updating",
        false,
        Some("6.9".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_upd.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("pihole").is_none());

    // 2. Pi-hole pinned install/reinstall fails closed with 409 CONFLICT
    let res_ph_pin = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "reinstall",
        "reinstalling",
        false,
        Some("6.8".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_pin.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("pihole").is_none());

    // 3. Threadfin mismatched target fails closed on install/reinstall/update with 409 CONFLICT
    let res_tf_bad = dispatch_package_lifecycle_with_target(
        "threadfin".into(),
        "reinstall",
        "reinstalling",
        false,
        Some("1.2.36".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_tf_bad.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("threadfin").is_none());

    // 4. Threadfin confirmed update to pinned 1.2.37 succeeds and records expected_target_version=1.2.37
    let tf_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &threadfin_pkg);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('threadfin', '1.2.36', '1.2.37', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [&tf_source],
        )
        .unwrap();
    }
    let res_tf_ok = dispatch_package_lifecycle_with_target(
        "threadfin".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_tf_ok.status(), StatusCode::OK);
    let tf_job = af_services::get_package_job_info("threadfin").unwrap();
    assert_eq!(tf_job.expected_target_version.as_deref(), Some("1.2.37"));
    af_services::clear_package_job_info("threadfin");

    // 5. Unpinned Pi-hole reinstall is accepted with expected_target_version = None
    let res_ph_ok = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "reinstall",
        "reinstalling",
        false,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_ok.status(), StatusCode::OK);
    let ph_job = af_services::get_package_job_info("pihole").unwrap();
    assert_eq!(ph_job.expected_target_version, None);
    af_services::clear_package_job_info("pihole");

    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn account_endpoints_report_sqlite_failures() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::extract::Extension;
    use axum::http::StatusCode;

    if run_plugin_test_in_subprocess() {
        return;
    }
    let admin = super::AuthUser {
        user_id: 891,
        username: "account-endpoint-fixture".into(),
        role: "admin".into(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    assert_eq!(
        super::get_users(Extension(admin.clone())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        super::delete_avatar(Extension(admin.clone()))
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
        super::get_users(Extension(admin.clone())).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        super::delete_avatar(Extension(admin.clone()))
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
        super::get_users(Extension(admin.clone())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        super::delete_avatar(Extension(admin)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_supports_listenarr_prerelease_updates_and_capitalized_receipt_path() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);

    // 1. resolve_candidate_receipt_paths includes /opt/Listenarr/.af-version
    let receipt_candidates = super::marketplace::resolve_candidate_receipt_paths("listenarr");
    assert!(
        receipt_candidates.contains(&root.join("opt/Listenarr/.af-version")),
        "expected /opt/Listenarr/.af-version in {receipt_candidates:?}"
    );

    let listenarr_pkg = af_models::Package {
        name: "listenarr".into(),
        label: "Listenarr".into(),
        service_name: "listenarr".into(),
        lock_file: "/install/.listenarr.lock".into(),
        status: "installed".into(),
        update_source: "github".into(),
        update_repo: "Listenarrs/Listenarr".into(),
        update_channel: "prerelease".into(),
        version_command: vec!["cat".into(), "/opt/Listenarr/.af-version".into()],
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![listenarr_pkg.clone()]).unwrap()).unwrap();
    std::fs::write(
        &automation,
        serde_json::json!({
            "listenarr": {
                "update_source": "github",
                "update_repo": "Listenarrs/Listenarr",
                "update_channel": "prerelease",
                "version_command": ["cat", "/opt/Listenarr/.af-version"],
                "require_download_sha256": true
            }
        })
        .to_string(),
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    std::fs::write(root.join("install/.listenarr.lock"), "installed\n").unwrap();
    let inst = root.join("packages/package/install/installpackage-listenarr");
    let rem = root.join("packages/package/remove/removepackage-listenarr");
    std::fs::write(&inst, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(&rem, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&rem, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    af_services::clear_package_job_info("listenarr");

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let admin = progress_test_user("admin", None);

    // 2. Floating non-concrete target fails closed before creating a job
    let res_bad = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "install",
        "installing",
        false,
        Some("canary".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_bad.status(), StatusCode::BAD_REQUEST);
    assert!(af_services::get_package_job_info("listenarr").is_none());

    // 3. Stale stable-channel app_updates row is rejected with 409 CONFLICT
    let stale_source = "github:https://api.github.com|listenarrs/listenarr|stable";
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('listenarr', '1.10.5-canary', '1.10.6-canary', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [stale_source],
        )
        .unwrap();
    }
    let res_stale = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_stale.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("listenarr").is_none());

    // 4. Confirmed prerelease-channel update dispatches with expected_target_version = 1.10.6-canary
    let expected_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &listenarr_pkg);
    assert!(expected_source.ends_with("|prerelease"), "{expected_source}");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('listenarr', '1.10.5-canary', '1.10.6-canary', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [&expected_source],
        )
        .unwrap();
    }
    let res_ok = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "update",
        "updating",
        false,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ok.status(), StatusCode::OK);
    let job = af_services::get_package_job_info("listenarr").unwrap();
    assert_eq!(job.expected_target_version.as_deref(), Some("1.10.6-canary"));
    af_services::clear_package_job_info("listenarr");

    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}
