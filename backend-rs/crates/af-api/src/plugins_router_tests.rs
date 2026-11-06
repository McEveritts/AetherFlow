use crate::plugins::*;
use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess, test_env_lock};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Json};
use http_body_util::BodyExt;
use std::fs;
use uuid::Uuid;

#[tokio::test]
async fn destructive_plugin_request_time_gate_preserves_admin_users_and_readers() {
    use axum::http::Method;
    use axum::middleware;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    let app = axum::Router::new()
        .route(
            "/api/v1/admin/packages/demo/uninstall",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/admin/services/aetherflow-api/control",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/admin/system/update/run",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/admin/services/restart/status",
            get(|| async { StatusCode::NO_CONTENT }),
        )
        .route_layer(middleware::from_fn(crate::auth::admin_only_middleware));
    for path in [
        "/api/v1/admin/packages/demo/uninstall",
        "/api/v1/admin/services/aetherflow-api/control",
        "/api/v1/admin/system/update/run",
        "/api/v1/admin/services/restart/status",
    ] {
        let method = if path.ends_with("/status") {
            Method::GET
        } else {
            Method::POST
        };
        for scope in [path, "/api/v1/admin/*", "/api/*"] {
            let claims = PluginTokenClaims {
                typ: PLUGIN_TOKEN_TYP.into(),
                iss: PLUGIN_TOKEN_ISSUER.into(),
                aud: PLUGIN_TOKEN_AUDIENCE.into(),
                sub: "plugin:fixture".into(),
                plugin_id: "fixture".into(),
                jti: "fixture".into(),
                iat: 1,
                exp: 2,
                epoch: 1,
                scopes: vec![PluginScopeRule {
                    method: method.to_string(),
                    route: scope.into(),
                }],
            };
            let mut request = Request::builder()
                .method(method.clone())
                .uri(path)
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(claims);
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                if method == Method::GET {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::FORBIDDEN
                },
                "{method} {path} from {scope}"
            );
        }
        for role in ["admin", "user", "plugin"] {
            let mut request = Request::builder()
                .method(method.clone())
                .uri(path)
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(crate::auth::AuthUser {
                user_id: 1,
                username: "fixture".into(),
                role: role.into(),
                jti: "fixture".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            });
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                if role == "admin" {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::FORBIDDEN
                }
            );
        }
    }
}

#[tokio::test]
async fn test_end_to_end_plugin_router_boundaries_revocation_and_proxy_stripping() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    use axum::routing::get as axum_get;
    use tower::ServiceExt;

    let _env_guard = test_env_lock().lock().await;
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    let _ = ensure_shared_test_db();

    let tmp = std::env::temp_dir().join(format!("af-plugin-e2e-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let plugin_dir = plugins_root.join("telemetry-inspector");
    fs::create_dir_all(&plugin_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755));
        let _ = fs::set_permissions(&plugin_dir, fs::Permissions::from_mode(0o755));
    }

    let manifest_json = serde_json::json!({
        "id": "telemetry-inspector",
        "name": "Telemetry Inspector",
        "version": "0.1.0",
        "sdk": "rust",
        "contract_version": "v1",
        "runtime_status": "managed",
        "description": "Test plugin",
        "author": "Test",
        "permissions": ["system:metrics:read"],
        "api_scopes": ["GET /api/v1/auth/system/metrics"],
        "backend": {
            "health_path": "/healthz",
            "port_allocation": "dynamic"
        },
        "frontend": {
            "slot": "marketplace"
        }
    });
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        serde_json::to_vec_pretty(&manifest_json).unwrap(),
    )
    .unwrap();

    std::env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);

    // Seed an admin user for operator session testing
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (1, 'admin', 'hash', 'admin')",
            [],
        );
        let _ = conn.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (2, 'viewer', 'hash', 'user')",
            [],
        );
        let _ = conn.execute(
            "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps, net_rx_bytes, net_tx_bytes, load_avg_1, active_conns) VALUES ('2026-11-03 05:00:00', 22.5, 4.0, 16.0, 100.0, 200.0, 1000, 2000, 0.5, 5)",
            [],
        );
    }

    // Start a mock plugin loopback HTTP server on an allowed port in 21000..21999
    let mut bound_listener = None;
    let mut plugin_port = 21050u16;
    for candidate in 21050..=21150 {
        if let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", candidate)).await {
            plugin_port = candidate;
            bound_listener = Some(l);
            break;
        }
    }
    let listener = bound_listener.expect("bind loopback plugin port");
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route(
                "/healthz",
                axum_get(|| async { Json(serde_json::json!({"status": "ok"})) }),
            )
            .route(
                "/echo",
                axum_get(|headers: HeaderMap| async move {
                    let had_cookie = headers.contains_key(header::COOKIE);
                    let had_auth = headers.contains_key(header::AUTHORIZATION);
                    let plugin_hdr = headers
                        .get("X-AetherFlow-Plugin-Id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let mut resp = Json(serde_json::json!({
                        "had_cookie": had_cookie,
                        "had_auth": had_auth,
                        "plugin_id": plugin_hdr,
                    }))
                    .into_response();
                    resp.headers_mut().insert(
                        header::SET_COOKIE,
                        HeaderValue::from_static("evil_cookie=1; Path=/"),
                    );
                    resp
                }),
            );
        let _ = axum::serve(listener, app).await;
    });

    let (manifests, rejected) = discover_plugins_in_dir(&plugins_root);
    assert!(rejected.is_empty(), "unexpected rejected manifests: {:?}", rejected);
    let manifest = manifests
        .into_iter()
        .find(|m| m.id == "telemetry-inspector")
        .expect("discovered telemetry-inspector");

    let _ = update_registry_state("telemetry-inspector", true, plugin_port, "running", "", false);
    let (plugin_token, claims) = mint_scoped_plugin_token(&manifest, Some(300)).unwrap();
    assert_eq!(claims.typ, "plugin");
    assert_eq!(claims.aud, PLUGIN_TOKEN_AUDIENCE);

    let router = crate::routes::build_router();

    // 1. Allowed GET /api/v1/auth/system/metrics succeeds with scoped plugin token
    let req_ok = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/system/metrics")
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", plugin_token))
        .body(Body::empty())
        .unwrap();
    let resp_ok = router.clone().oneshot(req_ok).await.unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);

    // 2. Alternate HTTP method (POST) on an otherwise allowed route is denied (403)
    let req_post = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/system/metrics")
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", plugin_token))
        .body(Body::empty())
        .unwrap();
    let resp_post = router.clone().oneshot(req_post).await.unwrap();
    assert_eq!(resp_post.status(), StatusCode::FORBIDDEN);

    // 3. Unscoped admin endpoint (/api/v1/admin/users) is denied (403)
    let req_admin = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/users")
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", plugin_token))
        .body(Body::empty())
        .unwrap();
    let resp_admin = router.clone().oneshot(req_admin).await.unwrap();
    assert_eq!(resp_admin.status(), StatusCode::FORBIDDEN);

    // 4. Default-denied session & refresh endpoints reject plugin token
    for denied_uri in ["/api/v1/auth/session", "/api/v1/auth/refresh", "/api/v1/public/auth/refresh"] {
        let method = if denied_uri.ends_with("/refresh") { "POST" } else { "GET" };
        let req_den = Request::builder()
            .method(method)
            .uri(denied_uri)
            .header("Host", "localhost")
            .header("Authorization", format!("Bearer {}", plugin_token))
            .body(Body::empty())
            .unwrap();
        let resp_den = router.clone().oneshot(req_den).await.unwrap();
        assert!(
            resp_den.status() == StatusCode::FORBIDDEN || resp_den.status() == StatusCode::UNAUTHORIZED,
            "expected 401/403 for {}, got {}",
            denied_uri,
            resp_den.status()
        );
    }

    // 5. Non-admin authenticated user can read /api/v1/auth/system/metrics/history
    let mut op_headers = HeaderMap::new();
    op_headers.insert(header::USER_AGENT, HeaderValue::from_static("test-agent"));
    let (viewer_jwt, _) = crate::auth::create_standard_jwt(2, &op_headers).unwrap();
    let req_hist = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/system/metrics/history?window=24h&limit=100")
        .header("Host", "localhost")
        .header("User-Agent", "test-agent")
        .header("Authorization", format!("Bearer {}", viewer_jwt))
        .body(Body::empty())
        .unwrap();
    let resp_hist = router.clone().oneshot(req_hist).await.unwrap();
    assert_eq!(resp_hist.status(), StatusCode::OK);

    // 6. Loopback proxy strips Cookie, Authorization, and Set-Cookie, and blocks .. traversal
    let req_proxy = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/plugins/telemetry-inspector/proxy/echo")
        .header("Host", "localhost")
        .header("User-Agent", "test-agent")
        .header("Cookie", format!("aetherflow_session={}; other=secret", viewer_jwt))
        .header("Authorization", format!("Bearer {}", viewer_jwt))
        .body(Body::empty())
        .unwrap();
    let resp_proxy = router.clone().oneshot(req_proxy).await.unwrap();
    assert_eq!(resp_proxy.status(), StatusCode::OK);
    assert!(!resp_proxy.headers().contains_key(header::SET_COOKIE));
    let body_bytes = resp_proxy.into_body().collect().await.unwrap().to_bytes();
    let echo_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(echo_json["had_cookie"], false);
    assert_eq!(echo_json["had_auth"], false);
    assert_eq!(echo_json["plugin_id"], "telemetry-inspector");

    // Traversal attempt on proxy is rejected with 400
    let req_trav = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/plugins/telemetry-inspector/proxy/%2e%2e/admin")
        .header("Host", "localhost")
        .header("User-Agent", "test-agent")
        .header("Authorization", format!("Bearer {}", viewer_jwt))
        .body(Body::empty())
        .unwrap();
    let resp_trav = router.clone().oneshot(req_trav).await.unwrap();
    assert_eq!(resp_trav.status(), StatusCode::BAD_REQUEST);

    // 7. Stopping plugin immediately revokes active plugin token
    let _ = stop_plugin_instance(&manifest).await;
    let req_after_stop = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/system/metrics")
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", plugin_token))
        .body(Body::empty())
        .unwrap();
    let resp_after_stop = router.oneshot(req_after_stop).await.unwrap();
    assert_eq!(resp_after_stop.status(), StatusCode::UNAUTHORIZED);

    let _ = fs::remove_dir_all(&tmp);
}
