use super::middleware::{
    admin_only_middleware, auth_middleware, csrf_middleware, is_csrf_disabled_for_env,
    issue_csrf_token,
};
use super::sessions::refresh_session_with_peer;
use super::tokens::{decode_session_claims, jwt_secret_bytes, mint_plugin_jwt, SessionClaims};
use axum::extract::Request;
use axum::http::{header, Method, StatusCode};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::env;
use uuid::Uuid;

#[test]
fn csrf_constant_time_equality_requires_all_bytes_and_equal_lengths() {
    assert!(af_models::constant_time_eq(b"", b""));
    assert!(af_models::constant_time_eq(b"csrf-token", b"csrf-token"));
    assert!(af_models::constant_time_eq(&[0, 128, 255], &[0, 128, 255]));
    for (a, b) in [
        (b"csrf-token".as_slice(), b"Csrf-token".as_slice()),
        (b"csrf-token".as_slice(), b"csrf-tokeN".as_slice()),
        (b"csrf-token".as_slice(), b"csrf-toke".as_slice()),
        (b"csrf-token".as_slice(), b"csrf-token-extra".as_slice()),
        (b"".as_slice(), b"csrf-token".as_slice()),
        (b"a\0b".as_slice(), b"a\0c".as_slice()),
    ] {
        assert!(!af_models::constant_time_eq(a, b));
        assert!(!af_models::constant_time_eq(b, a));
    }
}

#[tokio::test]
async fn csrf_token_cookie_is_http_only_strict_and_matches_the_json_body() {
    let response = issue_csrf_token().await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(cookie.split(';').any(|part| part.trim() == "HttpOnly"));
    assert!(cookie
        .split(';')
        .any(|part| part.trim() == "SameSite=Strict"));
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = data["csrf_token"].as_str().unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(cookie.starts_with(&format!("csrf_token={token};")));
}

#[tokio::test]
async fn csrf_middleware_accepts_matching_tokens_and_rejects_mismatches_and_prefixes() {
    use axum::{middleware, routing::any, Router};
    use tower::ServiceExt;

    let app = Router::new()
        .route("/api/v1/auth/protected", any(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(csrf_middleware));
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        for (header_token, cookie_token, expected) in [
            ("csrf-token", "csrf-token", StatusCode::OK),
            ("Csrf-token", "csrf-token", StatusCode::FORBIDDEN),
            ("csrf-tokeN", "csrf-token", StatusCode::FORBIDDEN),
            ("csrf-token-extra", "csrf-token", StatusCode::FORBIDDEN),
            ("csrf-token", "csrf-token-extra", StatusCode::FORBIDDEN),
            ("csrf-toke", "csrf-token", StatusCode::FORBIDDEN),
            ("", "csrf-token", StatusCode::FORBIDDEN),
            ("csrf-token", "", StatusCode::FORBIDDEN),
            ("", "", StatusCode::FORBIDDEN),
        ] {
            let request = Request::builder()
                .method(method)
                .uri("/api/v1/auth/protected")
                .header(header::COOKIE, format!("csrf_token={cookie_token}"))
                .header("X-CSRF-Token", header_token)
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                expected,
                "{method}: header={header_token:?}, cookie={cookie_token:?}"
            );
        }
    }
}

#[tokio::test]
async fn csrf_middleware_refuses_csrf_disabled_in_production_and_release() {
    use axum::{middleware, routing::any, Router};
    use tower::ServiceExt;

    assert!(is_csrf_disabled_for_env(Some("true"), None));
    assert!(is_csrf_disabled_for_env(Some("true"), Some("test")));
    assert!(!is_csrf_disabled_for_env(Some("true"), Some("production")));
    assert!(!is_csrf_disabled_for_env(Some("TRUE"), Some("PRODUCTION")));
    assert!(!is_csrf_disabled_for_env(Some("true"), Some("release")));
    assert!(!is_csrf_disabled_for_env(Some("true"), Some("Release")));

    const CHILD_ENV: &str = "AF_CSRF_PROD_TEST_CHILD";
    if env::var(CHILD_ENV).as_deref() != Ok("1") {
        let thread = std::thread::current();
        let test_name = thread.name().expect("named Rust test thread");
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    env::set_var("CSRF_DISABLED", "true");
    let app = Router::new()
        .route("/api/v1/auth/protected", any(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(csrf_middleware));

    for af_env in ["production", "PRODUCTION", "release", "Release"] {
        env::set_var("AETHERFLOW_ENV", af_env);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/protected")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "AETHERFLOW_ENV={af_env} must enforce CSRF even when CSRF_DISABLED=true"
        );
    }

    env::set_var("AETHERFLOW_ENV", "test");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/protected")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "non-production test env may honor CSRF_DISABLED=true"
    );
}

#[tokio::test]
async fn nested_refresh_suffixes_require_authentication_and_csrf() {
    use axum::{middleware, routing::post, Router};
    use tower::ServiceExt;
    for path in [
        "/api/v1/plugins/x/proxy/auth/refresh",
        "/plugins/x/proxy/auth/refresh",
        "/refresh",
    ] {
        let app = Router::new()
            .route(path, post(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(auth_middleware));
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let app = Router::new()
            .route(path, post(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(csrf_middleware));
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::COOKIE, "aetherflow_session=test")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    for path in [
        "/api/v1/auth/refresh",
        "/api/v1/public/auth/refresh",
        "/api/auth/refresh",
        "/api/public/auth/refresh",
    ] {
        let app = Router::new()
            .route(path, post(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(csrf_middleware))
            .layer(middleware::from_fn(auth_middleware));
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn cookie_refresh_requires_the_request_header_on_both_routes() {
    use axum::{routing::post, Router};
    use tower::ServiceExt;

    for path in ["/auth/refresh", "/public/auth/refresh"] {
        let app = Router::new().route(path, post(refresh_session_with_peer));
        for (request_header, expected) in [
            (None, StatusCode::FORBIDDEN),
            (Some("XMLHttpRequest"), StatusCode::UNAUTHORIZED),
        ] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::COOKIE, "aetherflow_session=invalid-fixture-token");
            if let Some(value) = request_header {
                request = request.header("x-requested-with", value);
            }
            let response = app
                .clone()
                .oneshot(request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
    }
}

#[tokio::test]
async fn admin_middleware_rejects_scoped_plugin_reads_and_writes() {
    use axum::{body::Body, middleware, routing::any, Router};
    use tower::ServiceExt;

    let app = Router::new()
        .route(
            "/api/v1/admin/services",
            any(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/ingress/configs",
            any(|| async { StatusCode::NO_CONTENT }),
        )
        .route_layer(middleware::from_fn(admin_only_middleware));
    for path in ["/api/v1/admin/services", "/api/ingress/configs"] {
        for method in ["GET", "POST"] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(crate::plugins::PluginTokenClaims {
                    typ: "plugin".into(),
                    iss: "aetherflow-plugin".into(),
                    aud: "aetherflow-plugin-api".into(),
                    sub: "plugin:fixture".into(),
                    plugin_id: "fixture".into(),
                    jti: "plg-fixture".into(),
                    iat: 0,
                    exp: 1,
                    epoch: 1,
                    scopes: vec![crate::plugins::PluginScopeRule {
                        method: method.into(),
                        route: path.into(),
                    }],
                });
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }
}

#[tokio::test]
async fn legacy_plugin_session_denies_destructive_http_capabilities() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::{
        body::Body,
        middleware,
        routing::{get, post},
        Router,
    };
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let app = Router::new()
        .route(
            "/api/v1/admin/packages/fixture/uninstall",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/admin/services/fixture/control",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/admin/system/update/run",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/v1/auth/system/metrics",
            get(|| async { StatusCode::NO_CONTENT }),
        )
        .layer(middleware::from_fn(auth_middleware));
    for path in [
        "/api/v1/admin/packages/fixture/uninstall",
        "/api/v1/admin/services/fixture/control",
        "/api/v1/admin/system/update/run",
        "/api/v1/auth/system/metrics",
    ] {
        let now = Utc::now().timestamp();
        let claims = SessionClaims {
            user_id: 1,
            sub: "1".into(),
            iss: "aetherflow".into(),
            iat: now,
            auth_time: now,
            exp: now + 600,
            jti: Uuid::new_v4().to_string(),
            cfp: String::new(),
            ver: 0,
            plugin_id: "fixture".into(),
            plugin_scopes: vec![path.into()],
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&jwt_secret_bytes()),
        )
        .unwrap();
        let read = path.ends_with("metrics");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(if read { "GET" } else { "POST" })
                    .uri(path)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[test]
fn legacy_plugin_jwt_is_rejected_by_both_token_decoders() {
    let scopes = vec![
        "/api/v1/public/marketplace".to_string(),
        "/api/v1/auth/system/metrics".to_string(),
    ];
    let (token, claims) = mint_plugin_jwt(1, "sdk-template-rust", &scopes, 600).unwrap();
    assert_eq!(claims.plugin_id, "sdk-template-rust");
    assert!(decode_session_claims(&token, false).is_err());
    assert!(crate::plugins::decode_and_verify_plugin_token(&token).is_err());
}

#[tokio::test]
async fn esc13_refresh_routes_are_rate_limited_and_production_ignores_disable_flag() {
    use crate::plugins::tests::run_plugin_test_in_subprocess;
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    env::set_var("AF_DISABLE_RATELIMIT", "true");
    env::set_var("AETHERFLOW_ENV", "production");
    env::set_var("ALLOWED_HOSTS", "localhost");
    let app = crate::routes::build_router();

    for path in ["/api/v1/auth/refresh", "/api/auth/refresh"] {
        let ip = if path.contains("/v1/") {
            "203.0.113.21"
        } else {
            "203.0.113.22"
        };
        for _ in 0..10 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(path)
                        .header(header::HOST, "localhost")
                        .header("x-real-ip", ip)
                        .extension(axum::extract::ConnectInfo(
                            "127.0.0.1:42000".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
        let limited = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::HOST, "localhost")
                    .header("x-real-ip", ip)
                    .extension(axum::extract::ConnectInfo(
                        "127.0.0.1:42000".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            limited.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{path} must enforce auth rate limit even when AF_DISABLE_RATELIMIT=true in production"
        );
    }
}
