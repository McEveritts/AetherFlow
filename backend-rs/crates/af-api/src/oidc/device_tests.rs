use super::device::{normalize_device_user_code, oidc_device_consent, oidc_device_verify};
use super::token_endpoint::consume_device_code;
use crate::auth::{create_standard_jwt, AuthUser};
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use chrono::{Duration, Utc};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;

#[test]
fn device_code_redemption_is_single_use_under_concurrency() {
    let path = env::temp_dir().join(format!("af-device-code-{}.sqlite", uuid::Uuid::new_v4()));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         CREATE TABLE oidc_device_codes (device_code TEXT PRIMARY KEY, client_id TEXT, user_id INTEGER, scope TEXT, status TEXT, expires_at TEXT);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oidc_device_codes VALUES ('device', 'client', 1, 'openid', 'approved', ?1)",
        params![(Utc::now() + Duration::minutes(1)).to_rfc3339()],
    )
    .unwrap();
    assert!(consume_device_code(&conn, "device", "wrong-client")
        .unwrap()
        .is_none());
    drop(conn);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut conn = rusqlite::Connection::open(path).unwrap();
                conn.busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                barrier.wait();
                let tx = conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                let consumed = consume_device_code(&tx, "device", "client")
                    .unwrap()
                    .is_some();
                tx.commit().unwrap();
                consumed
            })
        })
        .collect();
    assert_eq!(
        tasks
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

#[test]
fn normalize_device_user_code_accepts_short_codes_and_rejects_malformed_inputs() {
    for (raw, expected) in [
        ("BCDF-2345", "BCDF-2345"),
        ("bcdf-2345", "BCDF-2345"),
        ("bcdf2345", "BCDF-2345"),
        ("  bcdf 2345  ", "BCDF-2345"),
        ("wxyz9876", "WXYZ-9876"),
    ] {
        assert_eq!(
            normalize_device_user_code(raw),
            Ok(expected.to_string()),
            "{raw:?}"
        );
    }
    assert_eq!(normalize_device_user_code(""), Err("user_code is required"));
    assert_eq!(
        normalize_device_user_code("   "),
        Err("user_code is required")
    );
    for bad in [
        "BCDF",
        "BCDF-234",
        "BCDF-23456",
        "-BCDF2345",
        "BCDF2345-",
        "BCDF--2345",
        "BCDF_2345",
        "BCDF$2345",
        "ABCDEFGHIJKLMNOPQ",
    ] {
        assert_eq!(
            normalize_device_user_code(bad),
            Err("invalid_user_code"),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn oidc_device_flow_enforces_auth_csrf_client_identity_expiry_and_token_lifecycle() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;

    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    let fixture_root = db.parent().unwrap().join("oidc-device-spa-fixture");
    fs::create_dir_all(&fixture_root).unwrap();
    fs::write(
        fixture_root.join("index.html"),
        "<!doctype html><title>AetherFlow Device SPA</title>",
    )
    .unwrap();
    env::set_var("STATIC_DIR", &fixture_root);
    env::set_var(
        "OIDC_KEY_PATH",
        db.parent().unwrap().join("oidc-device.pem"),
    );
    env::set_var("OIDC_ISSUER", "https://auth.example.test");
    env::set_var("ALLOWED_HOSTS", "localhost");
    env::remove_var("CSRF_DISABLED");

    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (812, 'device-operator', 'user')",
        [],
    )
    .unwrap();
    let secret_hash = hex::encode(Sha256::digest(b"device-client-secret"));
    conn.execute(
        "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
         VALUES ('tv-client', ?1, 'Living Room Jellyfin TV', '[\"https://tv.example.test/cb\"]')",
        params![secret_hash],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
         VALUES ('public-spa', '', 'Public Browser Client', '[\"https://spa.example.test/cb\"]')",
        [],
    )
    .unwrap();
    drop(conn);

    let app = crate::routes::build_router();

    // 1. Discovery advertises the RFC 8628 device authorization endpoint and grant type.
    let discovery_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header(header::HOST, "localhost")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery_resp.status(), StatusCode::OK);
    let discovery: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(discovery_resp.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        discovery["device_authorization_endpoint"],
        "https://auth.example.test/api/v1/public/oidc/device/authorize"
    );
    assert!(discovery["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "urn:ietf:params:oauth:grant-type:device_code"));

    // 2. Normal SPA entry points `/oauth/device` and `/oauth/device?user_code=...` serve index.html.
    for uri in ["/oauth/device", "/oauth/device?user_code=BCDF-2345"] {
        let spa_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(spa_resp.status(), StatusCode::OK, "{uri}");
        let body = axum::body::to_bytes(spa_resp.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("AetherFlow Device SPA"),
            "{uri}"
        );
    }

    // 3. Public clients, missing secrets, wrong secrets, and ambiguous Basic+form credentials
    //    are consistently rejected; authenticated confidential clients (Basic or form) succeed.
    for form_body in [
        "client_id=public-spa&scope=openid",
        "client_id=public-spa&client_secret=any&scope=openid",
        "client_id=tv-client&scope=openid",
        "client_id=tv-client&client_secret=&scope=openid",
        "client_id=tv-client&client_secret=wrong-secret&scope=openid",
        "scope=openid",
    ] {
        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/public/oidc/device/authorize")
                    .header(header::HOST, "localhost")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            rejected.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 for {form_body}"
        );
        let err: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(rejected.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(err["error"], "invalid_client", "{form_body}");
    }

    let bad_basic = BASE64_STD.encode("tv-client:wrong-secret");
    let good_basic = BASE64_STD.encode("tv-client:device-client-secret");

    let bad_basic_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/device/authorize")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Basic {bad_basic}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("scope=openid"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_basic_attempt.status(), StatusCode::UNAUTHORIZED);
    assert!(bad_basic_attempt
        .headers()
        .contains_key(header::WWW_AUTHENTICATE));

    for (auth_hdr, ambiguous_body) in [
        (
            &good_basic,
            "client_secret=device-client-secret&scope=openid",
        ),
        (&good_basic, "client_id=tv-client&scope=openid"),
        (
            &bad_basic,
            "client_id=tv-client&client_secret=device-client-secret&scope=openid",
        ),
    ] {
        let ambig = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/public/oidc/device/authorize")
                    .header(header::HOST, "localhost")
                    .header(header::AUTHORIZATION, format!("Basic {auth_hdr}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(ambiguous_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            ambig.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for Basic + {ambiguous_body}"
        );
        let err: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(ambig.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(err["error"], "invalid_request", "{ambiguous_body}");
    }

    // Valid HTTP Basic confidential client authentication succeeds cleanly.
    let basic_authz = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/device/authorize")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Basic {good_basic}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("scope=openid"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(basic_authz.status(), StatusCode::OK);

    // Valid client_secret_post confidential client authentication succeeds cleanly.
    let authz_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/device/authorize")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "client_id=tv-client&client_secret=device-client-secret&scope=openid%20profile%20email",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authz_resp.status(), StatusCode::OK);
    let authz: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(authz_resp.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let device_code = authz["device_code"].as_str().unwrap().to_string();
    let user_code = authz["user_code"].as_str().unwrap().to_string();
    assert_eq!(
        authz["verification_uri"],
        "https://auth.example.test/oauth/device"
    );
    assert_eq!(
        authz["verification_uri_complete"],
        format!("https://auth.example.test/oauth/device?user_code={user_code}")
    );

    // 4. Verify and consent enforce authentication (401) and CSRF (403).
    let unauth_verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/verify")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"user_code": &user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_verify.status(), StatusCode::UNAUTHORIZED);

    let mut ua_headers = HeaderMap::new();
    ua_headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("af-device-test/1.0"),
    );
    let (session_jwt, _) = create_standard_jwt(812, &ua_headers).unwrap();
    let csrf_token = "csrf-device-test-token-0123456789abcdef";
    let cookie_header = format!("aetherflow_session={session_jwt}; csrf_token={csrf_token}");

    let no_csrf_verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/verify")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"user_code": &user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_csrf_verify.status(), StatusCode::FORBIDDEN);

    // 5. Lowercase unhyphenated short code normalizes and returns server-confirmed client & scopes.
    let compact_lower = user_code.replace('-', "").to_ascii_lowercase();
    let verify_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/verify")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"user_code": compact_lower}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), StatusCode::OK);
    let verified: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(verify_resp.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verified["status"], "pending");
    assert_eq!(verified["user_code"], user_code);
    assert_eq!(verified["client_id"], "tv-client");
    assert_eq!(verified["client_name"], "Living Room Jellyfin TV");
    assert_eq!(verified["scope"], "openid profile email");

    // 6. Token polling before approval returns authorization_pending; mismatched client_id on consent fails.
    let poll_pending = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/token")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=tv-client&client_secret=device-client-secret&device_code={device_code}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(poll_pending.status(), StatusCode::BAD_REQUEST);
    let pending_err: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(poll_pending.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pending_err["error"], "authorization_pending");

    let mismatched_consent = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/consent")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "user_code": &user_code,
                        "client_id": "spoofed-client",
                        "scope": "openid profile email",
                        "approved": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatched_consent.status(), StatusCode::BAD_REQUEST);

    // 7. Explicit approval issues single-use OIDC tokens and marks user_code non-reusable.
    let approve_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/consent")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "user_code": &user_code,
                        "client_id": "tv-client",
                        "scope": "openid profile email",
                        "approved": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approve_resp.status(), StatusCode::OK);

    let token_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/token")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=tv-client&client_secret=device-client-secret&device_code={device_code}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::OK);
    let tokens: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(token_resp.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(tokens["id_token"].as_str().is_some_and(|s| !s.is_empty()));

    // Re-verifying a consumed code returns invalid_user_code.
    let reverify_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/verify")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"user_code": &user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reverify_resp.status(), StatusCode::BAD_REQUEST);

    // 8. Denial and expired codes return exact RFC/UI error codes.
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) \
         VALUES ('dc-expired', 'EXPD-2345', 'tv-client', 'openid', ?1, 'pending')",
        params![(Utc::now() - Duration::minutes(1)).to_rfc3339()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) \
         VALUES ('dc-deny', 'DENY-2345', 'tv-client', 'openid', ?1, 'pending')",
        params![(Utc::now() + Duration::minutes(5)).to_rfc3339()],
    )
    .unwrap();
    drop(conn);

    for uri in [
        "/api/v1/auth/oidc/device/verify",
        "/api/v1/auth/oidc/device/consent",
    ] {
        let expired_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "af-device-test/1.0")
                    .header(header::COOKIE, &cookie_header)
                    .header("X-CSRF-Token", csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"user_code": "EXPD-2345", "approved": true}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        let err_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(expired_resp.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(err_json["error"], "expired_token", "{uri}");
    }

    let deny_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/device/consent")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "af-device-test/1.0")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"user_code": "DENY-2345", "approved": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deny_resp.status(), StatusCode::OK);
    let denied_poll = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/public/oidc/token")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=tv-client&client_secret=device-client-secret&device_code=dc-deny",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_poll.status(), StatusCode::BAD_REQUEST);
    let denied_err: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(denied_poll.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(denied_err["error"], "access_denied");

    let _ = fs::remove_dir_all(fixture_root);
}

#[tokio::test]
async fn oidc_device_consent_and_verify_propagate_sqlite_errors() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (813, 'device-err-user', 'user')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
             VALUES ('dev-err-client', 'secret-hash', 'DeviceErr', '[\"https://dev.example/cb\"]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) \
             VALUES ('dc-err-1', 'ERRC-2345', 'dev-err-client', 'openid', ?1, 'pending')",
            params![(Utc::now() + Duration::minutes(5)).to_rfc3339()],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER abort_consent_insert BEFORE INSERT ON oidc_consents \
             BEGIN SELECT RAISE(ABORT, 'consent write failure'); END;",
        )
        .unwrap();
    }

    let user = AuthUser {
        user_id: 813,
        username: "device-err-user".into(),
        role: "user".into(),
        jti: "jti-813".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut consent_req = Request::new(axum::body::Body::from(
        serde_json::json!({ "user_code": "ERRC-2345", "approved": true }).to_string(),
    ));
    consent_req.extensions_mut().insert(user.clone());
    assert_eq!(
        oidc_device_consent(consent_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "oidc_device_consent must return 500 when persisting consent fails"
    );

    // Rollback must preserve the pending device code rather than approving it without consent.
    {
        let conn = af_db::get_read_conn().unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM oidc_device_codes WHERE device_code = 'dc-err-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");
    }

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE oidc_device_codes", []).unwrap();
    }
    let mut verify_req = Request::new(axum::body::Body::from(
        serde_json::json!({ "user_code": "ERRC-2345" }).to_string(),
    ));
    verify_req.extensions_mut().insert(user);
    assert_eq!(
        oidc_device_verify(verify_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "oidc_device_verify must return 500 on SQLite errors rather than 400 invalid_user_code"
    );
}
