use super::mfa::{mfa_login_verify, MfaVerifyRequest};
use super::middleware::{auth_middleware, csrf_middleware};
use super::revocation::{
    is_session_token_revoked_beyond_grace, MIN_REVOCATION_TTL, ROTATED_SESSION_SUCCESSOR,
    ROTATED_TOKEN_GRACE,
};
use super::sessions::{
    is_session_active, list_active_sessions, logout, refresh_session, revoke_session,
    verify_proxy_auth,
};
use super::setup_login::{
    ensure_setup_bootstrap_token, get_session, local_login, local_login_blocking,
    setup_admin_blocking, CredentialsRequest,
};
use super::tokens::{
    client_fingerprint, create_session_jwt_in_conn, create_standard_jwt, decode_session_claims,
    jwt_secret_bytes, query_user_credential_version, resolve_raw_token,
    session_within_absolute_lifetime, AuthUser, SessionClaims, SESSION_ABSOLUTE_LIFETIME,
};
use crate::ws::extract_client_ip;
use axum::extract::{Path, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Json;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rusqlite::params;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn totp_now() -> String {
    let bytes = BASE32_NOPAD.decode(b"JBSWY3DPEHPK3PXP").unwrap();
    totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, Utc::now().timestamp() as u64)
}

#[tokio::test]
async fn refresh_rejects_absolute_expiry_even_with_a_fresh_exp() {
    let now = Utc::now().timestamp();
    let claims = SessionClaims {
        user_id: 1,
        sub: "1".into(),
        iss: "aetherflow".into(),
        iat: now,
        auth_time: now - SESSION_ABSOLUTE_LIFETIME - 1,
        exp: now + 900,
        jti: Uuid::new_v4().to_string(),
        cfp: String::new(),
        ver: 0,
        plugin_id: String::new(),
        plugin_scopes: Vec::new(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("aetherflow_session={token}").parse().unwrap(),
    );
    assert_eq!(
        refresh_session(headers).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut legacy = claims.clone();
    legacy.auth_time = 0;
    legacy.iat = now - SESSION_ABSOLUTE_LIFETIME - 1;
    assert!(!session_within_absolute_lifetime(&legacy, now));
    legacy.iat = now - 100;
    assert!(session_within_absolute_lifetime(&legacy, now));
}

#[tokio::test(flavor = "current_thread")]
async fn authentication_readers_and_runtime_progress_while_writer_is_held() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::{middleware, routing::get, Router};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (987, 'writer-test', 'user')",
        [],
    )
    .unwrap();
    drop(conn);
    let headers = HeaderMap::new();
    let (token, claims) = create_standard_jwt(987, &headers).unwrap();
    let writer = af_db::get_conn().unwrap();
    writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let app = Router::new()
        .route("/protected", get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(auth_middleware));
    let req = Request::builder()
        .uri("/protected")
        .header(header::COOKIE, format!("aetherflow_session={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let started = Instant::now();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), app.oneshot(req))
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    let mut req = Request::new(axum::body::Body::empty());
    req.extensions_mut().insert(AuthUser {
        user_id: 987,
        username: "writer-test".into(),
        role: "user".into(),
        jti: claims.jti,
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    let operation = tokio::spawn(logout(req));
    tokio::task::yield_now().await;
    let started = Instant::now();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "Blocked SQLite acquisition must not stall Tokio"
    );
    assert!(
        !operation.is_finished(),
        "Write operation remains queued until writer is released"
    );
    writer.execute_batch("ROLLBACK;").unwrap();
    drop(writer);
    assert_eq!(operation.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn login_hides_oauth_only_accounts_and_caps_password_bytes() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};

    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO users (username, role, password_hash, google_id) VALUES ('oauth-only-fixture', 'user', '', 'oauth-id')",
            [],
        )
        .unwrap();
    for username in ["missing-fixture", "oauth-only-fixture"] {
        let response = local_login_blocking(
            HeaderMap::new(),
            CredentialsRequest {
                username: username.into(),
                password: "wrong-password".into(),
                setup_token: None,
            },
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["message"],
            "Invalid credentials"
        );
    }
    let response = local_login_blocking(
        HeaderMap::new(),
        CredentialsRequest {
            username: "missing-fixture".into(),
            password: "é".repeat(37),
            setup_token: None,
        },
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gateway_auth_requires_a_live_admin_session() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (41, 'gateway-test', 'user')",
        [],
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    let (token, claims) =
        create_session_jwt_in_conn(&conn, 41, &headers, Utc::now().timestamp(), None, 0).unwrap();
    headers.insert(
        header::COOKIE,
        format!("aetherflow_session={token}").parse().unwrap(),
    );
    drop(conn);

    assert_eq!(
        verify_proxy_auth(headers.clone()).await.status(),
        StatusCode::FORBIDDEN
    );
    af_db::get_conn()
        .unwrap()
        .execute("UPDATE users SET role = 'admin' WHERE id = 41", [])
        .unwrap();
    let response = verify_proxy_auth(headers.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["Remote-User"], "gateway-test");

    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE users SET sessions_revoked_after = 1 WHERE id = 41",
            [],
        )
        .unwrap();
    assert_eq!(
        verify_proxy_auth(headers.clone()).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let writer = af_db::get_conn().unwrap();
    writer
        .execute(
            "UPDATE users SET sessions_revoked_after = 0 WHERE id = 41",
            [],
        )
        .unwrap();
    // Also reject a signed JWT when its backing session has been deleted,
    // even if no revocation-cache entry exists.
    writer
        .execute("DELETE FROM active_sessions WHERE jti = ?1", [&claims.jti])
        .unwrap();
    drop(writer);
    assert_eq!(
        verify_proxy_auth(headers).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn list_active_sessions_excludes_expired_rows_without_pruning_them() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let writer = af_db::get_conn().unwrap();
    writer
        .execute(
            "INSERT INTO users (id, username, role) VALUES (41, 'session-list-test', 'admin')",
            [],
        )
        .unwrap();
    let (_, claims) = create_session_jwt_in_conn(
        &writer,
        41,
        &HeaderMap::new(),
        Utc::now().timestamp(),
        None,
        0,
    )
    .unwrap();
    writer.execute(
        "INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at) VALUES ('expired', 41, '', '', '2000-01-01T00:00:00+00:00')",
        [],
    ).unwrap();
    let now = Utc::now().timestamp();
    writer
        .execute(
            "INSERT INTO active_sessions (jti, user_id, expires_at) VALUES ('legacy', 41, ?1), ('legacy-expired', 41, ?2)",
            params![now + 3600, now - 3600],
        )
        .unwrap();
    assert!(is_session_active(&writer, "legacy", 41).unwrap());
    assert!(!is_session_active(&writer, "legacy-expired", 41).unwrap());
    let mut request = Request::new(axum::body::Body::empty());
    request.extensions_mut().insert(AuthUser {
        user_id: 41,
        username: "session-list-test".into(),
        role: "admin".into(),
        jti: claims.jti,
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    // Hold the only writer checkout to ensure the GET needs only a reader.
    let response = list_active_sessions(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["count"], 2);
    assert!(payload["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|session| session["is_current"] == true));
    assert!(writer
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE jti = 'expired')",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert_eq!(
        af_db::prune_expired_active_sessions(&writer, now).unwrap(),
        2
    );
    assert!(is_session_active(&writer, "legacy", 41).unwrap());
}

#[tokio::test]
async fn proxy_auth_rejects_revocation_and_fingerprint_mismatch() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO users (id, username, password_hash, role) VALUES (1, 'proxy-test-user', 'hash', 'user')",
            [],
        )
        .unwrap();
    }
    for revoked in [false, true] {
        let now = Utc::now().timestamp();
        let claims = SessionClaims {
            user_id: 1,
            sub: "1".into(),
            iss: "aetherflow".into(),
            iat: now,
            auth_time: now,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            cfp: client_fingerprint("original-agent"),
            ver: 0,
            plugin_id: String::new(),
            plugin_scopes: Vec::new(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&jwt_secret_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(if revoked {
                "original-agent"
            } else {
                "different-agent"
            }),
        );
        if revoked {
            af_db::revoke_token(&claims.jti, MIN_REVOCATION_TTL).unwrap();
        }
        assert_eq!(
            verify_proxy_auth(headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[test]
fn session_prefix_lookup_is_literal_unambiguous_and_user_scoped() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE active_sessions (jti TEXT, user_id INTEGER); INSERT INTO active_sessions VALUES ('abcdefgh-1', 1), ('abcdefgh-2', 1), ('abcdefgi-3', 2);").unwrap();
    let lookup = |prefix: &str| {
        conn.query_row(
            "SELECT MIN(jti) FROM active_sessions WHERE substr(jti, 1, length(?1)) = ?1 AND user_id = ?2 HAVING COUNT(*) = 1",
            params![prefix, 1],
            |row| row.get::<_, String>(0),
        )
    };
    assert!(lookup("________").is_err());
    assert!(lookup("%%%%%%%%").is_err());
    assert!(lookup("abcdefgh").is_err());
    assert!(lookup("abcdefgi").is_err());
    assert_eq!(lookup("abcdefgh-1").unwrap(), "abcdefgh-1");
}

#[tokio::test]
async fn concurrent_refresh_is_single_winner_and_replay_after_grace_revokes_family() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (991, 'refresh-race', 'user')",
            [],
        )
        .unwrap();
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("race-agent"));
    let (seed_token, seed_claims) = create_standard_jwt(991, &headers).unwrap();
    headers.insert(
        header::COOKIE,
        format!("aetherflow_session={seed_token}").parse().unwrap(),
    );

    let (r1, r2) = tokio::join!(refresh_session(headers.clone()), refresh_session(headers));
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(r2.status(), StatusCode::OK);
    let b1 = axum::body::to_bytes(r1.into_body(), 8192).await.unwrap();
    let b2 = axum::body::to_bytes(r2.into_body(), 8192).await.unwrap();
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    let rotated_token = v1["token"].as_str().unwrap().to_string();
    assert_eq!(rotated_token, v2["token"].as_str().unwrap());

    let rotated_claims = decode_session_claims(&rotated_token, false).unwrap();
    {
        let conn = af_db::get_read_conn().unwrap();
        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM active_sessions WHERE user_id = 991",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active_count, 1);
    }

    // Expire grace and replay the already-consumed seed token: family must be wiped.
    ROTATED_TOKEN_GRACE.lock().unwrap().remove(&seed_claims.jti);
    let mut replay_headers = HeaderMap::new();
    replay_headers.insert(header::USER_AGENT, HeaderValue::from_static("race-agent"));
    replay_headers.insert(
        header::COOKIE,
        format!("aetherflow_session={seed_token}").parse().unwrap(),
    );
    assert_eq!(
        refresh_session(replay_headers).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(af_db::is_token_revoked(&rotated_claims.jti));
    let conn = af_db::get_read_conn().unwrap();
    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM active_sessions WHERE user_id = 991",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn suspended_accounts_return_forbidden_across_auth_surfaces() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::{middleware, routing::get, Router};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let pw_hash = bcrypt::hash("suspended-pass", 4).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret) \
             VALUES (993, 'suspended-user', ?1, 'user', 1, 'JBSWY3DPEHPK3PXP')",
            params![pw_hash],
        )
        .unwrap();
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("susp-agent"));
    let (session_tok, _) = create_standard_jwt(993, &headers).unwrap();
    af_db::store_mfa_challenge("susp-mfa", 993, Duration::from_secs(300)).unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO user_quotas (user_id, username, status) VALUES (993, 'suspended-user', 'suspended')",
            [],
        )
        .unwrap();
    }

    // 1. local_login -> 403 FORBIDDEN
    let login_resp = local_login(
        headers.clone(),
        Json(CredentialsRequest {
            username: "suspended-user".into(),
            password: "suspended-pass".into(),
            setup_token: None,
        }),
    )
    .await;
    assert_eq!(login_resp.status(), StatusCode::FORBIDDEN);

    // 2. auth_middleware -> 403 FORBIDDEN
    let app = Router::new()
        .route("/protected", get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(auth_middleware));
    let mw_resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::USER_AGENT, "susp-agent")
                .header(header::COOKIE, format!("aetherflow_session={session_tok}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mw_resp.status(), StatusCode::FORBIDDEN);

    // 3. refresh_session -> 403 FORBIDDEN
    let mut ref_headers = headers.clone();
    ref_headers.insert(
        header::COOKIE,
        format!("aetherflow_session={session_tok}").parse().unwrap(),
    );
    assert_eq!(
        refresh_session(ref_headers).await.status(),
        StatusCode::FORBIDDEN
    );

    // 4. mfa_login_verify -> 403 FORBIDDEN
    let mfa_resp = mfa_login_verify(
        headers,
        Json(MfaVerifyRequest {
            mfa_token: "susp-mfa".into(),
            code: totp_now(),
        }),
    )
    .await;
    assert_eq!(mfa_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn round6_chained_normal_rotation_preserves_grace_and_post_grace_replay_wipes_family() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, sessions_revoked_after) \
             VALUES (996, 'r6-chain-user', 'hash', 'user', 0)",
            [],
        )
        .unwrap();
    }

    let mut base_headers = HeaderMap::new();
    base_headers.insert(header::USER_AGENT, HeaderValue::from_static("r6-chain-ua"));
    let (s0, s0_claims) = create_standard_jwt(996, &base_headers).unwrap();

    let do_refresh = |tok: String| async move {
        let mut h = HeaderMap::new();
        h.insert(header::USER_AGENT, HeaderValue::from_static("r6-chain-ua"));
        h.insert(
            header::COOKIE,
            format!("aetherflow_session={tok}").parse().unwrap(),
        );
        let resp = refresh_session(h).await;
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let next_tok = val["token"].as_str().unwrap_or("").to_string();
        (status, next_tok)
    };

    let (st1, s1) = do_refresh(s0.clone()).await;
    assert_eq!(st1, StatusCode::OK);
    assert!(!s1.is_empty());

    let (st2, s2) = do_refresh(s1.clone()).await;
    assert_eq!(st2, StatusCode::OK);
    assert!(!s2.is_empty());
    let s2_claims = decode_session_claims(&s2, false).unwrap();

    // In-flight refresh using ancestor s0 within grace MUST return active leaf s2 (not wipe family)
    let (st_grace, s_grace) = do_refresh(s0.clone()).await;
    assert_eq!(st_grace, StatusCode::OK);
    assert_eq!(s_grace, s2);
    assert!(!is_session_token_revoked_beyond_grace(&s0_claims.jti, 996));
    assert!(!af_db::is_token_revoked(&s2_claims.jti));

    // Simulate restart / expired grace: replaying s0 MUST return 401 and wipe leaf s2
    ROTATED_TOKEN_GRACE.lock().unwrap().clear();
    ROTATED_SESSION_SUCCESSOR.lock().unwrap().clear();
    let (st_replay, _) = do_refresh(s0).await;
    assert_eq!(st_replay, StatusCode::UNAUTHORIZED);
    assert!(af_db::is_token_revoked(&s2_claims.jti));
}

#[tokio::test]
async fn expired_within_grace_logout_revokes_family_and_authoritative_bearer_blocks_cookie_fallback(
) {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::{routing::post, Router};
    use tower::ServiceExt;

    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO users (id, username, password_hash, role, totp_enabled, sessions_revoked_after) \
             VALUES (998, 'grace-logout-user', 'hash', 'admin', 0, 0)",
            [],
        )
        .unwrap();
    }

    let mut base_headers = HeaderMap::new();
    base_headers.insert(header::USER_AGENT, HeaderValue::from_static("grace-ua"));

    // 1. Authoritative Authorization header never falls back to aetherflow_session cookie
    let (valid_cookie_tok, _) = create_standard_jwt(998, &base_headers).unwrap();
    let mut mixed_headers = HeaderMap::new();
    mixed_headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer   "));
    mixed_headers.insert(
        header::COOKIE,
        format!("aetherflow_session={valid_cookie_tok}")
            .parse()
            .unwrap(),
    );
    assert!(resolve_raw_token(&mixed_headers).is_none());

    // 2. Access JWT expired 10 minutes ago (within 2h refresh grace window) MUST be accepted
    //    by auth_middleware + csrf_middleware + logout, revoking the family so subsequent
    //    refresh fails with 401.
    let now = Utc::now().timestamp();
    let expired_jti = format!("grace-exp-jti-{}", uuid::Uuid::new_v4());
    let ip = extract_client_ip(&base_headers);
    let expired_claims = SessionClaims {
        user_id: 998,
        sub: "998".to_string(),
        jti: expired_jti.clone(),
        cfp: client_fingerprint("grace-ua"),
        iss: "aetherflow".to_string(),
        iat: now - 2400,
        auth_time: now - 2400,
        exp: now - 600,
        ver: 0,
        plugin_id: String::new(),
        plugin_scopes: Vec::new(),
    };
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO active_sessions (jti, family_id, user_id, ip_address, user_agent, expires_at, last_active) \
             VALUES (?1, ?1, 998, ?2, 'grace-ua', ?3, ?4)",
            params![
                expired_jti,
                ip,
                (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
    }
    let expired_jwt = encode(
        &Header::new(Algorithm::HS256),
        &expired_claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )
    .unwrap();

    let app = Router::new()
        .route("/api/v1/auth/logout", post(logout))
        .layer(axum::middleware::from_fn(csrf_middleware))
        .layer(axum::middleware::from_fn(auth_middleware));

    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header(header::USER_AGENT, "grace-ua")
        .header(
            header::COOKIE,
            format!("aetherflow_session={expired_jwt}; csrf_token=csrf-grace"),
        )
        .header("X-CSRF-Token", "csrf-grace")
        .body(axum::body::Body::empty())
        .unwrap();
    let logout_resp = app.oneshot(logout_req).await.unwrap();
    assert_eq!(logout_resp.status(), StatusCode::OK);
    assert!(af_db::is_token_revoked(&expired_jti));

    let mut refresh_headers = HeaderMap::new();
    refresh_headers.insert(header::USER_AGENT, HeaderValue::from_static("grace-ua"));
    refresh_headers.insert(
        header::COOKIE,
        format!("aetherflow_session={expired_jwt}").parse().unwrap(),
    );
    let refresh_resp = refresh_session(refresh_headers).await;
    assert_eq!(refresh_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn setup_admin_requires_loopback_or_bootstrap_token_and_unlinks_token_file() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let tmp =
        std::env::temp_dir().join(format!("af-setup-bootstrap-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("setup.sqlite");
    let token_file = tmp.join(".setup-bootstrap-token");
    std::fs::write(&token_file, "boot-secret-token-991\n").unwrap();
    std::env::set_var("AETHERFLOW_DATA_DIR", &tmp);
    std::env::set_var("AF_DB_PATH", &db_path);
    std::env::set_var("DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_DB_PATH", &db_path);
    af_db::init_db().unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users", []).unwrap();
    }

    // Proxied request without setup token must receive 403 SETUP_TOKEN_REQUIRED
    let mut proxied_headers = HeaderMap::new();
    proxied_headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());
    let denied = setup_admin_blocking(
        Some("127.0.0.1".parse().unwrap()),
        true,
        proxied_headers.clone(),
        CredentialsRequest {
            username: "firstadmin".into(),
            password: "StrongPassword!123".into(),
            setup_token: None,
        },
    );
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(token_file.exists());

    // Proxied request WITH valid setup token succeeds and atomically unlinks token file
    let created = setup_admin_blocking(
        Some("127.0.0.1".parse().unwrap()),
        true,
        proxied_headers,
        CredentialsRequest {
            username: "firstadmin".into(),
            password: "StrongPassword!123".into(),
            setup_token: Some("boot-secret-token-991".into()),
        },
    );
    assert_eq!(created.status(), StatusCode::OK);
    assert!(!token_file.exists());

    // Verify ensure_setup_bootstrap_token auto-provisions 0600 token when users == 0
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users", []).unwrap();
    }
    ensure_setup_bootstrap_token();
    assert!(token_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(&token_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    let auto_tok = std::fs::read_to_string(&token_file)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(auto_tok.len(), 64);
    let mut proxied_headers2 = HeaderMap::new();
    proxied_headers2.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());
    let created2 = setup_admin_blocking(
        Some("127.0.0.1".parse().unwrap()),
        true,
        proxied_headers2,
        CredentialsRequest {
            username: "secondboot".into(),
            password: "StrongPassword!123".into(),
            setup_token: Some(auto_tok),
        },
    );
    assert_eq!(created2.status(), StatusCode::OK);
    assert!(!token_file.exists());
    // Does not recreate once a user exists
    ensure_setup_bootstrap_token();
    assert!(!token_file.exists());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn list_active_sessions_propagates_sqlite_row_errors_instead_of_swallowing() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let now = Utc::now().timestamp();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (711, 'corrupt-sess-user', 'user')",
            [],
        )
        .unwrap();
        // Store a BLOB in `jti` so `prepare` + `query_map` succeed but row decoding errors.
        conn.execute(
            "INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at) \
             VALUES (?1, 711, '127.0.0.1', 'agent', ?2)",
            params![vec![0xdeu8, 0xadu8, 0xbeu8, 0xefu8], now + 3600],
        )
        .unwrap();
    }
    let mut req = Request::new(axum::body::Body::empty());
    req.extensions_mut().insert(AuthUser {
        user_id: 711,
        username: "corrupt-sess-user".into(),
        role: "user".into(),
        jti: "current".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    let resp = list_active_sessions(req).await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Row decode/SQLite errors in list_active_sessions must return 500 rather than an empty 200 list"
    );
}

#[tokio::test]
async fn get_session_revoke_session_and_login_propagate_sqlite_errors() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE active_sessions", []).unwrap();
        conn.execute("DROP TABLE users", []).unwrap();
        // Verify credential version helper propagates SQLite errors when a query fails.
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, sessions_revoked_after INTEGER); INSERT INTO users VALUES (1, X'deadbeef');").unwrap();
        assert!(
            query_user_credential_version(&conn, 1).is_err(),
            "query_user_credential_version must propagate SQLite column type errors"
        );
        conn.execute("DROP TABLE users", []).unwrap();
    }

    let make_req = || {
        let mut req = Request::new(axum::body::Body::empty());
        req.extensions_mut().insert(AuthUser {
            user_id: 712,
            username: "missing-table-user".into(),
            role: "user".into(),
            jti: "12345678-1234-1234-1234-1234567890ab".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        req
    };

    assert_eq!(
        get_session(make_req()).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "get_session must return 500 on SQLite errors rather than 401 User not found"
    );
    assert_eq!(
        revoke_session(Path("12345678".to_string()), make_req())
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "revoke_session must return 500 on SQLite errors rather than 404 Session not found"
    );
    assert_eq!(
        local_login_blocking(
            HeaderMap::new(),
            CredentialsRequest {
                username: "anyone".into(),
                password: "StrongPassword123".into(),
                setup_token: None,
            },
        )
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "local_login must return 500 on SQLite errors rather than 401 Invalid credentials"
    );
}
