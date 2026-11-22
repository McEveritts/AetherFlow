use super::authorize::{
    generate_and_store_auth_code, oidc_authorize, oidc_consent, AuthorizeQuery,
};
use super::clients::{delete_oidc_client, get_oidc_clients};
use super::introspection::{
    access_token_subject_exists, oidc_introspect, oidc_revoke, oidc_userinfo,
};
use super::keys::OIDC_KEYS;
use super::token_endpoint::{issue_oidc_tokens_in_tx, oidc_token, IdTokenClaims};
use crate::auth::{create_standard_jwt, AuthUser};
use axum::extract::{Form, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, Validation};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;

#[test]
fn access_token_introspection_requires_a_live_subject_and_fails_closed_on_database_errors() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY); INSERT INTO users VALUES (1), (2);",
        )
        .unwrap();
    assert!(access_token_subject_exists(&connection, "1"));
    connection
        .execute("DELETE FROM users WHERE id = 1", [])
        .unwrap();
    assert!(!access_token_subject_exists(&connection, "1"));
    assert!(access_token_subject_exists(&connection, "2"));
    for invalid in ["", "-1", "0", "not-an-id", "9223372036854775808"] {
        assert!(!access_token_subject_exists(&connection, invalid));
    }
    connection.execute("DROP TABLE users", []).unwrap();
    assert!(!access_token_subject_exists(&connection, "2"));
}

#[tokio::test]
async fn oidc_nonce_roundtrips_authorization_consent_code_and_id_token() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    env::set_var("OIDC_KEY_PATH", db.parent().unwrap().join("oidc.pem"));
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (765, 'oidc-user', 'user')",
        [],
    )
    .unwrap();
    let secret = hex::encode(Sha256::digest(b"client-secret"));
    conn.execute(
        "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('client', ?1, 'test', '[\"https://client.example/callback\"]')",
        params![secret],
    )
    .unwrap();
    drop(conn);
    let (session, _) = create_standard_jwt(765, &HeaderMap::new()).unwrap();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let q = AuthorizeQuery {
        client_id: "client".into(),
        redirect_uri: "https://client.example/callback".into(),
        response_type: "code".into(),
        scope: "openid".into(),
        state: "state".into(),
        nonce: "nonce-value&?".into(),
        code_challenge: challenge,
        code_challenge_method: "S256".into(),
    };
    let req = Request::builder()
        .uri("/api/v1/public/oidc/authorize")
        .header(header::COOKIE, format!("aetherflow_session={session}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = oidc_authorize(Query(q), req).await;
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    let url = url::Url::parse(&format!("https://dashboard.example{location}")).unwrap();
    let values: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(values["nonce"], "nonce-value&?");
    let mut payload = serde_json::to_value(&values).unwrap();
    payload["approved"] = true.into();
    let mut req = Request::new(axum::body::Body::from(payload.to_string()));
    req.extensions_mut().insert(AuthUser {
        user_id: 765,
        username: "oidc-user".into(),
        role: "user".into(),
        jti: "consent".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    let response = oidc_consent(req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let redirect = url::Url::parse(value["redirect_uri"].as_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form: HashMap<String, String> = [
        ("grant_type", "authorization_code"),
        ("client_id", "client"),
        ("client_secret", "client-secret"),
        ("redirect_uri", "https://client.example/callback"),
        ("code", &code),
        ("code_verifier", verifier),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let response = oidc_token(
        crate::ws::PeerIp(None),
        HeaderMap::new(),
        Form(form.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 32768)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["client"]);
    let decoded = decode::<IdTokenClaims>(
        value["id_token"].as_str().unwrap(),
        &OIDC_KEYS.as_ref().unwrap().decoding_key,
        &validation,
    )
    .unwrap();
    assert_eq!(decoded.claims.nonce.as_deref(), Some("nonce-value&?"));
    assert_eq!(
        oidc_token(crate::ws::PeerIp(None), HeaderMap::new(), Form(form))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn oidc_refresh_reuse_wipes_family_and_revoke_or_client_delete_invalidates_access_tokens() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    env::set_var("OIDC_KEY_PATH", db.parent().unwrap().join("oidc-rev.pem"));
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, email, role) VALUES (888, 'oidc-rev-user', 'rev@example.com', 'user')",
        [],
    )
    .unwrap();
    let secret = hex::encode(Sha256::digest(b"rev-secret"));
    conn.execute(
        "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('rev-client', ?1, 'rev', '[\"https://client.example/cb\"]')",
        params![secret],
    )
    .unwrap();
    let v1 = issue_oidc_tokens_in_tx(
        &conn,
        &HeaderMap::new(),
        None,
        "rev-client",
        888,
        "openid profile email",
        None,
        None,
    )
    .expect("initial OIDC token issuance should succeed");
    drop(conn);
    let r1 = v1["refresh_token"].as_str().unwrap().to_string();
    let a1 = v1["access_token"].as_str().unwrap().to_string();

    // Rotate R1 -> R2.
    let rotate_form: HashMap<String, String> = [
        ("grant_type", "refresh_token"),
        ("client_id", "rev-client"),
        ("client_secret", "rev-secret"),
        ("refresh_token", r1.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let rot_resp = oidc_token(
        crate::ws::PeerIp(None),
        HeaderMap::new(),
        Form(rotate_form.clone()),
    )
    .await;
    assert_eq!(rot_resp.status(), StatusCode::OK);
    let b2 = axum::body::to_bytes(rot_resp.into_body(), 32768)
        .await
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    let r2 = v2["refresh_token"].as_str().unwrap().to_string();
    let a2 = v2["access_token"].as_str().unwrap().to_string();

    // Replaying R1 must fail AND wipe the entire refresh token family (invalidating R2!).
    let replay_resp =
        oidc_token(crate::ws::PeerIp(None), HeaderMap::new(), Form(rotate_form)).await;
    assert_eq!(replay_resp.status(), StatusCode::BAD_REQUEST);

    let r2_form: HashMap<String, String> = [
        ("grant_type", "refresh_token"),
        ("client_id", "rev-client"),
        ("client_secret", "rev-secret"),
        ("refresh_token", r2.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let r2_resp = oidc_token(crate::ws::PeerIp(None), HeaderMap::new(), Form(r2_form)).await;
    assert_eq!(
        r2_resp.status(),
        StatusCode::BAD_REQUEST,
        "Successor refresh token must be revoked when predecessor reuse is detected"
    );

    // Replaying R1 must also immediately invalidate access tokens (a1, a2) from that compromised family.
    for poisoned_at in [&a1, &a2] {
        let mut poisoned_headers = HeaderMap::new();
        poisoned_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {poisoned_at}")).unwrap(),
        );
        assert_eq!(
            oidc_userinfo(crate::ws::PeerIp(None), poisoned_headers)
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "Access tokens from a compromised refresh-token family must be rejected immediately"
        );
    }

    // Issue two fresh uncompromised grants (a3, a4) to verify /oidc/revoke and client deletion independently.
    let conn = af_db::get_conn().unwrap();
    let v3 = issue_oidc_tokens_in_tx(
        &conn,
        &HeaderMap::new(),
        None,
        "rev-client",
        888,
        "openid profile email",
        None,
        None,
    )
    .expect("fresh OIDC token issuance a3 should succeed");
    let v4 = issue_oidc_tokens_in_tx(
        &conn,
        &HeaderMap::new(),
        None,
        "rev-client",
        888,
        "openid profile email",
        None,
        None,
    )
    .expect("fresh OIDC token issuance a4 should succeed");
    drop(conn);
    let a3 = v3["access_token"].as_str().unwrap().to_string();
    let a4 = v4["access_token"].as_str().unwrap().to_string();

    // Userinfo accepts a3 initially, then rejects a3 immediately after /oidc/revoke.
    let mut ui_headers = HeaderMap::new();
    ui_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a3}")).unwrap(),
    );
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), ui_headers.clone())
            .await
            .status(),
        StatusCode::OK
    );

    let revoke_a3: HashMap<String, String> = [
        ("client_id", "rev-client"),
        ("client_secret", "rev-secret"),
        ("token", a3.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    assert_eq!(
        oidc_revoke(HeaderMap::new(), Form(revoke_a3))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), ui_headers)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let introspect_a3: HashMap<String, String> = [
        ("client_id", "rev-client"),
        ("client_secret", "rev-secret"),
        ("token", a3.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let intr_resp = oidc_introspect(
        crate::ws::PeerIp(None),
        HeaderMap::new(),
        Form(introspect_a3),
    )
    .await;
    let intr_bytes = axum::body::to_bytes(intr_resp.into_body(), 8192)
        .await
        .unwrap();
    let intr_val: serde_json::Value = serde_json::from_slice(&intr_bytes).unwrap();
    assert_eq!(intr_val["active"], false);

    // Deleting the client invalidates any remaining access token (a4) at /oidc/userinfo.
    let mut ui2_headers = HeaderMap::new();
    ui2_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {a4}")).unwrap(),
    );
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), ui2_headers.clone())
            .await
            .status(),
        StatusCode::OK
    );
    let del_resp = delete_oidc_client(
        Path("rev-client".to_string()),
        Request::new(axum::body::Body::empty()),
    )
    .await;
    assert_eq!(del_resp.status(), StatusCode::OK);
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), ui2_headers)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn id_token_claims_omit_pii_when_only_openid_scope_granted() {
    let minimal = IdTokenClaims {
        iss: "https://issuer.example".into(),
        sub: "42".into(),
        aud: "client".into(),
        exp: 2000,
        iat: 1000,
        name: None,
        email: None,
        picture: None,
        role: None,
        nonce: None,
    };
    let encoded = serde_json::to_value(&minimal).unwrap();
    assert!(encoded.get("email").is_none());
    assert!(encoded.get("name").is_none());
    assert!(encoded.get("picture").is_none());
    assert!(encoded.get("role").is_none());

    let rich = IdTokenClaims {
        name: Some("alice".into()),
        email: Some("alice@example.com".into()),
        ..minimal
    };
    let rich_json = serde_json::to_value(&rich).unwrap();
    assert_eq!(rich_json["name"], "alice");
    assert_eq!(rich_json["email"], "alice@example.com");
}

#[tokio::test]
async fn round8_session_scoped_oidc_revocation_and_auth_code_replay_wipes_grant_family() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    env::set_var("OIDC_KEY_PATH", db.parent().unwrap().join("oidc-r8.pem"));
    let secret_hash = hex::encode(Sha256::digest(b"r8-secret"));
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, email, role, sessions_revoked_after) \
             VALUES (889, 'r8-oidc-user', 'r8@example.com', 'user', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
             VALUES ('r8-client', ?1, 'R8Client', '[\"https://r8.example/cb\"]')",
            params![secret_hash],
        )
        .unwrap();
    }

    let mut ua_headers = HeaderMap::new();
    ua_headers.insert(header::USER_AGENT, HeaderValue::from_static("r8-oidc-ua"));
    let (sess_a_tok, sess_a_claims) = create_standard_jwt(889, &ua_headers).unwrap();
    let (_sess_b_tok, sess_b_claims) = create_standard_jwt(889, &ua_headers).unwrap();

    let (fam_a, fam_b) = {
        let conn = af_db::get_conn().unwrap();
        (
            crate::auth::resolve_session_family_id(&conn, 889, &sess_a_claims.jti),
            crate::auth::resolve_session_family_id(&conn, 889, &sess_b_claims.jti),
        )
    };

    let verifier = "v".repeat(43);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code_a = generate_and_store_auth_code(
        "r8-client",
        889,
        "https://r8.example/cb",
        "openid profile email",
        &challenge,
        "S256",
        "",
        Some(&fam_a),
    )
    .unwrap();
    let code_b = generate_and_store_auth_code(
        "r8-client",
        889,
        "https://r8.example/cb",
        "openid profile email",
        &challenge,
        "S256",
        "",
        Some(&fam_b),
    )
    .unwrap();

    let exchange = |code: String| {
        let verifier = verifier.clone();
        async move {
            let form: HashMap<String, String> = [
                ("grant_type", "authorization_code"),
                ("client_id", "r8-client"),
                ("client_secret", "r8-secret"),
                ("code", code.as_str()),
                ("redirect_uri", "https://r8.example/cb"),
                ("code_verifier", verifier.as_str()),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
            let resp = oidc_token(crate::ws::PeerIp(None), HeaderMap::new(), Form(form)).await;
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            (status, val)
        }
    };

    let (st_a, val_a) = exchange(code_a).await;
    assert_eq!(st_a, StatusCode::OK);
    let access_a = val_a["access_token"].as_str().unwrap().to_string();
    let refresh_a = val_a["refresh_token"].as_str().unwrap().to_string();

    let (st_b, val_b) = exchange(code_b.clone()).await;
    assert_eq!(st_b, StatusCode::OK);
    let access_b = val_b["access_token"].as_str().unwrap().to_string();
    let refresh_b = val_b["refresh_token"].as_str().unwrap().to_string();

    let bearer_headers = |tok: &str| {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
        );
        h
    };
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), bearer_headers(&access_a))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), bearer_headers(&access_b))
            .await
            .status(),
        StatusCode::OK
    );

    // 1. Logging out browser Session A revokes Session A's OIDC access + refresh tokens,
    //    while preserving sibling Session B's OIDC tokens.
    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header(header::USER_AGENT, "r8-oidc-ua")
        .header(header::COOKIE, format!("aetherflow_session={sess_a_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        crate::auth::logout(logout_req).await.status(),
        StatusCode::OK
    );

    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), bearer_headers(&access_a))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let refresh_a_form: HashMap<String, String> = [
        ("grant_type", "refresh_token"),
        ("client_id", "r8-client"),
        ("client_secret", "r8-secret"),
        ("refresh_token", refresh_a.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    assert_eq!(
        oidc_token(
            crate::ws::PeerIp(None),
            HeaderMap::new(),
            Form(refresh_a_form)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), bearer_headers(&access_b))
            .await
            .status(),
        StatusCode::OK
    );

    // 2. Replaying consumed authorization code `code_b` fails AND immediately revokes
    //    its issued grant family (`access_b` + `refresh_b`).
    let (st_replay, _) = exchange(code_b).await;
    assert_eq!(st_replay, StatusCode::BAD_REQUEST);
    assert_eq!(
        oidc_userinfo(crate::ws::PeerIp(None), bearer_headers(&access_b))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let refresh_b_form: HashMap<String, String> = [
        ("grant_type", "refresh_token"),
        ("client_id", "r8-client"),
        ("client_secret", "r8-secret"),
        ("refresh_token", refresh_b.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    assert_eq!(
        oidc_token(
            crate::ws::PeerIp(None),
            HeaderMap::new(),
            Form(refresh_b_form)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn oidc_authorize_login_redirect_preserves_original_nested_uri() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;

    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris)
             VALUES ('authorize-fixture', 'configured', 'Fixture', '[\"https://client.example/cb\"]')",
            [],
        )
        .unwrap();
    let uri = "/api/v1/public/oidc/authorize?client_id=authorize-fixture&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=openid&state=fixture&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256";
    let response = crate::routes::build_router()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::HOST, "localhost")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()[header::LOCATION].to_str().unwrap(),
        format!("/login?return_to={}", urlencoding::encode(uri))
    );
}

#[tokio::test]
async fn get_oidc_clients_propagates_sqlite_errors_instead_of_returning_empty_list() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        // Inject a BLOB into `name` so prepare + query_map succeed but row decoding errors.
        conn.execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
             VALUES ('corrupt-client', 'hash', ?1, '[\"https://client.example/cb\"]')",
            params![vec![0xffu8, 0x00u8, 0xfeu8]],
        )
        .unwrap();
    }
    assert_eq!(
        get_oidc_clients().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Row decoding error in get_oidc_clients must return 500 rather than silently returning 200 []"
    );
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE oidc_clients", []).unwrap();
    }
    assert_eq!(
        get_oidc_clients().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Missing oidc_clients table must return 500 rather than silently returning 200 []"
    );
}

#[tokio::test]
async fn oidc_token_auth_code_and_revoke_propagate_sqlite_errors() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    env::set_var("OIDC_KEY_PATH", db.parent().unwrap().join("oidc-err.pem"));
    let secret_hash = hex::encode(Sha256::digest(b"err-secret"));
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (791, 'oidc-err-user', 'user')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
             VALUES ('err-client', ?1, 'ErrClient', '[\"https://err.example/cb\"]')",
            params![secret_hash],
        )
        .unwrap();
    }
    let code = generate_and_store_auth_code(
        "err-client",
        791,
        "https://err.example/cb",
        "openid",
        &challenge,
        "S256",
        "",
        None,
    )
    .unwrap();

    // Abort UPDATE on oidc_auth_codes: must return 500 server_error, NOT 400 code already used.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER abort_code_consume BEFORE UPDATE ON oidc_auth_codes \
             BEGIN SELECT RAISE(ABORT, 'disk failure'); END;",
        )
        .unwrap();
    }
    let form: HashMap<String, String> = [
        ("grant_type", "authorization_code"),
        ("client_id", "err-client"),
        ("client_secret", "err-secret"),
        ("redirect_uri", "https://err.example/cb"),
        ("code", code.as_str()),
        ("code_verifier", verifier),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    assert_eq!(
        oidc_token(
            crate::ws::PeerIp(None),
            HeaderMap::new(),
            Form(form.clone())
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "SQLite UPDATE failure during auth-code consumption must return 500 rather than 400 invalid_grant"
    );

    // Dropping oidc_refresh_tokens must surface 500 server_error from oidc_revoke.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE oidc_refresh_tokens", []).unwrap();
    }
    let revoke_form: HashMap<String, String> = [
        ("client_id", "err-client"),
        ("client_secret", "err-secret"),
        ("token", "some-refresh-token"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    assert_eq!(
        oidc_revoke(HeaderMap::new(), Form(revoke_form))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "oidc_revoke must return 500 when oidc_refresh_tokens lookup fails"
    );

    // Dropping oidc_clients must surface 500 server_error from client authentication, not 401 invalid_client.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE oidc_clients", []).unwrap();
    }
    assert_eq!(
        oidc_token(crate::ws::PeerIp(None), HeaderMap::new(), Form(form))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "authenticate_oidc_client must return 500 on SQLite errors instead of 401 invalid_client"
    );
}

#[tokio::test]
async fn oidc_consent_rolls_back_auth_code_when_consent_persistence_fails() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (792, 'consent-err-user', 'user')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) \
             VALUES ('consent-err-client', 'hash', 'ConsentErr', '[\"https://consent.example/cb\"]')",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER abort_oidc_consent_write BEFORE INSERT ON oidc_consents \
             BEGIN SELECT RAISE(ABORT, 'consent write failure'); END;",
        )
        .unwrap();
    }

    let mut req = Request::new(axum::body::Body::from(
        serde_json::json!({
            "client_id": "consent-err-client",
            "redirect_uri": "https://consent.example/cb",
            "response_type": "code",
            "scope": "openid",
            "state": "s1",
            "nonce": "n1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "approved": true,
        })
        .to_string(),
    ));
    req.extensions_mut().insert(AuthUser {
        user_id: 792,
        username: "consent-err-user".into(),
        role: "user".into(),
        jti: "jti-792".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    assert_eq!(
        oidc_consent(req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "oidc_consent must surface 500 when persisting consent fails"
    );
    let conn = af_db::get_read_conn().unwrap();
    let code_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM oidc_auth_codes WHERE client_id = 'consent-err-client'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        code_count, 0,
        "Auth code insert must roll back cleanly if oidc_consents write fails"
    );
}
