use super::mfa::{
    consume_recovery_code, consume_totp_code, disable_2fa, generate_recovery_codes,
    hash_recovery_codes, match_recovery_in_connection, mfa_login_verify, normalized_recovery_code,
    recovery_hash, setup_2fa, store_recovery_codes, verify_2fa, verify_mfa_factor,
    MfaVerifyRequest,
};
use super::revocation::{
    revoke_all_user_credentials_in_tx, RotatedTokenGraceEntry, ROTATED_TOKEN_GRACE,
    ROTATED_TOKEN_GRACE_WINDOW,
};
use super::sessions::refresh_session;
use super::tokens::{
    create_session_jwt, create_standard_jwt, decode_session_claims, jwt_secret_bytes, AuthUser,
};
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Json;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn mfa_database() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, avatar_url TEXT, role TEXT, google_id TEXT, totp_secret TEXT, totp_enabled INTEGER, last_totp_step INTEGER DEFAULT -1, sessions_revoked_after INTEGER DEFAULT 0);
        INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1, 0);
        CREATE TABLE mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER, credential_ver INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, expires_at INTEGER);
        CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY, user_id INTEGER, code_hash TEXT, used INTEGER DEFAULT 0);",
    )
    .unwrap();
    conn
}

fn totp_now() -> String {
    let bytes = BASE32_NOPAD.decode(b"JBSWY3DPEHPK3PXP").unwrap();
    totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, Utc::now().timestamp() as u64)
}

fn add_challenge(conn: &rusqlite::Connection, token: &str) {
    conn.execute(
        "INSERT INTO mfa_challenges (token, user_id, expires_at) VALUES (?1, 1, ?2)",
        params![token, Utc::now().timestamp() + 300],
    )
    .unwrap();
}

fn validate_recovery_in_test(conn: &rusqlite::Connection, user_id: i64, raw_code: &str) -> bool {
    let matched = match_recovery_in_connection(conn, user_id, raw_code);
    consume_recovery_code(conn, user_id, matched.as_ref())
}

fn recovery_database() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, totp_recovery_codes TEXT);
         INSERT INTO users VALUES (1, '[\"old-plaintext\"]');
         CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, used INTEGER DEFAULT 0);",
    )
    .unwrap();
    conn
}

#[test]
fn mfa_attempt_limit_consumption_and_totp_replay_are_enforced() {
    let conn = mfa_database();
    add_challenge(&conn, "exhausted");
    for _ in 0..5 {
        assert!(verify_mfa_factor(&conn, "exhausted", "invalid")
            .unwrap()
            .is_none());
    }
    assert!(verify_mfa_factor(&conn, "exhausted", &totp_now())
        .unwrap()
        .is_none());
    add_challenge(&conn, "first");
    add_challenge(&conn, "second");
    let code = totp_now();
    assert!(verify_mfa_factor(&conn, "first", &code).unwrap().is_some());
    assert!(verify_mfa_factor(&conn, "first", &code).unwrap().is_none());
    assert!(verify_mfa_factor(&conn, "second", &code).unwrap().is_none());
    assert!(!consume_totp_code(&conn, 1, "JBSWY3DPEHPK3PXP", &code));
    conn.execute(
        "UPDATE mfa_challenges SET expires_at = 0 WHERE token = 'second'",
        [],
    )
    .unwrap();
    assert!(verify_mfa_factor(&conn, "second", &code).unwrap().is_none());
}

#[test]
fn mfa_recovery_codes_still_work_after_totp_and_are_consumed_atomically() {
    let conn = mfa_database();
    let codes = generate_recovery_codes();
    let tx = conn.unchecked_transaction().unwrap();
    store_recovery_codes(&tx, 1, &hash_recovery_codes(&codes).unwrap()).unwrap();
    tx.commit().unwrap();
    add_challenge(&conn, "totp");
    add_challenge(&conn, "recovery");
    add_challenge(&conn, "replay");
    assert!(verify_mfa_factor(&conn, "totp", &totp_now())
        .unwrap()
        .is_some());
    assert!(
        verify_mfa_factor(&conn, "recovery", &codes[0].replace('-', "").to_lowercase())
            .unwrap()
            .is_some()
    );
    assert!(verify_mfa_factor(&conn, "replay", &codes[0])
        .unwrap()
        .is_none());
}

#[test]
fn concurrent_mfa_redemption_allows_one_success_and_persists_replay_guard() {
    let path = std::env::temp_dir().join(format!("af-mfa-race-{}.sqlite", Uuid::new_v4()));
    let seed = mfa_database();
    let schema: Vec<String> = seed
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let conn = rusqlite::Connection::open(&path).unwrap();
    for sql in schema {
        conn.execute_batch(&sql).unwrap();
    }
    conn.execute(
        "INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1, 0)",
        [],
    )
    .unwrap();
    add_challenge(&conn, "shared");
    add_challenge(&conn, "later");
    drop(conn);
    let code = totp_now();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let code = code.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let conn = rusqlite::Connection::open(path).unwrap();
                conn.busy_timeout(Duration::from_secs(2)).unwrap();
                barrier.wait();
                verify_mfa_factor(&conn, "shared", &code).unwrap().is_some()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let reopened = rusqlite::Connection::open(&path).unwrap();
    assert!(verify_mfa_factor(&reopened, "later", &code)
        .unwrap()
        .is_none());
    drop(reopened);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn authenticated_wrong_2fa_code_is_forbidden_and_keeps_session() {
    af_db::store_2fa_pending(919, "JBSWY3DPEHPK3PXP", Duration::from_secs(300));
    let mut req = Request::new(axum::body::Body::from(r#"{"code":"invalid"}"#));
    req.extensions_mut().insert(AuthUser {
        user_id: 919,
        username: "setup-factor".into(),
        role: "user".into(),
        jti: "current-session".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    let response = verify_2fa(req).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["code"], "INVALID_2FA_CODE");
}

#[tokio::test]
async fn mfa_endpoint_race_issues_one_session_and_refresh_retains_original_auth_time() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute("INSERT INTO users (id, username, role, totp_enabled, totp_secret) VALUES (988, 'mfa-race', 'user', 1, 'JBSWY3DPEHPK3PXP')", []).unwrap();
    drop(conn);
    af_db::store_mfa_challenge("single-challenge", 988, Duration::from_secs(300)).unwrap();
    let code = totp_now();
    let (a, b) = tokio::join!(
        mfa_login_verify(
            HeaderMap::new(),
            Json(MfaVerifyRequest {
                mfa_token: "single-challenge".into(),
                code: code.clone()
            })
        ),
        mfa_login_verify(
            HeaderMap::new(),
            Json(MfaVerifyRequest {
                mfa_token: "single-challenge".into(),
                code
            })
        )
    );
    assert_eq!(
        [a.status(), b.status()]
            .into_iter()
            .filter(|status| *status == StatusCode::OK)
            .count(),
        1
    );
    let conn = af_db::get_read_conn().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM active_sessions WHERE user_id = 988",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    drop(conn);
    let original_time = Utc::now().timestamp() - 86400;
    let (old_token, _) = create_session_jwt(988, &HeaderMap::new(), original_time).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("aetherflow_session={old_token}").parse().unwrap(),
    );
    let response = refresh_session(headers.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let new_token = value["token"].as_str().unwrap();
    let claims = decode_session_claims(new_token, false).unwrap();
    assert_eq!(claims.auth_time, original_time);
    // Force a revocation query failure while a rotation-grace entry exists.
    let old_claims = decode_session_claims(&old_token, true).unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute("DROP TABLE revoked_tokens", []).unwrap();
    drop(conn);
    // Use another token JTI for the grace case to bypass the intentional in-memory blacklist fast path.
    let mut failure_claims = old_claims;
    failure_claims.jti = Uuid::new_v4().to_string();
    ROTATED_TOKEN_GRACE.lock().unwrap().insert(
        failure_claims.jti.clone(),
        RotatedTokenGraceEntry {
            user_id: 988,
            family_id: failure_claims.jti.clone(),
            successor_jti: claims.jti.clone(),
            new_token: new_token.into(),
            successor_exp: claims.exp,
            strict_fp: String::new(),
            expires_at: Instant::now() + ROTATED_TOKEN_GRACE_WINDOW,
        },
    );
    let failure_token = encode(
        &Header::new(Algorithm::HS256),
        &failure_claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )
    .unwrap();
    headers.insert(
        header::COOKIE,
        format!("aetherflow_session={failure_token}")
            .parse()
            .unwrap(),
    );
    assert_eq!(
        refresh_session(headers).await.status(),
        StatusCode::UNAUTHORIZED,
        "DB errors must fail closed even during rotation grace"
    );
}

#[test]
fn recovery_format_gate_excludes_totp_and_invalid_codes() {
    for invalid in [
        "123456",
        "ABCDEF",
        "ABCDEFXY",
        "123456789",
        "------",
        "１２３４５６",
    ] {
        assert!(normalized_recovery_code(invalid).is_none(), "{invalid}");
    }
    assert_eq!(
        normalized_recovery_code("ab12-cd34"),
        Some(("AB12CD34".into(), true))
    );
    for code in generate_recovery_codes() {
        assert!(matches!(normalized_recovery_code(&code), Some((_, false))));
    }
}

#[test]
fn recovery_codes_are_hashed_normalized_and_single_use() {
    let conn = recovery_database();
    let codes = generate_recovery_codes();
    assert_eq!(codes.len(), 8);
    for code in &codes {
        let compact: String = code.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            compact.len(),
            28,
            "recovery codes must carry 140 bits of entropy"
        );
    }
    let transaction = conn.unchecked_transaction().unwrap();
    store_recovery_codes(&transaction, 1, &hash_recovery_codes(&codes).unwrap()).unwrap();
    transaction.commit().unwrap();
    let legacy: String = conn
        .query_row(
            "SELECT totp_recovery_codes FROM users WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy, "[]");
    let hash: String = conn
        .query_row("SELECT code_hash FROM recovery_codes LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        hash.starts_with("$2b$") || hash.starts_with("$2a$"),
        "stored recovery code hash must use bcrypt KDF, got {hash}"
    );
    assert!(!codes.contains(&hash));
    assert!(!validate_recovery_in_test(&conn, 2, &codes[0]));
    assert!(validate_recovery_in_test(
        &conn,
        1,
        &codes[0].replace('-', "").to_lowercase()
    ));
    assert!(!validate_recovery_in_test(&conn, 1, &codes[0]));
}

#[test]
fn recovery_replacement_rolls_back_and_consumption_fails_closed() {
    let conn = recovery_database();
    conn.execute(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'old-hash')",
        [],
    )
    .unwrap();
    conn.execute_batch("CREATE TRIGGER reject_insert BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT, 'test failure'); END;").unwrap();
    {
        let transaction = conn.unchecked_transaction().unwrap();
        assert!(store_recovery_codes(
            &transaction,
            1,
            &hash_recovery_codes(&generate_recovery_codes()).unwrap()
        )
        .is_err());
    }
    let hash: String = conn
        .query_row("SELECT code_hash FROM recovery_codes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(hash, "old-hash");
    conn.execute_batch("DROP TRIGGER reject_insert; DELETE FROM recovery_codes;")
        .unwrap();
    let unsalted_sha = hex::encode(Sha256::digest(b"ABCD-EF12"));
    conn.execute(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, ?1)",
        params![unsalted_sha],
    )
    .unwrap();
    assert!(
        !validate_recovery_in_test(&conn, 1, "abcdef12"),
        "unsalted 64-hex SHA-256 recovery hashes must be rejected"
    );
    conn.execute("DELETE FROM recovery_codes", []).unwrap();
    let salt = [0x42u8; 16];
    let salted_hash = format!(
        "sha256:v1:{}:{}",
        hex::encode(salt),
        recovery_hash(&salt, "ABCDEF12")
    );
    conn.execute(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, ?1)",
        params![salted_hash],
    )
    .unwrap();
    conn.execute_batch("CREATE TRIGGER reject_consume BEFORE UPDATE ON recovery_codes BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(!validate_recovery_in_test(&conn, 1, "abcdef12"));
    conn.execute_batch("DROP TRIGGER reject_consume;").unwrap();
    assert!(validate_recovery_in_test(&conn, 1, "abcdef12"));
    conn.execute(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'ABCD-EF12')",
        [],
    )
    .unwrap();
    assert!(!validate_recovery_in_test(&conn, 1, "ABCD-EF12"));
}

#[test]
fn legacy_bcrypt_recovery_codes_remain_usable() {
    let conn = recovery_database();
    let hash = bcrypt::hash("ABCD-EF12", 4).unwrap();
    conn.execute(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, ?1)",
        params![hash],
    )
    .unwrap();
    assert!(validate_recovery_in_test(&conn, 1, "abcdef12"));
    assert!(!validate_recovery_in_test(&conn, 1, "ABCD-EF12"));
}

#[tokio::test]
async fn disable_2fa_rejects_missing_or_malformed_verification() {
    for body in ["", "{}", "{", "null", "{\"code\":\" \",\"password\":\"\"}"] {
        let mut req = Request::new(axum::body::Body::from(body.to_owned()));
        req.extensions_mut().insert(AuthUser {
            user_id: 1,
            username: "test".into(),
            role: "user".into(),
            jti: "test".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        assert_eq!(disable_2fa(req).await.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn disable_2fa_and_logout_revoke_concurrent_credentials_and_rotate_epoch() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let pw_hash = bcrypt::hash("correct-horse-battery", 4).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret) \
             VALUES (992, 'epoch-user', ?1, 'admin', 1, 'JBSWY3DPEHPK3PXP')",
            params![pw_hash],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES ('c1', 'App', 'h', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, revoked, family_id) \
             VALUES ('rt-epoch-1', 'c1', 992, 'openid', '2099-01-01T00:00:00Z', 0, 'fam-1')",
            [],
        )
        .unwrap();
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("epoch-agent"));
    let (other_session, other_claims) = create_standard_jwt(992, &headers).unwrap();
    let (_, caller_claims) = create_standard_jwt(992, &headers).unwrap();

    let mut pw_only_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/2fa/disable")
        .header(header::USER_AGENT, "epoch-agent")
        .body(axum::body::Body::from(
            r#"{"password":"correct-horse-battery"}"#,
        ))
        .unwrap();
    pw_only_req.extensions_mut().insert(AuthUser {
        user_id: 992,
        username: "epoch-user".into(),
        role: "admin".into(),
        jti: caller_claims.jti.clone(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    assert_eq!(
        disable_2fa(pw_only_req).await.status(),
        StatusCode::BAD_REQUEST
    );

    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/2fa/disable")
        .header(header::USER_AGENT, "epoch-agent")
        .body(axum::body::Body::from(format!(
            r#"{{"password":"correct-horse-battery","code":"{}"}}"#,
            totp_now()
        )))
        .unwrap();
    req.extensions_mut().insert(AuthUser {
        user_id: 992,
        username: "epoch-user".into(),
        role: "admin".into(),
        jti: caller_claims.jti.clone(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    let resp = disable_2fa(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap();
    let replacement = set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("aetherflow_session=")
        .unwrap();
    let replacement_claims = decode_session_claims(replacement, false).unwrap();
    assert_eq!(replacement_claims.ver, 1);
    assert!(af_db::is_token_revoked(&other_claims.jti));

    // Concurrent old token fails auth_middleware even if forged without JTI blacklist hit.
    let mut old_headers = HeaderMap::new();
    old_headers.insert(header::USER_AGENT, HeaderValue::from_static("epoch-agent"));
    old_headers.insert(
        header::COOKIE,
        format!("aetherflow_session={other_session}")
            .parse()
            .unwrap(),
    );
    assert_eq!(
        refresh_session(old_headers).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let conn = af_db::get_read_conn().unwrap();
    let rt_revoked: i64 = conn
        .query_row(
            "SELECT revoked FROM oidc_refresh_tokens WHERE token = 'rt-epoch-1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rt_revoked, 1);
}

#[tokio::test]
async fn round3_disable_2fa_requires_second_factor_and_mfa_epoch_invalidation() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let pw_hash = bcrypt::hash("r3-strong-pass", 4).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret, sessions_revoked_after) \
             VALUES (994, 'r3-mfa-user', ?1, 'user', 1, 'JBSWY3DPEHPK3PXP', 50)",
            params![pw_hash],
        )
        .unwrap();
    }

    // 1. disable_2fa with password only (no second-factor `code`) MUST return 400 BAD_REQUEST
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/2fa/disable")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"password":"r3-strong-pass"}"#))
        .unwrap();
    req.extensions_mut().insert(AuthUser {
        user_id: 994,
        username: "r3-mfa-user".into(),
        role: "user".into(),
        jti: "jti-994".into(),
        plugin_id: None,
        plugin_scopes: vec![],
    });
    let disable_resp = disable_2fa(req).await;
    assert_eq!(disable_resp.status(), StatusCode::BAD_REQUEST);

    // 2. Pending MFA challenge issued at epoch 50 MUST fail after sessions_revoked_after advances to 60
    {
        let conn = af_db::get_conn().unwrap();
        af_db::store_mfa_challenge_in_tx(&conn, "r3-epoch-mfa", 994, 50, Duration::from_secs(300))
            .unwrap();
        conn.execute(
            "UPDATE users SET sessions_revoked_after = 60 WHERE id = 994",
            [],
        )
        .unwrap();
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("r3-agent"));
    let epoch_resp = mfa_login_verify(
        headers,
        Json(MfaVerifyRequest {
            mfa_token: "r3-epoch-mfa".into(),
            code: totp_now(),
        }),
    )
    .await;
    assert_eq!(epoch_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn round8_verify_2fa_conflict_and_refresh_grace_strict_fingerprint_enforcement() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret, sessions_revoked_after) \
             VALUES (997, 'r8-auth-user', 'hash', 'user', 1, 'JBSWY3DPEHPK3PXP', 0)",
            [],
        )
        .unwrap();
    }

    // 1. verify_2fa MUST return 409 CONFLICT when totp_enabled == 1
    let code = totp_now();
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/user/2fa/verify")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(format!(r#"{{"code":"{code}"}}"#)))
        .unwrap();
    req.extensions_mut().insert(AuthUser {
        user_id: 997,
        username: "r8-auth-user".into(),
        role: "user".into(),
        jti: "jti-997".into(),
        plugin_id: None,
        plugin_scopes: vec![],
    });
    assert_eq!(verify_2fa(req).await.status(), StatusCode::CONFLICT);

    // 2. Within 10s grace, replaying rotated s0 from a DIFFERENT User-Agent MUST reject with 401
    //    and wipe the session family (`s1`).
    let mut h1 = HeaderMap::new();
    h1.insert(header::USER_AGENT, HeaderValue::from_static("r8-legit-ua"));
    let (s0, _) = create_standard_jwt(997, &h1).unwrap();
    h1.insert(
        header::COOKIE,
        format!("aetherflow_session={s0}").parse().unwrap(),
    );
    let resp1 = refresh_session(h1).await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let b1 = axum::body::to_bytes(resp1.into_body(), 16384)
        .await
        .unwrap();
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    let s1 = v1["token"].as_str().unwrap().to_string();
    let s1_claims = decode_session_claims(&s1, false).unwrap();

    let mut h_mismatch = HeaderMap::new();
    h_mismatch.insert(
        header::USER_AGENT,
        HeaderValue::from_static("r8-different-ua"),
    );
    h_mismatch.insert(
        header::COOKIE,
        format!("aetherflow_session={s0}").parse().unwrap(),
    );
    let resp_mismatch = refresh_session(h_mismatch).await;
    assert_eq!(resp_mismatch.status(), StatusCode::UNAUTHORIZED);
    assert!(af_db::is_token_revoked(&s1_claims.jti));
}

#[tokio::test]
async fn disable_2fa_rejects_empty_password_for_password_account_and_setup_guards_remote() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    let pw_hash = bcrypt::hash("valid-pass-123", 4).unwrap();
    let secret_plain = "JBSWY3DPEHPK3PXP";
    let secret_enc = af_db::encrypt_key(secret_plain).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users WHERE id = 9751", [])
            .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role, password_hash, totp_secret, totp_enabled, last_totp_step) VALUES (9751, 'disable2fa-user', 'admin', ?1, ?2, 1, -1)",
            params![pw_hash, secret_enc],
        )
        .unwrap();
    }
    let now_secs = Utc::now().timestamp().max(0) as u64;
    let secret_bytes = BASE32_NOPAD.decode(secret_plain.as_bytes()).unwrap();
    let totp_code = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, now_secs);
    let user = AuthUser {
        user_id: 9751,
        username: "disable2fa-user".into(),
        role: "admin".into(),
        jti: "jti-9751".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut denied_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/user/2fa/disable")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "code": totp_code,
                "password": "",
            }))
            .unwrap(),
        ))
        .unwrap();
    denied_req.extensions_mut().insert(user.clone());
    let denied = disable_2fa(denied_req).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let mut allowed_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/user/2fa/disable")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "code": totp_code,
                "password": "valid-pass-123",
            }))
            .unwrap(),
        ))
        .unwrap();
    allowed_req.extensions_mut().insert(user);
    let allowed = disable_2fa(allowed_req).await;
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn setup_2fa_and_disable_2fa_propagate_sqlite_errors_and_reject_missing_user() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();

    let missing_user = AuthUser {
        user_id: 999999,
        username: "ghost".into(),
        role: "user".into(),
        jti: "jti-ghost".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut missing_req = Request::new(axum::body::Body::empty());
    missing_req.extensions_mut().insert(missing_user.clone());
    assert_eq!(
        setup_2fa(missing_req).await.status(),
        StatusCode::UNAUTHORIZED,
        "setup_2fa must reject a missing user rather than minting a pending 2FA secret"
    );

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE users", []).unwrap();
    }
    let mut setup_err_req = Request::new(axum::body::Body::empty());
    setup_err_req.extensions_mut().insert(missing_user.clone());
    assert_eq!(
        setup_2fa(setup_err_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "setup_2fa must return 500 on SQLite errors rather than swallowing them as disabled"
    );

    let mut disable_err_req = Request::new(axum::body::Body::from(r#"{"code":"123456"}"#));
    disable_err_req
        .extensions_mut()
        .insert(missing_user.clone());
    assert_eq!(
        disable_2fa(disable_err_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "disable_2fa must return 500 on SQLite errors rather than 401 User not found"
    );

    let mut verify_err_req = Request::new(axum::body::Body::from(r#"{"code":"123456"}"#));
    verify_err_req.extensions_mut().insert(missing_user);
    assert_eq!(
        verify_2fa(verify_err_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "verify_2fa must return 500 on SQLite errors rather than swallowing them as disabled"
    );
}

#[test]
fn revoke_all_credentials_and_mfa_cleanup_fail_closed_on_sqlite_errors() {
    let conn = mfa_database();
    add_challenge(&conn, "stale-epoch");
    conn.execute(
        "UPDATE users SET sessions_revoked_after = 5 WHERE id = 1",
        [],
    )
    .unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_mfa_delete BEFORE DELETE ON mfa_challenges \
         BEGIN SELECT RAISE(ABORT, 'delete failed'); END;",
    )
    .unwrap();
    assert!(
        verify_mfa_factor(&conn, "stale-epoch", &totp_now()).is_err(),
        "redeem_mfa_challenge_in_tx must propagate SQLite delete failures instead of swallowing them"
    );
    conn.execute_batch("DROP TRIGGER reject_mfa_delete;")
        .unwrap();

    // Missing `users` row for credential revocation must fail instead of succeeding silently.
    assert!(
        revoke_all_user_credentials_in_tx(&conn, 404).is_err(),
        "revoke_all_user_credentials_in_tx must fail when user epoch update matches no row"
    );
}
