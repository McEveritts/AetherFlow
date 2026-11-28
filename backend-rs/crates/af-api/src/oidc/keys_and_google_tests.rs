use super::authorize::{is_safe_redirect_uri, validate_pkce_request_params};
use super::google::{
    complete_google_login, google_callback, google_email_allowed, resolve_google_user,
    safe_login_return_to, valid_google_state,
};
use super::keys::{
    get_base_url, get_base_url_for_peer, load_or_generate_oidc_key_at, oidc_key_path, read_oidc_key,
};
use super::token_endpoint::verify_pkce;
use crate::auth::decode_session_claims;
use axum::extract::Query;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

#[test]
fn continuation_validation_rejects_external_and_normalized_authorities() {
    for path in [
        "https://example.test/",
        "//example.test/",
        "/a/..//example.test/",
        "/%2fexample.test",
        "/\\example.test",
        "/%5cexample.test",
        "/path%0aLocation:evil",
        " /local",
    ] {
        assert!(safe_login_return_to(path).is_none(), "{path}");
    }
    assert_eq!(
        safe_login_return_to("/api/v1/public/oidc/authorize?state=hello%20world"),
        Some("/api/v1/public/oidc/authorize?state=hello%20world".into())
    );
}

#[tokio::test]
async fn callback_errors_are_relative_and_preserve_safe_continuation() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HOST,
        HeaderValue::from_static("localhost:@example.test"),
    );
    headers.insert("x-forwarded-host", HeaderValue::from_static("example.test"));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "oauth2_return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dretained",
        ),
    );
    let response = google_callback(
        None,
        headers.clone(),
        Query(HashMap::from([("error".into(), "access_denied".into())])),
    )
    .await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "/login?error=access_denied&return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dretained"
    );
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|cookie| {
            let cookie = cookie.to_str().unwrap();
            cookie.starts_with("oauth2_state=;") && cookie.contains("Max-Age=0")
        }));
    let response = google_callback(None, headers, Query(HashMap::new())).await;
    assert!(response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .starts_with("/login?error=invalid_state&return_to="));
}

#[test]
fn google_state_requires_sufficient_hex_and_exact_cookie_match() {
    let state = "257bfead502df61a";
    assert!(valid_google_state(state, state));
    for invalid in ["", "abcd", "257bfead502df61", "257bfead502df61g"] {
        assert!(!valid_google_state(invalid, invalid));
    }
    assert!(!valid_google_state(state, "257bfead502df61b"));
    assert!(!valid_google_state(state, ""));
}

fn google_database() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, google_id TEXT DEFAULT '', email TEXT DEFAULT '', avatar_url TEXT DEFAULT '', role TEXT DEFAULT 'user', totp_enabled INTEGER DEFAULT 0);").unwrap();
    conn
}

fn identity(verified: bool) -> serde_json::Value {
    serde_json::json!({"id":"google-123", "email":"person@example.com", "verified_email": verified, "picture":"avatar"})
}

#[test]
fn google_provisioning_denies_by_default_and_never_bootstraps_an_admin() {
    let conn = google_database();
    assert!(resolve_google_user(&conn, &identity(true), "", "", None)
        .unwrap()
        .is_none());
    assert!(resolve_google_user(
        &conn,
        &identity(false),
        "person@example.com",
        "example.com",
        None
    )
    .unwrap()
    .is_none());
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let (id, mfa) = resolve_google_user(&conn, &identity(true), " PERSON@example.com ", "", None)
        .unwrap()
        .unwrap();
    assert!(!mfa);
    let role: String = conn
        .query_row("SELECT role FROM users WHERE id = ?1", params![id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(role, "user");
    assert!(google_email_allowed(
        "other@EXAMPLE.com",
        "",
        "example.com,company.org"
    ));
    for email in [
        "evil@sub.example.com",
        "person@example.com.evil",
        "bad@@example.com",
        "@example.com",
    ] {
        assert!(!google_email_allowed(email, "", "example.com"));
    }
}

#[test]
fn google_linking_requires_verification_and_preserves_existing_configuration() {
    let conn = google_database();
    conn.execute("INSERT INTO users (id, username, email, role, totp_enabled) VALUES (1, 'configured-admin', 'PERSON@example.com', 'admin', 1)", []).unwrap();
    assert!(resolve_google_user(&conn, &identity(false), "", "", None)
        .unwrap()
        .is_none());
    assert_eq!(
        resolve_google_user(&conn, &identity(true), "", "", None).unwrap(),
        Some((1, true))
    );
    let (name, role, email): (String, String, String) = conn
        .query_row(
            "SELECT username, role, email FROM users WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (name.as_str(), role.as_str(), email.as_str()),
        ("configured-admin", "admin", "PERSON@example.com")
    );
    let mut other = identity(true);
    other["id"] = "different-id".into();
    assert!(
        resolve_google_user(&conn, &other, "person@example.com", "", None)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        resolve_google_user(&conn, &identity(true), "", "", None).unwrap(),
        Some((1, true))
    );
}

#[test]
fn google_linking_rejects_unauthenticated_password_bearing_local_account_prehijack() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT DEFAULT '', google_id TEXT DEFAULT '', email TEXT DEFAULT '', avatar_url TEXT DEFAULT '', role TEXT DEFAULT 'user', totp_enabled INTEGER DEFAULT 0);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO users (id, username, password_hash, email, role, totp_enabled) VALUES (7, 'local-attacker', '$argon2id$v=19$m=19456,t=2,p=1$hash', 'person@example.com', 'user', 0)",
        [],
    )
    .unwrap();
    assert!(
        resolve_google_user(
            &conn,
            &identity(true),
            "person@example.com",
            "example.com",
            None
        )
        .unwrap()
        .is_none(),
        "Unauthenticated Google login must never auto-link to a password-bearing local account"
    );
    assert!(
        resolve_google_user(
            &conn,
            &identity(true),
            "person@example.com",
            "example.com",
            Some(999)
        )
        .unwrap()
        .is_none(),
        "Mismatched authenticated session must never link another local user"
    );
    assert_eq!(
        resolve_google_user(
            &conn,
            &identity(true),
            "person@example.com",
            "example.com",
            Some(7)
        )
        .unwrap(),
        Some((7, false)),
        "Explicitly authenticated local user may link their own Google identity"
    );
}

#[tokio::test]
async fn google_callback_mfa_has_no_session_until_factor_verification() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    env::remove_var("AETHERFLOW_GOOGLE_ALLOWED_EMAILS");
    env::remove_var("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS");
    let denied = complete_google_login(&HeaderMap::new(), None, &identity(true));
    assert_eq!(
        denied.headers()[header::LOCATION],
        "/login?error=not_authorized"
    );
    assert!(denied
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .all(|v| !v.to_str().unwrap().starts_with("aetherflow_session=")));
    let conn = af_db::get_conn().unwrap();
    conn.execute("INSERT INTO users (id, username, google_id, email, role, totp_enabled, totp_secret) VALUES (654, 'google-mfa', 'google-123', 'person@example.com', 'admin', 1, 'JBSWY3DPEHPK3PXP')", []).unwrap();
    drop(conn);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "oauth2_return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dmfa",
        ),
    );
    let response = complete_google_login(&headers, None, &identity(true));
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.ends_with("&return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dmfa"));
    let challenge = location
        .strip_prefix("/login?mfa=")
        .expect("Exact MFA query contract")
        .split('&')
        .next()
        .unwrap();
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .all(|v| !v.to_str().unwrap().starts_with("aetherflow_session=")));
    let conn = af_db::get_read_conn().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM active_sessions WHERE user_id = 654",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    drop(conn);
    let secret = data_encoding::BASE32_NOPAD
        .decode(b"JBSWY3DPEHPK3PXP")
        .unwrap();
    let code =
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret, Utc::now().timestamp() as u64);
    let response = crate::auth::mfa_login_verify(
        HeaderMap::new(),
        Json(crate::auth::MfaVerifyRequest {
            mfa_token: challenge.into(),
            code,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));
    let raw = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("aetherflow_session=")
        .unwrap();
    let claims = decode_session_claims(raw, false).unwrap();
    assert_eq!(claims.user_id, 654);
    assert_eq!(claims.exp - claims.iat, 900);
    let conn = af_db::get_read_conn().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM active_sessions WHERE user_id = 654 AND jti = ?1",
            params![claims.jti],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn oidc_key_defaults_use_persistent_state_and_explicit_override() {
    assert_eq!(
        oidc_key_path(None, None),
        PathBuf::from("/var/lib/aetherflow/oidc_rsa.pem")
    );
    assert_eq!(
        oidc_key_path(None, Some("/state/aetherflow:/state/other")),
        PathBuf::from("/state/aetherflow/oidc_rsa.pem")
    );
    assert_eq!(
        oidc_key_path(Some("/custom/key.pem"), Some("/state")),
        PathBuf::from("/custom/key.pem")
    );
}

#[test]
fn oidc_key_is_private_persistent_and_never_replaces_corrupt_or_inaccessible_keys() {
    let root = env::temp_dir().join(format!("af-oidc-key-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("oidc.pem");
    let first = load_or_generate_oidc_key_at(&path).unwrap();
    let second = load_or_generate_oidc_key_at(&path).unwrap();
    assert_eq!(first.kid, second.kid);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = root.join("symlink.pem");
        symlink(&path, &link).unwrap();
        assert!(load_or_generate_oidc_key_at(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_generate_oidc_key_at(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(&path, "corrupt key").unwrap();
    assert!(load_or_generate_oidc_key_at(&path).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "corrupt key");
    let parent_file = root.join("not-directory");
    fs::write(&parent_file, "x").unwrap();
    assert!(load_or_generate_oidc_key_at(&parent_file.join("key.pem")).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn oidc_key_concurrent_creation_publishes_one_identity() {
    let root = env::temp_dir().join(format!("af-oidc-key-race-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("oidc.pem");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                load_or_generate_oidc_key_at(&path).unwrap().kid
            })
        })
        .collect();
    let kids: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(kids[0], kids[1]);
    assert_eq!(kids[0], read_oidc_key(&path).unwrap().kid);
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        1,
        "Temporary private files must be removed"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn base_url_ignores_forwarded_headers_unless_trusted() {
    let prev_public = env::var("PUBLIC_URL").ok();
    let prev_trust = env::var("TRUST_PROXY_HEADERS").ok();
    let prev_hosts = env::var("ALLOWED_HOSTS").ok();
    env::remove_var("PUBLIC_URL");
    env::remove_var("TRUST_PROXY_HEADERS");
    env::set_var("ALLOWED_HOSTS", "panel.example.com,proxy.example.com");

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("panel.example.com"));
    headers.insert("X-Forwarded-Proto", HeaderValue::from_static("http"));
    headers.insert(
        "X-Forwarded-Host",
        HeaderValue::from_static("evil.attacker.test"),
    );
    assert_eq!(get_base_url(&headers), "https://panel.example.com");

    env::set_var("TRUST_PROXY_HEADERS", "true");
    // Untrusted public peer IP or unallowed X-Forwarded-Host must never spoof base_url.
    let public_peer: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    let loopback_peer: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(
        get_base_url_for_peer(&headers, Some(public_peer)),
        "https://panel.example.com"
    );
    assert_eq!(
        get_base_url_for_peer(&headers, Some(loopback_peer)),
        "https://panel.example.com"
    );

    headers.insert(
        "X-Forwarded-Host",
        HeaderValue::from_static("proxy.example.com"),
    );
    headers.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
    assert_eq!(
        get_base_url_for_peer(&headers, Some(public_peer)),
        "https://panel.example.com"
    );
    assert_eq!(
        get_base_url_for_peer(&headers, Some(loopback_peer)),
        "https://proxy.example.com"
    );

    match prev_public {
        Some(v) => env::set_var("PUBLIC_URL", v),
        None => env::remove_var("PUBLIC_URL"),
    }
    match prev_trust {
        Some(v) => env::set_var("TRUST_PROXY_HEADERS", v),
        None => env::remove_var("TRUST_PROXY_HEADERS"),
    }
    match prev_hosts {
        Some(v) => env::set_var("ALLOWED_HOSTS", v),
        None => env::remove_var("ALLOWED_HOSTS"),
    }
}

#[test]
fn redirect_uri_validation_rejects_unsafe_schemes_fragments_and_userinfo() {
    assert!(is_safe_redirect_uri("https://app.example.com/cb"));
    assert!(is_safe_redirect_uri("http://127.0.0.1:8080/cb"));
    assert!(is_safe_redirect_uri("http://localhost:3000/cb"));
    for bad in [
        "http://app.example.com/cb",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://files.example.com/cb",
        "https://app.example.com/cb#frag",
        "https://user:pass@app.example.com/cb",
        "/relative/path",
    ] {
        assert!(!is_safe_redirect_uri(bad), "expected reject for {bad}");
    }
}

#[test]
fn pkce_rejects_plain_and_requires_s256_for_public_clients() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert!(verify_pkce(verifier, &challenge, "S256"));
    assert!(!verify_pkce(verifier, verifier, "plain"));
    assert!(!verify_pkce(verifier, verifier, ""));
    assert!(!verify_pkce(verifier, &challenge, "plain"));
    assert!(!verify_pkce("short-verifier", &challenge, "S256"));
    assert!(!verify_pkce(&"a".repeat(129), &challenge, "S256"));
    assert!(!verify_pkce(
        "invalid space in verifier 1234567890123456789012",
        &challenge,
        "S256"
    ));
    assert!(validate_pkce_request_params("", "").is_err());
    assert!(validate_pkce_request_params(&challenge, "plain").is_err());
    assert!(validate_pkce_request_params(&challenge, "").is_err());
    assert!(validate_pkce_request_params("too-short", "S256").is_err());
    assert!(validate_pkce_request_params(&challenge, "S256").is_ok());
}

#[test]
fn resolve_google_user_propagates_sqlite_errors_instead_of_returning_not_authorized() {
    let conn = google_database();
    conn.execute(
        "INSERT INTO users (id, username, google_id, email, role, totp_enabled) VALUES (1, 'guser', 'google-123', 'person@example.com', 'user', 0)",
        [],
    )
    .unwrap();
    // Create a broken `user_quotas` schema (missing `status` column) so `load_active_human_subject`
    // returns `SubjectStatusError::DbError`.
    conn.execute("CREATE TABLE user_quotas (user_id INTEGER PRIMARY KEY)", [])
        .unwrap();
    assert!(
        resolve_google_user(&conn, &identity(true), "", "", None).is_err(),
        "resolve_google_user must propagate SubjectStatusError::DbError rather than swallowing it as Ok(None)"
    );
}
