use crate::auth::{
    api_error, blocking_response, decode_session_claims, secure_cookie_enabled, SubjectStatusError,
};
use crate::ws::{build_set_cookie, extract_cookie};
use axum::extract::Query;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::env;

pub(super) fn safe_login_return_to(raw: &str) -> Option<String> {
    if raw.len() > 2048
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\')
    {
        return None;
    }
    let decoded = urlencoding::decode(raw).ok()?;
    if decoded.starts_with("//") || decoded.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return None;
    }
    let url = url::Url::parse(&format!("https://aetherflow.invalid{raw}")).ok()?;
    if url.host_str() != Some("aetherflow.invalid") || url.path().starts_with("//") {
        return None;
    }
    Some(url[url::Position::BeforePath..].to_string())
}

fn google_return_to(headers: &HeaderMap) -> Option<String> {
    let cookie = extract_cookie(headers, "oauth2_return_to")?;
    safe_login_return_to(&urlencoding::decode(&cookie).ok()?)
}

fn google_login_location(headers: &HeaderMap, parameter: &str, value: &str) -> String {
    let mut location = format!("/login?{parameter}={}", urlencoding::encode(value));
    if let Some(destination) = google_return_to(headers) {
        location.push_str(&format!("&return_to={}", urlencoding::encode(&destination)));
    }
    location
}

fn clear_google_cookies(response: &mut Response) {
    for name in ["oauth2_state", "oauth2_return_to"] {
        let cookie = build_set_cookie(name, "", 0, "Lax", secure_cookie_enabled(), true);
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

fn google_login_error(headers: &HeaderMap, error: &str) -> Response {
    Redirect::temporary(&google_login_location(headers, "error", error)).into_response()
}

pub async fn google_login(Query(q): Query<HashMap<String, String>>) -> Response {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap_or_default();
    if client_id.is_empty() || redirect_uri.is_empty() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "OAuth not configured",
        );
    }

    let mut state_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut state_bytes);
    let state = hex::encode(state_bytes);

    let cookie = build_set_cookie(
        "oauth2_state",
        &state,
        600,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=offline&prompt=consent",
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state
    );

    let mut resp = Redirect::temporary(&auth_url).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    // Keep continuation out of the external provider URL; clear any stale value.
    let destination = q
        .get("return_to")
        .and_then(|value| safe_login_return_to(value));
    let continuation = destination
        .as_deref()
        .map(urlencoding::encode)
        .unwrap_or_default();
    let cookie = build_set_cookie(
        "oauth2_return_to",
        &continuation,
        if destination.is_some() { 600 } else { -1 },
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

static GOOGLE_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub async fn google_callback(
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut response = complete_google_callback(headers, q).await;
    clear_google_cookies(&mut response);
    response
}

pub(super) fn valid_google_state(state: &str, cookie_state: &str) -> bool {
    // google_login generates cryptographic randomness and encodes it as hex.
    state.len() >= 16
        && state.bytes().all(|byte| byte.is_ascii_hexdigit())
        && af_models::constant_time_eq(state.as_bytes(), cookie_state.as_bytes())
}

async fn complete_google_callback(headers: HeaderMap, q: HashMap<String, String>) -> Response {
    if let Some(err_param) = q.get("error") {
        if !err_param.is_empty() {
            return google_login_error(&headers, err_param);
        }
    }

    let code = q.get("code").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    let cookie_state = extract_cookie(&headers, "oauth2_state").unwrap_or_default();
    if !valid_google_state(&state, &cookie_state) {
        return google_login_error(&headers, "invalid_state");
    }

    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap_or_default();

    let client = &*GOOGLE_HTTP_CLIENT;
    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;

    let Ok(resp) = token_res else {
        return google_login_error(&headers, "token_exchange_failed");
    };
    if !resp.status().is_success() {
        return google_login_error(&headers, "token_exchange_failed");
    }

    let Ok(token_json) = resp.json::<serde_json::Value>().await else {
        return google_login_error(&headers, "token_exchange_failed");
    };
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if access_token.is_empty() {
        return google_login_error(&headers, "no_access_token");
    }

    let Ok(info_resp) = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
    else {
        return google_login_error(&headers, "userinfo_failed");
    };
    let info_resp_status_success = info_resp.status().is_success();
    let Ok(user_info) = info_resp.json::<serde_json::Value>().await else {
        return google_login_error(&headers, "userinfo_failed");
    };

    if !info_resp_status_success {
        return google_login_error(&headers, "userinfo_failed");
    }
    blocking_response(move || complete_google_login(&headers, &user_info)).await
}

pub(super) fn google_email_allowed(email: &str, emails: &str, domains: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    let entries = |list: &str| {
        list.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|item| !item.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<HashSet<_>>()
    };
    entries(emails).contains(&email.to_ascii_lowercase())
        || entries(domains).contains(&domain.to_ascii_lowercase())
}

pub(super) fn resolve_google_user(
    conn: &rusqlite::Connection,
    info: &serde_json::Value,
    emails: &str,
    domains: &str,
    authenticated_user_id: Option<i64>,
) -> anyhow::Result<Option<(i64, bool)>> {
    let google_id = info.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let email = info
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let verified = info
        .get("verified_email")
        .or_else(|| info.get("email_verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if google_id.is_empty() || email.is_empty() || !verified {
        return Ok(None);
    }
    let avatar = info.get("picture").and_then(|v| v.as_str()).unwrap_or("");
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let existing: Option<(i64, bool)> = tx
        .query_row(
            "SELECT id, COALESCE(totp_enabled, 0) FROM users WHERE google_id = ?1",
            params![google_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let user = if let Some(user) = existing {
        // Preserve configured role, username and email for a previously linked identity.
        tx.execute(
            "UPDATE users SET avatar_url = ?1 WHERE id = ?2",
            params![avatar, user.0],
        )?;
        user
    } else {
        let matches: i64 = tx.query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1 COLLATE NOCASE",
            params![email],
            |r| r.get(0),
        )?;
        if matches > 1 {
            return Ok(None);
        }
        if matches == 1 {
            let has_pw_col = crate::auth::column_exists(&tx, "users", "password_hash")?;
            let (id, linked, mfa, pw_hash): (i64, String, bool, String) = if has_pw_col {
                tx.query_row(
                    "SELECT id, COALESCE(google_id, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE email = ?1 COLLATE NOCASE",
                    params![email],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?
            } else {
                tx.query_row(
                    "SELECT id, COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users WHERE email = ?1 COLLATE NOCASE",
                    params![email],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, String::new())),
                )?
            };
            if !linked.is_empty() {
                return Ok(None);
            }
            // Never auto-bind a Google identity to an existing password-bearing local account
            // unless the caller is already authenticated as that local user; otherwise an attacker
            // can pre-set a victim's email on their own password-protected account and retain access.
            if !pw_hash.trim().is_empty() && authenticated_user_id != Some(id) {
                return Ok(None);
            }
            tx.execute(
                "UPDATE users SET google_id = ?1, avatar_url = ?2 WHERE id = ?3 AND COALESCE(google_id, '') = ''",
                params![google_id, avatar, id],
            )?;
            (id, mfa)
        } else {
            if !google_email_allowed(email, emails, domains) {
                return Ok(None);
            }
            let prefix: String = email
                .split('@')
                .next()
                .unwrap_or("user")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                .take(48)
                .collect();
            let username = format!(
                "{}-{}",
                if prefix.is_empty() { "user" } else { &prefix },
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            tx.execute(
                "INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?1, ?2, ?3, ?4, 'user')",
                params![username, google_id, email, avatar],
            )?;
            (tx.last_insert_rowid(), false)
        }
    };
    match crate::auth::load_active_human_subject(&tx, user.0) {
        Ok(_) => {}
        Err(SubjectStatusError::DbError) => {
            anyhow::bail!("Database error checking Google user status");
        }
        Err(SubjectStatusError::MissingOrPlugin | SubjectStatusError::Suspended) => {
            return Ok(None);
        }
    }
    tx.commit()?;
    Ok(Some(user))
}

pub(super) fn complete_google_login(headers: &HeaderMap, info: &serde_json::Value) -> Response {
    let authenticated_user_id = crate::auth::resolve_raw_token(headers)
        .and_then(|raw| decode_session_claims(&raw, false).ok())
        .filter(|claims| {
            !claims.jti.is_empty()
                && !crate::auth::is_session_token_revoked_beyond_grace(&claims.jti, claims.user_id)
                && af_db::get_read_conn().ok().is_some_and(|c| {
                    crate::auth::load_active_human_subject(&c, claims.user_id)
                        .is_ok_and(|subj| claims.ver >= subj.sessions_revoked_after)
                })
        })
        .map(|claims| claims.user_id);
    enum GoogleLoginDecision {
        NotAuthorized,
        MfaChallenge(String),
        SessionIssued(String),
    }

    let outcome = (|| -> anyhow::Result<GoogleLoginDecision> {
        let mut conn = af_db::get_conn()?;
        let Some((user_id, mfa_hint)) = resolve_google_user(
            &conn,
            info,
            &env::var("AETHERFLOW_GOOGLE_ALLOWED_EMAILS").unwrap_or_default(),
            &env::var("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS").unwrap_or_default(),
            authenticated_user_id,
        )?
        else {
            return Ok(GoogleLoginDecision::NotAuthorized);
        };

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let subj = match crate::auth::load_active_human_subject(&tx, user_id) {
            Ok(subj) => subj,
            Err(SubjectStatusError::DbError) => {
                anyhow::bail!("Database error checking Google user status");
            }
            Err(SubjectStatusError::MissingOrPlugin | SubjectStatusError::Suspended) => {
                return Ok(GoogleLoginDecision::NotAuthorized);
            }
        };
        let current_mfa: bool = if crate::auth::column_exists(&tx, "users", "totp_enabled")? {
            tx.query_row(
                "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )?
        } else {
            mfa_hint
        };

        if current_mfa {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let challenge = hex::encode(bytes);
            af_db::store_mfa_challenge_in_tx(
                &tx,
                &challenge,
                user_id,
                subj.sessions_revoked_after,
                std::time::Duration::from_secs(300),
            )?;
            tx.commit()?;
            return Ok(GoogleLoginDecision::MfaChallenge(challenge));
        }

        let (token, _) = crate::auth::create_session_jwt_in_conn(
            &tx,
            user_id,
            headers,
            Utc::now().timestamp(),
            None,
            subj.sessions_revoked_after,
        )
        .map_err(|_| anyhow::anyhow!("jwt_failed"))?;
        if crate::auth::table_exists(&tx, "login_history")? {
            if let Err(err) = tx.execute(
                "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
                params![
                    user_id,
                    crate::ws::extract_client_ip(headers),
                    headers
                        .get(header::USER_AGENT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                ],
            ) {
                tracing::warn!(user_id, error = %err, "Failed to record Google login history");
            }
        }
        tx.commit()?;
        Ok(GoogleLoginDecision::SessionIssued(token))
    })();

    match outcome {
        Ok(GoogleLoginDecision::MfaChallenge(challenge)) => {
            Redirect::temporary(&google_login_location(headers, "mfa", &challenge)).into_response()
        }
        Ok(GoogleLoginDecision::SessionIssued(token)) => {
            let mut response =
                Redirect::temporary(google_return_to(headers).as_deref().unwrap_or("/"))
                    .into_response();
            crate::auth::set_session_cookie(&mut response, &token);
            response
        }
        Ok(GoogleLoginDecision::NotAuthorized) => google_login_error(headers, "not_authorized"),
        Err(e) if e.to_string() == "jwt_failed" => google_login_error(headers, "jwt_failed"),
        Err(_) => google_login_error(headers, "db_error"),
    }
}
