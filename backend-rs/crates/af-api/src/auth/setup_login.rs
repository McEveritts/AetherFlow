use super::tokens::{
    api_error, blocking_response, create_session_jwt_in_conn, create_standard_jwt,
    load_active_human_subject, secure_cookie_enabled, table_exists, AuthUser, SubjectStatusError,
    SESSION_COOKIE_MAX_AGE,
};
use crate::ws::{build_set_cookie, extract_client_ip};
use af_models::User;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use std::env;
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CredentialsRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, alias = "setupToken")]
    pub setup_token: Option<String>,
}

pub async fn check_setup_needed() -> Response {
    blocking_response(check_setup_needed_blocking).await
}

fn check_setup_needed_blocking() -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Database unavailable",
        );
    };
    let Ok(count) = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0)) else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Failed to query setup state",
        );
    };
    Json(serde_json::json!({ "setupRequired": count == 0 })).into_response()
}

pub fn save_master_credentials(username: &str, password: &str) {
    let u = username.trim();
    if u.is_empty() || password.is_empty() {
        return;
    }
    if let Err(err) = af_services::mutators::save_master_credentials(u, password) {
        tracing::warn!(username = %u, error = %err, "Failed to persist master credentials");
    }
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    if password.is_empty() || password.len() > 72 || password_hash.is_empty() {
        return false;
    }
    bcrypt::verify(password, password_hash).unwrap_or(false)
}

fn setup_bootstrap_token_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for env_key in ["DATA_DIR", "AETHERFLOW_DATA_DIR"] {
        if let Ok(raw_dir) = env::var(env_key) {
            let clean = raw_dir.trim();
            if !clean.is_empty() {
                let candidate = std::path::PathBuf::from(clean).join(".setup-bootstrap-token");
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
        }
    }
    let db_path = af_db::get_db_path();
    if db_path != ":memory:" && !db_path.starts_with("file:") {
        if let Some(parent) = std::path::Path::new(&db_path).parent() {
            if !parent.as_os_str().is_empty() {
                let candidate = parent.join(".setup-bootstrap-token");
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
        }
    }
    let default_path = std::path::PathBuf::from("/var/lib/aetherflow/.setup-bootstrap-token");
    if !paths.contains(&default_path) {
        paths.push(default_path);
    }
    paths
}

fn read_setup_bootstrap_token_file(path: &std::path::Path) -> Option<String> {
    let lmeta = std::fs::symlink_metadata(path).ok()?;
    if lmeta.file_type().is_symlink() || !lmeta.is_file() {
        return None;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = opts.open(path).ok()?;
    let fmeta = file.metadata().ok()?;
    if !fmeta.is_file() || fmeta.len() > 4096 {
        return None;
    }
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents).ok()?;
    let trimmed = contents.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn configured_setup_bootstrap_tokens() -> Vec<String> {
    let mut expected = Vec::new();
    if let Ok(env_tok) = env::var("AETHERFLOW_SETUP_TOKEN") {
        let trimmed = env_tok.trim().to_string();
        if !trimmed.is_empty() {
            expected.push(trimmed);
        }
    }
    for path in setup_bootstrap_token_paths() {
        if let Some(file_tok) = read_setup_bootstrap_token_file(&path) {
            if !expected.contains(&file_tok) {
                expected.push(file_tok);
            }
        }
    }
    expected
}

fn unlink_setup_bootstrap_token_files() {
    for path in setup_bootstrap_token_paths() {
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Ensures a one-time `.setup-bootstrap-token` file (mode `0600`) exists on disk whenever
/// no administrator account exists yet and no bootstrap token is already configured.
/// This prevents headless or Apache-proxied installations from being locked out of
/// first-admin setup while keeping the token strictly out of application logs.
pub fn ensure_setup_bootstrap_token() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let Ok(user_count) = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
    else {
        return;
    };
    if user_count > 0 || !configured_setup_bootstrap_tokens().is_empty() {
        return;
    }

    let generated = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    for target in setup_bootstrap_token_paths() {
        let Some(parent) = target.parent() else {
            continue;
        };
        let Ok(pmeta) = std::fs::symlink_metadata(parent) else {
            continue;
        };
        if pmeta.file_type().is_symlink() || !pmeta.is_dir() {
            continue;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        if let Ok(mut file) = opts.open(&target) {
            if std::io::Write::write_all(&mut file, format!("{generated}\n").as_bytes()).is_ok() {
                let _ = file.sync_all();
                tracing::info!(
                    path = %target.display(),
                    "First-admin setup pending: generated one-time setup bootstrap token file (read via SSH for remote/proxied onboarding)"
                );
                return;
            }
            let _ = std::fs::remove_file(&target);
        }
    }
}

fn has_raw_proxy_forwarding_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-real-ip")
        || headers.contains_key("forwarded")
}

pub async fn setup_admin(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    inbound_forwarded: Option<axum::Extension<crate::ws::InboundProxyForwarded>>,
    headers: HeaderMap,
    Json(req): Json<CredentialsRequest>,
) -> Response {
    let was_proxied = inbound_forwarded
        .map(|axum::Extension(f)| f.0)
        .unwrap_or_else(|| has_raw_proxy_forwarding_headers(&headers));
    blocking_response(move || setup_admin_blocking(peer_ip, was_proxied, headers, req)).await
}

pub(super) fn setup_admin_blocking(
    peer_ip: Option<std::net::IpAddr>,
    was_proxied: bool,
    headers: HeaderMap,
    req: CredentialsRequest,
) -> Response {
    if req.password.len() > 72 {
        return password_too_long();
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Database unavailable",
        );
    };

    let Ok(count) = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0)) else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Failed to verify existing user accounts",
        );
    };
    if count > 0 {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Admin account already exists",
        );
    }

    let is_direct_unproxied_loopback = !was_proxied
        && match peer_ip {
            Some(ip) => ip.to_canonical().is_loopback(),
            None => true,
        };

    let provided_setup_token = req
        .setup_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("X-AetherFlow-Setup-Token")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });

    if !is_direct_unproxied_loopback {
        let expected_tokens = configured_setup_bootstrap_tokens();
        let token_valid = match provided_setup_token {
            Some(candidate) if !expected_tokens.is_empty() => expected_tokens.iter().any(|exp| {
                !candidate.is_empty()
                    && af_models::constant_time_eq(candidate.as_bytes(), exp.as_bytes())
            }),
            _ => false,
        };
        if !token_valid {
            return api_error(
                StatusCode::FORBIDDEN,
                "SETUP_TOKEN_REQUIRED",
                "Valid setup bootstrap token required for remote or proxied first-admin setup",
            );
        }
    }

    let trimmed_username = req.username.trim();
    if trimmed_username.is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
        );
    }
    if trimmed_username.to_ascii_lowercase().starts_with("plugin:") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Reserved username prefix",
        );
    }
    if req.password.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Password must be at least 8 characters",
        );
    }

    drop(conn);
    let Ok(hash) = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to hash password",
        );
    };

    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Database unavailable",
        );
    };
    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Database unavailable",
            );
        }
    };
    let live_count = match tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0)) {
        Ok(c) => c,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Failed to verify existing user accounts",
            );
        }
    };
    if live_count > 0 {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Admin account already exists",
        );
    }

    if tx
        .execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, 'admin')",
            params![trimmed_username, hash],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create admin account",
        );
    }
    let user_id = tx.last_insert_rowid();
    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to commit admin account",
        );
    }
    drop(conn);

    unlink_setup_bootstrap_token_files();

    // Provision dedicated random package credentials rather than persisting the operator's control-plane password.
    af_services::mutators::ensure_provisioning_credentials(trimmed_username);

    let Ok((token, _)) = create_standard_jwt(user_id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };

    let cookie = build_set_cookie(
        "aetherflow_session",
        &token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({
        "message": "Admin account created",
        "username": trimmed_username,
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

const DUMMY_PASSWORD_HASH: &str = "$2b$12$abcdefghijklmnopqrstuu2gT3wAA4iQTZ8ANQTNQ2enUSBvzvE8a";

pub(crate) fn password_too_long() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "VALIDATION_ERROR",
        "Password must not exceed 72 bytes",
    )
}

pub async fn local_login(headers: HeaderMap, Json(req): Json<CredentialsRequest>) -> Response {
    blocking_response(move || local_login_blocking(headers, req)).await
}

pub(super) fn local_login_blocking(headers: HeaderMap, req: CredentialsRequest) -> Response {
    if req.password.len() > 72 {
        return password_too_long();
    }
    let trimmed_username = req.username.trim();
    if trimmed_username.is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
        );
    }
    if trimmed_username.to_ascii_lowercase().starts_with("plugin:") {
        let _ = bcrypt::verify(&req.password, DUMMY_PASSWORD_HASH);
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credentials",
        );
    }

    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let row = conn
        .query_row(
            "SELECT id, COALESCE(password_hash, '') FROM users WHERE username = ?1",
            params![trimmed_username],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .optional();

    let (id, password_hash) = match row {
        Ok(Some(found)) => found,
        Ok(None) => {
            drop(conn);
            let _ = bcrypt::verify(&req.password, DUMMY_PASSWORD_HASH);
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid credentials",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        }
    };

    let subject_status = load_active_human_subject(&conn, id);
    drop(conn);

    if password_hash.is_empty() {
        let _ = bcrypt::verify(&req.password, DUMMY_PASSWORD_HASH);
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credentials",
        );
    }

    let password_ok = bcrypt::verify(&req.password, &password_hash).unwrap_or(false);
    if !password_ok {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credentials",
        );
    }

    let pre_auth_ver = match subject_status {
        Ok(subj) => subj.sessions_revoked_after,
        Err(SubjectStatusError::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid credentials",
            );
        }
        Err(SubjectStatusError::DbError) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        }
    };

    let Ok(mut write_conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok(tx) = write_conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let current_ver = match load_active_human_subject(&tx, id) {
        Ok(subj) => subj.sessions_revoked_after,
        Err(SubjectStatusError::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid credentials",
            );
        }
        Err(SubjectStatusError::DbError) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        }
    };
    let current_row = tx
        .query_row(
            "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
             COALESCE(password_hash, ''), COALESCE(google_id, ''), COALESCE(totp_enabled, 0) \
             FROM users WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, bool>(6)?,
                ))
            },
        )
        .optional();
    let (username, email, avatar_url, role, current_password_hash, google_id, totp_enabled) =
        match current_row {
            Ok(Some(row)) => row,
            Ok(None) => {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "Invalid credentials",
                );
            }
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Database unavailable",
                );
            }
        };
    if current_password_hash.is_empty()
        || current_password_hash != password_hash
        || current_ver != pre_auth_ver
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credentials",
        );
    }

    if totp_enabled {
        let mut raw_token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_token);
        let mfa_token = hex::encode(raw_token);
        if af_db::store_mfa_challenge_in_tx(
            &tx,
            &mfa_token,
            id,
            current_ver,
            Duration::from_secs(300),
        )
        .is_err()
            || tx.commit().is_err()
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to create MFA challenge",
            );
        }
        return Json(serde_json::json!({
            "requires_mfa": true,
            "mfa_token": mfa_token,
        }))
        .into_response();
    }

    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let has_login_history = match table_exists(&tx, "login_history") {
        Ok(exists) => exists,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to record login session",
            );
        }
    };
    if has_login_history {
        if let Err(err) = tx.execute(
            "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
            params![id, client_ip, user_agent],
        ) {
            tracing::warn!(user_id = id, error = %err, "Failed to record local login history");
        }
    }

    let Ok((token, _)) =
        create_session_jwt_in_conn(&tx, id, &headers, Utc::now().timestamp(), None, current_ver)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };
    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    }
    drop(write_conn);

    let user = User {
        id,
        username,
        email,
        avatar_url,
        role,
        google_id: google_id.clone(),
        is_oauth: !google_id.is_empty(),
        totp_enabled,
    };

    let cookie = build_set_cookie(
        "aetherflow_session",
        &token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({
        "message": "Login successful",
        "user": user,
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn get_session(req: Request) -> Response {
    blocking_response(move || get_session_blocking(req)).await
}

fn get_session_blocking(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let row = conn
        .query_row(
            "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
             COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
            params![auth_user.user_id],
            |r| {
                let google_id: String = r.get(5)?;
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    email: r.get(2)?,
                    avatar_url: r.get(3)?,
                    role: r.get(4)?,
                    is_oauth: !google_id.is_empty(),
                    google_id,
                    totp_enabled: r.get(6)?,
                })
            },
        )
        .optional();

    match row {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found"),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        ),
    }
}
