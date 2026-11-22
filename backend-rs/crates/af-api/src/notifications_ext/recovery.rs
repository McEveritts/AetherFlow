use super::models::RegenerateRecoveryReq;
use crate::auth::{api_error, generate_recovery_codes, store_recovery_codes, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;

fn replace_recovery_hashes(
    conn: &rusqlite::Connection,
    user_id: i64,
    encrypted_secret: &str,
    password_hash: &str,
    code: &str,
    recovery: Option<crate::auth::RecoveryCodeMatch>,
    hashes: &[String],
) -> anyhow::Result<bool> {
    let secret = af_db::decrypt_key(encrypted_secret)?;
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let current: (String, bool, String) = transaction.query_row(
        "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![user_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !current.1 || current.0 != encrypted_secret || current.2 != password_hash {
        return Ok(false);
    }
    if !crate::auth::consume_totp_code(&transaction, user_id, &secret, code)
        && !crate::auth::consume_recovery_code(&transaction, user_id, recovery.as_ref())
    {
        return Ok(false);
    }
    store_recovery_codes(&transaction, user_id, hashes)?;
    transaction.commit()?;
    Ok(true)
}

#[cfg(test)]
pub(super) fn replace_verified_recovery_codes(
    conn: &rusqlite::Connection,
    user_id: i64,
    encrypted_secret: &str,
    password_hash: &str,
    code: &str,
    password_ok: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    if !password_ok || code.trim().is_empty() {
        return Ok(None);
    }
    let recovery = crate::auth::match_recovery_in_connection(conn, user_id, code);
    let codes = generate_recovery_codes();
    let hashes = crate::auth::hash_recovery_codes(&codes)?;
    Ok(replace_recovery_hashes(
        conn,
        user_id,
        encrypted_secret,
        password_hash,
        code,
        recovery,
        &hashes,
    )?
    .then_some(codes))
}

pub async fn regenerate_2fa_recovery_codes(
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<RegenerateRecoveryReq>,
) -> Response {
    if req.code.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "A valid TOTP or recovery code is required",
        );
    }

    crate::auth::blocking_response(move || {
        let Ok(conn) = af_db::get_read_conn() else {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Database unavailable");
        };
        let row = conn.query_row(
            "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
            params![user.user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, String>(2)?)),
        );
        drop(conn);
        let Ok((encrypted_secret, totp_enabled, password_hash)) = row else {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to query user");
        };
        if !totp_enabled {
            return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Two-factor authentication is not enabled");
        }
        let password_ok = password_hash.is_empty()
            || (!req.password.is_empty()
                && crate::auth::verify_password(&req.password, &password_hash));
        let result = (|| -> anyhow::Result<Option<Vec<String>>> {
            if !password_ok {
                return Ok(None);
            }
            let recovery = crate::auth::validate_recovery_code(user.user_id, &req.code);
            if recovery.is_none()
                && !crate::auth::has_matching_totp_code(&af_db::decrypt_key(&encrypted_secret)?, &req.code)
            {
                return Ok(None);
            }
            let codes = generate_recovery_codes();
            let hashes = crate::auth::hash_recovery_codes(&codes)?;
            let conn = af_db::get_conn()?;
            Ok(replace_recovery_hashes(
                &conn, user.user_id, &encrypted_secret, &password_hash, &req.code, recovery, &hashes,
            )?.then_some(codes))
        })();
        let codes = match result {
            Ok(Some(codes)) => codes,
            Ok(None) => {
                let err_code = if !password_ok {
                    "INVALID_CURRENT_PASSWORD"
                } else {
                    "INVALID_2FA_CODE"
                };
                return api_error(StatusCode::FORBIDDEN, err_code, "Invalid verification code or password");
            }
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to regenerate recovery codes"),
        };
        let ip = extract_client_ip(&headers);
        let ua = headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).unwrap_or("");
        af_db::record_audit(user.user_id, &user.username, "2fa_recovery_regenerate", "user", "", "", &ip, ua);
        Json(serde_json::json!({
            "message": "Recovery codes regenerated",
            "recovery_codes": codes,
        })).into_response()
    }).await
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Action Approval Gate Lookup (`GET /actions/:id`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_pending_action(Path(id): Path<i64>) -> Response {
    match af_db::get_pending_action_by_id(id) {
        Ok(Some(action)) => {
            let reconciled = crate::routes::reconcile_pending_action(action).await;
            Json(reconciled).into_response()
        }
        Ok(None) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Action not found"),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_ERROR",
            "Could not load action",
        ),
    }
}
