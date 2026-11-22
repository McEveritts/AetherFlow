use super::revocation::{finalize_user_credential_revocation, revoke_all_user_credentials_in_tx};
use super::setup_login::verify_password;
use super::tokens::{
    api_error, blocking_auth_work, blocking_response, create_session_jwt_in_conn,
    load_active_human_subject, set_session_cookie, table_exists, AuthUser, SubjectStatusError,
};
use crate::ws::extract_client_ip;
use af_models::User;
use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn matching_totp_step(secret_b32: &str, code: &str, now_secs: u64) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let secret_bytes = BASE32_NOPAD
        .decode(secret_b32.trim().to_uppercase().as_bytes())
        .ok()?;
    if secret_bytes.is_empty() {
        return None;
    }
    for offset in [0i64, -30, 30] {
        let ts = (now_secs as i64 + offset).max(0) as u64;
        let expected = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, ts);
        if af_models::constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Some((ts / 30) as i64);
        }
    }
    None
}

pub(crate) fn has_matching_totp_code(secret: &str, code: &str) -> bool {
    matching_totp_step(secret, code, Utc::now().timestamp().max(0) as u64).is_some()
}

pub(crate) fn consume_totp_code(
    conn: &rusqlite::Connection,
    user_id: i64,
    secret: &str,
    code: &str,
) -> bool {
    let Some(step) = matching_totp_step(secret, code, Utc::now().timestamp().max(0) as u64) else {
        return false;
    };
    matches!(
        conn.execute(
            "UPDATE users SET last_totp_step = ?1 WHERE id = ?2 AND totp_enabled = 1 AND last_totp_step < ?1",
            params![step, user_id],
        ),
        Ok(1)
    )
}

const RECOVERY_BCRYPT_COST: u32 = if cfg!(test) { 6 } else { bcrypt::DEFAULT_COST };
const RECOVERY_CODE_GROUPS: usize = 4;
const RECOVERY_CODE_GROUP_LEN: usize = 7;
const RECOVERY_CODE_TOTAL_CHARS: usize = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_LEN; // 28 chars * 5 bits = 140 bits entropy
const RECOVERY_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(super) fn recovery_hash(salt: &[u8], compact: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aetherflow-recovery-v1\0");
    hash.update(salt);
    hash.update(compact.as_bytes());
    hex::encode(hash.finalize())
}

pub(crate) fn generate_recovery_codes() -> Vec<String> {
    const UNBIASED_CEILING: usize = 256 - (256 % RECOVERY_CODE_CHARSET.len());
    let mut codes = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut chars = Vec::with_capacity(RECOVERY_CODE_TOTAL_CHARS);
        while chars.len() < RECOVERY_CODE_TOTAL_CHARS {
            let mut raw = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            for &b in &raw {
                if (b as usize) < UNBIASED_CEILING {
                    chars.push(
                        RECOVERY_CODE_CHARSET[(b as usize) % RECOVERY_CODE_CHARSET.len()] as char,
                    );
                    if chars.len() == RECOVERY_CODE_TOTAL_CHARS {
                        break;
                    }
                }
            }
        }
        let code = chars
            .chunks(RECOVERY_CODE_GROUP_LEN)
            .map(|grp| grp.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-");
        codes.push(code);
    }
    codes
}

pub(crate) fn hash_recovery_codes(codes: &[String]) -> anyhow::Result<Vec<String>> {
    codes
        .iter()
        .map(|code| {
            let compact: String = code.trim().chars().filter(|c| *c != '-').collect();
            bcrypt::hash(compact, RECOVERY_BCRYPT_COST).map_err(Into::into)
        })
        .collect()
}

pub(crate) fn store_recovery_codes(
    transaction: &rusqlite::Transaction<'_>,
    user_id: i64,
    hashes: &[String],
) -> anyhow::Result<()> {
    transaction.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    for hash in hashes {
        transaction.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (?1, ?2, 0)",
            params![user_id, hash],
        )?;
    }
    let has_legacy_column: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'totp_recovery_codes')",
        [],
        |row| row.get(0),
    )?;
    if has_legacy_column {
        transaction.execute(
            "UPDATE users SET totp_recovery_codes = '[]' WHERE id = ?1",
            params![user_id],
        )?;
    }
    Ok(())
}

pub(crate) struct RecoveryCodeMatch {
    id: i64,
    hash: String,
}

pub(super) fn normalized_recovery_code(raw_code: &str) -> Option<(String, bool)> {
    if raw_code.len() > 64 {
        return None;
    }
    let compact: String = raw_code
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|&ch| ch != '-')
        .collect();
    let legacy = compact.len() == 8 && compact.bytes().all(|ch| ch.is_ascii_hexdigit());
    // Current issues use four groups of seven characters. Keep their entropy and
    // accept only the exact alphabet generated for those codes.
    let current = compact.len() == RECOVERY_CODE_TOTAL_CHARS
        && compact
            .bytes()
            .all(|ch| RECOVERY_CODE_CHARSET.contains(&ch));
    (legacy || current).then_some((compact, legacy))
}

fn recovery_candidates(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> rusqlite::Result<Vec<RecoveryCodeMatch>> {
    let mut stmt = conn.prepare(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ?1 AND COALESCE(used, 0) = 0",
    )?;
    let rows = stmt.query_map(params![user_id], |row| {
        Ok(RecoveryCodeMatch {
            id: row.get(0)?,
            hash: row.get(1)?,
        })
    })?;
    rows.collect()
}

fn match_recovery_code(
    candidates: Vec<RecoveryCodeMatch>,
    compact: &str,
    legacy: bool,
) -> Option<RecoveryCodeMatch> {
    let dashed = legacy.then(|| format!("{}-{}", &compact[..4], &compact[4..]));
    candidates.into_iter().find(|candidate| {
        let hash = candidate.hash.trim();
        if let Some((salt, expected)) = hash
            .strip_prefix("sha256:v1:")
            .and_then(|value| value.split_once(':'))
        {
            return hex::decode(salt).ok().is_some_and(|salt| {
                salt.len() == 16
                    && af_models::constant_time_eq(
                        recovery_hash(&salt, compact).as_bytes(),
                        expected.as_bytes(),
                    )
            });
        }
        hash.starts_with("$2")
            && (bcrypt::verify(compact, hash).unwrap_or(false)
                || dashed.as_ref().is_some_and(|dashed| {
                    dashed != compact && bcrypt::verify(dashed, hash).unwrap_or(false)
                }))
    })
}

pub(crate) fn validate_recovery_code(user_id: i64, raw_code: &str) -> Option<RecoveryCodeMatch> {
    let (compact, legacy) = normalized_recovery_code(raw_code)?;
    let conn = af_db::get_read_conn().ok()?;
    let candidates = recovery_candidates(&conn, user_id).ok()?;
    drop(conn);
    match_recovery_code(candidates, &compact, legacy)
}

pub(crate) fn consume_recovery_code(
    conn: &rusqlite::Connection,
    user_id: i64,
    matched: Option<&RecoveryCodeMatch>,
) -> bool {
    matched.is_some_and(|matched| {
        matches!(
            conn.execute(
                "UPDATE recovery_codes SET used = 1 WHERE id = ?1 AND user_id = ?2 AND code_hash = ?3 AND COALESCE(used, 0) = 0",
                params![matched.id, user_id, matched.hash],
            ),
            Ok(1)
        )
    })
}

#[cfg(test)]
pub(crate) fn match_recovery_in_connection(
    conn: &rusqlite::Connection,
    user_id: i64,
    code: &str,
) -> Option<RecoveryCodeMatch> {
    let (compact, legacy) = normalized_recovery_code(code)?;
    match_recovery_code(recovery_candidates(conn, user_id).ok()?, &compact, legacy)
}

pub async fn setup_2fa(req: Request) -> Response {
    blocking_response(move || setup_2fa_blocking(req)).await
}

fn setup_2fa_blocking(req: Request) -> Response {
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

    let enabled = match conn
        .query_row(
            "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
            params![auth_user.user_id],
            |r| r.get::<_, bool>(0),
        )
        .optional()
    {
        Ok(Some(enabled)) => enabled,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found"),
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        }
    };
    if enabled {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Two-factor authentication is already enabled",
        );
    }

    let mut raw_secret = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut raw_secret);
    let secret = BASE32_NOPAD.encode(&raw_secret);
    af_db::store_2fa_pending(auth_user.user_id, &secret, Duration::from_secs(300));

    let uri = format!(
        "otpauth://totp/AetherFlow:{}?secret={}&issuer=AetherFlow&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(&auth_user.username),
        secret
    );

    Json(serde_json::json!({
        "otpauth_uri": uri,
        "secret": secret,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CodeRequest {
    #[serde(default)]
    pub code: String,
}

#[derive(Deserialize, Default)]
pub struct Disable2FaRequest {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
}

pub async fn verify_2fa(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid body"),
    };
    let Ok(payload) = serde_json::from_slice::<CodeRequest>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON");
    };

    blocking_response(move || {
        if let Ok(conn) = af_db::get_read_conn() {
            match conn
                .query_row(
                    "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                    params![auth_user.user_id],
                    |r| r.get::<_, bool>(0),
                )
                .optional()
            {
                Ok(Some(true)) => {
                    af_db::delete_2fa_pending(auth_user.user_id);
                    return api_error(
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        "Two-factor authentication is already enabled",
                    );
                }
                Ok(Some(false) | None) => {}
                Err(_) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Database error",
                    );
                }
            }
        }
        let Some(secret) = af_db::get_2fa_pending(auth_user.user_id) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "No pending 2FA setup found",
            );
        };

        let Some(verified_step) =
            matching_totp_step(&secret, &payload.code, Utc::now().timestamp().max(0) as u64)
        else {
            return api_error(
                StatusCode::FORBIDDEN,
                "INVALID_2FA_CODE",
                "Invalid verification code",
            );
        };

        let Ok(enc_secret) = af_db::encrypt_key(&secret) else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CRYPTO_ERROR",
                "Failed to encrypt two-factor secret",
            );
        };
        let recovery_codes = generate_recovery_codes();
        let result = (|| -> Result<bool, anyhow::Error> {
            let recovery_hashes = hash_recovery_codes(&recovery_codes)?;
            let conn = af_db::get_conn()?;
            let transaction = rusqlite::Transaction::new_unchecked(
                &conn,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let affected = transaction.execute(
                "UPDATE users SET totp_secret = ?1, totp_enabled = 1, last_totp_step = ?3 WHERE id = ?2 AND COALESCE(totp_enabled, 0) = 0",
                params![enc_secret, auth_user.user_id, verified_step],
            )?;
            if affected == 0 {
                let already_enabled: Option<bool> = transaction
                    .query_row(
                        "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                        params![auth_user.user_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if already_enabled == Some(true) {
                    return Ok(false);
                }
                anyhow::bail!("User missing");
            }
            store_recovery_codes(&transaction, auth_user.user_id, &recovery_hashes)?;
            transaction.commit()?;
            Ok(true)
        })();
        match result {
            Ok(true) => {}
            Ok(false) => {
                af_db::delete_2fa_pending(auth_user.user_id);
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Two-factor authentication is already enabled",
                );
            }
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to enable two-factor authentication",
                );
            }
        }
        af_db::delete_2fa_pending(auth_user.user_id);

        Json(serde_json::json!({
            "message": "Two-factor authentication enabled",
            "recovery_codes": recovery_codes,
        }))
        .into_response()
    })
    .await
}

pub(crate) fn verify_user_totp_stepup(user_id: i64, code: &str) -> bool {
    let trimmed = code.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return false;
    }
    let recovery = validate_recovery_code(user_id, trimmed);
    if recovery.is_none()
        && !(trimmed.len() == 6 && trimmed.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let Ok(mut conn) = af_db::get_conn() else {
        return false;
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return false;
    };
    let Ok((totp_enabled, enc_secret)) = tx.query_row(
        "SELECT COALESCE(totp_enabled, 0), COALESCE(totp_secret, '') FROM users WHERE id = ?1",
        params![user_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    ) else {
        return false;
    };
    if totp_enabled == 0 || enc_secret.is_empty() {
        return false;
    }
    let Ok(secret) = af_db::decrypt_key(&enc_secret) else {
        return false;
    };
    let ok = consume_totp_code(&tx, user_id, &secret, trimmed)
        || consume_recovery_code(&tx, user_id, recovery.as_ref());
    ok && tx.commit().is_ok()
}

pub async fn disable_2fa(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let headers = req.headers().clone();
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 4096).await else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid body");
    };
    let Ok(payload) = serde_json::from_slice::<Disable2FaRequest>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON");
    };
    if payload.code.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "A valid TOTP or recovery code is required",
        );
    }
    blocking_auth_work(move || {
        let Ok(conn) = af_db::get_read_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        };
        let (encrypted_secret, password_hash) = match conn
            .query_row(
                "SELECT COALESCE(totp_secret, ''), COALESCE(password_hash, '') FROM users WHERE id = ?1",
                params![auth_user.user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
        {
            Ok(Some(pair)) => pair,
            Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found"),
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Database error",
                );
            }
        };
        drop(conn);
        let secret = if encrypted_secret.is_empty() {
            String::new()
        } else {
            match af_db::decrypt_key(&encrypted_secret) {
                Ok(s) => s,
                Err(_) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "CRYPTO_ERROR",
                        "Failed to decrypt 2FA secret",
                    );
                }
            }
        };
        let password_ok = password_hash.is_empty()
            || (!payload.password.is_empty() && verify_password(&payload.password, &password_hash));
        let recovery = password_ok
            .then(|| validate_recovery_code(auth_user.user_id, &payload.code))
            .flatten();
        let result = (|| -> anyhow::Result<Option<(String, Vec<String>)>> {
            let mut conn = af_db::get_conn()?;
            let transaction =
                conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current: (String, String) = transaction.query_row(
                "SELECT COALESCE(totp_secret, ''), COALESCE(password_hash, '') FROM users WHERE id = ?1",
                params![auth_user.user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let current_secret = if current.0.is_empty() {
                String::new()
            } else {
                af_db::decrypt_key(&current.0)?
            };
            anyhow::ensure!(
                current_secret == secret && current.1 == password_hash,
                "Credentials changed"
            );
            if !password_ok {
                return Ok(None);
            }
            if !consume_totp_code(&transaction, auth_user.user_id, &secret, &payload.code)
                && !consume_recovery_code(&transaction, auth_user.user_id, recovery.as_ref())
            {
                return Ok(None);
            }
            let affected = transaction.execute(
                "UPDATE users SET totp_secret = '', totp_enabled = 0, last_totp_step = -1 WHERE id = ?1",
                params![auth_user.user_id],
            )?;
            anyhow::ensure!(affected == 1, "User not found");
            store_recovery_codes(&transaction, auth_user.user_id, &[])?;
            let (new_ver, revoked_jtis) =
                revoke_all_user_credentials_in_tx(&transaction, auth_user.user_id)?;
            let (new_token, _) = create_session_jwt_in_conn(
                &transaction,
                auth_user.user_id,
                &headers,
                Utc::now().timestamp(),
                None,
                new_ver,
            )?;
            transaction.commit()?;
            Ok(Some((new_token, revoked_jtis)))
        })();
        let (new_token, revoked_jtis) = match result {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                let err_code = if !password_ok {
                    "INVALID_CURRENT_PASSWORD"
                } else {
                    "INVALID_2FA_CODE"
                };
                return api_error(
                    StatusCode::FORBIDDEN,
                    err_code,
                    "Invalid verification code or password",
                );
            }
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to disable two-factor authentication",
                );
            }
        };
        finalize_user_credential_revocation(auth_user.user_id, &revoked_jtis);
        af_db::record_audit(
            auth_user.user_id,
            &auth_user.username,
            "totp_disable",
            "user",
            &auth_user.user_id.to_string(),
            "Two-factor authentication disabled",
            &ip,
            &ua,
        );
        let mut resp =
            Json(serde_json::json!({ "message": "Two-factor authentication disabled" }))
                .into_response();
        set_session_cookie(&mut resp, &new_token);
        resp
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Verification failed",
        )
    })
}

#[derive(Deserialize)]
pub struct MfaVerifyRequest {
    #[serde(default)]
    pub mfa_token: String,
    #[serde(default)]
    pub code: String,
}

pub async fn mfa_login_verify(headers: HeaderMap, Json(req): Json<MfaVerifyRequest>) -> Response {
    blocking_response(move || mfa_login_verify_blocking(headers, req)).await
}

#[derive(Debug)]
enum MfaVerifyOutcome {
    Verified(User, Option<String>),
    Invalid,
    Suspended,
}

fn mfa_recovery_user(conn: &rusqlite::Connection, token: &str) -> Option<i64> {
    conn.query_row(
        "SELECT user_id FROM mfa_challenges WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3",
        params![token, af_db::MAX_MFA_ATTEMPTS, Utc::now().timestamp()],
        |row| row.get(0),
    )
    .ok()
}

fn redeem_mfa_challenge_in_tx(
    transaction: rusqlite::Transaction<'_>,
    token: &str,
    code: &str,
    session_headers: Option<&HeaderMap>,
    recovery: Option<(i64, RecoveryCodeMatch)>,
) -> anyhow::Result<MfaVerifyOutcome> {
    let Some((user_id, challenge_ver)) = af_db::begin_mfa_attempt_with_epoch(&transaction, token)?
    else {
        return Ok(MfaVerifyOutcome::Invalid);
    };
    let subj = match load_active_human_subject(&transaction, user_id) {
        Ok(subj) => subj,
        Err(SubjectStatusError::Suspended) => {
            transaction.execute(
                "DELETE FROM mfa_challenges WHERE token = ?1",
                params![token],
            )?;
            transaction.commit()?;
            return Ok(MfaVerifyOutcome::Suspended);
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            transaction.execute(
                "DELETE FROM mfa_challenges WHERE token = ?1",
                params![token],
            )?;
            transaction.commit()?;
            return Ok(MfaVerifyOutcome::Invalid);
        }
        Err(SubjectStatusError::DbError) => {
            anyhow::bail!("Failed to verify account status during MFA");
        }
    };
    if subj.sessions_revoked_after != challenge_ver {
        transaction.execute(
            "DELETE FROM mfa_challenges WHERE token = ?1",
            params![token],
        )?;
        transaction.commit()?;
        return Ok(MfaVerifyOutcome::Invalid);
    }
    let (user, encrypted): (User, String) = transaction.query_row(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), COALESCE(google_id, ''), COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
        params![user_id],
        |r| {
            let google_id: String = r.get(5)?;
            Ok((
                User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    email: r.get(2)?,
                    avatar_url: r.get(3)?,
                    role: r.get(4)?,
                    is_oauth: !google_id.is_empty(),
                    google_id,
                    totp_enabled: r.get(7)?,
                },
                r.get(6)?,
            ))
        },
    )?;
    let verified = user.totp_enabled
        && (af_db::decrypt_key(&encrypted)
            .ok()
            .is_some_and(|secret| consume_totp_code(&transaction, user_id, &secret, code))
            || recovery.as_ref().is_some_and(|(matched_user, matched)| {
                *matched_user == user_id
                    && consume_recovery_code(&transaction, user_id, Some(matched))
            }));
    if !verified {
        // Commit failed attempts, including the final allowed guess.
        transaction.execute(
            "DELETE FROM mfa_challenges WHERE token = ?1 AND attempts >= ?2",
            params![token, af_db::MAX_MFA_ATTEMPTS],
        )?;
        transaction.commit()?;
        return Ok(MfaVerifyOutcome::Invalid);
    }
    anyhow::ensure!(
        af_db::consume_mfa_challenge_with_epoch(&transaction, token, user_id, challenge_ver)?,
        "Challenge already consumed"
    );
    let session_token = if let Some(headers) = session_headers {
        let (jwt, _) = create_session_jwt_in_conn(
            &transaction,
            user.id,
            headers,
            Utc::now().timestamp(),
            None,
            challenge_ver,
        )?;
        if table_exists(&transaction, "login_history")? {
            if let Err(err) = transaction.execute(
                "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
                params![
                    user.id,
                    extract_client_ip(headers),
                    headers
                        .get(header::USER_AGENT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                ],
            ) {
                tracing::warn!(user_id = user.id, error = %err, "Failed to record MFA login history");
            }
        }
        Some(jwt)
    } else {
        None
    };
    transaction.commit()?;
    Ok(MfaVerifyOutcome::Verified(user, session_token))
}

#[cfg(test)]
fn verify_mfa_factor_outcome(
    conn: &rusqlite::Connection,
    token: &str,
    code: &str,
) -> anyhow::Result<MfaVerifyOutcome> {
    let recovery = mfa_recovery_user(conn, token)
        .and_then(|id| match_recovery_in_connection(conn, id, code).map(|matched| (id, matched)));
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    redeem_mfa_challenge_in_tx(transaction, token, code, None, recovery)
}

#[cfg(test)]
pub(super) fn verify_mfa_factor(
    conn: &rusqlite::Connection,
    token: &str,
    code: &str,
) -> anyhow::Result<Option<User>> {
    match verify_mfa_factor_outcome(conn, token, code)? {
        MfaVerifyOutcome::Verified(user, _) => Ok(Some(user)),
        MfaVerifyOutcome::Invalid | MfaVerifyOutcome::Suspended => Ok(None),
    }
}

fn mfa_login_verify_blocking(headers: HeaderMap, req: MfaVerifyRequest) -> Response {
    let recovery = normalized_recovery_code(&req.code).and_then(|_| {
        let conn = af_db::get_read_conn().ok()?;
        let user_id = mfa_recovery_user(&conn, &req.mfa_token)?;
        drop(conn);
        validate_recovery_code(user_id, &req.code).map(|matched| (user_id, matched))
    });
    let result = (|| -> anyhow::Result<MfaVerifyOutcome> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        redeem_mfa_challenge_in_tx(tx, &req.mfa_token, &req.code, Some(&headers), recovery)
    })();
    let (user, token_opt) = match result {
        Ok(MfaVerifyOutcome::Verified(user, token_opt)) => (user, token_opt),
        Ok(MfaVerifyOutcome::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is suspended",
            );
        }
        Ok(MfaVerifyOutcome::Invalid) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "INVALID_2FA_CODE",
                "Invalid code or expired MFA challenge",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "MFA verification failed",
            );
        }
    };
    let Some(token) = token_opt else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };
    let mut resp =
        Json(serde_json::json!({ "message": "Login successful", "user": user })).into_response();
    set_session_cookie(&mut resp, &token);
    resp
}
