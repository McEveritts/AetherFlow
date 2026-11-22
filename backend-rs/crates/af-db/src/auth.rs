use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pool::{get_conn, get_read_conn};
use crate::schema::ensure_column;

// ─────────────────────────────────────────────────────────────────────────────
// Session Revocation, 2FA Pending & MFA Challenge Store
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) static TOKEN_BLACKLIST: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PENDING_2FA_CACHE: Lazy<Mutex<HashMap<i64, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn ensure_revoked_tokens_table(conn: &Connection) -> bool {
    if conn
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                family_id TEXT NOT NULL DEFAULT '',
                user_id INTEGER NOT NULL DEFAULT 0
            );",
        )
        .is_err()
    {
        return false;
    }
    let _ = ensure_column(
        conn,
        "revoked_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    );
    let _ = ensure_column(
        conn,
        "revoked_tokens",
        "user_id",
        "INTEGER NOT NULL DEFAULT 0",
    );
    true
}

pub fn cache_revoked_token(jti: &str, ttl: Duration) {
    if jti.is_empty() {
        return;
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    let exp = Instant::now() + ttl;
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        map.retain(|_, v| *v > Instant::now());
        map.insert(jti.to_string(), exp);
    }
}

pub fn revoke_token_in_tx(conn: &Connection, jti: &str, ttl: Duration) -> anyhow::Result<()> {
    if jti.is_empty() {
        return Ok(());
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    if !ensure_revoked_tokens_table(conn) {
        anyhow::bail!("failed to ensure revoked_tokens table");
    }
    let mut family_id = String::new();
    let mut user_id = 0i64;
    if let Ok(Some((fam, uid))) = conn
        .query_row(
            "SELECT COALESCE(family_id, ''), user_id FROM active_sessions WHERE jti = ?1",
            params![jti],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
    {
        family_id = if fam.trim().is_empty() {
            jti.to_string()
        } else {
            fam
        };
        user_id = uid;
    } else if let Ok(Some((fam, uid))) = conn
        .query_row(
            "SELECT COALESCE(family_id, ''), COALESCE(user_id, 0) FROM revoked_tokens WHERE jti = ?1",
            params![jti],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
    {
        family_id = fam;
        user_id = uid;
    }
    let exp_rfc3339 = (Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at, family_id, user_id) VALUES (?1, ?2, ?3, ?4)",
        params![jti, exp_rfc3339, family_id, user_id],
    )?;
    let _ = conn.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti]);
    Ok(())
}

/// Atomically marks `jti` as revoked inside an active `BEGIN IMMEDIATE` transaction
/// ONLY if it is not currently revoked. Returns `Ok(true)` exclusively for the single
/// winning caller that consumed `jti`.
pub fn try_consume_session_jti_in_tx(
    conn: &Connection,
    jti: &str,
    ttl: Duration,
) -> anyhow::Result<bool> {
    if jti.is_empty() {
        return Ok(false);
    }
    let ttl = ttl.max(Duration::from_secs(8160));
    if token_revocation_status_with_conn(conn, jti)? {
        return Ok(false);
    }
    let _ = conn.execute("DELETE FROM revoked_tokens WHERE jti = ?1", params![jti]);
    let exp_rfc3339 = (Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339();
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)",
        params![jti, exp_rfc3339],
    )?;
    Ok(inserted == 1)
}

pub fn record_revoked_token_lineage_in_tx(
    conn: &Connection,
    jti: &str,
    family_id: &str,
    user_id: i64,
) -> anyhow::Result<()> {
    if jti.is_empty() || family_id.trim().is_empty() {
        return Ok(());
    }
    match conn.execute(
        "UPDATE revoked_tokens SET family_id = ?1, user_id = ?2 WHERE jti = ?3",
        params![family_id.trim(), user_id, jti],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("family_id") || e.to_string().contains("user_id") => {
            let _ = ensure_column(
                conn,
                "revoked_tokens",
                "family_id",
                "TEXT NOT NULL DEFAULT ''",
            );
            let _ = ensure_column(
                conn,
                "revoked_tokens",
                "user_id",
                "INTEGER NOT NULL DEFAULT 0",
            );
            conn.execute(
                "UPDATE revoked_tokens SET family_id = ?1, user_id = ?2 WHERE jti = ?3",
                params![family_id.trim(), user_id, jti],
            )?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn resolve_revoked_token_family_in_tx(
    conn: &Connection,
    jti: &str,
    user_id: i64,
) -> anyhow::Result<Option<String>> {
    if jti.is_empty() {
        return Ok(None);
    }
    let query = || {
        conn.query_row(
            "SELECT COALESCE(family_id, '') FROM revoked_tokens \
             WHERE jti = ?1 AND (COALESCE(user_id, 0) = 0 OR user_id = ?2) LIMIT 1",
            params![jti, user_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    };
    let fam: Option<String> = match query() {
        Ok(v) => v,
        Err(e) if e.to_string().contains("family_id") || e.to_string().contains("user_id") => None,
        Err(e) => return Err(e.into()),
    };
    Ok(fam.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

pub fn revoke_token(jti: &str, ttl: Duration) -> anyhow::Result<()> {
    if jti.is_empty() {
        return Ok(());
    }
    // Refresh accepts a token for 7200s after exp (900s), plus 60s clock skew tolerance = 8160s.
    let ttl = ttl.max(Duration::from_secs(8160));
    let conn = get_conn()?;
    revoke_token_in_tx(&conn, jti, ttl)?;
    let _ = conn.execute(
        "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND TRIM(expires_at) != '' AND datetime(expires_at) IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        [],
    );
    cache_revoked_token(jti, ttl);
    Ok(())
}

/// Errors are distinct from a confirmed revocation so rotation grace cannot mask a DB failure.
pub fn token_revocation_status(jti: &str) -> anyhow::Result<bool> {
    if jti.is_empty() {
        return Ok(true);
    }
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        if let Some(&exp) = map.get(jti) {
            if exp > Instant::now() {
                return Ok(true);
            }
            map.remove(jti);
        }
    }
    let conn = get_read_conn()?;
    token_revocation_status_with_conn(&conn, jti)
}

fn parse_revocation_expiry_utc(raw: &str) -> anyhow::Result<DateTime<Utc>> {
    let trimmed = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Ok(naive.and_utc());
    }
    anyhow::bail!("invalid revoked_tokens.expires_at timestamp: {}", trimmed)
}

pub fn token_revocation_status_with_conn(conn: &Connection, jti: &str) -> anyhow::Result<bool> {
    let expiry: Option<String> = conn
        .query_row(
            "SELECT expires_at FROM revoked_tokens WHERE jti = ?1",
            params![jti],
            |r| r.get(0),
        )
        .optional()?;
    match expiry {
        None => Ok(false),
        Some(expiry) => Ok(parse_revocation_expiry_utc(&expiry)? > Utc::now()),
    }
}

pub fn is_token_revoked(jti: &str) -> bool {
    token_revocation_status(jti).unwrap_or(true)
}

pub fn store_2fa_pending(user_id: i64, secret: &str, ttl: Duration) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        let now = Instant::now();
        map.retain(|_, (_, expires)| *expires > now);
        map.insert(user_id, (secret.to_string(), now + ttl));
    }
}

pub fn get_2fa_pending(user_id: i64) -> Option<String> {
    let mut map = PENDING_2FA_CACHE.lock().ok()?;
    if let Some((secret, exp)) = map.get(&user_id) {
        if *exp > Instant::now() {
            return Some(secret.clone());
        }
        map.remove(&user_id);
    }
    None
}

pub fn delete_2fa_pending(user_id: i64) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        map.remove(&user_id);
    }
}

pub const MAX_MFA_ATTEMPTS: i64 = 5;

pub fn store_mfa_challenge_in_tx(
    conn: &Connection,
    token: &str,
    user_id: i64,
    credential_ver: i64,
    ttl: Duration,
) -> anyhow::Result<()> {
    let now = Utc::now().timestamp();
    let exp = now + ttl.as_secs().min(300) as i64;
    conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now],
    )?;
    match conn.execute(
        "INSERT INTO mfa_challenges (token, user_id, credential_ver, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token, user_id, credential_ver, exp],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("credential_ver") => {
            ensure_column(
                conn,
                "mfa_challenges",
                "credential_ver",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            conn.execute(
                "INSERT INTO mfa_challenges (token, user_id, credential_ver, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![token, user_id, credential_ver, exp],
            )?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn store_mfa_challenge(token: &str, user_id: i64, ttl: Duration) -> anyhow::Result<()> {
    let conn = get_conn()?;
    let ver: i64 = conn
        .query_row(
            "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    store_mfa_challenge_in_tx(&conn, token, user_id, ver, ttl)
}

pub fn delete_user_mfa_challenges_in_tx(conn: &Connection, user_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'mfa_challenges'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if exists {
        conn.execute(
            "DELETE FROM mfa_challenges WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    Ok(())
}

/// Call within the same write transaction as factor verification and consumption.
/// Failed verification must commit this attempt; successful consumption must commit with the factor.
pub fn begin_mfa_attempt_with_epoch(
    conn: &Connection,
    token: &str,
) -> anyhow::Result<Option<(i64, i64)>> {
    let now = Utc::now().timestamp();
    match conn
        .query_row(
            "UPDATE mfa_challenges SET attempts = attempts + 1 \
             WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3 \
             RETURNING user_id, COALESCE(credential_ver, 0)",
            params![token, MAX_MFA_ATTEMPTS, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
    {
        Ok(res) => Ok(res),
        Err(e) if e.to_string().contains("credential_ver") => Ok(conn
            .query_row(
                "UPDATE mfa_challenges SET attempts = attempts + 1 \
                 WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3 \
                 RETURNING user_id",
                params![token, MAX_MFA_ATTEMPTS, now],
                |r| Ok((r.get(0)?, 0i64)),
            )
            .optional()?),
        Err(e) => Err(e.into()),
    }
}

pub fn begin_mfa_attempt(conn: &Connection, token: &str) -> anyhow::Result<Option<i64>> {
    Ok(begin_mfa_attempt_with_epoch(conn, token)?.map(|(uid, _)| uid))
}

pub fn consume_mfa_challenge_with_epoch(
    conn: &Connection,
    token: &str,
    user_id: i64,
    credential_ver: i64,
) -> anyhow::Result<bool> {
    let now = Utc::now().timestamp();
    match conn
        .query_row(
            "DELETE FROM mfa_challenges \
             WHERE token = ?1 AND user_id = ?2 AND COALESCE(credential_ver, 0) = ?3 \
               AND attempts <= ?4 AND expires_at > ?5 \
             RETURNING user_id",
            params![token, user_id, credential_ver, MAX_MFA_ATTEMPTS, now],
            |r| r.get::<_, i64>(0),
        )
        .optional()
    {
        Ok(consumed) => Ok(consumed == Some(user_id)),
        Err(e) if e.to_string().contains("credential_ver") => {
            if credential_ver != 0 {
                return Ok(false);
            }
            consume_mfa_challenge(conn, token, user_id)
        }
        Err(e) => Err(e.into()),
    }
}

pub fn consume_mfa_challenge(conn: &Connection, token: &str, user_id: i64) -> anyhow::Result<bool> {
    let consumed: Option<i64> = conn
        .query_row(
            "DELETE FROM mfa_challenges WHERE token = ?1 AND user_id = ?2 AND attempts <= ?3 AND expires_at > ?4 RETURNING user_id",
            params![token, user_id, MAX_MFA_ATTEMPTS, Utc::now().timestamp()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(consumed == Some(user_id))
}
