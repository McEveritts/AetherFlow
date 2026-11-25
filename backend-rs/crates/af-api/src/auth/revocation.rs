use super::tokens::{column_exists, decode_session_claims, table_exists};
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const MIN_REVOCATION_TTL: Duration = Duration::from_secs(8160);
pub(super) const ROTATED_TOKEN_GRACE_WINDOW: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(super) struct RotatedTokenGraceEntry {
    pub(super) user_id: i64,
    pub(super) family_id: String,
    pub(super) successor_jti: String,
    pub(super) new_token: String,
    pub(super) successor_exp: i64,
    pub(super) strict_fp: String,
    pub(super) expires_at: Instant,
}

pub(super) static ROTATED_TOKEN_GRACE: Lazy<Mutex<HashMap<String, RotatedTokenGraceEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) static ROTATED_SESSION_SUCCESSOR: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn oidc_session_tag(family_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-oidc-sess:");
    hasher.update(family_id.trim().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..32].to_string()
}

pub(crate) fn resolve_session_family_id(
    conn: &rusqlite::Connection,
    user_id: i64,
    jti: &str,
) -> String {
    let trimmed = jti.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let resolved_jti = resolve_current_session_jti(trimmed);
    if let Some(fam) = ROTATED_TOKEN_GRACE
        .lock()
        .ok()
        .and_then(|map| map.get(trimmed).cloned())
        .filter(|e| e.user_id == user_id && !e.family_id.trim().is_empty())
        .map(|e| e.family_id)
    {
        return fam;
    }
    if table_exists(conn, "active_sessions").unwrap_or(false)
        && column_exists(conn, "active_sessions", "family_id").unwrap_or(false)
    {
        if let Ok(Some(fam)) = conn
            .query_row(
                "SELECT COALESCE(family_id, '') FROM active_sessions \
                 WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3) AND COALESCE(family_id, '') != '' LIMIT 1",
                params![user_id, trimmed, resolved_jti],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            if !fam.trim().is_empty() {
                return fam.trim().to_string();
            }
        }
    }
    if let Ok(Some(fam)) = af_db::resolve_revoked_token_family_in_tx(conn, trimmed, user_id) {
        if !fam.trim().is_empty() {
            return fam.trim().to_string();
        }
    }
    trimmed.to_string()
}

pub(crate) fn resolve_current_session_jti(jti: &str) -> String {
    if jti.is_empty() {
        return String::new();
    }
    let Ok(mut map) = ROTATED_SESSION_SUCCESSOR.lock() else {
        return jti.to_string();
    };
    let now = Instant::now();
    if map.len() > 4096 {
        map.retain(|_, (_, exp)| *exp > now);
    }
    let mut current = jti.to_string();
    for _ in 0..32 {
        match map.get(&current) {
            Some((next, exp)) if *exp > now && next != &current => {
                current = next.clone();
            }
            _ => break,
        }
    }
    current
}

fn check_rotation_grace(jti: &str) -> Option<RotatedTokenGraceEntry> {
    let mut map = ROTATED_TOKEN_GRACE.lock().ok()?;
    map.retain(|_, v| v.expires_at > Instant::now());
    map.get(jti).cloned()
}

pub(super) fn resolve_latest_grace_token(
    jti: &str,
    user_id: i64,
    caller_strict_fp: Option<&str>,
) -> Option<(RotatedTokenGraceEntry, String, i64, String)> {
    let grace = check_rotation_grace(jti).filter(|g| g.user_id == user_id)?;
    if let Some(fp) = caller_strict_fp.filter(|s| !s.is_empty()) {
        if !grace.strict_fp.is_empty() && grace.strict_fp != fp {
            return None;
        }
    }
    if grace.successor_jti.is_empty() || grace.new_token.is_empty() {
        return None;
    }
    let mut latest_token = grace.new_token.clone();
    let mut latest_exp = grace.successor_exp;
    if let Ok(map) = ROTATED_TOKEN_GRACE.lock() {
        let now = Instant::now();
        let mut cur_succ = grace.successor_jti.clone();
        for _ in 0..32 {
            let Some(next) = map.get(&cur_succ) else {
                break;
            };
            if next.user_id != user_id
                || next.expires_at <= now
                || next.new_token.is_empty()
                || next.successor_jti == cur_succ
            {
                break;
            }
            if let Some(fp) = caller_strict_fp.filter(|s| !s.is_empty()) {
                if !next.strict_fp.is_empty() && next.strict_fp != fp {
                    return None;
                }
            }
            latest_token = next.new_token.clone();
            if next.successor_exp > 0 {
                latest_exp = next.successor_exp;
            }
            if next.successor_jti.is_empty() {
                break;
            }
            cur_succ = next.successor_jti.clone();
        }
    }
    let leaf_jti = resolve_current_session_jti(&grace.successor_jti);
    if leaf_jti.is_empty() {
        return None;
    }
    if latest_exp <= 0 {
        latest_exp = decode_session_claims(&latest_token, true)
            .map(|c| c.exp)
            .unwrap_or_else(|_| Utc::now().timestamp() + 900);
    }
    Some((grace, latest_token, latest_exp, leaf_jti))
}

pub(crate) fn is_session_token_revoked_beyond_grace_with_conn(
    conn: &rusqlite::Connection,
    jti: &str,
    user_id: i64,
) -> bool {
    match af_db::token_revocation_status_with_conn(conn, jti) {
        Ok(false) => false,
        Err(_) => true,
        Ok(true) => {
            let Some((grace, _, _, leaf_jti)) = resolve_latest_grace_token(jti, user_id, None)
            else {
                return true;
            };
            let now = Utc::now().timestamp();
            if matches!(
                af_db::token_revocation_status_with_conn(conn, &leaf_jti),
                Ok(false)
            ) && matches!(
                af_db::has_unexpired_active_session(conn, &leaf_jti, user_id, now),
                Ok(true)
            ) {
                false
            } else {
                evict_rotation_grace_for_family(&grace.family_id, jti);
                true
            }
        }
    }
}

pub(crate) fn is_session_token_revoked_beyond_grace_for_fp(
    jti: &str,
    user_id: i64,
    caller_strict_fp: Option<&str>,
) -> bool {
    match af_db::token_revocation_status(jti) {
        Ok(false) => false,
        Err(_) => true,
        Ok(true) => {
            let Some((grace, _, _, leaf_jti)) =
                resolve_latest_grace_token(jti, user_id, caller_strict_fp)
            else {
                return true;
            };
            let now = Utc::now().timestamp();
            let leaf_live = af_db::get_read_conn().ok().is_some_and(|conn| {
                matches!(
                    af_db::token_revocation_status_with_conn(&conn, &leaf_jti),
                    Ok(false)
                ) && matches!(
                    af_db::has_unexpired_active_session(&conn, &leaf_jti, user_id, now),
                    Ok(true)
                )
            });
            if leaf_live {
                false
            } else {
                evict_rotation_grace_for_family(&grace.family_id, jti);
                true
            }
        }
    }
}

pub(crate) fn is_session_token_revoked_beyond_grace(jti: &str, user_id: i64) -> bool {
    is_session_token_revoked_beyond_grace_for_fp(jti, user_id, None)
}

pub(crate) fn evict_rotation_grace_for_family(family_id: &str, target_jti: &str) {
    let mut evicted_jtis = std::collections::HashSet::new();
    if !target_jti.is_empty() {
        evicted_jtis.insert(target_jti.to_string());
    }
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        map.retain(|old_jti, entry| {
            let leaf = resolve_current_session_jti(&entry.successor_jti);
            let keep = old_jti != target_jti
                && entry.successor_jti != target_jti
                && (target_jti.is_empty() || leaf != target_jti)
                && (family_id.is_empty() || entry.family_id != family_id);
            if !keep {
                evicted_jtis.insert(old_jti.clone());
                if !entry.successor_jti.is_empty() {
                    evicted_jtis.insert(entry.successor_jti.clone());
                }
                if !leaf.is_empty() {
                    evicted_jtis.insert(leaf);
                }
            }
            keep
        });
    }
    if !evicted_jtis.is_empty() {
        if let Ok(mut succ) = ROTATED_SESSION_SUCCESSOR.lock() {
            succ.retain(|old_jti, (next_jti, _)| {
                !evicted_jtis.contains(old_jti) && !evicted_jtis.contains(next_jti)
            });
        }
    }
}

pub(crate) fn evict_rotation_grace_for_user(user_id: i64) {
    let mut evicted_jtis = std::collections::HashSet::new();
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        map.retain(|old_jti, entry| {
            let keep = entry.user_id != user_id;
            if !keep {
                evicted_jtis.insert(old_jti.clone());
                if !entry.successor_jti.is_empty() {
                    evicted_jtis.insert(entry.successor_jti.clone());
                }
            }
            keep
        });
    }
    if !evicted_jtis.is_empty() {
        if let Ok(mut succ) = ROTATED_SESSION_SUCCESSOR.lock() {
            succ.retain(|old_jti, (next_jti, _)| {
                !evicted_jtis.contains(old_jti) && !evicted_jtis.contains(next_jti)
            });
        }
    }
}

/// Bumps `users.sessions_revoked_after` (monotonic credential epoch), revokes all
/// active session JTIs for `user_id` into `revoked_tokens`, deletes `active_sessions`,
/// and revokes all OIDC refresh tokens, auth codes, and pending device codes for `user_id`.
/// Returns `(new_credential_ver, revoked_jtis)` so callers can cache JTIs and evict
/// rotation grace after committing the SQLite transaction.
pub(crate) fn revoke_all_user_credentials_in_tx(
    tx: &rusqlite::Connection,
    user_id: i64,
) -> anyhow::Result<(i64, Vec<String>)> {
    let mut new_ver = 1i64;
    if column_exists(tx, "users", "sessions_revoked_after")? {
        new_ver = tx.query_row(
            "UPDATE users SET sessions_revoked_after = COALESCE(sessions_revoked_after, 0) + 1 \
             WHERE id = ?1 RETURNING sessions_revoked_after",
            params![user_id],
            |r| r.get(0),
        )?;
    }

    let mut revoked_jtis = Vec::new();
    if table_exists(tx, "active_sessions")? {
        if column_exists(tx, "active_sessions", "jti")? {
            let mut stmt = tx.prepare("SELECT jti FROM active_sessions WHERE user_id = ?1")?;
            let rows = stmt.query_map(params![user_id], |r| r.get::<_, String>(0))?;
            for row in rows {
                revoked_jtis.push(row?);
            }
            drop(stmt);
            if table_exists(tx, "revoked_tokens")? {
                for jti in &revoked_jtis {
                    af_db::revoke_token_in_tx(tx, jti, MIN_REVOCATION_TTL)?;
                }
            }
        }
        tx.execute(
            "DELETE FROM active_sessions WHERE user_id = ?1",
            params![user_id],
        )?;
    }

    if table_exists(tx, "oidc_refresh_tokens")?
        && column_exists(tx, "oidc_refresh_tokens", "revoked")?
    {
        tx.execute(
            "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    if table_exists(tx, "oidc_auth_codes")? && column_exists(tx, "oidc_auth_codes", "used")? {
        tx.execute(
            "UPDATE oidc_auth_codes SET used = 1 WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    if table_exists(tx, "oidc_device_codes")? {
        tx.execute(
            "DELETE FROM oidc_device_codes WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    af_db::delete_user_mfa_challenges_in_tx(tx, user_id)?;

    Ok((new_ver, revoked_jtis))
}

pub(crate) fn finalize_user_credential_revocation(user_id: i64, revoked_jtis: &[String]) {
    for jti in revoked_jtis {
        af_db::cache_revoked_token(jti, MIN_REVOCATION_TTL);
    }
    evict_rotation_grace_for_user(user_id);
    af_db::delete_2fa_pending(user_id);
}

pub(super) fn revoke_session_family_in_tx(
    tx: &rusqlite::Connection,
    user_id: i64,
    target_jti: &str,
    revoke_oidc_grants: bool,
) -> anyhow::Result<(String, Vec<String>)> {
    let resolved_jti = resolve_current_session_jti(target_jti);
    let grace_info = ROTATED_TOKEN_GRACE
        .lock()
        .ok()
        .and_then(|map| map.get(target_jti).cloned())
        .filter(|e| e.user_id == user_id);
    let mut family_id = grace_info
        .as_ref()
        .map(|e| e.family_id.clone())
        .unwrap_or_default();

    let mut jtis_to_revoke = vec![target_jti.to_string()];
    if !resolved_jti.is_empty() && !jtis_to_revoke.contains(&resolved_jti) {
        jtis_to_revoke.push(resolved_jti.clone());
    }
    if let Some(ref g) = grace_info {
        if !g.successor_jti.is_empty() && !jtis_to_revoke.contains(&g.successor_jti) {
            jtis_to_revoke.push(g.successor_jti.clone());
        }
    }

    if family_id.is_empty() && table_exists(tx, "revoked_tokens")? {
        if let Some(fam) = af_db::resolve_revoked_token_family_in_tx(tx, target_jti, user_id)? {
            if !fam.trim().is_empty() {
                family_id = fam.trim().to_string();
            }
        }
        if family_id.is_empty() && !resolved_jti.is_empty() && resolved_jti != target_jti {
            if let Some(fam) =
                af_db::resolve_revoked_token_family_in_tx(tx, &resolved_jti, user_id)?
            {
                if !fam.trim().is_empty() {
                    family_id = fam.trim().to_string();
                }
            }
        }
    }

    let has_active_sessions = table_exists(tx, "active_sessions")?;
    let has_family = if has_active_sessions {
        column_exists(tx, "active_sessions", "family_id")?
    } else {
        false
    };

    if has_active_sessions {
        if has_family && family_id.is_empty() {
            family_id = tx
                .query_row(
                    "SELECT COALESCE(family_id, '') FROM active_sessions \
                     WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3 OR family_id = ?2 OR family_id = ?3) \
                     AND COALESCE(family_id, '') != '' LIMIT 1",
                    params![user_id, target_jti, resolved_jti],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_default();
        }
        if family_id.is_empty() {
            family_id = target_jti.to_string();
        }
        if has_family && !family_id.is_empty() {
            let mut stmt = tx.prepare(
                "SELECT jti FROM active_sessions WHERE user_id = ?1 AND (family_id = ?2 OR jti = ?3 OR jti = ?4)",
            )?;
            let rows = stmt
                .query_map(params![user_id, family_id, target_jti, resolved_jti], |r| {
                    r.get::<_, String>(0)
                })?;
            for row in rows {
                let found = row?;
                if !found.is_empty() && !jtis_to_revoke.contains(&found) {
                    jtis_to_revoke.push(found);
                }
            }
        }
    } else if family_id.is_empty() {
        family_id = target_jti.to_string();
    }

    for jti in &jtis_to_revoke {
        af_db::revoke_token_in_tx(tx, jti, MIN_REVOCATION_TTL)?;
        if !family_id.is_empty() {
            af_db::record_revoked_token_lineage_in_tx(tx, jti, &family_id, user_id)?;
        }
    }

    if has_active_sessions {
        if !family_id.is_empty() && has_family {
            tx.execute(
                "DELETE FROM active_sessions WHERE user_id = ?1 AND family_id = ?2",
                params![user_id, family_id],
            )?;
        }
        for jti in &jtis_to_revoke {
            tx.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti])?;
        }
    }

    if revoke_oidc_grants {
        let mut sess_tags = Vec::new();
        if !family_id.is_empty() {
            sess_tags.push(oidc_session_tag(&family_id));
        }
        let jti_tag = oidc_session_tag(target_jti);
        if !sess_tags.contains(&jti_tag) {
            sess_tags.push(jti_tag);
        }
        let has_oidc_table = table_exists(tx, "oidc_refresh_tokens")?;
        let has_oidc_fam = has_oidc_table && column_exists(tx, "oidc_refresh_tokens", "family_id")?;
        for tag in sess_tags {
            let marker = format!("oidc-sess:{}", tag);
            af_db::revoke_token_in_tx(tx, &marker, MIN_REVOCATION_TTL)?;
            if !jtis_to_revoke.contains(&marker) {
                jtis_to_revoke.push(marker);
            }
            if has_oidc_fam {
                let prefix = format!("sf:{}:", tag);
                tx.execute(
                    "UPDATE oidc_refresh_tokens SET revoked = 1 \
                     WHERE user_id = ?1 AND substr(COALESCE(family_id, ''), 1, 36) = ?2",
                    params![user_id, prefix],
                )?;
            }
        }
    }

    Ok((family_id, jtis_to_revoke))
}
