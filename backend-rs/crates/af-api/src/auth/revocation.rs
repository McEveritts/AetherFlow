use super::tokens::{column_exists, decode_session_claims, table_exists};
use af_models::secret_zeroize::SecretString;
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const MIN_REVOCATION_TTL: Duration = Duration::from_secs(8160);
pub(super) const ROTATED_TOKEN_GRACE_WINDOW: Duration = Duration::from_secs(10);
/// Lifetime of a `ROTATED_SESSION_SUCCESSOR` hop (`old_jti -> successor_jti`).
pub(super) const ROTATED_SESSION_SUCCESSOR_TTL: Duration = Duration::from_secs(86400);
/// Hard cap on entries held by each in-memory rotation map (`SEC-01`). When an insert would
/// exceed the cap after pruning expired entries, the entry with the earliest expiry is evicted.
pub(crate) const ROTATION_STATE_MAX_ENTRIES: usize = 4096;
/// Period of the background idle sweep that prunes expired rotation state (`SEC-01`).
pub(crate) const ROTATION_STATE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Short-lived (10 s) record of a rotated session JWT.
///
/// `new_token` is the freshly minted successor JWT. It is a bearer credential, so it is held in a
/// zeroize-on-drop [`SecretString`] (full `0..capacity` wipe) and is redacted from `Debug`.
#[derive(Clone)]
pub(super) struct RotatedTokenGraceEntry {
    pub(super) user_id: i64,
    pub(super) family_id: String,
    pub(super) successor_jti: String,
    pub(super) new_token: SecretString,
    pub(super) successor_exp: i64,
    pub(super) strict_fp: String,
    pub(super) expires_at: Instant,
}

impl std::fmt::Debug for RotatedTokenGraceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatedTokenGraceEntry")
            .field("user_id", &self.user_id)
            .field("family_id", &self.family_id)
            .field("successor_jti", &self.successor_jti)
            .field("new_token", &self.new_token)
            .field("successor_exp", &self.successor_exp)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

pub(super) static ROTATED_TOKEN_GRACE: Lazy<Mutex<HashMap<String, RotatedTokenGraceEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) static ROTATED_SESSION_SUCCESSOR: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Prunes expired entries, then (if `key` is new and the map is at `cap`) evicts entries with the
/// earliest expiry until one slot is free. Never evicts the entry being replaced.
fn prune_and_reserve_slot<V>(
    map: &mut HashMap<String, V>,
    key: &str,
    now: Instant,
    cap: usize,
    expires_at: impl Fn(&V) -> Instant,
) {
    map.retain(|_, v| expires_at(v) > now);
    if map.contains_key(key) {
        return;
    }
    while map.len() >= cap.max(1) {
        let Some(victim) = map
            .iter()
            .min_by_key(|(_, v)| expires_at(v))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&victim);
    }
}

fn insert_rotation_grace_into(
    map: &mut HashMap<String, RotatedTokenGraceEntry>,
    old_jti: String,
    entry: RotatedTokenGraceEntry,
    now: Instant,
    cap: usize,
) {
    prune_and_reserve_slot(map, &old_jti, now, cap, |e| e.expires_at);
    map.insert(old_jti, entry);
}

fn insert_session_successor_into(
    map: &mut HashMap<String, (String, Instant)>,
    old_jti: String,
    successor_jti: String,
    expires_at: Instant,
    now: Instant,
    cap: usize,
) {
    prune_and_reserve_slot(map, &old_jti, now, cap, |(_, exp)| *exp);
    map.insert(old_jti, (successor_jti, expires_at));
}

/// Records a rotated-token grace entry, pruning expired entries on every insert and enforcing
/// [`ROTATION_STATE_MAX_ENTRIES`] with earliest-expiry eviction.
pub(super) fn insert_rotation_grace(old_jti: String, entry: RotatedTokenGraceEntry) {
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        insert_rotation_grace_into(
            &mut map,
            old_jti,
            entry,
            Instant::now(),
            ROTATION_STATE_MAX_ENTRIES,
        );
    }
}

/// Records an `old_jti -> successor_jti` hop with the same prune/cap policy as
/// [`insert_rotation_grace`].
pub(super) fn insert_session_successor(
    old_jti: String,
    successor_jti: String,
    expires_at: Instant,
) {
    if let Ok(mut map) = ROTATED_SESSION_SUCCESSOR.lock() {
        insert_session_successor_into(
            &mut map,
            old_jti,
            successor_jti,
            expires_at,
            Instant::now(),
            ROTATION_STATE_MAX_ENTRIES,
        );
    }
}

/// Removes every expired entry from both in-memory rotation maps. Returns
/// `(grace_removed, successor_removed)`. Dropping a grace entry zeroizes its successor token.
pub fn sweep_expired_rotation_state() -> (usize, usize) {
    let now = Instant::now();
    let grace_removed = ROTATED_TOKEN_GRACE.lock().map_or(0, |mut map| {
        let before = map.len();
        map.retain(|_, e| e.expires_at > now);
        before - map.len()
    });
    let successor_removed = ROTATED_SESSION_SUCCESSOR.lock().map_or(0, |mut map| {
        let before = map.len();
        map.retain(|_, (_, exp)| *exp > now);
        before - map.len()
    });
    (grace_removed, successor_removed)
}

/// Spawns the 60 s idle sweep of expired rotation state. The task exits promptly once `shutdown`
/// observes `true` (or its sender is dropped), so callers can await the handle during graceful
/// shutdown.
pub fn spawn_rotation_state_sweeper(
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ROTATION_STATE_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick; inserts already prune on the hot path.
        interval.tick().await;
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = interval.tick() => {
                    let (grace, successor) = sweep_expired_rotation_state();
                    if grace + successor > 0 {
                        tracing::debug!(grace, successor, "swept expired session rotation state");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

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
    if map.len() > ROTATION_STATE_MAX_ENTRIES {
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
) -> Option<(RotatedTokenGraceEntry, SecretString, i64, String)> {
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
        latest_exp = decode_session_claims(latest_token.expose_secret(), true)
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

#[cfg(test)]
mod rotation_state_tests {
    use super::*;

    fn grace_entry(token: &str, expires_at: Instant) -> RotatedTokenGraceEntry {
        RotatedTokenGraceEntry {
            user_id: 7,
            family_id: "fam".to_string(),
            successor_jti: "succ".to_string(),
            new_token: SecretString::from(token),
            successor_exp: 0,
            strict_fp: String::new(),
            expires_at,
        }
    }

    #[test]
    fn grace_insert_prunes_expired_entries() {
        let now = Instant::now();
        let mut map = HashMap::new();
        map.insert(
            "expired-a".to_string(),
            grace_entry("tok-a", now - Duration::from_secs(1)),
        );
        map.insert("expired-b".to_string(), grace_entry("tok-b", now));
        map.insert(
            "live".to_string(),
            grace_entry("tok-live", now + Duration::from_secs(5)),
        );
        insert_rotation_grace_into(
            &mut map,
            "fresh".to_string(),
            grace_entry("tok-fresh", now + ROTATED_TOKEN_GRACE_WINDOW),
            now,
            ROTATION_STATE_MAX_ENTRIES,
        );
        let mut keys: Vec<_> = map.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["fresh".to_string(), "live".to_string()]);
    }

    #[test]
    fn successor_insert_prunes_expired_entries() {
        let now = Instant::now();
        let mut map = HashMap::new();
        map.insert(
            "old".to_string(),
            ("next".to_string(), now - Duration::from_millis(1)),
        );
        insert_session_successor_into(
            &mut map,
            "a".to_string(),
            "b".to_string(),
            now + ROTATED_SESSION_SUCCESSOR_TTL,
            now,
            ROTATION_STATE_MAX_ENTRIES,
        );
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("a").map(|(n, _)| n.as_str()), Some("b"));
    }

    #[test]
    fn grace_cap_evicts_earliest_expiry_at_4096_entries() {
        assert_eq!(ROTATION_STATE_MAX_ENTRIES, 4096);
        let now = Instant::now();
        let mut map = HashMap::new();
        for i in 0..ROTATION_STATE_MAX_ENTRIES {
            // Entry 17 expires first; every other entry expires later.
            let ttl = if i == 17 { 1 } else { 100 + i as u64 };
            map.insert(
                format!("jti-{i}"),
                grace_entry("t", now + Duration::from_secs(ttl)),
            );
        }
        insert_rotation_grace_into(
            &mut map,
            "jti-new".to_string(),
            grace_entry("t", now + Duration::from_secs(10_000)),
            now,
            ROTATION_STATE_MAX_ENTRIES,
        );
        assert_eq!(map.len(), ROTATION_STATE_MAX_ENTRIES);
        assert!(map.contains_key("jti-new"));
        assert!(
            !map.contains_key("jti-17"),
            "earliest-expiry entry must be evicted"
        );
        assert!(map.contains_key("jti-0") && map.contains_key("jti-4095"));

        // Replacing an existing key at the cap must not evict anything else.
        insert_rotation_grace_into(
            &mut map,
            "jti-0".to_string(),
            grace_entry("t2", now + Duration::from_secs(1)),
            now,
            ROTATION_STATE_MAX_ENTRIES,
        );
        assert_eq!(map.len(), ROTATION_STATE_MAX_ENTRIES);
        assert_eq!(map["jti-0"].new_token.expose_secret(), "t2");
    }

    #[test]
    fn successor_cap_evicts_earliest_expiry_and_never_exceeds_4096() {
        let now = Instant::now();
        let mut map = HashMap::new();
        for i in 0..(ROTATION_STATE_MAX_ENTRIES + 50) {
            insert_session_successor_into(
                &mut map,
                format!("old-{i}"),
                format!("new-{i}"),
                now + Duration::from_secs(1_000 + i as u64),
                now,
                ROTATION_STATE_MAX_ENTRIES,
            );
            assert!(map.len() <= ROTATION_STATE_MAX_ENTRIES);
        }
        assert_eq!(map.len(), ROTATION_STATE_MAX_ENTRIES);
        for i in 0..50 {
            assert!(
                !map.contains_key(&format!("old-{i}")),
                "old-{i} must be evicted"
            );
        }
        assert!(map.contains_key(&format!("old-{}", ROTATION_STATE_MAX_ENTRIES + 49)));
    }

    #[test]
    fn grace_entry_token_is_secret_string_and_redacted_in_debug() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        let entry = grace_entry(token, Instant::now() + ROTATED_TOKEN_GRACE_WINDOW);
        let rendered = format!("{entry:?}");
        assert!(!rendered.contains(token), "{rendered}");
        assert!(!rendered.contains("c2lnbmF0dXJl"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert_eq!(entry.new_token.expose_secret(), token);

        // The successor token buffer is wiped in place on zeroize/drop (full-capacity
        // volatile wipe is unit-tested inside `af_models::secret_zeroize`).
        let mut owned = String::with_capacity(256);
        owned.push_str(token);
        let ptr = owned.as_ptr();
        let mut secret = SecretString::new(owned);
        assert_eq!(
            secret.expose_secret().as_ptr(),
            ptr,
            "wrapping must not copy"
        );
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(secret.expose_secret(), "");
    }

    #[test]
    fn sweep_removes_only_expired_global_state() {
        let now = Instant::now();
        let expired_jti = format!("sweep-expired-{}", uuid::Uuid::new_v4());
        let live_jti = format!("sweep-live-{}", uuid::Uuid::new_v4());
        {
            let mut grace = ROTATED_TOKEN_GRACE.lock().unwrap();
            grace.insert(
                expired_jti.clone(),
                grace_entry("x", now - Duration::from_secs(1)),
            );
            grace.insert(
                live_jti.clone(),
                grace_entry("y", now + Duration::from_secs(30)),
            );
            let mut succ = ROTATED_SESSION_SUCCESSOR.lock().unwrap();
            succ.insert(
                expired_jti.clone(),
                ("n".to_string(), now - Duration::from_secs(1)),
            );
            succ.insert(
                live_jti.clone(),
                ("n".to_string(), now + Duration::from_secs(30)),
            );
        }
        let (grace_removed, successor_removed) = sweep_expired_rotation_state();
        assert!(grace_removed >= 1 && successor_removed >= 1);
        let grace = ROTATED_TOKEN_GRACE.lock().unwrap();
        assert!(!grace.contains_key(&expired_jti) && grace.contains_key(&live_jti));
        drop(grace);
        let succ = ROTATED_SESSION_SUCCESSOR.lock().unwrap();
        assert!(!succ.contains_key(&expired_jti) && succ.contains_key(&live_jti));
        drop(succ);
        ROTATED_TOKEN_GRACE.lock().unwrap().remove(&live_jti);
        ROTATED_SESSION_SUCCESSOR.lock().unwrap().remove(&live_jti);
    }

    #[tokio::test]
    async fn sweeper_task_exits_on_shutdown_signal() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = spawn_rotation_state_sweeper(rx);
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("sweeper must stop promptly on shutdown")
            .unwrap();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = spawn_rotation_state_sweeper(rx);
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("sweeper must stop when the shutdown sender is dropped")
            .unwrap();
    }
}
