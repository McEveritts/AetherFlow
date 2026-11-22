use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic & Constant-Time Helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn generate_raw_share_token() -> String {
    let mut bytes = [0u8; SHARE_TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_share_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-mcbrowser-share-token-v1:");
    hasher.update(raw_token.as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn prehash_share_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-mcbrowser-share-password-v1:");
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_share_password(password: &str) -> Result<String, McBrowserError> {
    if password.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Share password cannot be empty".to_string(),
        ));
    }
    if password.len() > MAX_SHARE_PASSWORD_BYTES || password.as_bytes().contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Share password exceeds maximum length or contains invalid characters".to_string(),
        ));
    }
    let prehashed = prehash_share_password(password);
    bcrypt::hash(&prehashed, BCRYPT_SHARE_COST)
        .map_err(|_| McBrowserError::Internal("Failed to hash share password".to_string()))
}

pub fn verify_share_password_constant_time(password: &str, stored_hash: &str) -> bool {
    if password.is_empty()
        || password.len() > MAX_SHARE_PASSWORD_BYTES
        || password.as_bytes().contains(&0)
        || stored_hash.is_empty()
    {
        // Perform dummy work to avoid fast-return timing side-channels
        let dummy_pre = prehash_share_password("dummy-invalid-password");
        let _ = std::hint::black_box(af_models::constant_time_eq(
            dummy_pre.as_bytes(),
            stored_hash.as_bytes(),
        ));
        return false;
    }
    let prehashed = prehash_share_password(password);
    bcrypt::verify(&prehashed, stored_hash).unwrap_or(false)
}

pub(super) fn share_cookie_name(token_hash: &str) -> String {
    let prefix = &token_hash[..token_hash.len().min(16)];
    format!("mcbrowser_share_{prefix}")
}

pub(super) fn password_hash_digest(password_hash: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-share-pw-digest-v1:");
    hasher.update(password_hash.unwrap_or("").as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn mint_scoped_unlock_token(share: &StoredShareRow, now_unix: i64) -> (String, i64) {
    let max_exp = now_unix.saturating_add(UNLOCK_TOKEN_TTL_SECS);
    let exp_unix = match share.expires_at_unix {
        Some(share_exp) => max_exp.min(share_exp),
        None => max_exp,
    };
    let ttl_secs = (exp_unix - now_unix).max(1);

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let pw_digest = password_hash_digest(share.password_hash.as_deref());

    let mut mac = HmacSha256::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts keys of any byte length");
    mac.update(b"af-mcbrowser-share-unlock-v1|");
    mac.update(share.id.as_bytes());
    mac.update(b"|");
    mac.update(share.token_hash.as_bytes());
    mac.update(b"|");
    mac.update(pw_digest.as_bytes());
    mac.update(b"|");
    mac.update(exp_unix.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let raw_payload = format!("v1.{}.{exp_unix}.{nonce}.{sig}", share.id);
    let opaque_token = URL_SAFE_NO_PAD.encode(raw_payload.as_bytes());

    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        if map.len() >= MAX_UNLOCK_SESSIONS {
            map.retain(|_, v| v.expires_at_unix > now_unix);
            while map.len() >= MAX_UNLOCK_SESSIONS {
                if let Some(oldest_k) = map
                    .iter()
                    .min_by_key(|(_, v)| v.created_instant)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_k);
                } else {
                    break;
                }
            }
        }
        map.insert(
            opaque_token.clone(),
            UnlockSessionEntry {
                share_id: share.id.clone(),
                token_hash: share.token_hash.clone(),
                pw_digest,
                expires_at_unix: exp_unix,
                created_instant: Instant::now(),
            },
        );
    }

    (opaque_token, ttl_secs)
}

pub(super) fn verify_scoped_unlock_token(
    candidate_token: &str,
    share: &StoredShareRow,
    now_unix: i64,
) -> bool {
    let trimmed = candidate_token.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 {
        return false;
    }

    let Ok(decoded_bytes) = URL_SAFE_NO_PAD.decode(trimmed) else {
        return false;
    };
    let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) else {
        return false;
    };
    let parts: Vec<&str> = decoded_str.split('.').collect();
    if parts.len() != 5 || parts[0] != "v1" {
        return false;
    }
    let token_share_id = parts[1];
    let Ok(exp_unix) = parts[2].parse::<i64>() else {
        return false;
    };
    let nonce = parts[3];
    let provided_sig = parts[4];

    if exp_unix <= now_unix {
        return false;
    }
    if !af_models::constant_time_eq(token_share_id.as_bytes(), share.id.as_bytes()) {
        return false;
    }

    let pw_digest = password_hash_digest(share.password_hash.as_deref());
    let mut mac = HmacSha256::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts keys of any byte length");
    mac.update(b"af-mcbrowser-share-unlock-v1|");
    mac.update(share.id.as_bytes());
    mac.update(b"|");
    mac.update(share.token_hash.as_bytes());
    mac.update(b"|");
    mac.update(pw_digest.as_bytes());
    mac.update(b"|");
    mac.update(exp_unix.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    let expected_sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    if !af_models::constant_time_eq(provided_sig.as_bytes(), expected_sig.as_bytes()) {
        return false;
    }

    // Also verify against the in-memory session store if present
    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        if let Some(entry) = map.get(trimmed) {
            if entry.expires_at_unix <= now_unix
                || !af_models::constant_time_eq(entry.share_id.as_bytes(), share.id.as_bytes())
                || !af_models::constant_time_eq(
                    entry.token_hash.as_bytes(),
                    share.token_hash.as_bytes(),
                )
                || !af_models::constant_time_eq(entry.pw_digest.as_bytes(), pw_digest.as_bytes())
            {
                map.remove(trimmed);
                return false;
            }
        }
    }

    true
}

pub(super) fn revoke_unlock_sessions_for_share(share_id: &str) {
    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        map.retain(|_, v| v.share_id != share_id);
    }
}

pub(super) fn extract_unlock_credential(
    headers: &HeaderMap,
    share: &StoredShareRow,
) -> Option<String> {
    if let Some(hv) = headers.get("X-McBrowser-Share-Token") {
        if let Ok(s) = hv.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    let scoped_cookie = share_cookie_name(&share.token_hash);
    if let Some(val) = extract_cookie(headers, &scoped_cookie) {
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    if let Some(val) = extract_cookie(headers, "mcbrowser_share_token") {
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    None
}

pub(super) fn build_scoped_share_cookie(
    token_hash: &str,
    access_token: &str,
    max_age: i64,
) -> String {
    let name = share_cookie_name(token_hash);
    let mut parts = vec![
        format!("{name}={access_token}"),
        "Path=/".to_string(),
        format!("Max-Age={max_age}"),
        "SameSite=Lax".to_string(),
    ];
    if secure_cookie_enabled() {
        parts.push("Secure".to_string());
    }
    parts.push("HttpOnly".to_string());
    parts.join("; ")
}
