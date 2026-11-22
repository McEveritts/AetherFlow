use super::types::{PortabilityError, PortabilityResult, RestoreMode};
use super::{APPROVAL_TTL_SECS, MAX_APPROVALS};
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub(super) struct Approval {
    pub(super) actor_id: i64,
    pub(super) mode: RestoreMode,
    pub(super) archive_sha256: String,
    pub(super) preview_sha256: String,
    pub(super) expires_at: i64,
}

pub(super) static APPROVALS: Lazy<Mutex<HashMap<String, Approval>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) fn issue_approval(
    actor_id: i64,
    mode: RestoreMode,
    archive_sha256: &str,
    preview_sha256: &str,
    now: i64,
) -> PortabilityResult<(String, i64)> {
    let expires_at = now
        .checked_add(APPROVAL_TTL_SECS)
        .ok_or_else(PortabilityError::invalid)?;
    let mut approvals = APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    approvals.retain(|_, approval| approval.expires_at > now);
    if approvals.len() >= MAX_APPROVALS {
        return Err(PortabilityError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_streaming_previews",
            "Too many pending streaming restore previews; retry after they expire",
        ));
    }
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    approvals.insert(
        token.clone(),
        Approval {
            actor_id,
            mode,
            archive_sha256: archive_sha256.to_owned(),
            preview_sha256: preview_sha256.to_owned(),
            expires_at,
        },
    );
    Ok((token, expires_at))
}

pub(super) fn revoke_approval(token: &str) {
    APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(token);
}

pub(super) fn consume_approval(
    token: &str,
    actor_id: i64,
    mode: RestoreMode,
    archive_sha256: &str,
    now: i64,
) -> PortabilityResult<Approval> {
    if token.len() > 128 {
        return Err(PortabilityError::invalid_approval());
    }
    let mut approvals = APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let approval = approvals
        .get(token)
        .cloned()
        .ok_or_else(PortabilityError::invalid_approval)?;
    if approval.expires_at <= now {
        approvals.remove(token);
        return Err(PortabilityError::invalid_approval());
    }
    if approval.actor_id != actor_id
        || approval.mode != mode
        || approval.archive_sha256 != archive_sha256
    {
        return Err(PortabilityError::invalid_approval());
    }
    approvals.remove(token);
    Ok(approval)
}
