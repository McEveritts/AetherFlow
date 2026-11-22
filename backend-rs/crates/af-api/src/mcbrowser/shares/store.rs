use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Database & Owner Re-Evaluation Helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn row_to_stored_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredShareRow> {
    let scope_dev_i64: i64 = r.get(4)?;
    let scope_ino_i64: i64 = r.get(5)?;
    let dev_i64: i64 = r.get(9)?;
    let ino_i64: i64 = r.get(10)?;
    Ok(StoredShareRow {
        id: r.get(0)?,
        token_hash: r.get(1)?,
        owner_user_id: r.get(2)?,
        owner_scope: r.get(3)?,
        scope_root_dev: scope_dev_i64 as u64,
        scope_root_ino: scope_ino_i64 as u64,
        target_path: r.get(6)?,
        target_name: r.get(7)?,
        is_directory: r.get(8)?,
        target_dev: dev_i64 as u64,
        target_ino: ino_i64 as u64,
        password_hash: r.get(11)?,
        allow_download: r.get(12)?,
        expires_at: r.get(13)?,
        expires_at_unix: r.get(14)?,
        revoked: r.get(15)?,
        created_at: r.get(16)?,
    })
}

pub(super) fn stored_to_share_record(row: &StoredShareRow, raw_token: Option<&str>) -> ShareRecord {
    ShareRecord {
        id: row.id.clone(),
        path: row.target_path.clone(),
        name: row.target_name.clone(),
        is_directory: row.is_directory,
        password_required: row.password_hash.is_some(),
        expires_at: row.expires_at.clone(),
        allow_download: row.allow_download,
        created_at: row.created_at.clone(),
        url: raw_token.map(|t| format!("/share?token={t}")),
    }
}

pub(super) fn is_share_expired(row: &StoredShareRow, now: DateTime<Utc>) -> bool {
    if let Some(exp_unix) = row.expires_at_unix {
        if now.timestamp() >= exp_unix {
            return true;
        }
    }
    if let Some(ref raw_exp) = row.expires_at {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(raw_exp) {
            if now >= parsed.with_timezone(&Utc) {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

pub(super) fn load_active_share_by_token(
    conn: &Connection,
    raw_token: &str,
    now: DateTime<Utc>,
) -> Result<StoredShareRow, McBrowserError> {
    let trimmed = raw_token.trim();
    if trimmed.len() < 16 || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    }
    let token_hash = hash_share_token(trimmed);
    let row: Option<StoredShareRow> = conn
        .query_row(
            "SELECT id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
                    target_path, target_name, is_directory, target_dev, target_ino, \
                    password_hash, allow_download, expires_at, expires_at_unix, revoked, \
                    created_at \
             FROM mcbrowser_shares \
             WHERE token_hash = ?1",
            params![token_hash],
            row_to_stored_share,
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to look up share".to_string()))?;

    let Some(share) = row else {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    };

    if share.revoked || is_share_expired(&share, now) {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    }

    Ok(share)
}

/// Loads the share owner's current `AuthUser` identity and verifies that their account still
/// exists, is not a plugin identity, and has an active storage quota status.
pub(super) fn load_and_verify_active_owner(
    conn: &Connection,
    owner_user_id: i64,
) -> Result<AuthUser, McBrowserError> {
    if owner_user_id <= 0 {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    let user_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![owner_user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify share owner".to_string()))?;

    let Some((username, role)) = user_row else {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    };

    let owner_user = AuthUser {
        user_id: owner_user_id,
        username,
        role,
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    if validate_mcbrowser_user(&owner_user).is_err() {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }

    if load_active_quota_conn(conn, owner_user_id, 0).is_err() {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }

    Ok(owner_user)
}

/// Verifies owner policy (`Permission::Share` and `Permission::Read`, plus `Permission::Download`
/// when `require_download` is true) on the share root and every descendant component down to
/// `rel_sub_path`.
pub(super) fn authorize_owner_share_subpath(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    share_root_path: &str,
    rel_sub_path: &str,
    require_download: bool,
) -> Result<String, McBrowserError> {
    policy(
        conn,
        owner_user,
        crate::mcbrowser::policy::Permission::Share,
        share_root_path,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    policy(
        conn,
        owner_user,
        crate::mcbrowser::policy::Permission::Read,
        share_root_path,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;

    if require_download {
        policy(
            conn,
            owner_user,
            crate::mcbrowser::policy::Permission::Download,
            share_root_path,
        )
        .map_err(|_| {
            McBrowserError::Forbidden("Download of requested path is not permitted".to_string())
        })?;
    }

    if rel_sub_path.is_empty() {
        return Ok(share_root_path.to_string());
    }

    let mut current = share_root_path.to_string();
    for seg in rel_sub_path.split('/').filter(|s| !s.is_empty()) {
        current = if current.is_empty() {
            seg.to_string()
        } else {
            format!("{current}/{seg}")
        };
        policy(
            conn,
            owner_user,
            crate::mcbrowser::policy::Permission::Share,
            &current,
        )
        .map_err(|_| {
            McBrowserError::Forbidden("Access to requested path is not permitted".to_string())
        })?;
        policy(
            conn,
            owner_user,
            crate::mcbrowser::policy::Permission::Read,
            &current,
        )
        .map_err(|_| {
            McBrowserError::Forbidden("Access to requested path is not permitted".to_string())
        })?;
        if require_download {
            policy(
                conn,
                owner_user,
                crate::mcbrowser::policy::Permission::Download,
                &current,
            )
            .map_err(|_| {
                McBrowserError::Forbidden("Download of requested path is not permitted".to_string())
            })?;
        }
    }

    Ok(current)
}

/// Rejects any query string that includes `password`, `access_token`, or `share_token` so
/// secret credentials are never transmitted in URLs.
pub fn reject_secret_query_params(raw_query: Option<&str>) -> Result<(), McBrowserError> {
    let Some(q) = raw_query else {
        return Ok(());
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case("password")
            || key.eq_ignore_ascii_case("access_token")
            || key.eq_ignore_ascii_case("share_token")
        {
            return Err(McBrowserError::BadRequest(
                "Passing share passwords or unlock tokens in URL query parameters is not permitted"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Maps internal `McBrowserError` into a sanitized public HTTP response that never leaks
/// owner account states, usernames, or private paths.
pub(super) fn public_share_error_response(err: McBrowserError) -> Response {
    match err {
        McBrowserError::BadRequest(msg) => api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
        McBrowserError::Unauthorized(msg) => {
            api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg)
        }
        McBrowserError::Forbidden(msg) => api_error(StatusCode::FORBIDDEN, "FORBIDDEN", msg),
        McBrowserError::NotFound(msg) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", msg),
        McBrowserError::RangeNotSatisfiable(total) => {
            McBrowserError::RangeNotSatisfiable(total).into_response()
        }
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to process public share request",
        ),
    }
}
