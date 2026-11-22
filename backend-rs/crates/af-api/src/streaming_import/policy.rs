use super::types::{
    ensure_admin, DeleteStreamingUserLinkRequest, ImportResult, PolicyScopeSemantics,
    PolicyScopeTarget, StreamingImportError, StreamingUserLinkRecord, StreamingUserLinksResponse,
    TrackingPolicyResponse, UpdateTrackingPolicyRequest, UpsertStreamingUserLinkRequest,
};
use super::validation::{
    current_history_revision, normalize_nonempty_token, normalize_provider, record_admin_audit,
};
use crate::auth::AuthUser;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;

const POLICY_SEMANTICS: PolicyScopeSemantics = PolicyScopeSemantics {
    minimum_watch_secs_effect: "Applies dynamically to analytical inclusion of observed_session and imported_event rows (COALESCE(watched_secs, 0) >= minimum_watch_secs). Item summaries and raw stored rows are never deleted.",
    excluded_users_effect: "Excludes matching (provider, serverId, userId) rows from standard analytics and included cohorts while preserving raw rows for admin includeExcluded inspection.",
    excluded_libraries_effect: "Excludes rows tagged in streaming_history_labels with matching (provider, serverId, libraryId) from standard analytics while preserving raw rows.",
    reconnect_window_secs_effect: "Configures the session-continuity window (0..=300s) used to merge/classify brief collector disconnects and imported event overlap windows.",
    raw_evidence_preserved: true,
};

fn normalize_policy_targets(
    raw: Vec<PolicyScopeTarget>,
    field: &'static str,
) -> ImportResult<Vec<PolicyScopeTarget>> {
    if raw.len() > 500 {
        return Err(StreamingImportError::bad_request(
            "policy_targets_too_large",
            format!("{field} cannot exceed 500 entries"),
        ));
    }
    let mut dedup: BTreeMap<(String, String, String), PolicyScopeTarget> = BTreeMap::new();
    for item in raw {
        let provider = normalize_provider(&item.provider)?;
        let server_id = normalize_nonempty_token(&item.server_id, "serverId", 128)?;
        let id = normalize_nonempty_token(&item.id, "id", 128)?;
        let name = if item.name.trim().is_empty() {
            id.clone()
        } else {
            normalize_nonempty_token(&item.name, "name", 256)?
        };
        dedup.insert(
            (provider.clone(), server_id.clone(), id.clone()),
            PolicyScopeTarget {
                provider,
                server_id,
                id,
                name,
            },
        );
    }
    Ok(dedup.into_values().collect())
}

pub fn get_tracking_policy(
    conn: &Connection,
    user: &AuthUser,
) -> ImportResult<TrackingPolicyResponse> {
    ensure_admin(user)?;
    let (min_watch, excluded_users_json, excluded_libs_json, reconnect_window, policy_rev): (
        i64,
        String,
        String,
        i64,
        i64,
    ) = conn.query_row(
        "SELECT minimum_watch_secs, excluded_users, excluded_libraries, reconnect_window_secs, revision
         FROM streaming_tracking_policies
         WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let excluded_users: Vec<PolicyScopeTarget> =
        serde_json::from_str(&excluded_users_json).unwrap_or_default();
    let excluded_libraries: Vec<PolicyScopeTarget> =
        serde_json::from_str(&excluded_libs_json).unwrap_or_default();
    let history_revision = current_history_revision(conn)?;

    Ok(TrackingPolicyResponse {
        minimum_watch_secs: min_watch,
        reconnect_window_secs: reconnect_window,
        excluded_users,
        excluded_libraries,
        policy_revision: policy_rev,
        history_revision,
        semantics: POLICY_SEMANTICS,
    })
}

pub fn update_tracking_policy(
    conn: &Connection,
    request: UpdateTrackingPolicyRequest,
    user: &AuthUser,
) -> ImportResult<TrackingPolicyResponse> {
    ensure_admin(user)?;
    if !(0..=86_400).contains(&request.minimum_watch_secs) {
        return Err(StreamingImportError::bad_request(
            "invalid_minimum_watch_secs",
            "minimumWatchSecs must be between 0 and 86400",
        ));
    }
    if !(0..=300).contains(&request.reconnect_window_secs) {
        return Err(StreamingImportError::bad_request(
            "invalid_reconnect_window_secs",
            "reconnectWindowSecs must be between 0 and 300",
        ));
    }
    let excluded_users = normalize_policy_targets(request.excluded_users, "excludedUsers")?;
    let excluded_libraries =
        normalize_policy_targets(request.excluded_libraries, "excludedLibraries")?;

    let excluded_users_json = serde_json::to_string(&excluded_users)
        .map_err(|e| StreamingImportError::internal(e.to_string()))?;
    let excluded_libraries_json = serde_json::to_string(&excluded_libraries)
        .map_err(|e| StreamingImportError::internal(e.to_string()))?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        conn.execute(
            "UPDATE streaming_tracking_policies
             SET minimum_watch_secs = ?1,
                 excluded_users = ?2,
                 excluded_libraries = ?3,
                 reconnect_window_secs = ?4,
                 revision = revision + 1
             WHERE id = 1",
            params![
                request.minimum_watch_secs,
                excluded_users_json,
                excluded_libraries_json,
                request.reconnect_window_secs
            ],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.policy.update",
            "streaming_tracking_policies",
            "1",
            &format!(
                "min_watch={} reconnect={} excluded_users={} excluded_libraries={}",
                request.minimum_watch_secs,
                request.reconnect_window_secs,
                excluded_users.len(),
                excluded_libraries.len()
            ),
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    get_tracking_policy(conn, user)
}

pub fn list_user_links(
    conn: &Connection,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    let mut stmt = conn.prepare(
        "SELECT l.af_user_id, u.username, l.provider, l.server_id, l.provider_user_id
         FROM streaming_user_links l
         LEFT JOIN users u ON u.id = l.af_user_id
         ORDER BY l.af_user_id ASC, l.provider ASC, l.server_id ASC, l.provider_user_id ASC",
    )?;
    let links: Vec<StreamingUserLinkRecord> = stmt
        .query_map([], |row| {
            Ok(StreamingUserLinkRecord {
                af_user_id: row.get(0)?,
                af_username: row.get(1)?,
                provider: row.get(2)?,
                server_id: row.get(3)?,
                provider_user_id: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let history_revision = current_history_revision(conn)?;

    Ok(StreamingUserLinksResponse {
        links,
        history_revision,
        identity_semantics: "Non-admin users can view only rows matching an explicit (af_user_id, provider, server_id, provider_user_id) link; display names are never used for implicit matching.",
    })
}

pub fn upsert_user_link(
    conn: &Connection,
    request: UpsertStreamingUserLinkRequest,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    if request.af_user_id <= 0 {
        return Err(StreamingImportError::bad_request(
            "invalid_af_user_id",
            "afUserId must be a positive user ID",
        ));
    }
    let provider = normalize_provider(&request.provider)?;
    let server_id = normalize_nonempty_token(&request.server_id, "serverId", 128)?;
    let provider_user_id =
        normalize_nonempty_token(&request.provider_user_id, "providerUserId", 128)?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        let user_exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM users WHERE id = ?1",
                params![request.af_user_id],
                |row| row.get(0),
            )
            .optional()?;
        if user_exists.is_none() {
            return Err(StreamingImportError::bad_request(
                "unknown_af_user",
                format!("AetherFlow user id={} does not exist", request.af_user_id),
            ));
        }
        conn.execute(
            "INSERT INTO streaming_user_links (af_user_id, provider, server_id, provider_user_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(af_user_id, provider, server_id, provider_user_id) DO NOTHING",
            params![request.af_user_id, provider, server_id, provider_user_id],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.user_link.upsert",
            "streaming_user_links",
            &format!(
                "{}:{}:{}:{}",
                request.af_user_id, provider, server_id, provider_user_id
            ),
            "Explicit streaming provider identity link configured",
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    list_user_links(conn, user)
}

pub fn delete_user_link(
    conn: &Connection,
    request: DeleteStreamingUserLinkRequest,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    let provider = normalize_provider(&request.provider)?;
    let server_id = normalize_nonempty_token(&request.server_id, "serverId", 128)?;
    let provider_user_id =
        normalize_nonempty_token(&request.provider_user_id, "providerUserId", 128)?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        conn.execute(
            "DELETE FROM streaming_user_links
             WHERE af_user_id = ?1 AND provider = ?2 AND server_id = ?3 AND provider_user_id = ?4",
            params![request.af_user_id, provider, server_id, provider_user_id],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.user_link.delete",
            "streaming_user_links",
            &format!(
                "{}:{}:{}:{}",
                request.af_user_id, provider, server_id, provider_user_id
            ),
            "Explicit streaming provider identity link removed",
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    list_user_links(conn, user)
}
