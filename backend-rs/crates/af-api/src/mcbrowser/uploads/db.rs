use super::protocol::{now_unix_secs, ConflictPolicy, PublishingResolution, UploadSessionRecord};
use super::staging::{
    commit_proven_upload_at, inspect_existing_target_in_bfs, open_bound_scope_browser_fs_at,
    open_existing_staging_file_at, open_verified_user_root_fd, prepared_publication_matches,
    publish_staging_file_to_browser_fs, read_publication_proof_at, remove_publication_proof_at,
    remove_staging_file_at, verify_bound_target_unchanged, verify_session_scope_matches,
    write_publication_proof_at, UploadPublicationProof,
};
use super::UPLOAD_SESSION_EXPIRY_SECS;
use crate::auth::AuthUser;
use crate::mcbrowser::{map_fs_io_error, release_user_quota_conn, McBrowserError};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Schema & Durable State Management
// ─────────────────────────────────────────────────────────────────────────────

pub(super) const SESSION_SELECT_COLUMNS: &str = "\
    id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, \
    staging_rel_path, quota_reserved, created_at, updated_at, expires_at, \
    owner_scope, scope_root_dev, scope_root_ino, conflict_policy, reserved_bytes, \
    base_target_exists, base_target_dev, base_target_ino, base_target_size, audit_event_id";

pub fn ensure_uploads_schema(conn: &Connection) -> Result<(), McBrowserError> {
    crate::mcbrowser::events::ensure_events_tables(conn)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mcbrowser_uploads (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            owner_scope TEXT NOT NULL DEFAULT '',
            scope_root_dev INTEGER NOT NULL DEFAULT 0,
            scope_root_ino INTEGER NOT NULL DEFAULT 0,
            target_path TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
            offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0 AND offset_bytes <= upload_length),
            status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'publishing', 'completed')),
            staging_rel_path TEXT NOT NULL DEFAULT '',
            quota_reserved INTEGER NOT NULL DEFAULT 1,
            conflict_policy TEXT NOT NULL DEFAULT 'error',
            reserved_bytes INTEGER NOT NULL DEFAULT 0,
            base_target_exists INTEGER NOT NULL DEFAULT 0,
            base_target_dev INTEGER NOT NULL DEFAULT 0,
            base_target_ino INTEGER NOT NULL DEFAULT 0,
            base_target_size INTEGER NOT NULL DEFAULT 0,
            audit_event_id TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_user_status
            ON mcbrowser_uploads(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expires
            ON mcbrowser_uploads(expires_at);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_lookup
            ON mcbrowser_uploads(user_id, status, target_path, upload_length, fingerprint);
        CREATE TABLE IF NOT EXISTS mcbrowser_upload_cleanup_cursor (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            expires_at INTEGER NOT NULL,
            upload_id TEXT NOT NULL
        );
        INSERT OR IGNORE INTO mcbrowser_upload_cleanup_cursor
            (singleton, expires_at, upload_id) VALUES (1, -9223372036854775808, '');
        "#,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize mcbrowser_uploads schema");
        McBrowserError::Internal("Failed to initialize upload session storage".to_string())
    })?;

    // Ensure scope-binding and conflict-parity columns exist on any pre-existing table.
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN owner_scope TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN scope_root_dev INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN scope_root_ino INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN conflict_policy TEXT NOT NULL DEFAULT 'error'",
        [],
    );
    if conn
        .execute(
            "ALTER TABLE mcbrowser_uploads ADD COLUMN reserved_bytes INTEGER NOT NULL DEFAULT -1",
            [],
        )
        .is_ok()
    {
        let _ = conn.execute(
            "UPDATE mcbrowser_uploads \
             SET reserved_bytes = CASE WHEN quota_reserved != 0 THEN upload_length ELSE 0 END \
             WHERE reserved_bytes < 0",
            [],
        );
    }
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_exists INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_dev INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_ino INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_size INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN audit_event_id TEXT NOT NULL DEFAULT ''",
        [],
    );

    // Transparently upgrade any pre-existing table created before `'publishing'` was added to the
    // `status` CHECK constraint.
    let schema_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'mcbrowser_uploads'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| {
            McBrowserError::Internal("Failed to inspect upload session schema".to_string())
        })?;

    if let Some(sql) = schema_sql {
        if !sql.contains("'publishing'") {
            conn.execute_batch(
                r#"
                BEGIN IMMEDIATE TRANSACTION;
                CREATE TABLE mcbrowser_uploads_v2 (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    owner_scope TEXT NOT NULL DEFAULT '',
                    scope_root_dev INTEGER NOT NULL DEFAULT 0,
                    scope_root_ino INTEGER NOT NULL DEFAULT 0,
                    target_path TEXT NOT NULL,
                    fingerprint TEXT NOT NULL DEFAULT '',
                    upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
                    offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0 AND offset_bytes <= upload_length),
                    status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'publishing', 'completed')),
                    staging_rel_path TEXT NOT NULL DEFAULT '',
                    quota_reserved INTEGER NOT NULL DEFAULT 1,
                    conflict_policy TEXT NOT NULL DEFAULT 'error',
                    reserved_bytes INTEGER NOT NULL DEFAULT 0,
                    base_target_exists INTEGER NOT NULL DEFAULT 0,
                    base_target_dev INTEGER NOT NULL DEFAULT 0,
                    base_target_ino INTEGER NOT NULL DEFAULT 0,
                    base_target_size INTEGER NOT NULL DEFAULT 0,
                    audit_event_id TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                INSERT INTO mcbrowser_uploads_v2
                    (id, user_id, owner_scope, scope_root_dev, scope_root_ino, target_path, fingerprint,
                     upload_length, offset_bytes, status, staging_rel_path, quota_reserved,
                     conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size,
                     audit_event_id, created_at, updated_at, expires_at)
                    SELECT id, user_id, CASE WHEN owner_scope = '/' THEN '' ELSE COALESCE(owner_scope, '') END,
                           scope_root_dev, scope_root_ino,
                           target_path, fingerprint, upload_length, offset_bytes, status,
                           staging_rel_path, quota_reserved,
                           COALESCE(conflict_policy, 'error'),
                           CASE WHEN reserved_bytes >= 0 THEN reserved_bytes WHEN quota_reserved != 0 THEN upload_length ELSE 0 END,
                           COALESCE(base_target_exists, 0),
                           COALESCE(base_target_dev, 0),
                           COALESCE(base_target_ino, 0),
                           COALESCE(base_target_size, 0),
                           COALESCE(audit_event_id, ''),
                           created_at, updated_at, expires_at
                    FROM mcbrowser_uploads;
                DROP TABLE mcbrowser_uploads;
                ALTER TABLE mcbrowser_uploads_v2 RENAME TO mcbrowser_uploads;
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_user_status
                    ON mcbrowser_uploads(user_id, status);
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expires
                    ON mcbrowser_uploads(expires_at);
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_lookup
                    ON mcbrowser_uploads(user_id, status, target_path, upload_length, fingerprint);
                COMMIT;
                "#,
            )
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK");
                tracing::error!(error = %e, "Failed to migrate mcbrowser_uploads schema to support 'publishing' status");
                McBrowserError::Internal("Failed to migrate upload session storage".to_string())
            })?;
        }
    }

    Ok(())
}

pub(super) fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<UploadSessionRecord> {
    let len_i64: i64 = row.get(4)?;
    let _: i64 = row.get(9)?;
    let off_i64: i64 = row.get(5)?;
    let reserved_flag_i64: i64 = row.get(8)?;
    let raw_scope: String = row.get(12).unwrap_or_default();
    let dev_i64: i64 = row.get(13).unwrap_or(0);
    let ino_i64: i64 = row.get(14).unwrap_or(0);
    let raw_policy: String = row.get(15).unwrap_or_else(|_| "error".to_string());
    let reserved_bytes_i64: i64 = row.get(16).unwrap_or(-1);
    let base_exists_i64: i64 = row.get(17).unwrap_or(0);
    let base_dev_i64: i64 = row.get(18).unwrap_or(0);
    let base_ino_i64: i64 = row.get(19).unwrap_or(0);
    let base_size_i64: i64 = row.get(20).unwrap_or(0);
    let audit_event_id: String = row.get(21).unwrap_or_default();

    let upload_length = u64::try_from(len_i64.max(0)).unwrap_or(0);
    let quota_reserved = reserved_flag_i64 != 0;
    let reserved_bytes = if reserved_bytes_i64 >= 0 {
        u64::try_from(reserved_bytes_i64).unwrap_or(0)
    } else if quota_reserved {
        upload_length
    } else {
        0
    };

    Ok(UploadSessionRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        owner_scope: if raw_scope == "/" {
            String::new()
        } else {
            raw_scope
        },
        scope_root_dev: dev_i64 as u64,
        scope_root_ino: ino_i64 as u64,
        target_path: row.get(2)?,
        fingerprint: row.get(3)?,
        upload_length,
        offset_bytes: u64::try_from(off_i64.max(0)).unwrap_or(0),
        status: row.get(6)?,
        staging_rel_path: row.get(7)?,
        quota_reserved,
        reserved_bytes,
        conflict_policy: ConflictPolicy::from_db_str(&raw_policy),
        base_target_exists: base_exists_i64 != 0,
        base_target_dev: base_dev_i64 as u64,
        base_target_ino: base_ino_i64 as u64,
        base_target_size: u64::try_from(base_size_i64.max(0)).unwrap_or(0),
        audit_event_id,
        updated_at: row.get(10)?,
        expires_at: row.get(11)?,
    })
}

pub(super) fn load_session_conn(
    conn: &Connection,
    upload_id: &str,
) -> Result<Option<UploadSessionRecord>, McBrowserError> {
    let sql = format!("SELECT {SESSION_SELECT_COLUMNS} FROM mcbrowser_uploads WHERE id = ?1");
    conn.query_row(&sql, params![upload_id], row_to_session)
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to query upload session".to_string()))
}

pub(super) fn upload_audit_error_code(err: &McBrowserError) -> &'static str {
    match err {
        McBrowserError::BadRequest(_) => "BAD_REQUEST",
        McBrowserError::Unauthorized(_) => "UNAUTHORIZED",
        McBrowserError::Forbidden(_) => "FORBIDDEN",
        McBrowserError::NotFound(_) => "NOT_FOUND",
        McBrowserError::Conflict(_) => "CONFLICT",
        McBrowserError::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
        McBrowserError::QuotaExceeded(_) => "QUOTA_EXCEEDED",
        McBrowserError::InsufficientStorage(_) => "INSUFFICIENT_STORAGE",
        McBrowserError::RangeNotSatisfiable(_) => "RANGE_NOT_SATISFIABLE",
        McBrowserError::RequestTimeout(_) => "REQUEST_TIMEOUT",
        McBrowserError::Internal(_) => "INTERNAL_ERROR",
        McBrowserError::AccountingPending(_) => "ACCOUNTING_PENDING",
    }
}

pub(super) fn session_published_byte_delta(session: &UploadSessionRecord) -> i64 {
    if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
        return 0;
    }
    if session.base_target_exists {
        let new_len = i128::from(session.upload_length);
        let old_len = i128::from(session.base_target_size);
        let diff = new_len - old_len;
        diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    } else {
        i64::try_from(session.upload_length).unwrap_or(i64::MAX)
    }
}

pub(super) fn load_session_actor_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<AuthUser, McBrowserError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![user_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            },
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to load upload session actor".to_string()))?;
    let (username, role) = row.unwrap_or_else(|| (format!("user-{user_id}"), "user".to_string()));
    Ok(AuthUser {
        user_id,
        username,
        role: if role.trim().is_empty() {
            "user".to_string()
        } else {
            role
        },
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    })
}

pub(super) fn ensure_session_pending_audit_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
) -> Result<String, McBrowserError> {
    crate::mcbrowser::events::ensure_events_tables(conn)?;
    let existing_id = session.audit_event_id.trim();
    if !existing_id.is_empty() {
        if let Some(rec) =
            crate::mcbrowser::events::load_audit_record_by_id_with_conn(conn, existing_id)?
        {
            if matches!(
                rec.status,
                crate::mcbrowser::events::AuditEventStatus::Pending
                    | crate::mcbrowser::events::AuditEventStatus::Completed
            ) {
                return Ok(rec.event.event_id);
            }
        }
    }
    conn.execute_batch("SAVEPOINT mcbrowser_upload_audit_binding")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin upload audit binding".to_string())
        })?;
    let binding =
        (|| -> Result<String, McBrowserError> {
            let actor = load_session_actor_conn(conn, session.user_id)?;
            let pending = crate::mcbrowser::events::record_pending_intent_with_conn(
                conn,
                &actor,
                crate::mcbrowser::events::McBrowserEventTrigger::UploadCompleted,
                &session.target_path,
                None,
                session_published_byte_delta(session),
            )?;
            let event_id = pending.event.event_id;
            let changed = conn.execute(
            "UPDATE mcbrowser_uploads SET audit_event_id = ?1 WHERE id = ?2 AND user_id = ?3",
            params![event_id, session.id, session.user_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to bind upload audit event ID".to_string()))?;
            if changed != 1 {
                return Err(McBrowserError::NotFound(
                    "Upload session not found".to_string(),
                ));
            }
            conn.execute_batch("RELEASE mcbrowser_upload_audit_binding")
                .map_err(|_| {
                    McBrowserError::Internal("Failed to commit upload audit binding".to_string())
                })?;
            Ok(event_id)
        })();
    let event_id = match binding {
        Ok(event_id) => event_id,
        Err(error) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_upload_audit_binding; RELEASE mcbrowser_upload_audit_binding",
            );
            return Err(error);
        }
    };
    session.audit_event_id = event_id.clone();
    Ok(event_id)
}

pub(super) fn discard_unpublished_session_conn(
    conn: &Connection,
    session: &UploadSessionRecord,
    error: &McBrowserError,
) -> Result<(), McBrowserError> {
    conn.execute_batch("SAVEPOINT mcbrowser_upload_discard")
        .map_err(|_| McBrowserError::Internal("Failed to begin upload cleanup".to_string()))?;
    let cleanup = (|| {
        let Some(current) = load_session_conn(conn, &session.id)? else {
            conn.execute_batch("RELEASE mcbrowser_upload_discard")
                .map_err(|_| {
                    McBrowserError::Internal("Failed to commit upload cleanup".to_string())
                })?;
            return Ok(());
        };
        if current.user_id != session.user_id || current.status == "completed" {
            return Err(McBrowserError::Conflict(
                "Upload is no longer unpublished".to_string(),
            ));
        }
        if !current.audit_event_id.is_empty() {
            crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &current.audit_event_id,
                Some(upload_audit_error_code(error)),
            )?;
        }
        if current.quota_reserved && current.reserved_bytes > 0 {
            release_user_quota_conn(conn, current.user_id, current.reserved_bytes)?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1 AND user_id = ?2",
            params![current.id, current.user_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to delete unpublished upload".to_string()))?;
        conn.execute_batch("RELEASE mcbrowser_upload_discard")
            .map_err(|_| McBrowserError::Internal("Failed to commit upload cleanup".to_string()))?;
        Ok(())
    })();
    match cleanup {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_upload_discard; RELEASE mcbrowser_upload_discard",
            );
            Err(error)
        }
    }
}

pub(super) fn mark_session_skipped_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> Result<(), McBrowserError> {
    if session.conflict_policy != ConflictPolicy::Skip {
        return Err(McBrowserError::Internal(
            "Cannot skip a non-skip upload".to_string(),
        ));
    }
    let expires_at = now_secs + UPLOAD_SESSION_EXPIRY_SECS;
    conn.execute_batch("SAVEPOINT mcbrowser_upload_skip")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin skipped upload completion".to_string())
        })?;
    let completion = (|| -> Result<(), McBrowserError> {
        let changed = conn
            .execute(
                "UPDATE mcbrowser_uploads SET offset_bytes = upload_length, status = 'completed',
             staging_rel_path = '', quota_reserved = 0, reserved_bytes = 0, audit_event_id = '',
             base_target_exists = 1, updated_at = ?1, expires_at = ?2
             WHERE id = ?3 AND user_id = ?4 AND status != 'completed'",
                params![now_secs, expires_at, session.id, session.user_id],
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to persist skipped upload completion".to_string())
            })?;
        if changed > 0 {
            if session.quota_reserved && session.reserved_bytes > 0 {
                release_user_quota_conn(conn, session.user_id, session.reserved_bytes)?;
            }
            if !session.audit_event_id.is_empty() {
                crate::mcbrowser::events::finalize_event_failed_with_conn(
                    conn,
                    &session.audit_event_id,
                    Some("SKIPPED_CONFLICT"),
                )?;
            }
        }
        conn.execute_batch("RELEASE mcbrowser_upload_skip")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit skipped upload completion".to_string())
            })?;
        Ok(())
    })();
    if let Err(error) = completion {
        let _ =
            conn.execute_batch("ROLLBACK TO mcbrowser_upload_skip; RELEASE mcbrowser_upload_skip");
        return Err(error);
    }
    session.offset_bytes = session.upload_length;
    session.status = "completed".to_string();
    session.staging_rel_path.clear();
    session.quota_reserved = false;
    session.reserved_bytes = 0;
    session.audit_event_id.clear();
    session.base_target_exists = true;
    session.updated_at = now_secs;
    session.expires_at = expires_at;
    Ok(())
}

pub(super) fn mark_session_completed_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> Result<(), McBrowserError> {
    let len_i64 = i64::try_from(session.upload_length).unwrap_or(i64::MAX);
    let new_expires = if session.expires_at > now_secs {
        session
            .expires_at
            .max(now_secs + UPLOAD_SESSION_EXPIRY_SECS)
    } else {
        session.expires_at
    };
    let no_publication = (session.conflict_policy == ConflictPolicy::Skip
        && session.base_target_exists)
        || (session.conflict_policy == ConflictPolicy::Resume
            && session.base_target_exists
            && session.base_target_size == session.upload_length);
    crate::mcbrowser::events::ensure_events_tables(conn)?;
    conn.execute_batch("SAVEPOINT mcbrowser_upload_completion")
        .map_err(|_| McBrowserError::Internal("Failed to begin upload completion".to_string()))?;
    let mut final_audit_id = session.audit_event_id.clone();
    let completion = (|| -> Result<(), McBrowserError> {
        if !no_publication && final_audit_id.trim().is_empty() {
            final_audit_id = ensure_session_pending_audit_conn(conn, session)?;
        }
        let changed = conn.execute(
            "UPDATE mcbrowser_uploads \
             SET offset_bytes = ?1, status = 'completed', staging_rel_path = '', audit_event_id = ?2, updated_at = ?3, expires_at = ?4 \
             WHERE id = ?5 AND user_id = ?6 AND status != 'completed'",
            params![
                len_i64,
                final_audit_id,
                now_secs,
                new_expires,
                session.id,
                session.user_id
            ],
        ).map_err(|_| McBrowserError::Internal("Failed to transition upload session to completed".to_string()))?;
        if changed > 0
            && session.base_target_exists
            && session.conflict_policy != ConflictPolicy::Skip
        {
            let shrink_bytes = session
                .base_target_size
                .saturating_sub(session.upload_length);
            if shrink_bytes > 0 {
                release_user_quota_conn(conn, session.user_id, shrink_bytes)?;
            }
        }
        if !no_publication {
            let delta = session_published_byte_delta(session);
            crate::mcbrowser::events::finalize_event_completed_with_conn(
                conn,
                &final_audit_id,
                None,
                None,
                delta,
            )?;
        }
        conn.execute_batch("RELEASE mcbrowser_upload_completion")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit upload completion".to_string())
            })?;
        Ok(())
    })();
    if let Err(error) = completion {
        let _ = conn.execute_batch(
            "ROLLBACK TO mcbrowser_upload_completion; RELEASE mcbrowser_upload_completion",
        );
        return Err(error);
    }
    session.audit_event_id = final_audit_id;
    session.offset_bytes = session.upload_length;
    session.status = "completed".to_string();
    session.staging_rel_path.clear();
    session.updated_at = now_secs;
    session.expires_at = new_expires;
    Ok(())
}

pub(crate) fn reconcile_publishing_session_at(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
    attempt_finish_publish: bool,
    now_secs: i64,
) -> Result<PublishingResolution, McBrowserError> {
    let proof = match read_publication_proof_at(base_root, session) {
        Ok(Some(proof)) => proof,
        _ => return Ok(PublishingResolution::AmbiguousRetainQuota),
    };
    let bfs = match open_bound_scope_browser_fs_at(
        base_root,
        session.user_id,
        &session.owner_scope,
        session.scope_root_dev,
        session.scope_root_ino,
    ) {
        Ok(bfs) => bfs,
        Err(_) => return Ok(PublishingResolution::AmbiguousRetainQuota),
    };
    match proof {
        UploadPublicationProof::Published {} => {
            mark_session_completed_conn(conn, session, now_secs)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            return Ok(PublishingResolution::Completed);
        }
        UploadPublicationProof::Prepared {
            device,
            inode,
            nonce,
        } => {
            let proven = bfs
                .open_file(&session.target_path)
                .ok()
                .is_some_and(|file| {
                    prepared_publication_matches(&file, device, inode, nonce.as_deref())
                });
            if !proven {
                return Ok(PublishingResolution::AmbiguousRetainQuota);
            }
            write_publication_proof_at(base_root, session, &UploadPublicationProof::Published {})?;
            mark_session_completed_conn(conn, session, now_secs)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            return Ok(PublishingResolution::Completed);
        }
        UploadPublicationProof::Unpublished {} => {}
    }
    if session.conflict_policy == ConflictPolicy::Skip && !session.base_target_exists {
        match inspect_existing_target_in_bfs(&bfs, &session.target_path) {
            Ok(Some(_)) => {
                mark_session_skipped_conn(conn, session, now_secs)?;
                let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
                return Ok(PublishingResolution::Completed);
            }
            Ok(None) => {}
            Err(error) => {
                discard_unpublished_session_conn(conn, session, &error)?;
                let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
                let _ = remove_publication_proof_at(base_root, session.user_id, &session.id);
                return Err(error);
            }
        }
    }
    if session.status == "publishing" {
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'uploading', updated_at = ?1 WHERE id = ?2 AND user_id = ?3 AND status = 'publishing'",
            params![now_secs, session.id, session.user_id],
        ).map_err(|_| McBrowserError::Internal("Failed to restore unpublished upload status".to_string()))?;
        session.status = "uploading".to_string();
    }
    if !attempt_finish_publish {
        return Ok(PublishingResolution::UnpublishedStagingIntact);
    }
    let current_root = open_verified_user_root_fd(conn, base_root, session.user_id)?;
    verify_session_scope_matches(session, &current_root)?;
    let expected = verify_bound_target_unchanged(&bfs, session)?;
    ensure_session_pending_audit_conn(conn, session)?;
    if session.upload_length == 0 {
        let pending = if session.base_target_exists {
            bfs.begin_replace(&session.target_path)
        } else {
            bfs.begin_upload(&session.target_path)
        }
        .map_err(|error| map_fs_io_error(error, "Failed to prepare recovered upload"))?;
        commit_proven_upload_at(base_root, session, pending, expected.as_ref())?;
    } else {
        let staging = match open_existing_staging_file_at(base_root, session.user_id, &session.id) {
            Ok(staging) => staging,
            Err(McBrowserError::NotFound(_)) => {
                return Ok(PublishingResolution::UnpublishedStagingIntact)
            }
            Err(error) => return Err(error),
        };
        if staging
            .metadata()
            .map_err(|error| map_fs_io_error(error, "Failed to inspect recovered staging"))?
            .len()
            != session.upload_length
        {
            return Ok(PublishingResolution::UnpublishedStagingIntact);
        }
        publish_staging_file_to_browser_fs(
            staging,
            &bfs,
            &session.target_path,
            session.upload_length,
            expected.as_ref(),
            base_root,
            session,
        )?;
    }
    mark_session_completed_conn(conn, session, now_secs)?;
    let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
    Ok(PublishingResolution::Completed)
}

fn cleanup_single_expired_upload_locked(
    conn: &Connection,
    base_root: &Path,
    rec: UploadSessionRecord,
    now_secs: i64,
) -> Result<bool, McBrowserError> {
    let Some(mut rec) = load_session_conn(conn, &rec.id)? else {
        return Ok(false);
    };
    if rec.expires_at > now_secs {
        return Ok(false);
    }

    let may_have_published = rec.status == "publishing"
        || (rec.status == "uploading" && rec.offset_bytes == rec.upload_length);

    let resolution = if may_have_published {
        reconcile_publishing_session_at(conn, base_root, &mut rec, false, now_secs)
            .unwrap_or(PublishingResolution::AmbiguousRetainQuota)
    } else {
        PublishingResolution::UnpublishedStagingIntact
    };

    if matches!(resolution, PublishingResolution::AmbiguousRetainQuota) {
        return Ok(false);
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            McBrowserError::Internal("Failed to start expiry cleanup transaction".to_string())
        })?;

    let step = (|| -> Result<bool, McBrowserError> {
        let Some(current) = load_session_conn(conn, &rec.id)? else {
            return Ok(false);
        };
        if current.expires_at > now_secs {
            return Ok(false);
        }

        let safe_to_release_quota = match current.status.as_str() {
            "completed" => false,
            "publishing" => {
                // `reconcile_publishing_session_at` transitions proven-unpublished `'publishing'`
                // sessions back to `'uploading'`. Seeing `'publishing'` here means a publish is
                // active or ambiguous; retain row and quota.
                return Ok(false);
            }
            "uploading" => {
                // Fresh publication-proof re-check inside BEGIN IMMEDIATE BEFORE releasing quota
                // or deleting the row so an in-flight or crashed publication is never undercounted.
                let proof_confirms_unpublished =
                    match read_publication_proof_at(base_root, &current) {
                        Ok(Some(UploadPublicationProof::Unpublished {})) => true,
                        Ok(None) if current.offset_bytes < current.upload_length => true,
                        _ => false,
                    };
                if !proof_confirms_unpublished {
                    return Ok(false);
                }
                if current.offset_bytes == current.upload_length
                    && !matches!(resolution, PublishingResolution::UnpublishedStagingIntact)
                {
                    return Ok(false);
                }
                true
            }
            _ => return Ok(false),
        };

        if safe_to_release_quota && current.quota_reserved && current.reserved_bytes > 0 {
            release_user_quota_conn(conn, current.user_id, current.reserved_bytes)?;
        }

        if safe_to_release_quota && !current.audit_event_id.trim().is_empty() {
            crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &current.audit_event_id,
                Some("UPLOAD_EXPIRED"),
            )?;
        }

        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1",
            params![current.id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to delete expired upload row".to_string()))?;
        Ok(true)
    })();

    match step {
        Ok(removed) => {
            conn.execute_batch("COMMIT").map_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
                McBrowserError::Internal("Failed to commit expiry cleanup".to_string())
            })?;
            if removed {
                let _ = remove_staging_file_at(base_root, rec.user_id, &rec.id);
                let _ = remove_publication_proof_at(base_root, rec.user_id, &rec.id);
            }
            Ok(removed)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Opportunistically cleans up expired upload sessions for a single user without reading or
/// advancing the global `mcbrowser_upload_cleanup_cursor`.
///
/// Callers must already hold `user_mutation_stripe(user_id)`. Each candidate session acquires
/// `session_lock(&rec.id).try_lock()` so it never blocks or creates an ABBA deadlock with handlers
/// locking `session_lock -> user_mutation_stripe`.
pub(crate) fn cleanup_expired_uploads_for_user_at(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
    now_secs: i64,
) -> Result<usize, McBrowserError> {
    ensure_uploads_schema(conn)?;
    let sql = format!(
        "SELECT {SESSION_SELECT_COLUMNS} FROM mcbrowser_uploads \
         WHERE user_id = ?1 AND expires_at <= ?2 ORDER BY expires_at, id LIMIT 128"
    );
    let mut statement = conn
        .prepare(&sql)
        .map_err(|_| McBrowserError::Internal("Failed to prepare user expiry query".to_string()))?;
    let rows = statement
        .query_map(params![user_id, now_secs], row_to_session)
        .map_err(|_| McBrowserError::Internal("Failed to scan user expired uploads".to_string()))?;
    let expired = rows.collect::<Result<Vec<_>, _>>().map_err(|_| {
        McBrowserError::Internal("Failed to read user expired upload row".to_string())
    })?;
    drop(statement);

    let mut cleaned = 0usize;
    for rec in expired {
        let sess_mutex = super::session_lock(&rec.id);
        let Ok(_sess_guard) = sess_mutex.try_lock() else {
            continue;
        };
        if cleanup_single_expired_upload_locked(conn, base_root, rec, now_secs)? {
            cleaned += 1;
        }
    }

    Ok(cleaned)
}

#[allow(dead_code)]
pub(super) fn cleanup_expired_uploads_with_user_stripe_at<F>(
    conn: &Connection,
    base_root: &Path,
    now_secs: i64,
    mut user_stripe_for: F,
) -> Result<usize, McBrowserError>
where
    F: FnMut(i64) -> Arc<AsyncMutex<()>>,
{
    ensure_uploads_schema(conn)?;

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expiry_cursor ON mcbrowser_uploads(expires_at, id)",
    ).map_err(|_| McBrowserError::Internal("Failed to index upload cleanup cursor".to_string()))?;
    let (cursor_expiry, cursor_id): (i64, String) = conn
        .query_row(
            "SELECT expires_at, upload_id FROM mcbrowser_upload_cleanup_cursor WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to load upload cleanup cursor".to_string())
        })?;
    let sql = format!(
        "SELECT {SESSION_SELECT_COLUMNS} FROM mcbrowser_uploads WHERE expires_at <= ?1 \
         AND (expires_at, id) > (?2, ?3) ORDER BY expires_at, id LIMIT 128"
    );
    let scan = |expiry: i64, upload_id: &str| -> Result<Vec<UploadSessionRecord>, McBrowserError> {
        let mut statement = conn
            .prepare(&sql)
            .map_err(|_| McBrowserError::Internal("Failed to prepare expiry query".to_string()))?;
        let rows = statement
            .query_map(params![now_secs, expiry, upload_id], row_to_session)
            .map_err(|_| McBrowserError::Internal("Failed to scan expired uploads".to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| McBrowserError::Internal("Failed to read expired upload row".to_string()))
    };
    let mut expired = scan(cursor_expiry, &cursor_id)?;
    if expired.is_empty() && (cursor_expiry != i64::MIN || !cursor_id.is_empty()) {
        expired = scan(i64::MIN, "")?;
    }

    if expired.is_empty() {
        return Ok(0);
    }
    let last = expired.last().expect("nonempty expiry page");
    conn.execute(
        "UPDATE mcbrowser_upload_cleanup_cursor SET expires_at = ?1, upload_id = ?2 WHERE singleton = 1",
        params![last.expires_at, last.id],
    ).map_err(|_| McBrowserError::Internal("Failed to advance upload cleanup cursor".to_string()))?;

    let mut cleaned = 0usize;
    for rec in expired {
        let sess_mutex = super::session_lock(&rec.id);
        let Ok(_sess_guard) = sess_mutex.try_lock() else {
            continue;
        };
        let user_stripe = user_stripe_for(rec.user_id);
        let Ok(_user_guard) = user_stripe.try_lock() else {
            continue;
        };
        if cleanup_single_expired_upload_locked(conn, base_root, rec, now_secs)? {
            cleaned += 1;
        }
    }

    Ok(cleaned)
}

/// Cleans up expired upload sessions (`expires_at <= now`) globally using a persistent cursor.
/// - Acquires non-blocking `session_lock(&rec.id).try_lock()` -> `user_mutation_stripe(rec.user_id).try_lock()`
///   for every expired session and holds those guards across reconciliation, `BEGIN IMMEDIATE`
///   (with a fresh publication-proof re-check), and staging/proof file unlinks.
/// - Before releasing any quota, reconciles `'publishing'` sessions (and `'uploading'` sessions
///   at `offset_bytes == upload_length`) against disk:
///   - If the file was already published to `BrowserFs`, transitions the session to `'completed'`
///     and NEVER releases quota.
///   - If publication state is ambiguous, conservatively retains the quota reservation (never
///     undercounts a potentially published file).
///   - Only when an unfinished upload is proven unpublished (`status == 'uploading'` with
///     `offset_bytes < upload_length`, or `UnpublishedStagingIntact`) is its `reserved_bytes` released.
/// - For expired `'completed'` sessions: deletes the DB tracking row ONLY and NEVER releases quota.
#[allow(dead_code)]
pub fn cleanup_expired_uploads_at(
    conn: &Connection,
    base_root: &Path,
    now_secs: i64,
) -> Result<usize, McBrowserError> {
    cleanup_expired_uploads_with_user_stripe_at(
        conn,
        base_root,
        now_secs,
        crate::mcbrowser::user_mutation_stripe,
    )
}

pub(super) fn cancel_and_release_session_conn(
    conn: &Connection,
    base_root: &Path,
    rec: &UploadSessionRecord,
) -> Result<(), McBrowserError> {
    let now = now_unix_secs();
    let mut probe = rec.clone();
    let may_have_published = probe.status == "publishing"
        || (probe.status == "uploading" && probe.offset_bytes == probe.upload_length);
    let resolution = if may_have_published {
        reconcile_publishing_session_conn_safe(conn, base_root, &mut probe, now)
    } else {
        PublishingResolution::UnpublishedStagingIntact
    };

    if matches!(resolution, PublishingResolution::Completed) {
        return Ok(());
    }

    if matches!(resolution, PublishingResolution::AmbiguousRetainQuota) {
        return Err(McBrowserError::Conflict(
            "Upload publication remains ambiguous".to_string(),
        ));
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin session cleanup transaction".to_string())
        })?;
    let step = (|| -> Result<(), McBrowserError> {
        let Some(cur) = load_session_conn(conn, &rec.id)? else {
            return Ok(());
        };
        if cur.status == "completed" {
            return Ok(());
        }
        let safe_to_release = matches!(resolution, PublishingResolution::UnpublishedStagingIntact)
            && cur.status == "uploading";
        if safe_to_release && cur.quota_reserved && cur.reserved_bytes > 0 {
            release_user_quota_conn(conn, cur.user_id, cur.reserved_bytes)?;
        }
        if safe_to_release && !cur.audit_event_id.trim().is_empty() {
            crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &cur.audit_event_id,
                Some("STAGING_MISSING"),
            )?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1",
            params![cur.id],
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to remove broken upload session".to_string())
        })?;
        Ok(())
    })();
    match step {
        Ok(()) => {
            conn.execute_batch("COMMIT").map_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
                McBrowserError::Internal("Failed to commit upload cleanup".to_string())
            })?;
            let _ = remove_staging_file_at(base_root, rec.user_id, &rec.id);
            let _ = remove_publication_proof_at(base_root, rec.user_id, &rec.id);
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

pub(super) fn reconcile_publishing_session_conn_safe(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> PublishingResolution {
    reconcile_publishing_session_at(conn, base_root, session, false, now_secs)
        .unwrap_or(PublishingResolution::AmbiguousRetainQuota)
}
