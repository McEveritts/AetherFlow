use super::db::{
    cancel_and_release_session_conn, cleanup_expired_uploads_for_user_at,
    discard_unpublished_session_conn, ensure_session_pending_audit_conn, ensure_uploads_schema,
    load_session_conn, mark_session_completed_conn, mark_session_skipped_conn,
    reconcile_publishing_session_at, reconcile_publishing_session_conn_safe, row_to_session,
    session_published_byte_delta, SESSION_SELECT_COLUMNS,
};
use super::protocol::{
    authorize_conflict_policy_permissions_with_conn, configured_max_upload_bytes,
    encode_session_metadata_header, map_mcbrowser_err_tus, now_unix_secs, parse_upload_metadata,
    resolve_effective_conflict_policy, tus_error, validate_conflict_policy,
    validate_fingerprint_value, validate_tus_version, validate_upload_id, with_tus_headers,
    ConflictPolicy, DiscoverUploadsQuery, DiscoverUploadsResponse, PublishingResolution,
    UploadSessionRecord, UploadSessionSummary,
};
use super::staging::{
    copy_existing_prefix_to_staging, create_exclusive_staging_file_at,
    inspect_existing_target_in_bfs, open_verified_user_root_fd, publish_staging_file_to_browser_fs,
    publish_zero_byte_upload_conn, reconcile_staging_offset_at, remove_publication_proof_at,
    remove_staging_file_at, verify_bound_target_unchanged, verify_session_scope_matches,
    write_publication_proof_at, UploadPublicationProof,
};
use super::{MAX_ACTIVE_UPLOADS_PER_USER, MAX_CHUNK_BYTES, UPLOAD_SESSION_EXPIRY_SECS};
use crate::auth::AuthUser;
use crate::mcbrowser::{
    check_fd_free_space, load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    release_user_quota_conn, validate_mcbrowser_user, McBrowserError,
};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use rusqlite::{params, Connection, OptionalExtension};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::Path;
use uuid::Uuid;

pub(crate) fn create_upload_session_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    headers: &HeaderMap,
    policy_query: Option<&str>,
) -> Result<(UploadSessionRecord, Response), Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    validate_conflict_policy(policy_query).map_err(map_mcbrowser_err_tus)?;
    let header_conflict = headers
        .get("X-Upload-Conflict")
        .and_then(|v| v.to_str().ok());
    validate_conflict_policy(header_conflict).map_err(map_mcbrowser_err_tus)?;

    // Parse Upload-Length
    let Some(len_hv) = headers.get("Upload-Length") else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Missing required Upload-Length header",
        ));
    };
    let Ok(len_str) = len_hv.to_str() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid Upload-Length header",
        ));
    };
    let Ok(upload_length) = len_str.trim().parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Upload-Length must be a non-negative integer",
        ));
    };

    let max_bytes = configured_max_upload_bytes();
    if upload_length > max_bytes {
        return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
            format!(
                "Upload-Length {upload_length} exceeds maximum allowed size of {max_bytes} bytes"
            ),
        )));
    }

    // Reject Content-Length > 0 on POST (creation with upload is not part of core TUS creation)
    if let Some(cl_hv) = headers.get(header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_hv.to_str() {
            if let Ok(cl) = cl_str.trim().parse::<u64>() {
                if cl > 0 {
                    return Err(tus_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "POST /mcbrowser/uploads does not accept a request body; send data via PATCH",
                    ));
                }
            }
        }
    }

    let meta_raw = headers.get("Upload-Metadata").and_then(|v| v.to_str().ok());
    let parsed_meta = parse_upload_metadata(meta_raw).map_err(map_mcbrowser_err_tus)?;
    let conflict_policy = resolve_effective_conflict_policy(
        policy_query,
        header_conflict,
        parsed_meta.conflict_policy,
    )
    .map_err(map_mcbrowser_err_tus)?;
    let fingerprint = parsed_meta.fingerprint.unwrap_or_default();

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_for_user_at(conn, base_root, user_id, now);

    // Open the user's verified scoped root directory and inspect whether the target file exists.
    let scoped_root =
        open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
    let existing_target = inspect_existing_target_in_bfs(&scoped_root.bfs, &parsed_meta.path)
        .map_err(map_mcbrowser_err_tus)?;
    let (existing_file_opt, base_target_exists, base_target_dev, base_target_ino, base_target_size) =
        match existing_target {
            Some((file, dev, ino, size)) => (Some(file), true, dev, ino, size),
            None => (None, false, 0, 0, 0),
        };

    // Enforce policy permissions (`Permission::Modify` for Overwrite/Resume, `Permission::Create` for new files)
    authorize_conflict_policy_permissions_with_conn(
        conn,
        user,
        &parsed_meta.path,
        conflict_policy,
        base_target_exists,
    )
    .map_err(map_mcbrowser_err_tus)?;

    let upload_id = Uuid::new_v4().simple().to_string();
    let expires_at = now + UPLOAD_SESSION_EXPIRY_SECS;
    let owner_scope = scoped_root.scope.clone();
    let scope_root_dev = scoped_root.scope_dev;
    let scope_root_ino = scoped_root.scope_ino;

    // Fast path for `ConflictPolicy::Skip` when the target regular file already exists:
    // leave the existing file untouched, reserve 0 bytes of quota, and complete immediately.
    if conflict_policy == ConflictPolicy::Skip && base_target_exists {
        drop(existing_file_opt);
        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
            .map_err(|_| {
                map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to begin skipped upload session transaction".to_string(),
                ))
            })?;

        let skip_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
            let username_opt: Option<String> = conn
                .query_row(
                    "SELECT username FROM users WHERE id = ?1",
                    params![user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| McBrowserError::Internal("Failed to query user record".to_string()))?;
            if username_opt.is_none() {
                return Err(McBrowserError::Unauthorized(
                    "User account not found".to_string(),
                ));
            }
            load_active_quota_conn(conn, user_id, 0)?;

            let len_i64 = i64::try_from(upload_length).map_err(|_| {
                McBrowserError::PayloadTooLarge(
                    "Upload-Length exceeds supported integer range".to_string(),
                )
            })?;
            let dev_i64 = i64::try_from(scope_root_dev).unwrap_or(0);
            let ino_i64 = i64::try_from(scope_root_ino).unwrap_or(0);
            let base_dev_i64 = i64::try_from(base_target_dev).unwrap_or(0);
            let base_ino_i64 = i64::try_from(base_target_ino).unwrap_or(0);
            let base_size_i64 = i64::try_from(base_target_size).unwrap_or(0);

            conn.execute(
                "INSERT INTO mcbrowser_uploads \
                 (id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, staging_rel_path, \
                  quota_reserved, conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size, \
                  created_at, updated_at, expires_at, owner_scope, scope_root_dev, scope_root_ino) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 'completed', '', 0, 'skip', 0, 1, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13)",
                params![
                    upload_id,
                    user_id,
                    parsed_meta.path,
                    fingerprint,
                    len_i64,
                    base_dev_i64,
                    base_ino_i64,
                    base_size_i64,
                    now,
                    expires_at,
                    owner_scope,
                    dev_i64,
                    ino_i64,
                ],
            )
            .map_err(|_| McBrowserError::Internal("Failed to persist skipped upload session".to_string()))?;

            Ok(UploadSessionRecord {
                id: upload_id.clone(),
                user_id,
                owner_scope: owner_scope.clone(),
                scope_root_dev,
                scope_root_ino,
                target_path: parsed_meta.path.clone(),
                fingerprint: fingerprint.clone(),
                upload_length,
                offset_bytes: upload_length,
                status: "completed".to_string(),
                staging_rel_path: String::new(),
                quota_reserved: false,
                reserved_bytes: 0,
                conflict_policy: ConflictPolicy::Skip,
                base_target_exists: true,
                base_target_dev,
                base_target_ino,
                base_target_size,
                audit_event_id: String::new(),
                updated_at: now,
                expires_at,
            })
        })();

        let record = match skip_res {
            Ok(rec) => {
                if conn.execute_batch("COMMIT").is_err() {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                        "Failed to commit skipped upload session".to_string(),
                    )));
                }
                rec
            }
            Err(err) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(err));
            }
        };

        let location = format!("/api/v1/auth/mcbrowser/uploads/{}", record.id);
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::CREATED;
        let h = resp.headers_mut();
        if let Ok(loc_hv) = HeaderValue::from_str(&location) {
            h.insert(header::LOCATION, loc_hv);
        }
        if let Ok(off_hv) = HeaderValue::from_str(&record.offset_bytes.to_string()) {
            h.insert("Upload-Offset", off_hv);
        }
        h.insert("Upload-Status", HeaderValue::from_static("completed"));
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
        let encoded_meta = encode_session_metadata_header(&record);
        if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
            h.insert("Upload-Metadata", meta_hv);
        }
        if let Ok(path_hv) = HeaderValue::from_str(&record.target_path) {
            h.insert("Upload-Path", path_hv);
        }
        return Ok((record, with_tus_headers(resp)));
    }

    // Validate conflict policy against target existence and preflight `begin_upload` / `begin_replace`.
    let preflight_pending = match conflict_policy {
        ConflictPolicy::Error => {
            if base_target_exists {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                    "Target file already exists".to_string(),
                )));
            }
            scoped_root
                .bfs
                .begin_upload(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                })?
        }
        ConflictPolicy::Skip => {
            // `base_target_exists == false` here because `base_target_exists == true` returned above.
            scoped_root
                .bfs
                .begin_upload(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                })?
        }
        ConflictPolicy::Overwrite => {
            if base_target_exists {
                scoped_root
                    .bfs
                    .begin_replace(&parsed_meta.path)
                    .map_err(|e| {
                        map_mcbrowser_err_tus(map_fs_io_error(
                            e,
                            "Failed to initiate replacement upload",
                        ))
                    })?
            } else {
                scoped_root
                    .bfs
                    .begin_upload(&parsed_meta.path)
                    .map_err(|e| {
                        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                    })?
            }
        }
        ConflictPolicy::Resume => {
            if !base_target_exists {
                return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                    "Target file does not exist for resume".to_string(),
                )));
            }
            if base_target_size > upload_length {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(format!(
                    "Existing target file size ({base_target_size} bytes) exceeds Upload-Length ({upload_length} bytes); refusing to truncate live file"
                ))));
            }
            scoped_root
                .bfs
                .begin_replace(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(
                        e,
                        "Failed to initiate resume replacement upload",
                    ))
                })?
        }
    };

    let preflight_file = preflight_pending.file().map_err(|e| {
        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to inspect target directory"))
    })?;
    check_fd_free_space(preflight_file.as_raw_fd(), upload_length.max(1))
        .map_err(map_mcbrowser_err_tus)?;

    let initial_offset = if conflict_policy == ConflictPolicy::Resume {
        base_target_size
    } else {
        0
    };
    let reserved_bytes = if base_target_exists {
        upload_length.saturating_sub(base_target_size)
    } else {
        upload_length
    };
    let completes_immediately = initial_offset == upload_length;
    let initial_status = if completes_immediately {
        "publishing"
    } else {
        "uploading"
    };
    let staging_rel = if completes_immediately {
        String::new()
    } else {
        format!("user-{user_id}/{upload_id}.part")
    };
    let is_noop_resume =
        completes_immediately && conflict_policy == ConflictPolicy::Resume && base_target_exists;
    crate::mcbrowser::events::ensure_events_tables(conn).map_err(map_mcbrowser_err_tus)?;

    // Reserve positive-delta quota + enforce active session cap + insert upload record in one atomic SQLite transaction
    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to begin upload creation transaction".to_string(),
            ))
        })?;

    let tx_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
        let username: Option<String> = conn
            .query_row(
                "SELECT username FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| McBrowserError::Internal("Failed to query user record".to_string()))?;

        let Some(username) = username else {
            return Err(McBrowserError::Unauthorized(
                "User account not found".to_string(),
            ));
        };

        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mcbrowser_uploads WHERE user_id = ?1 AND status IN ('uploading', 'publishing') AND expires_at > ?2",
                params![user_id, now],
                |r| r.get(0),
            )
            .map_err(|_| McBrowserError::Internal("Failed to count active upload sessions".to_string()))?;

        if !completes_immediately && active_count >= MAX_ACTIVE_UPLOADS_PER_USER {
            return Err(McBrowserError::Conflict(format!(
                "Maximum of {MAX_ACTIVE_UPLOADS_PER_USER} active resumable uploads per user reached"
            )));
        }

        let snapshot = load_active_quota_conn(conn, user_id, reserved_bytes)?;
        if reserved_bytes > 0 {
            let delta_i64 = i64::try_from(reserved_bytes).unwrap_or(i64::MAX);
            let new_used = snapshot.used_bytes.saturating_add(delta_i64);
            conn.execute(
                "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, updated_at) \
                 VALUES (?1, ?2, 0, ?3, 'active', 'manual', CURRENT_TIMESTAMP) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                    used_bytes = ?3, \
                    updated_at = CURRENT_TIMESTAMP",
                params![user_id, username, new_used],
            )
            .map_err(|_| McBrowserError::Internal("Failed to reserve user storage quota".to_string()))?;
        }

        let len_i64 = i64::try_from(upload_length).map_err(|_| {
            McBrowserError::PayloadTooLarge(
                "Upload-Length exceeds supported integer range".to_string(),
            )
        })?;
        let off_i64 = i64::try_from(initial_offset).unwrap_or(0);
        let reserved_i64 = i64::try_from(reserved_bytes).unwrap_or(i64::MAX);
        let dev_i64 = i64::try_from(scope_root_dev).unwrap_or(0);
        let ino_i64 = i64::try_from(scope_root_ino).unwrap_or(0);
        let base_exists_i64 = if base_target_exists { 1i64 } else { 0i64 };
        let base_dev_i64 = i64::try_from(base_target_dev).unwrap_or(0);
        let base_ino_i64 = i64::try_from(base_target_ino).unwrap_or(0);
        let base_size_i64 = i64::try_from(base_target_size).unwrap_or(0);

        let expected_delta = if base_target_exists {
            let diff = i128::from(upload_length) - i128::from(base_target_size);
            diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        } else {
            len_i64
        };
        let audit_event_id = if is_noop_resume {
            String::new()
        } else {
            crate::mcbrowser::events::record_pending_intent_with_conn(
                conn,
                user,
                crate::mcbrowser::events::McBrowserEventTrigger::UploadCompleted,
                &parsed_meta.path,
                None,
                expected_delta,
            )?
            .event
            .event_id
        };

        conn.execute(
            "INSERT INTO mcbrowser_uploads \
             (id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, staging_rel_path, \
              quota_reserved, conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size, \
              audit_event_id, created_at, updated_at, expires_at, owner_scope, scope_root_dev, scope_root_ino) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17, ?18, ?19, ?20)",
            params![
                upload_id,
                user_id,
                parsed_meta.path,
                fingerprint,
                len_i64,
                off_i64,
                initial_status,
                staging_rel,
                conflict_policy.as_str(),
                reserved_i64,
                base_exists_i64,
                base_dev_i64,
                base_ino_i64,
                base_size_i64,
                audit_event_id,
                now,
                expires_at,
                owner_scope,
                dev_i64,
                ino_i64,
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist upload session".to_string()))?;

        Ok(UploadSessionRecord {
            id: upload_id.clone(),
            user_id,
            target_path: parsed_meta.path.clone(),
            fingerprint: fingerprint.clone(),
            upload_length,
            offset_bytes: initial_offset,
            status: initial_status.to_string(),
            staging_rel_path: staging_rel,
            quota_reserved: true,
            reserved_bytes,
            conflict_policy,
            base_target_exists,
            base_target_dev,
            base_target_ino,
            base_target_size,
            audit_event_id,
            updated_at: now,
            expires_at,
            owner_scope: owner_scope.clone(),
            scope_root_dev,
            scope_root_ino,
        })
    })();

    let mut record = match tx_res {
        Ok(rec) => {
            if conn.execute_batch("COMMIT").is_err() {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to commit upload session creation".to_string(),
                )));
            }
            rec
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(map_mcbrowser_err_tus(err));
        }
    };

    if record.status != "completed" {
        if let Err(error) =
            write_publication_proof_at(base_root, &record, &UploadPublicationProof::Unpublished {})
        {
            discard_unpublished_session_conn(conn, &record, &error)
                .map_err(map_mcbrowser_err_tus)?;
            let _ = remove_publication_proof_at(base_root, user_id, &record.id);
            return Err(map_mcbrowser_err_tus(error));
        }
    }

    if completes_immediately {
        if conflict_policy != ConflictPolicy::Resume && upload_length == 0 {
            publish_zero_byte_upload_conn(
                conn,
                base_root,
                &scoped_root.bfs,
                &mut record,
                preflight_pending,
                existing_file_opt.as_ref(),
                now,
            )
            .map_err(map_mcbrowser_err_tus)?;
        } else {
            // `ConflictPolicy::Resume` where `base_target_size == upload_length`:
            // verify the existing file still matches its bound identity/size and mark completed.
            drop(preflight_pending);
            if let Err(verify_err) = verify_bound_target_unchanged(&scoped_root.bfs, &record) {
                let _ = conn.execute(
                    "DELETE FROM mcbrowser_uploads WHERE id = ?1",
                    params![record.id],
                );
                return Err(map_mcbrowser_err_tus(verify_err));
            }
            mark_session_completed_conn(conn, &mut record, now).map_err(map_mcbrowser_err_tus)?;
        }
    } else {
        // Drop preflight_pending (unlinks `.af-upload-tmp.*` in user root) and create private staging file
        drop(preflight_pending);
        let mut staging_file =
            match create_exclusive_staging_file_at(base_root, user_id, &record.id) {
                Ok(f) => f,
                Err(staging_err) => {
                    discard_unpublished_session_conn(conn, &record, &staging_err)
                        .map_err(map_mcbrowser_err_tus)?;
                    let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                    return Err(map_mcbrowser_err_tus(staging_err));
                }
            };

        if conflict_policy == ConflictPolicy::Resume && initial_offset > 0 {
            let Some(existing_file) = existing_file_opt else {
                let error =
                    McBrowserError::NotFound("Target file does not exist for resume".to_string());
                discard_unpublished_session_conn(conn, &record, &error)
                    .map_err(map_mcbrowser_err_tus)?;
                let _ = remove_staging_file_at(base_root, user_id, &record.id);
                let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                return Err(map_mcbrowser_err_tus(error));
            };

            if let Err(copy_err) = copy_existing_prefix_to_staging(
                existing_file,
                &mut staging_file,
                base_target_dev,
                base_target_ino,
                initial_offset,
            ) {
                drop(staging_file);
                discard_unpublished_session_conn(conn, &record, &copy_err)
                    .map_err(map_mcbrowser_err_tus)?;
                let _ = remove_staging_file_at(base_root, user_id, &record.id);
                let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                return Err(map_mcbrowser_err_tus(copy_err));
            }
        }
    }

    let location = format!("/api/v1/auth/mcbrowser/uploads/{}", record.id);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::CREATED;
    let h = resp.headers_mut();
    if let Ok(loc_hv) = HeaderValue::from_str(&location) {
        h.insert(header::LOCATION, loc_hv);
    }
    if let Ok(off_hv) = HeaderValue::from_str(&record.offset_bytes.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(status_hv) = HeaderValue::from_str(&record.status) {
        h.insert("Upload-Status", status_hv);
    }
    if record.status == "completed"
        && record.conflict_policy == ConflictPolicy::Skip
        && record.base_target_exists
    {
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
    }
    let encoded_meta = encode_session_metadata_header(&record);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&record.target_path) {
        h.insert("Upload-Path", path_hv);
    }
    Ok((record, with_tus_headers(resp)))
}

pub(crate) fn discover_uploads_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    query: &DiscoverUploadsQuery,
) -> Result<DiscoverUploadsResponse, Response> {
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let raw_path = query.path.as_deref().unwrap_or("");
    let normalized_path =
        normalize_relative_path(raw_path, false).map_err(map_mcbrowser_err_tus)?;

    let Some(raw_len) = query
        .length
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' is required for upload discovery",
        ));
    };
    let Ok(upload_length) = raw_len.parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' must be a non-negative integer",
        ));
    };
    let len_i64 = i64::try_from(upload_length).map_err(|_| {
        tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' exceeds supported range",
        )
    })?;

    // Fingerprint is required to prevent unsafe same-name+size resume across modified files
    let Some(raw_fp) = query
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'fingerprint' is required for safe resumable upload discovery",
        ));
    };
    let fingerprint = validate_fingerprint_value(raw_fp).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_for_user_at(conn, base_root, user_id, now);

    let scoped_root_opt = open_verified_user_root_fd(conn, base_root, user_id).ok();

    let sql = format!(
        "SELECT {SESSION_SELECT_COLUMNS} \
         FROM mcbrowser_uploads \
         WHERE user_id = ?1 AND status IN ('uploading', 'publishing') AND target_path = ?2 \
           AND upload_length = ?3 AND fingerprint = ?4 AND expires_at > ?5 \
         ORDER BY updated_at DESC, created_at DESC"
    );
    let mut stmt = conn.prepare(&sql).map_err(|_| {
        map_mcbrowser_err_tus(McBrowserError::Internal(
            "Failed to query resumable uploads".to_string(),
        ))
    })?;

    let rows: Vec<UploadSessionRecord> = stmt
        .query_map(
            params![user_id, normalized_path, len_i64, fingerprint, now],
            row_to_session,
        )
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to execute resumable uploads query".to_string(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to read resumable upload row".to_string(),
            ))
        })?;
    drop(stmt);

    let mut uploads = Vec::new();
    for rec in rows {
        // Callers hold `user_mutation_stripe(user_id)`. Acquire per-session lock strictly via
        // non-blocking `try_lock()` (NEVER `.lock().await`) to avoid ABBA deadlock with handlers
        // locking `session_lock -> user_mutation_stripe`, while preventing races with in-flight
        // PATCH streaming or finalization.
        let sess_mutex = super::session_lock(&rec.id);
        let Ok(_sess_guard) = sess_mutex.try_lock() else {
            continue;
        };
        let Ok(Some(mut rec)) = load_session_conn(conn, &rec.id) else {
            continue;
        };
        if rec.user_id != user_id
            || rec.expires_at <= now
            || !matches!(rec.status.as_str(), "uploading" | "publishing")
        {
            continue;
        }
        if rec.status == "publishing"
            || (rec.status == "uploading" && rec.offset_bytes == rec.upload_length)
        {
            match reconcile_publishing_session_at(conn, base_root, &mut rec, false, now) {
                Ok(PublishingResolution::Completed) => {
                    continue;
                }
                Ok(PublishingResolution::AmbiguousRetainQuota) => {
                    continue;
                }
                Ok(PublishingResolution::UnpublishedStagingIntact) => {
                    let Some(ref scoped_root) = scoped_root_opt else {
                        continue;
                    };
                    if verify_session_scope_matches(&rec, scoped_root).is_err() {
                        continue;
                    }
                    if verify_bound_target_unchanged(&scoped_root.bfs, &rec).is_err() {
                        continue;
                    }
                    uploads.push(UploadSessionSummary {
                        id: rec.id,
                        path: rec.target_path,
                        length: rec.upload_length,
                        offset: rec.offset_bytes,
                        status: "uploading".to_string(),
                        fingerprint: rec.fingerprint,
                    });
                    continue;
                }
                Err(_) => continue,
            }
        }

        let Some(ref scoped_root) = scoped_root_opt else {
            continue;
        };
        if verify_session_scope_matches(&rec, scoped_root).is_err() {
            continue;
        }
        if verify_bound_target_unchanged(&scoped_root.bfs, &rec).is_err() {
            continue;
        }

        match reconcile_staging_offset_at(conn, base_root, &mut rec) {
            Ok(_) => {
                uploads.push(UploadSessionSummary {
                    id: rec.id,
                    path: rec.target_path,
                    length: rec.upload_length,
                    offset: rec.offset_bytes,
                    status: rec.status,
                    fingerprint: rec.fingerprint,
                });
            }
            Err(_) => {
                let _ = cancel_and_release_session_conn(conn, base_root, &rec);
            }
        }
    }

    Ok(DiscoverUploadsResponse { uploads })
}

pub(crate) fn head_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    raw_id: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let upload_id = validate_upload_id(raw_id).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_for_user_at(conn, base_root, user_id, now);

    let Some(mut session) = load_session_conn(conn, &upload_id).map_err(map_mcbrowser_err_tus)?
    else {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    };

    // Enforce strict owner isolation (return 404 NotFound to avoid leaking cross-user session existence)
    if session.user_id != user_id || session.expires_at <= now {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    }

    if session.status == "publishing"
        || (session.status == "uploading" && session.offset_bytes == session.upload_length)
    {
        // Re-check bound scope + policy + active quota before attempting to finish an interrupted publish
        let scope_check = open_verified_user_root_fd(conn, base_root, user_id)
            .and_then(|root| verify_session_scope_matches(&session, &root));
        let perm_check = authorize_conflict_policy_permissions_with_conn(
            conn,
            user,
            &session.target_path,
            session.conflict_policy,
            session.base_target_exists,
        );
        let can_finish = scope_check.is_ok()
            && perm_check.is_ok()
            && load_active_quota_conn(conn, user_id, 0).is_ok();
        let res = reconcile_publishing_session_at(conn, base_root, &mut session, can_finish, now)
            .map_err(map_mcbrowser_err_tus)?;
        if session.status != "completed" {
            if let Err(scope_err) = scope_check {
                return Err(map_mcbrowser_err_tus(scope_err));
            }
            if let Err(perm_err) = perm_check {
                return Err(map_mcbrowser_err_tus(perm_err));
            }
            if matches!(res, PublishingResolution::AmbiguousRetainQuota) {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                    "Upload session is in an ambiguous publication state; quota remains conservatively reserved".to_string(),
                )));
            }
        }
    } else if session.status == "uploading" {
        authorize_conflict_policy_permissions_with_conn(
            conn,
            user,
            &session.target_path,
            session.conflict_policy,
            session.base_target_exists,
        )
        .map_err(map_mcbrowser_err_tus)?;

        let scoped_root =
            open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
        verify_session_scope_matches(&session, &scoped_root).map_err(map_mcbrowser_err_tus)?;
        verify_bound_target_unchanged(&scoped_root.bfs, &session).map_err(map_mcbrowser_err_tus)?;

        if reconcile_staging_offset_at(conn, base_root, &mut session).is_err() {
            let _ = cancel_and_release_session_conn(conn, base_root, &session);
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload staging file is no longer available".to_string(),
            )));
        }
    }

    if session.status == "completed" && !session.audit_event_id.trim().is_empty() {
        let delta = session_published_byte_delta(&session);
        crate::mcbrowser::events::finalize_event_completed_with_conn(
            conn,
            &session.audit_event_id,
            None,
            None,
            delta,
        )
        .map_err(map_mcbrowser_err_tus)?;
    }

    let wire_status = if session.status == "completed" {
        "completed"
    } else {
        "uploading"
    };

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    if let Ok(off_hv) = HeaderValue::from_str(&session.offset_bytes.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(len_hv) = HeaderValue::from_str(&session.upload_length.to_string()) {
        h.insert("Upload-Length", len_hv);
    }
    if let Ok(st_hv) = HeaderValue::from_str(wire_status) {
        h.insert("Upload-Status", st_hv);
    }
    if session.status == "completed"
        && session.conflict_policy == ConflictPolicy::Skip
        && session.base_target_exists
    {
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
    }
    let encoded_meta = encode_session_metadata_header(&session);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&session.target_path) {
        h.insert("Upload-Path", path_hv);
    }

    Ok(with_tus_headers(resp))
}

pub(crate) fn delete_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    raw_id: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let upload_id = validate_upload_id(raw_id).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_for_user_at(conn, base_root, user_id, now);

    // Pre-reconcile if the session is in 'publishing' or at full offset so we NEVER cancel and
    // release quota for a file that was already published to BrowserFs before a crash.
    if let Some(mut pre_session) =
        load_session_conn(conn, &upload_id).map_err(map_mcbrowser_err_tus)?
    {
        if pre_session.user_id == user_id
            && pre_session.expires_at > now
            && (pre_session.status == "publishing"
                || (pre_session.status == "uploading"
                    && pre_session.offset_bytes == pre_session.upload_length))
        {
            let resolution =
                reconcile_publishing_session_conn_safe(conn, base_root, &mut pre_session, now);
            match resolution {
                PublishingResolution::Completed => {
                    return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                        "Completed upload session cannot be cancelled".to_string(),
                    )));
                }
                PublishingResolution::AmbiguousRetainQuota => {
                    return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                        "Upload session is in an ambiguous publication state and cannot release quota".to_string(),
                    )));
                }
                PublishingResolution::UnpublishedStagingIntact => {
                    // Proven unpublished with staging intact: allow cancellation and quota release below.
                }
            }
        }
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to start upload cancellation transaction".to_string(),
            ))
        })?;

    let tx_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
        let Some(session) = load_session_conn(conn, &upload_id)? else {
            return Err(McBrowserError::NotFound(
                "Upload session not found".to_string(),
            ));
        };
        if session.user_id != user_id || session.expires_at <= now {
            return Err(McBrowserError::NotFound(
                "Upload session not found".to_string(),
            ));
        }
        if session.status == "completed" {
            return Err(McBrowserError::Conflict(
                "Completed upload session cannot be cancelled".to_string(),
            ));
        }
        if session.quota_reserved && session.reserved_bytes > 0 {
            release_user_quota_conn(conn, user_id, session.reserved_bytes)?;
        }
        if !session.audit_event_id.trim().is_empty() {
            crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &session.audit_event_id,
                Some("UPLOAD_CANCELLED"),
            )?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1",
            params![upload_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to delete upload session".to_string()))?;
        Ok(session)
    })();

    let session = match tx_res {
        Ok(s) => {
            if conn.execute_batch("COMMIT").is_err() {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to commit upload cancellation".to_string(),
                )));
            }
            s
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(map_mcbrowser_err_tus(err));
        }
    };

    let _ = remove_staging_file_at(base_root, user_id, &session.id);
    let _ = remove_publication_proof_at(base_root, user_id, &session.id);

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    Ok(with_tus_headers(resp))
}

pub(crate) fn prepare_patch_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    upload_id: &str,
    client_offset: u64,
    declared_cl: Option<u64>,
) -> Result<(UploadSessionRecord, File), Response> {
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    ensure_uploads_schema(conn).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();

    let Some(mut session) = load_session_conn(conn, upload_id).map_err(map_mcbrowser_err_tus)?
    else {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    };

    if session.user_id != user_id || session.expires_at <= now {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    }

    authorize_conflict_policy_permissions_with_conn(
        conn,
        user,
        &session.target_path,
        session.conflict_policy,
        session.base_target_exists,
    )
    .map_err(map_mcbrowser_err_tus)?;

    // Check user quota status is still active
    load_active_quota_conn(conn, user_id, 0).map_err(map_mcbrowser_err_tus)?;

    if session.status == "publishing"
        || (session.status == "uploading" && session.offset_bytes == session.upload_length)
    {
        // Reconcile any previously interrupted publication before accepting a new PATCH
        let res = reconcile_publishing_session_at(conn, base_root, &mut session, false, now)
            .map_err(map_mcbrowser_err_tus)?;
        if matches!(res, PublishingResolution::Completed) {
            if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
                return Err(skipped_upload_patch_response(&session));
            }
            return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                "Upload session is already completed".to_string(),
            )));
        }
        if matches!(res, PublishingResolution::AmbiguousRetainQuota) {
            return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                "Upload session is in an ambiguous publication state".to_string(),
            )));
        }
    }

    if session.status == "completed" {
        if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
            return Err(skipped_upload_patch_response(&session));
        }
        return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
            "Upload session is already completed".to_string(),
        )));
    }

    // Fail closed if the user's policy scope was remapped, the scoped root directory was replaced on disk,
    // or the bound original target file changed on disk.
    let scoped_root =
        open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
    verify_session_scope_matches(&session, &scoped_root).map_err(map_mcbrowser_err_tus)?;
    verify_bound_target_unchanged(&scoped_root.bfs, &session).map_err(map_mcbrowser_err_tus)?;

    let mut staging_file = match reconcile_staging_offset_at(conn, base_root, &mut session) {
        Ok(f) => f,
        Err(_) => {
            let _ = cancel_and_release_session_conn(conn, base_root, &session);
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload staging file is missing".to_string(),
            )));
        }
    };

    if client_offset != session.offset_bytes {
        return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(format!(
            "Upload-Offset mismatch: client sent {client_offset}, server is at {}",
            session.offset_bytes
        ))));
    }

    let remaining = session.upload_length.saturating_sub(session.offset_bytes);
    if let Some(cl) = declared_cl {
        if cl > remaining {
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH Content-Length exceeds remaining Upload-Length",
            ));
        }
    }

    check_fd_free_space(
        staging_file.as_raw_fd(),
        declared_cl.unwrap_or(remaining.min(MAX_CHUNK_BYTES)).max(1),
    )
    .map_err(map_mcbrowser_err_tus)?;

    staging_file
        .seek(SeekFrom::Start(session.offset_bytes))
        .map_err(|e| {
            map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to seek upload staging file"))
        })?;

    Ok((session, staging_file))
}

pub(super) fn finish_unpublished_skip_conn(
    conn: &Connection,
    base_root: &Path,
    bfs: &af_files::BrowserFs,
    session: &UploadSessionRecord,
    now: i64,
) -> Result<Option<Response>, McBrowserError> {
    if session.conflict_policy != ConflictPolicy::Skip || session.base_target_exists {
        return Ok(None);
    }
    match inspect_existing_target_in_bfs(bfs, &session.target_path) {
        Ok(None) => return Ok(None),
        Err(error) => {
            discard_unpublished_session_conn(conn, session, &error)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            let _ = remove_publication_proof_at(base_root, session.user_id, &session.id);
            return Err(error);
        }
        Ok(Some(_)) => {}
    }
    let mut skipped = load_session_conn(conn, &session.id)?.ok_or_else(|| {
        McBrowserError::NotFound("Upload session is no longer active".to_string())
    })?;
    mark_session_skipped_conn(conn, &mut skipped, now)?;
    let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
    Ok(Some(skipped_upload_patch_response(&skipped)))
}

pub(super) fn skipped_upload_patch_response(skipped: &UploadSessionRecord) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&skipped.upload_length.to_string()) {
        headers.insert("Upload-Offset", value);
    }
    headers.insert("Upload-Status", HeaderValue::from_static("completed"));
    headers.insert("Upload-Skipped", HeaderValue::from_static("true"));
    if let Ok(value) = HeaderValue::from_str(&encode_session_metadata_header(skipped)) {
        headers.insert("Upload-Metadata", value);
    }
    if let Ok(value) = HeaderValue::from_str(&skipped.target_path) {
        headers.insert("Upload-Path", value);
    }
    with_tus_headers(response)
}

pub(crate) fn finalize_patch_upload_at(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
    session: &UploadSessionRecord,
    staging_file: File,
    new_offset: u64,
) -> Result<Response, Response> {
    staging_file.sync_data().map_err(|e| {
        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to sync upload staging file"))
    })?;

    let reaches_completion = new_offset == session.upload_length;
    let now = now_unix_secs();
    let new_expires = now + UPLOAD_SESSION_EXPIRY_SECS;
    let new_offset_i64 = i64::try_from(new_offset).unwrap_or(i64::MAX);

    let updated = conn
        .execute(
            "UPDATE mcbrowser_uploads \
                 SET offset_bytes = ?1, updated_at = ?2, expires_at = ?3 \
                 WHERE id = ?4 AND user_id = ?5 AND status = 'uploading'",
            params![new_offset_i64, now, new_expires, session.id, user_id],
        )
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to update upload offset".to_string(),
            ))
        })?;
    if updated == 0 {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session is no longer active".to_string(),
        )));
    }
    if reaches_completion {
        // Re-verify active quota status and bound scoped root BEFORE publishing
        load_active_quota_conn(conn, user_id, 0).map_err(map_mcbrowser_err_tus)?;
        let scoped_root =
            open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
        verify_session_scope_matches(session, &scoped_root).map_err(map_mcbrowser_err_tus)?;

        if let Some(response) =
            finish_unpublished_skip_conn(conn, base_root, &scoped_root.bfs, session, now)
                .map_err(map_mcbrowser_err_tus)?
        {
            return Ok(response);
        }

        // Verify bound target identity/size BEFORE entering `'publishing'`.
        // If the bound target was modified/replaced/deleted (or a concurrent file appeared),
        // persist `offset_bytes = new_offset` in `'uploading'` and fail closed with `409 Conflict`.
        let expected_replace_file = match verify_bound_target_unchanged(&scoped_root.bfs, session) {
            Ok(f) => f,
            Err(conflict_err) => {
                if let Some(response) =
                    finish_unpublished_skip_conn(conn, base_root, &scoped_root.bfs, session, now)
                        .map_err(map_mcbrowser_err_tus)?
                {
                    return Ok(response);
                }
                let _ = conn.execute(
                    "UPDATE mcbrowser_uploads \
                     SET offset_bytes = ?1, status = 'uploading', updated_at = ?2, expires_at = ?3 \
                     WHERE id = ?4 AND user_id = ?5 AND status IN ('uploading', 'publishing')",
                    params![new_offset_i64, now, new_expires, session.id, user_id],
                );
                return Err(map_mcbrowser_err_tus(conflict_err));
            }
        };

        let mut publishing_session = session.clone();
        publishing_session.offset_bytes = new_offset;
        conn.execute_batch("SAVEPOINT mcbrowser_upload_begin_publish")
            .map_err(|_| {
                map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to begin upload publishing transaction".to_string(),
                ))
            })?;
        let begin_publish = (|| -> Result<usize, McBrowserError> {
            let audit_id = ensure_session_pending_audit_conn(conn, &mut publishing_session)?;
            let updated = conn
                .execute(
                    "UPDATE mcbrowser_uploads \
                     SET offset_bytes = ?1, status = 'publishing', audit_event_id = ?2, updated_at = ?3, expires_at = ?4 \
                     WHERE id = ?5 AND user_id = ?6 AND status IN ('uploading', 'publishing')",
                    params![
                        new_offset_i64,
                        audit_id,
                        now,
                        new_expires,
                        session.id,
                        user_id
                    ],
                )
                .map_err(|_| {
                    McBrowserError::Internal("Failed to record upload publishing intent".to_string())
                })?;
            conn.execute_batch("RELEASE mcbrowser_upload_begin_publish")
                .map_err(|_| {
                    McBrowserError::Internal(
                        "Failed to commit upload publishing intent".to_string(),
                    )
                })?;
            Ok(updated)
        })();
        let updated = match begin_publish {
            Ok(u) => u,
            Err(err) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO mcbrowser_upload_begin_publish; RELEASE mcbrowser_upload_begin_publish",
                );
                return Err(map_mcbrowser_err_tus(err));
            }
        };
        if updated == 0 {
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload session is no longer active".to_string(),
            )));
        }

        if let Err(pub_err) = publish_staging_file_to_browser_fs(
            staging_file,
            &scoped_root.bfs,
            &session.target_path,
            session.upload_length,
            expected_replace_file.as_ref(),
            base_root,
            &publishing_session,
        ) {
            if let Some(response) = finish_unpublished_skip_conn(
                conn,
                base_root,
                &scoped_root.bfs,
                &publishing_session,
                now,
            )
            .map_err(map_mcbrowser_err_tus)?
            {
                return Ok(response);
            }
            let mut probe = publishing_session.clone();
            probe.offset_bytes = new_offset;
            probe.status = "publishing".to_string();
            if matches!(
                reconcile_publishing_session_conn_safe(conn, base_root, &mut probe, now),
                PublishingResolution::UnpublishedStagingIntact
            ) {
                let _ = conn.execute(
                    "UPDATE mcbrowser_uploads \
                     SET status = 'uploading', updated_at = ?1 \
                     WHERE id = ?2 AND user_id = ?3 AND status = 'publishing'",
                    params![now, session.id, user_id],
                );
            }
            return Err(map_mcbrowser_err_tus(pub_err));
        }

        mark_session_completed_conn(conn, &mut publishing_session, now).map_err(|_| {
            tracing::error!(
                upload_id = %session.id,
                user_id,
                path = %session.target_path,
                "File published to BrowserFs, but status update to 'completed' failed; session remains in 'publishing' for reconciliation"
            );
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Upload published, but session completion state could not be updated".to_string(),
            ))
        })?;

        let _ = remove_staging_file_at(base_root, user_id, &session.id);
    }

    let final_status = if reaches_completion {
        "completed"
    } else {
        "uploading"
    };
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    let h = resp.headers_mut();
    if let Ok(off_hv) = HeaderValue::from_str(&new_offset.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(st_hv) = HeaderValue::from_str(final_status) {
        h.insert("Upload-Status", st_hv);
    }
    let encoded_meta = encode_session_metadata_header(session);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&session.target_path) {
        h.insert("Upload-Path", path_hv);
    }
    Ok(with_tus_headers(resp))
}
