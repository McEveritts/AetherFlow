use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Core Business Logic (`_at` functions for both Production and Isolated Tests)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn create_share_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    auth_user: &AuthUser,
    req: CreateShareRequest,
) -> Result<(ShareRecord, String), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_path = normalize_relative_path(&req.path, false)?;
    let allow_download = req.allow_download.unwrap_or(true);

    // Verify policy permissions on the requested path
    policy(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Share,
        &normalized_path,
    )?;
    policy(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Read,
        &normalized_path,
    )?;
    if allow_download {
        policy(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Download,
            &normalized_path,
        )?;
    }

    // Verify active user & quota state
    load_active_quota_conn(conn, user_id, 0)?;

    // Validate optional expiration timestamp
    let now = Utc::now();
    let (expires_at_rfc3339, expires_at_unix) = match req
        .expires_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_exp) => {
            let parsed = DateTime::parse_from_rfc3339(raw_exp).map_err(|_| {
                McBrowserError::BadRequest(
                    "Invalid expires_at: must be a valid RFC3339 timestamp".to_string(),
                )
            })?;
            let exp_utc = parsed.with_timezone(&Utc);
            if exp_utc <= now {
                return Err(McBrowserError::BadRequest(
                    "Share expiration timestamp must be in the future".to_string(),
                ));
            }
            (Some(exp_utc.to_rfc3339()), Some(exp_utc.timestamp()))
        }
        None => (None, None),
    };

    // Validate & hash optional password
    let password_hash = match req.password.as_deref().filter(|s| !s.is_empty()) {
        Some(pw) => Some(hash_share_password(pw)?),
        None => None,
    };

    // Inspect target on owner's scoped filesystem (rejecting missing targets, symlinks, hardlinks, special files)
    let scoped_root = open_verified_user_root_fd(conn, base_root, user_id)?;
    let (stat_info, leaf_name) = inspect_share_target(
        conn,
        policy,
        auth_user,
        &scoped_root.bfs,
        &normalized_path,
        allow_download,
    )?;

    if stat_info.is_directory {
        let shared = scoped_root
            .bfs
            .scoped_resolving_internal_links(&normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share directory"))?;
        let roots = authorize_share_resolution(
            conn,
            policy,
            auth_user,
            &normalized_path,
            &shared.resolution_paths,
            &shared.resolved_path,
            allow_download,
        )?;
        crate::mcbrowser::policy::authorize_recursive_paths_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Share,
            roots.iter().map(String::as_str),
        )?;
        let descendants = shared
            .fs
            .walk("", 10_000)
            .map_err(|e| map_fs_io_error(e, "Failed to inspect directory descendants for share"))?;
        for descendant in &descendants {
            for root in &roots {
                let owner_path = if root.is_empty() {
                    descendant.path.clone()
                } else {
                    format!("{root}/{}", descendant.path)
                };
                authorize_share_resolution(
                    conn,
                    policy,
                    auth_user,
                    &owner_path,
                    &[],
                    &owner_path,
                    allow_download,
                )?;
            }
        }
    }

    let share_id = Uuid::new_v4().to_string();
    let raw_token = generate_raw_share_token();
    let token_hash = hash_share_token(&raw_token);
    let created_at_rfc3339 = now.to_rfc3339();
    let created_at_unix = now.timestamp();

    crate::mcbrowser::events::ensure_events_tables(conn)?;
    let pending = crate::mcbrowser::events::record_pending_intent_with_conn(
        conn,
        auth_user,
        crate::mcbrowser::events::McBrowserEventTrigger::ShareCreated,
        &normalized_path,
        None,
        0,
    )?;

    conn.execute_batch("SAVEPOINT mcbrowser_share_create")
        .map_err(|_| {
            let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &pending.event.event_id,
                Some("INTERNAL_ERROR"),
            );
            McBrowserError::Internal("Failed to begin share creation transaction".to_string())
        })?;

    let publish_res = (|| -> Result<(), McBrowserError> {
        conn.execute(
            "INSERT INTO mcbrowser_shares \
             (id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
              target_path, target_name, is_directory, target_dev, target_ino, \
              password_hash, allow_download, expires_at, expires_at_unix, revoked, \
              created_at, created_at_unix) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0, ?16, ?17)",
            params![
                &share_id,
                &token_hash,
                user_id,
                &scoped_root.scope,
                scoped_root.scope_dev as i64,
                scoped_root.scope_ino as i64,
                &normalized_path,
                &leaf_name,
                stat_info.is_directory,
                stat_info.dev as i64,
                stat_info.ino as i64,
                &password_hash,
                allow_download,
                &expires_at_rfc3339,
                expires_at_unix,
                &created_at_rfc3339,
                created_at_unix,
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist share record".to_string()))?;

        crate::mcbrowser::events::finalize_event_completed_with_conn(
            conn,
            &pending.event.event_id,
            None,
            None,
            0,
        )?;

        conn.execute_batch("RELEASE mcbrowser_share_create")
            .map_err(|_| McBrowserError::Internal("Failed to commit share creation".to_string()))?;
        Ok(())
    })();

    if let Err(err) = publish_res {
        let _ = conn
            .execute_batch("ROLLBACK TO mcbrowser_share_create; RELEASE mcbrowser_share_create");
        let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
            conn,
            &pending.event.event_id,
            Some(share_audit_error_code(&err)),
        );
        return Err(err);
    }

    let record = ShareRecord {
        id: share_id,
        path: normalized_path,
        name: leaf_name,
        is_directory: stat_info.is_directory,
        password_required: password_hash.is_some(),
        expires_at: expires_at_rfc3339,
        allow_download,
        created_at: created_at_rfc3339,
        url: Some(format!("/share?token={raw_token}")),
    };

    Ok((record, raw_token))
}

pub(super) fn share_audit_error_code(err: &McBrowserError) -> &'static str {
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

pub(crate) fn list_shares_at(
    conn: &Connection,
    auth_user: &AuthUser,
) -> Result<Vec<ShareRecord>, McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    load_active_quota_conn(conn, user_id, 0)?;
    let raw_scope = crate::mcbrowser::policy::effective_scope_with_conn(conn, user_id)?;
    let current_scope = crate::mcbrowser::policy::normalize_scope_path(&raw_scope)?;

    let now = Utc::now();
    let mut stmt = conn
        .prepare(
            "SELECT id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
                    target_path, target_name, is_directory, target_dev, target_ino, \
                    password_hash, allow_download, expires_at, expires_at_unix, revoked, \
                    created_at \
             FROM mcbrowser_shares \
             WHERE owner_user_id = ?1 AND revoked = 0 \
             ORDER BY created_at_unix DESC, id DESC",
        )
        .map_err(|_| McBrowserError::Internal("Failed to query shares".to_string()))?;

    let rows: Vec<StoredShareRow> = stmt
        .query_map(params![user_id], row_to_stored_share)
        .map_err(|_| McBrowserError::Internal("Failed to read shares".to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| McBrowserError::Internal("Failed to decode share row".to_string()))?;

    let shares = rows
        .into_iter()
        .filter(|row| !is_share_expired(row, now) && row.owner_scope == current_scope)
        .map(|row| stored_to_share_record(&row, None))
        .collect();

    Ok(shares)
}

pub(crate) fn delete_share_at(
    conn: &Connection,
    auth_user: &AuthUser,
    share_id: &str,
) -> Result<(), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let clean_id = share_id.trim();
    if clean_id.is_empty() || clean_id.len() > 128 {
        return Err(McBrowserError::NotFound("Share not found".to_string()));
    }

    crate::mcbrowser::events::ensure_events_tables(conn)?;
    let target_path: Option<String> = conn
        .query_row(
            "SELECT target_path FROM mcbrowser_shares WHERE id = ?1 AND owner_user_id = ?2 AND revoked = 0",
            params![clean_id, user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to query share for revocation".to_string()))?;

    let Some(target_path) = target_path else {
        return Err(McBrowserError::NotFound("Share not found".to_string()));
    };

    let pending = crate::mcbrowser::events::record_pending_intent_with_conn(
        conn,
        auth_user,
        crate::mcbrowser::events::McBrowserEventTrigger::ShareRevoked,
        &target_path,
        None,
        0,
    )?;

    conn.execute_batch("SAVEPOINT mcbrowser_share_revoke")
        .map_err(|_| {
            let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &pending.event.event_id,
                Some("INTERNAL_ERROR"),
            );
            McBrowserError::Internal("Failed to begin share revocation transaction".to_string())
        })?;

    let revoke_res = (|| -> Result<(), McBrowserError> {
        let updated = conn
            .execute(
                "UPDATE mcbrowser_shares SET revoked = 1 \
                 WHERE id = ?1 AND owner_user_id = ?2 AND revoked = 0",
                params![clean_id, user_id],
            )
            .map_err(|_| McBrowserError::Internal("Failed to revoke share".to_string()))?;

        if updated == 0 {
            return Err(McBrowserError::NotFound("Share not found".to_string()));
        }

        crate::mcbrowser::events::finalize_event_completed_with_conn(
            conn,
            &pending.event.event_id,
            None,
            None,
            0,
        )?;

        conn.execute_batch("RELEASE mcbrowser_share_revoke")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit share revocation".to_string())
            })?;
        Ok(())
    })();

    if let Err(err) = revoke_res {
        let _ = conn
            .execute_batch("ROLLBACK TO mcbrowser_share_revoke; RELEASE mcbrowser_share_revoke");
        let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
            conn,
            &pending.event.event_id,
            Some(share_audit_error_code(&err)),
        );
        return Err(err);
    }

    revoke_unlock_sessions_for_share(clean_id);
    Ok(())
}

pub(crate) fn get_public_metadata_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
) -> Result<PublicShareMetadataResponse, McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;

    // Open owner's configured scoped root and verify scope & scoped-root inode have not changed
    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    // Re-evaluate owner's Share & Read policy on the shared path
    authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)?;

    if share.is_directory {
        let _ = open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
    } else {
        let _ = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
    }

    Ok(PublicShareMetadataResponse {
        name: share.target_name,
        is_directory: share.is_directory,
        password_required: share.password_hash.is_some(),
        allow_download: share.allow_download,
        expires_at: share.expires_at,
    })
}

#[allow(clippy::result_large_err)]
pub(crate) fn unlock_public_share_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    password: &str,
    client_ip: &str,
) -> Result<(StoredShareRow, String, i64), Response> {
    let now = Utc::now();
    let now_inst = Instant::now();

    // Check IP-level brute-force throttle even before token lookup so invalid tokens cannot bypass IP limits
    let trimmed_token = raw_token.trim();
    let candidate_hash = hash_share_token(trimmed_token);
    {
        let mut throttle = match UNLOCK_THROTTLE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if throttle.is_throttled(client_ip, &candidate_hash, now_inst) {
            return Err(api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_REQUESTS",
                "Too many failed password attempts. Please try again later.",
            ));
        }
    }

    let share = match load_active_share_by_token(conn, trimmed_token, now) {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
                throttle.record_failure(client_ip, &candidate_hash, now_inst);
            }
            return Err(public_share_error_response(e));
        }
    };

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)
        .map_err(public_share_error_response)?;

    let scoped_root =
        open_verified_user_root_fd(conn, base_root, share.owner_user_id).map_err(|_| {
            public_share_error_response(McBrowserError::NotFound(
                "Share is no longer available".to_string(),
            ))
        })?;
    verify_share_scope_matches(&share, &scoped_root).map_err(public_share_error_response)?;

    authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)
        .map_err(public_share_error_response)?;

    if share.is_directory {
        open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )
        .map_err(public_share_error_response)?;
    } else {
        open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )
        .map_err(public_share_error_response)?;
    }

    if let Some(ref stored_pw_hash) = share.password_hash {
        if !verify_share_password_constant_time(password, stored_pw_hash) {
            if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
                throttle.record_failure(client_ip, &share.token_hash, now_inst);
            }
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "SHARE_PASSWORD_INVALID",
                "Invalid share password",
            ));
        }
        if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
            throttle.clear_share_ip(client_ip, &share.token_hash);
        }
    }

    let (access_token, ttl_secs) = mint_scoped_unlock_token(&share, now.timestamp());
    Ok((share, access_token, ttl_secs))
}

pub(super) fn require_unlocked_if_password_protected(
    headers: &HeaderMap,
    share: &StoredShareRow,
    now_unix: i64,
) -> Result<(), McBrowserError> {
    if share.password_hash.is_none() {
        return Ok(());
    }
    let Some(cred) = extract_unlock_credential(headers, share) else {
        return Err(McBrowserError::Unauthorized(
            "Password authentication is required to access this share".to_string(),
        ));
    };
    if !verify_scoped_unlock_token(&cred, share, now_unix) {
        return Err(McBrowserError::Unauthorized(
            "Share access credential is invalid or has expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn list_public_entries_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    raw_sub_path: &str,
    headers: &HeaderMap,
) -> Result<PublicEntriesResponse, McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    require_unlocked_if_password_protected(headers, &share, now.timestamp())?;

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;
    let normalized_sub_path = normalize_relative_path(raw_sub_path, true)?;

    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    if !share.is_directory {
        // Single-file share: never expose parent directory or sibling files!
        if !normalized_sub_path.is_empty() {
            return Err(McBrowserError::BadRequest(
                "Single-file share does not support directory path traversal".to_string(),
            ));
        }
        authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)?;
        let (_file, entry) = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
        return Ok(PublicEntriesResponse {
            path: String::new(),
            entries: vec![entry],
        });
    }

    // Directory share: re-evaluate owner policy on share root and every segment down to `normalized_sub_path`
    authorize_owner_share_subpath(
        conn,
        policy,
        &owner_user,
        &share.target_path,
        &normalized_sub_path,
        false,
    )?;

    let (scoped_bfs, root_paths) = open_verified_shared_directory_fs(
        conn,
        policy,
        &owner_user,
        &scoped_root.bfs,
        &share,
        false,
    )?;
    let listing = scoped_bfs
        .list_with_trace_resolving_internal_links(&normalized_sub_path)
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => {
                McBrowserError::NotFound("Requested directory was not found".to_string())
            }
            ErrorKind::InvalidInput | ErrorKind::InvalidData => {
                McBrowserError::BadRequest("Invalid directory path".to_string())
            }
            ErrorKind::PermissionDenied => {
                McBrowserError::Forbidden("Access to directory is not permitted".to_string())
            }
            _ => map_fs_io_error(e, "Failed to list shared directory"),
        })?;
    authorize_shared_relative_resolution(
        conn,
        policy,
        &owner_user,
        &root_paths,
        &normalized_sub_path,
        &listing.resolution_paths,
        &listing.resolved_path,
        false,
    )?;

    let mut filtered_entries = Vec::with_capacity(listing.entries.len());
    for listed in listing.entries {
        let alias_path = if normalized_sub_path.is_empty() {
            listed.name.clone()
        } else {
            format!("{normalized_sub_path}/{}", listed.name)
        };
        let Ok(resolved) = scoped_bfs.metadata_resolving_internal_links(&alias_path) else {
            continue;
        };
        if authorize_shared_relative_resolution(
            conn,
            policy,
            &owner_user,
            &root_paths,
            &alias_path,
            &resolved.resolution_paths,
            &resolved.resolved_path,
            false,
        )
        .is_err()
        {
            continue;
        }
        let mut entry = resolved.entry;
        entry.name = listed.name;
        entry.path = alias_path;
        filtered_entries.push(entry);
    }

    Ok(PublicEntriesResponse {
        path: normalized_sub_path,
        entries: filtered_entries,
    })
}

pub(crate) fn open_public_download_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    raw_sub_path: &str,
    headers: &HeaderMap,
) -> Result<(File, String, u64, ParsedByteRange), McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    require_unlocked_if_password_protected(headers, &share, now.timestamp())?;

    if !share.allow_download {
        return Err(McBrowserError::Forbidden(
            "Downloads are disabled for this share".to_string(),
        ));
    }

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;
    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    let (mut file, download_name) = if !share.is_directory {
        // Single-file share: only empty path or exact leaf filename is permitted
        let normalized_sub = normalize_relative_path(raw_sub_path, true)?;
        if !normalized_sub.is_empty() && normalized_sub != share.target_name {
            return Err(McBrowserError::Forbidden(
                "Requested path is outside the shared file scope".to_string(),
            ));
        }
        authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", true)?;
        let (f, _) = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            true,
        )?;
        (f, share.target_name.clone())
    } else {
        // Directory share: require a non-empty relative file path beneath the shared folder
        let normalized_sub = normalize_relative_path(raw_sub_path, false)?;
        authorize_owner_share_subpath(
            conn,
            policy,
            &owner_user,
            &share.target_path,
            &normalized_sub,
            true,
        )?;
        let (scoped_bfs, root_paths) = open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            true,
        )?;
        let opened = scoped_bfs
            .open_file_resolving_internal_links(&normalized_sub)
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => {
                    McBrowserError::NotFound("Requested file was not found".to_string())
                }
                ErrorKind::InvalidInput | ErrorKind::InvalidData => McBrowserError::BadRequest(
                    "Requested path is not a downloadable file".to_string(),
                ),
                ErrorKind::PermissionDenied => McBrowserError::Forbidden(
                    "Access to requested file is not permitted".to_string(),
                ),
                _ => map_fs_io_error(e, "Failed to open shared file"),
            })?;
        authorize_shared_relative_resolution(
            conn,
            policy,
            &owner_user,
            &root_paths,
            &normalized_sub,
            &opened.resolution_paths,
            &opened.resolved_path,
            true,
        )?;
        let f = opened.file;
        let leaf = normalized_sub
            .rsplit('/')
            .next()
            .unwrap_or("download")
            .to_string();
        (f, leaf)
    };

    let meta = file
        .metadata()
        .map_err(|_| McBrowserError::Internal("Failed to read shared file metadata".to_string()))?;
    let total_size = meta.len();

    let range_hdr = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let parsed_range = parse_single_byte_range(range_hdr.as_deref(), total_size)?;
    if let ParsedByteRange::Partial { start, .. } = parsed_range {
        file.seek(SeekFrom::Start(start)).map_err(|_| {
            McBrowserError::Internal("Failed to seek shared file for range download".to_string())
        })?;
    }

    Ok((file, download_name, total_size, parsed_range))
}
