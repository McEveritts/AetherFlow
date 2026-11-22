use super::copy::{
    allocate_version_suffix_path, validate_conflict_destination,
    validate_distinct_non_nested_paths, MAX_VERSION_SUFFIX_ATTEMPTS,
};
use super::types::{CopyMoveResponse, OperationConflictPolicy, RenameMoveRequest};
use super::MAX_SEARCH_ENTRIES;
use crate::auth::AuthUser;
use crate::mcbrowser::{
    load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    open_configured_user_browser_fs_with_conn, release_user_quota_conn, user_mutation_stripe,
    validate_mcbrowser_user, McBrowserError,
};
use af_files::BrowserFs;
use std::io::ErrorKind;

pub(super) fn move_single_file_overwrite_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_path: &str,
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, 0)?;
    let expected_target = bfs.open_file(destination_path).map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to open existing destination file for rename overwrite",
        )
    })?;
    let replaced_bytes = bfs
        .replace_file_by_rename(source_path, destination_path, &expected_target)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => McBrowserError::Conflict(
                "Destination file changed concurrently during rename overwrite".to_string(),
            ),
            _ => map_fs_io_error(error, "Failed to overwrite destination file by rename"),
        })?;
    if replaced_bytes > 0 {
        *accounting_complete &= release_user_quota_conn(conn, user_id, replaced_bytes).is_ok();
    }
    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, source_path);
    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, destination_path);
    Ok(())
}

pub(super) fn execute_rename_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    let from_prefix = validate_conflict_destination(from_path, to_path, "move", conflict_policy)?;
    load_active_quota_conn(conn, user_id, 0)?;

    let src_meta = bfs
        .metadata(from_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source entry for rename"))?;
    if src_meta.kind != "file" && src_meta.kind != "directory" && src_meta.kind != "symlink" {
        return Err(McBrowserError::Forbidden(
            "Cannot rename special files".to_string(),
        ));
    }

    let source_descendants = if src_meta.kind == "directory" {
        bfs.walk(from_path, MAX_SEARCH_ENTRIES).map_err(|error| {
            map_fs_io_error(error, "Failed to inspect source directory for rename")
        })?
    } else {
        Vec::new()
    };

    let dst_meta_opt = match bfs.metadata(to_path) {
        Ok(entry) => Some(entry),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(map_fs_io_error(
                error,
                "Failed to inspect rename destination",
            ))
        }
    };

    match (conflict_policy, dst_meta_opt) {
        (_, None) => {
            bfs.rename_allowing_leaf_symlink(from_path, to_path)
                .map_err(|error| map_fs_io_error(error, "Failed to rename entry"))?;
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, from_path);
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, to_path);
            Ok(to_path.to_string())
        }
        (OperationConflictPolicy::Error, Some(_)) => Err(McBrowserError::Conflict(
            "Failed to rename entry: destination path already exists".to_string(),
        )),
        (OperationConflictPolicy::KeepBoth, Some(_)) => {
            let mut next_index = 1usize;
            for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
                let (candidate_to, allocated_index) =
                    allocate_version_suffix_path(bfs, to_path, next_index)?;
                let _ = validate_distinct_non_nested_paths(from_path, &candidate_to, "move")?;
                match bfs.rename_allowing_leaf_symlink(from_path, &candidate_to) {
                    Ok(()) => {
                        crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, from_path);
                        crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, &candidate_to);
                        return Ok(candidate_to);
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        next_index = allocated_index.saturating_add(1);
                        continue;
                    }
                    Err(error) => {
                        return Err(map_fs_io_error(error, "Failed to rename entry"));
                    }
                }
            }
            Err(McBrowserError::Conflict(
                "Failed to allocate a unique versioned destination filename".to_string(),
            ))
        }
        (OperationConflictPolicy::Overwrite, Some(dst_meta)) => {
            if src_meta.kind == "symlink" || dst_meta.kind == "symlink" {
                return Err(McBrowserError::Forbidden(
                    "Overwriting with or replacing symlinks is not permitted".to_string(),
                ));
            }
            if dst_meta.kind != "file" && dst_meta.kind != "directory" {
                return Err(McBrowserError::Forbidden(
                    "Cannot overwrite special files".to_string(),
                ));
            }
            if src_meta.kind != dst_meta.kind {
                return Err(McBrowserError::Conflict(
                    "Cannot overwrite destination entry with a different entry type".to_string(),
                ));
            }

            if src_meta.kind == "file" {
                move_single_file_overwrite_with_quota(
                    conn,
                    bfs,
                    from_path,
                    to_path,
                    user_id,
                    accounting_complete,
                )?;
                return Ok(to_path.to_string());
            }

            for child in &source_descendants {
                if child.kind != "file" && child.kind != "directory" && child.kind != "symlink" {
                    return Err(McBrowserError::Forbidden(
                        "Cannot move special files".to_string(),
                    ));
                }
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_child_path = format!("{to_path}/{rel_suffix}");
                if let Ok(existing_dst_child) = bfs.metadata(&dst_child_path) {
                    if child.kind == "symlink" || existing_dst_child.kind == "symlink" {
                        return Err(McBrowserError::Forbidden(
                            "Overwriting with or replacing symlinks is not permitted".to_string(),
                        ));
                    }
                    if existing_dst_child.kind != "file" && existing_dst_child.kind != "directory" {
                        return Err(McBrowserError::Forbidden(
                            "Cannot overwrite special files".to_string(),
                        ));
                    }
                    if existing_dst_child.kind != child.kind {
                        return Err(McBrowserError::Conflict(format!(
                            "Cannot overwrite destination descendant '{dst_child_path}' with a different entry type"
                        )));
                    }
                }
            }

            let mut directories_to_remove = Vec::new();
            for child in &source_descendants {
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_child_path = format!("{to_path}/{rel_suffix}");
                match child.kind.as_str() {
                    "directory" => match bfs.metadata(&dst_child_path) {
                        Ok(existing) if existing.kind == "directory" => {
                            directories_to_remove.push(child.path.clone());
                        }
                        Ok(_) => {
                            return Err(McBrowserError::Conflict(format!(
                                "Cannot overwrite non-directory '{dst_child_path}' with a directory"
                            )));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.create_directory(&dst_child_path).map_err(|err| {
                                map_fs_io_error(err, "Failed to create destination subdirectory")
                            })?;
                            directories_to_remove.push(child.path.clone());
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination subdirectory",
                            ));
                        }
                    },
                    "file" => match bfs.metadata(&dst_child_path) {
                        Ok(existing) if existing.kind == "file" => {
                            move_single_file_overwrite_with_quota(
                                conn,
                                bfs,
                                &child.path,
                                &dst_child_path,
                                user_id,
                                accounting_complete,
                            )?;
                        }
                        Ok(_) => {
                            return Err(McBrowserError::Conflict(format!(
                                "Cannot overwrite non-file '{dst_child_path}' with a file"
                            )));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.rename(&child.path, &dst_child_path).map_err(|err| {
                                map_fs_io_error(
                                    err,
                                    "Failed to move file into destination directory",
                                )
                            })?;
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination file during directory move",
                            ));
                        }
                    },
                    "symlink" => match bfs.metadata(&dst_child_path) {
                        Ok(_) => {
                            return Err(McBrowserError::Forbidden(
                                "Overwriting with or replacing symlinks is not permitted"
                                    .to_string(),
                            ));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.rename_allowing_leaf_symlink(&child.path, &dst_child_path)
                                .map_err(|err| {
                                    map_fs_io_error(
                                        err,
                                        "Failed to move symlink into destination directory",
                                    )
                                })?;
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination symlink during directory move",
                            ));
                        }
                    },
                    _ => {
                        return Err(McBrowserError::Forbidden(
                            "Cannot move special files".to_string(),
                        ));
                    }
                }
            }

            for dir_path in directories_to_remove.iter().rev() {
                bfs.remove(dir_path).map_err(|error| {
                    map_fs_io_error(error, "Failed to remove merged source subdirectory")
                })?;
            }
            bfs.remove(from_path).map_err(|error| {
                map_fs_io_error(error, "Failed to remove merged source directory")
            })?;
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, from_path);
            crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, to_path);

            Ok(to_path.to_string())
        }
    }
}

pub(super) fn authorize_symlink_target_if_internal(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    symlink_path: &str,
) -> Result<(), McBrowserError> {
    if let Ok(resolved) = bfs.metadata_resolving_internal_links(symlink_path) {
        for resolution_path in resolved
            .resolution_paths
            .iter()
            .chain(std::iter::once(&resolved.resolved_path))
        {
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Read,
                resolution_path,
            )?;
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Rename,
                resolution_path,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn execute_rename_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    execute_rename_for_user_with_accounting_conn(
        conn,
        bfs,
        auth_user,
        from_path,
        to_path,
        conflict_policy,
        &mut true,
    )
}

pub(super) fn execute_rename_for_user_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_from = crate::mcbrowser::policy::normalize_target_path(from_path, false)?;
    let normalized_to = crate::mcbrowser::policy::normalize_target_path(to_path, false)?;
    let from_prefix =
        validate_conflict_destination(&normalized_from, &normalized_to, "move", conflict_policy)?;

    crate::mcbrowser::policy::authorize_with_conn(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Rename,
        &normalized_from,
    )?;

    let src_meta = bfs
        .metadata(&normalized_from)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source entry for rename"))?;
    if src_meta.kind == "symlink" {
        authorize_symlink_target_if_internal(conn, bfs, auth_user, &normalized_from)?;
    }

    let source_descendants = if src_meta.kind == "directory" {
        crate::mcbrowser::policy::authorize_recursive_paths_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Rename,
            [normalized_from.as_str()],
        )?;
        let descendants = bfs
            .walk(&normalized_from, MAX_SEARCH_ENTRIES)
            .map_err(|error| {
                map_fs_io_error(error, "Failed to inspect source directory for rename")
            })?;
        for child in &descendants {
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Rename,
                &child.path,
            )?;
            if child.kind == "symlink" {
                authorize_symlink_target_if_internal(conn, bfs, auth_user, &child.path)?;
            }
        }
        descendants
    } else {
        Vec::new()
    };

    let dst_exists = match bfs.metadata(&normalized_to) {
        Ok(_) => true,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => {
            return Err(map_fs_io_error(
                error,
                "Failed to inspect rename destination",
            ))
        }
    };

    let target_to = if conflict_policy == OperationConflictPolicy::KeepBoth && dst_exists {
        let (candidate, _) = allocate_version_suffix_path(bfs, &normalized_to, 1)?;
        candidate
    } else {
        normalized_to.clone()
    };

    crate::mcbrowser::policy::authorize_with_conn(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Rename,
        &target_to,
    )?;
    if conflict_policy == OperationConflictPolicy::Overwrite && dst_exists {
        crate::mcbrowser::policy::authorize_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Modify,
            &target_to,
        )?;
    }

    for child in &source_descendants {
        let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
            McBrowserError::Internal("Invalid source descendant path".to_string())
        })?;
        let dst_descendant = format!("{target_to}/{rel_suffix}");
        crate::mcbrowser::policy::authorize_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Rename,
            &dst_descendant,
        )?;
        if conflict_policy == OperationConflictPolicy::Overwrite
            && dst_exists
            && bfs.metadata(&dst_descendant).is_ok()
        {
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Modify,
                &dst_descendant,
            )?;
        }
    }

    if conflict_policy == OperationConflictPolicy::KeepBoth && dst_exists {
        load_active_quota_conn(conn, user_id, 0)?;
        let mut next_index = 1usize;
        for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
            let (candidate_to, allocated_index) =
                allocate_version_suffix_path(bfs, &normalized_to, next_index)?;
            let _ = validate_distinct_non_nested_paths(&normalized_from, &candidate_to, "move")?;
            crate::mcbrowser::policy::authorize_with_conn(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Rename,
                &candidate_to,
            )?;
            for child in &source_descendants {
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_descendant = format!("{candidate_to}/{rel_suffix}");
                crate::mcbrowser::policy::authorize_with_conn(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Rename,
                    &dst_descendant,
                )?;
            }
            match bfs.rename_allowing_leaf_symlink(&normalized_from, &candidate_to) {
                Ok(()) => {
                    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, &normalized_from);
                    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, &candidate_to);
                    return Ok(candidate_to);
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    next_index = allocated_index.saturating_add(1);
                    continue;
                }
                Err(error) => {
                    return Err(map_fs_io_error(error, "Failed to rename entry"));
                }
            }
        }
        return Err(McBrowserError::Conflict(
            "Failed to allocate a unique versioned destination filename".to_string(),
        ));
    }

    execute_rename_with_accounting_conn(
        conn,
        bfs,
        &normalized_from,
        &normalized_to,
        conflict_policy,
        user_id,
        accounting_complete,
    )
}

pub(crate) async fn execute_rename_request(
    auth_user: AuthUser,
    req: RenameMoveRequest,
) -> Result<CopyMoveResponse, McBrowserError> {
    let user_id = validate_mcbrowser_user(&auth_user)?;
    let from_path = normalize_relative_path(&req.from, false)?;
    let to_path = normalize_relative_path(&req.to, false)?;
    let conflict_policy = req.resolved_conflict_policy()?;
    let _ = validate_conflict_destination(&from_path, &to_path, "move", conflict_policy)?;

    let from_for_task = from_path.clone();
    let to_for_task = to_path;
    let user_for_task = auth_user;

    let task_res =
        tokio::task::spawn_blocking(move || -> Result<(String, bool), McBrowserError> {
            let _guard = user_mutation_stripe(user_id).blocking_lock_owned();
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for rename operation".to_string())
            })?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let previous_usage = load_active_quota_conn(&conn, user_id, 0)?.used_bytes;
            let audit = crate::mcbrowser::events::record_pending_intent_with_conn(
                &conn,
                &user_for_task,
                crate::mcbrowser::events::McBrowserEventTrigger::EntryRenamed,
                &from_for_task,
                Some(&to_for_task),
                0,
            )?;
            let mut accounting_complete = true;
            let final_to = execute_rename_for_user_with_accounting_conn(
                &conn,
                &bfs,
                &user_for_task,
                &from_for_task,
                &to_for_task,
                conflict_policy,
                &mut accounting_complete,
            )?;
            if let Some(quota) = load_active_quota_conn(&conn, user_id, 0)
                .ok()
                .filter(|_| accounting_complete)
            {
                crate::mcbrowser::events::finalize_published_mutation_with_conn(
                    &conn,
                    &audit,
                    None,
                    Some(&final_to),
                    quota.used_bytes.saturating_sub(previous_usage),
                );
            }
            Ok((final_to, !accounting_complete))
        })
        .await;

    match task_res {
        Ok(Ok((final_to, accounting_pending))) => Ok(CopyMoveResponse {
            success: true,
            path: final_to.clone(),
            from: from_path,
            to: final_to,
            accounting_pending,
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(McBrowserError::Internal("Rename task failed".to_string())),
    }
}
