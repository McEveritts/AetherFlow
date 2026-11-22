use super::types::{CopyMoveResponse, CopyRequest, OperationConflictPolicy};
use super::MAX_SEARCH_ENTRIES;
use crate::auth::AuthUser;
use crate::mcbrowser::{
    check_fd_free_space, load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    open_configured_user_browser_fs_with_conn, release_user_quota_conn, reserve_user_quota_atomic,
    user_mutation_stripe, validate_mcbrowser_user, McBrowserError,
};
use af_files::BrowserFs;
use axum::extract::Extension;
use axum::response::{IntoResponse, Json, Response};
use std::fs::File;
use std::io::{self, ErrorKind, Write};
use std::os::fd::AsRawFd;

pub(super) const MAX_VERSION_SUFFIX_ATTEMPTS: usize = 10_000;

pub fn split_version_suffix_stem_and_ext(leaf_name: &str) -> (&str, &str) {
    match leaf_name.rfind('.') {
        Some(dot_index) => (&leaf_name[..dot_index], &leaf_name[dot_index..]),
        None => (leaf_name, ""),
    }
}

pub fn format_version_suffix_candidate(normalized_path: &str, version_index: usize) -> String {
    let (parent_prefix, leaf_name) = match normalized_path.rsplit_once('/') {
        Some((parent, leaf)) => (Some(parent), leaf),
        None => (None, normalized_path),
    };
    let (stem, extension) = split_version_suffix_stem_and_ext(leaf_name);
    let suffixed_leaf = format!("{stem}({version_index}){extension}");
    match parent_prefix {
        Some(parent) if !parent.is_empty() => format!("{parent}/{suffixed_leaf}"),
        _ => suffixed_leaf,
    }
}

pub fn allocate_version_suffix_path(
    bfs: &BrowserFs,
    base_path: &str,
    start_index: usize,
) -> Result<(String, usize), McBrowserError> {
    let normalized_base = normalize_relative_path(base_path, false)?;
    let initial_index = start_index.max(1);
    for offset in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
        let candidate_index = initial_index.saturating_add(offset);
        let candidate_path = format_version_suffix_candidate(&normalized_base, candidate_index);
        let validated_candidate = crate::mcbrowser::policy::normalize_target_path(&candidate_path, false)?;
        match bfs.metadata(&validated_candidate) {
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok((validated_candidate, candidate_index));
            }
            Err(error) => {
                return Err(map_fs_io_error(
                    error,
                    "Failed to inspect versioned destination candidate",
                ));
            }
        }
    }
    Err(McBrowserError::Conflict(
        "Failed to allocate a unique versioned destination filename".to_string(),
    ))
}

pub(super) fn validate_distinct_non_nested_paths(
    from_path: &str,
    to_path: &str,
    action_verb: &str,
) -> Result<String, McBrowserError> {
    if from_path == to_path {
        return Err(McBrowserError::BadRequest(
            "Source and destination paths must be different".to_string(),
        ));
    }
    let from_prefix = format!("{from_path}/");
    if to_path.starts_with(&from_prefix) {
        return Err(McBrowserError::BadRequest(format!(
            "Cannot {action_verb} a directory into itself"
        )));
    }
    Ok(from_prefix)
}

pub(super) fn validate_conflict_destination(
    from_path: &str,
    to_path: &str,
    action_verb: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    if from_path == to_path && conflict_policy == OperationConflictPolicy::KeepBoth {
        return Ok(format!("{from_path}/"));
    }
    validate_distinct_non_nested_paths(from_path, to_path, action_verb)
}

#[cfg(test)]
pub(super) fn copy_single_file_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_path: &str,
    destination_path: &str,
    expected_bytes: u64,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    match bfs.copy(source_path, destination_path) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(map_fs_io_error(copy_err, "Failed to copy entry"))
        }
    }
}

pub(super) const MAX_COPY_DIRECTORY_DEPTH: usize = 64;

pub(super) enum PlannedCopyDescendant {
    Directory {
        rel_suffix: String,
    },
    File {
        rel_suffix: String,
        file: File,
        size: u64,
    },
}

impl PlannedCopyDescendant {
    fn rel_suffix(&self) -> &str {
        match self {
            Self::Directory { rel_suffix } | Self::File { rel_suffix, .. } => rel_suffix,
        }
    }

    fn kind_str(&self) -> &'static str {
        match self {
            Self::Directory { .. } => "directory",
            Self::File { .. } => "file",
        }
    }
}

pub(super) enum CopySourcePlan {
    File {
        file: File,
        size: u64,
        resolved_path: String,
    },
    Directory {
        resolved_directory_paths: Vec<String>,
        descendants: Vec<PlannedCopyDescendant>,
    },
}

impl CopySourcePlan {
    fn kind_str(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Directory { .. } => "directory",
        }
    }
}

pub(super) fn push_unique_copy_hop(hops: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !hops.iter().any(|existing| existing == candidate) {
        hops.push(candidate.to_string());
    }
}

pub(super) fn authorize_copy_permission_if_user(
    conn: &rusqlite::Connection,
    auth_user: Option<&AuthUser>,
    permission: crate::mcbrowser::policy::Permission,
    target_path: &str,
) -> Result<(), McBrowserError> {
    if let Some(user) = auth_user {
        crate::mcbrowser::policy::authorize_with_conn(conn, user, permission, target_path)?;
    }
    Ok(())
}

pub(super) fn verify_pinned_copy_source_metadata(
    source_file: &File,
) -> Result<std::fs::Metadata, McBrowserError> {
    let source_meta = source_file
        .metadata()
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source file for copy"))?;
    if std::os::unix::fs::MetadataExt::nlink(&source_meta) > 1 {
        return Err(McBrowserError::Forbidden(
            "Hardlinked copy sources are not permitted".to_string(),
        ));
    }
    Ok(source_meta)
}

pub(super) fn stage_and_commit_pinned_file_new(
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    expected_bytes: u64,
) -> Result<u64, McBrowserError> {
    let _ = verify_pinned_copy_source_metadata(source_file)?;
    std::io::Seek::seek(source_file, std::io::SeekFrom::Start(0))
        .map_err(|error| map_fs_io_error(error, "Failed to rewind source file for copy"))?;
    let mut pending = bfs
        .begin_upload(destination_path)
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    let staging_file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to access staging file for copy"))?;
    check_fd_free_space(staging_file.as_raw_fd(), expected_bytes.max(1))?;
    let actual_bytes = io::copy(source_file, &mut pending)
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    pending
        .flush()
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    pending
        .commit()
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    Ok(actual_bytes)
}

pub(super) fn copy_pinned_file_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    expected_bytes: u64,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    match stage_and_commit_pinned_file_new(bfs, source_file, destination_path, expected_bytes) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(copy_err)
        }
    }
}

pub(super) fn copy_pinned_file_overwrite_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    let source_meta = verify_pinned_copy_source_metadata(source_file)?;
    std::io::Seek::seek(source_file, std::io::SeekFrom::Start(0))
        .map_err(|error| map_fs_io_error(error, "Failed to rewind source file for copy"))?;
    let source_size = source_meta.len();

    let expected_target = bfs.open_file(destination_path).map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to open existing destination file for overwrite",
        )
    })?;
    let target_meta = expected_target.metadata().map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to inspect existing destination file for overwrite",
        )
    })?;
    let old_size = target_meta.len();

    let additional_needed = source_size.saturating_sub(old_size);
    load_active_quota_conn(conn, user_id, additional_needed)?;

    let mut pending = bfs
        .begin_replace(destination_path)
        .map_err(|error| map_fs_io_error(error, "Failed to stage file copy overwrite"))?;
    let staging_file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to access staging file for copy"))?;
    check_fd_free_space(staging_file.as_raw_fd(), source_size.max(1))?;

    let copied_bytes = io::copy(source_file, &mut pending)
        .map_err(|error| map_fs_io_error(error, "Failed to copy file content"))?;
    pending
        .flush()
        .map_err(|error| map_fs_io_error(error, "Failed to flush copied file content"))?;

    let actual_additional = copied_bytes.saturating_sub(old_size);
    if actual_additional > 0 {
        reserve_user_quota_atomic(conn, user_id, actual_additional)?;
    }

    if let Err(commit_err) = pending.commit_replace(&expected_target) {
        if actual_additional > 0 {
            release_user_quota_conn(conn, user_id, actual_additional).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy was not published; quota cleanup requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(match commit_err.kind() {
            ErrorKind::AlreadyExists | ErrorKind::InvalidInput | ErrorKind::NotFound => {
                McBrowserError::Conflict(
                    "Destination file changed concurrently during copy overwrite".to_string(),
                )
            }
            _ => map_fs_io_error(commit_err, "Failed to commit file copy overwrite"),
        });
    }

    let released_bytes = old_size.saturating_sub(copied_bytes);
    if released_bytes > 0 {
        *accounting_complete &= release_user_quota_conn(conn, user_id, released_bytes).is_ok();
    }
    crate::mcbrowser::media::invalidate_thumbnail_cache(user_id, destination_path);

    Ok(())
}

pub(super) fn populate_planned_directory_tree(
    bfs: &BrowserFs,
    descendants: &mut [PlannedCopyDescendant],
    destination_path: &str,
) -> Result<u64, McBrowserError> {
    let mut actual_bytes = 0u64;
    for descendant in descendants.iter_mut() {
        match descendant {
            PlannedCopyDescendant::Directory { rel_suffix } => {
                let dst_child_path = format!("{destination_path}/{rel_suffix}");
                bfs.create_directory(&dst_child_path)
                    .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
            }
            PlannedCopyDescendant::File {
                rel_suffix,
                file,
                size,
            } => {
                let dst_child_path = format!("{destination_path}/{rel_suffix}");
                let copied_file_bytes =
                    stage_and_commit_pinned_file_new(bfs, file, &dst_child_path, *size)?;
                actual_bytes = actual_bytes.saturating_add(copied_file_bytes);
            }
        }
    }
    Ok(actual_bytes)
}

pub(super) fn copy_planned_directory_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    descendants: &mut [PlannedCopyDescendant],
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    let expected_bytes: u64 = descendants.iter().fold(0u64, |acc, item| match item {
        PlannedCopyDescendant::Directory { .. } => acc,
        PlannedCopyDescendant::File { size, .. } => acc.saturating_add(*size),
    });

    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    if let Err(create_err) = bfs.create_directory(destination_path) {
        if expected_bytes > 0 {
            release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy quota cleanup requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(map_fs_io_error(create_err, "Failed to copy entry"));
    }

    match populate_planned_directory_tree(bfs, descendants, destination_path) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_tree_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            bfs.remove_tree_with_size(destination_path).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy cleanup requires reconciliation".to_string(),
                )
            })?;
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(copy_err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_copy_directory_descendants(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: Option<&AuthUser>,
    from_prefix: &str,
    alias_dir_path: &str,
    inherited_hops: &[String],
    depth: usize,
    active_resolved_dirs: &mut Vec<String>,
    resolved_directory_paths: &mut Vec<String>,
    descendants: &mut Vec<PlannedCopyDescendant>,
) -> Result<(), McBrowserError> {
    if depth > MAX_COPY_DIRECTORY_DEPTH {
        return Err(McBrowserError::BadRequest(
            "Path exceeds maximum directory depth".to_string(),
        ));
    }

    authorize_copy_permission_if_user(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Read,
        alias_dir_path,
    )?;
    for hop in inherited_hops {
        authorize_copy_permission_if_user(conn, auth_user, crate::mcbrowser::policy::Permission::Read, hop)?;
    }

    let listing = bfs
        .list_with_trace_resolving_internal_links(alias_dir_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source directory for copy"))?;
    for hop in &listing.resolution_paths {
        authorize_copy_permission_if_user(conn, auth_user, crate::mcbrowser::policy::Permission::Read, hop)?;
    }
    if !listing.resolved_path.is_empty() {
        authorize_copy_permission_if_user(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Read,
            &listing.resolved_path,
        )?;
    }

    if listing.resolved_path.is_empty()
        || active_resolved_dirs.iter().any(|ancestor| {
            ancestor == &listing.resolved_path
                || ancestor.starts_with(&format!("{}/", listing.resolved_path))
        })
    {
        return Err(McBrowserError::Forbidden(
            "Cannot copy cyclic directory symlink".to_string(),
        ));
    }

    push_unique_copy_hop(resolved_directory_paths, &listing.resolved_path);

    let mut current_dir_hops = Vec::new();
    for hop in inherited_hops {
        push_unique_copy_hop(&mut current_dir_hops, hop);
    }
    push_unique_copy_hop(&mut current_dir_hops, alias_dir_path);
    for hop in &listing.resolution_paths {
        push_unique_copy_hop(&mut current_dir_hops, hop);
    }
    push_unique_copy_hop(&mut current_dir_hops, &listing.resolved_path);

    active_resolved_dirs.push(listing.resolved_path);

    for child in listing.entries {
        if descendants.len() >= MAX_SEARCH_ENTRIES {
            active_resolved_dirs.pop();
            return Err(McBrowserError::Forbidden(
                "Directory tree exceeds maximum entry limit".to_string(),
            ));
        }

        let child_alias_path = format!("{alias_dir_path}/{}", child.name);
        let rel_suffix = match child_alias_path.strip_prefix(from_prefix) {
            Some(suffix) => suffix.to_string(),
            None => {
                active_resolved_dirs.pop();
                return Err(McBrowserError::Internal(
                    "Invalid source descendant path".to_string(),
                ));
            }
        };

        let child_hops: Vec<String> = current_dir_hops
            .iter()
            .map(|dir_hop| format!("{dir_hop}/{}", child.name))
            .collect();

        if let Err(auth_err) = authorize_copy_permission_if_user(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Read,
            &child_alias_path,
        ) {
            active_resolved_dirs.pop();
            return Err(auth_err);
        }
        for child_hop in &child_hops {
            if let Err(auth_err) = authorize_copy_permission_if_user(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Read,
                child_hop,
            ) {
                active_resolved_dirs.pop();
                return Err(auth_err);
            }
        }

        match child.kind.as_str() {
            "file" => {
                let opened = match bfs.open_file_resolving_internal_links(&child_alias_path) {
                    Ok(resolved_file) => resolved_file,
                    Err(error) => {
                        active_resolved_dirs.pop();
                        return Err(map_fs_io_error(
                            error,
                            "Failed to open source file for copy",
                        ));
                    }
                };
                for hop in &opened.resolution_paths {
                    if let Err(auth_err) = authorize_copy_permission_if_user(
                        conn,
                        auth_user,
                        crate::mcbrowser::policy::Permission::Read,
                        hop,
                    ) {
                        active_resolved_dirs.pop();
                        return Err(auth_err);
                    }
                }
                if let Err(auth_err) = authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Read,
                    &opened.resolved_path,
                ) {
                    active_resolved_dirs.pop();
                    return Err(auth_err);
                }
                let file_meta = match verify_pinned_copy_source_metadata(&opened.file) {
                    Ok(meta) => meta,
                    Err(error) => {
                        active_resolved_dirs.pop();
                        return Err(error);
                    }
                };
                descendants.push(PlannedCopyDescendant::File {
                    rel_suffix,
                    file: opened.file,
                    size: file_meta.len(),
                });
            }
            "directory" => {
                descendants.push(PlannedCopyDescendant::Directory { rel_suffix });
                if let Err(sub_err) = collect_copy_directory_descendants(
                    conn,
                    bfs,
                    auth_user,
                    from_prefix,
                    &child_alias_path,
                    &child_hops,
                    depth + 1,
                    active_resolved_dirs,
                    resolved_directory_paths,
                    descendants,
                ) {
                    active_resolved_dirs.pop();
                    return Err(sub_err);
                }
            }
            "symlink" => match bfs.open_file_resolving_internal_links(&child_alias_path) {
                Ok(opened) => {
                    for hop in &opened.resolution_paths {
                        if let Err(auth_err) = authorize_copy_permission_if_user(
                            conn,
                            auth_user,
                            crate::mcbrowser::policy::Permission::Read,
                            hop,
                        ) {
                            active_resolved_dirs.pop();
                            return Err(auth_err);
                        }
                    }
                    if let Err(auth_err) = authorize_copy_permission_if_user(
                        conn,
                        auth_user,
                        crate::mcbrowser::policy::Permission::Read,
                        &opened.resolved_path,
                    ) {
                        active_resolved_dirs.pop();
                        return Err(auth_err);
                    }
                    let file_meta = match verify_pinned_copy_source_metadata(&opened.file) {
                        Ok(meta) => meta,
                        Err(error) => {
                            active_resolved_dirs.pop();
                            return Err(error);
                        }
                    };
                    descendants.push(PlannedCopyDescendant::File {
                        rel_suffix,
                        file: opened.file,
                        size: file_meta.len(),
                    });
                }
                Err(open_err) => {
                    let resolved_child =
                        match bfs.metadata_resolving_internal_links(&child_alias_path) {
                            Ok(resolved) if resolved.entry.kind == "directory" => resolved,
                            Ok(resolved) => {
                                for hop in &resolved.resolution_paths {
                                    if let Err(auth_err) = authorize_copy_permission_if_user(
                                        conn,
                                        auth_user,
                                        crate::mcbrowser::policy::Permission::Read,
                                        hop,
                                    ) {
                                        active_resolved_dirs.pop();
                                        return Err(auth_err);
                                    }
                                }
                                if !resolved.resolved_path.is_empty() {
                                    if let Err(auth_err) = authorize_copy_permission_if_user(
                                        conn,
                                        auth_user,
                                        crate::mcbrowser::policy::Permission::Read,
                                        &resolved.resolved_path,
                                    ) {
                                        active_resolved_dirs.pop();
                                        return Err(auth_err);
                                    }
                                }
                                active_resolved_dirs.pop();
                                return Err(map_fs_io_error(
                                    open_err,
                                    "Failed to open source file for copy",
                                ));
                            }
                            Err(_) => {
                                active_resolved_dirs.pop();
                                return Err(map_fs_io_error(
                                    open_err,
                                    "Failed to inspect source symlink for copy",
                                ));
                            }
                        };
                    for hop in &resolved_child.resolution_paths {
                        if let Err(auth_err) = authorize_copy_permission_if_user(
                            conn,
                            auth_user,
                            crate::mcbrowser::policy::Permission::Read,
                            hop,
                        ) {
                            active_resolved_dirs.pop();
                            return Err(auth_err);
                        }
                    }
                    if !resolved_child.resolved_path.is_empty() {
                        if let Err(auth_err) = authorize_copy_permission_if_user(
                            conn,
                            auth_user,
                            crate::mcbrowser::policy::Permission::Read,
                            &resolved_child.resolved_path,
                        ) {
                            active_resolved_dirs.pop();
                            return Err(auth_err);
                        }
                    }
                    descendants.push(PlannedCopyDescendant::Directory { rel_suffix });
                    let mut symlink_dir_hops = child_hops;
                    for hop in &resolved_child.resolution_paths {
                        push_unique_copy_hop(&mut symlink_dir_hops, hop);
                    }
                    if !resolved_child.resolved_path.is_empty() {
                        push_unique_copy_hop(&mut symlink_dir_hops, &resolved_child.resolved_path);
                    }
                    if let Err(sub_err) = collect_copy_directory_descendants(
                        conn,
                        bfs,
                        auth_user,
                        from_prefix,
                        &child_alias_path,
                        &symlink_dir_hops,
                        depth + 1,
                        active_resolved_dirs,
                        resolved_directory_paths,
                        descendants,
                    ) {
                        active_resolved_dirs.pop();
                        return Err(sub_err);
                    }
                }
            },
            _ => {
                active_resolved_dirs.pop();
                return Err(McBrowserError::Forbidden(
                    "Cannot copy symlinks or special files".to_string(),
                ));
            }
        }
    }

    active_resolved_dirs.pop();
    Ok(())
}

pub(super) fn prepare_copy_source_plan(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    from_prefix: &str,
    auth_user: Option<&AuthUser>,
) -> Result<CopySourcePlan, McBrowserError> {
    authorize_copy_permission_if_user(conn, auth_user, crate::mcbrowser::policy::Permission::Read, from_path)?;

    match bfs.open_file_resolving_internal_links(from_path) {
        Ok(opened) => {
            for hop in &opened.resolution_paths {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Read,
                    hop,
                )?;
            }
            authorize_copy_permission_if_user(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Read,
                &opened.resolved_path,
            )?;
            let file_meta = verify_pinned_copy_source_metadata(&opened.file)?;
            Ok(CopySourcePlan::File {
                file: opened.file,
                size: file_meta.len(),
                resolved_path: opened.resolved_path,
            })
        }
        Err(open_err) => {
            let root_resolved = match bfs.metadata_resolving_internal_links(from_path) {
                Ok(resolved) => resolved,
                Err(_) => {
                    return Err(map_fs_io_error(
                        open_err,
                        "Failed to inspect source entry for copy",
                    ))
                }
            };
            for hop in &root_resolved.resolution_paths {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Read,
                    hop,
                )?;
            }
            if !root_resolved.resolved_path.is_empty() {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Read,
                    &root_resolved.resolved_path,
                )?;
            }
            if root_resolved.entry.kind != "directory" {
                return Err(map_fs_io_error(
                    open_err,
                    "Failed to open source file for copy",
                ));
            }

            let mut active_resolved_dirs = Vec::new();
            let segments: Vec<&str> = from_path.split('/').collect();
            if segments.len() > 1 {
                let mut prefix_acc = String::new();
                for segment in &segments[..segments.len() - 1] {
                    if !prefix_acc.is_empty() {
                        prefix_acc.push('/');
                    }
                    prefix_acc.push_str(segment);
                    if let Ok(resolved_parent) = bfs.metadata_resolving_internal_links(&prefix_acc)
                    {
                        if !resolved_parent.resolved_path.is_empty() {
                            push_unique_copy_hop(
                                &mut active_resolved_dirs,
                                &resolved_parent.resolved_path,
                            );
                        }
                    }
                }
            }

            let mut root_hops = Vec::new();
            push_unique_copy_hop(&mut root_hops, from_path);
            for hop in &root_resolved.resolution_paths {
                push_unique_copy_hop(&mut root_hops, hop);
            }
            if !root_resolved.resolved_path.is_empty() {
                push_unique_copy_hop(&mut root_hops, &root_resolved.resolved_path);
            }

            let mut resolved_directory_paths = Vec::new();
            let mut descendants = Vec::new();
            collect_copy_directory_descendants(
                conn,
                bfs,
                auth_user,
                from_prefix,
                from_path,
                &root_hops,
                1,
                &mut active_resolved_dirs,
                &mut resolved_directory_paths,
                &mut descendants,
            )?;

            Ok(CopySourcePlan::Directory {
                resolved_directory_paths,
                descendants,
            })
        }
    }
}

pub(super) fn validate_resolved_source_against_destination(
    source_plan: &CopySourcePlan,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<(), McBrowserError> {
    let allow_same_for_keep_both =
        from_path == to_path && conflict_policy == OperationConflictPolicy::KeepBoth;
    match source_plan {
        CopySourcePlan::File { resolved_path, .. } => {
            if !allow_same_for_keep_both && to_path == resolved_path {
                return Err(McBrowserError::BadRequest(
                    "Source and destination paths must be different".to_string(),
                ));
            }
        }
        CopySourcePlan::Directory {
            resolved_directory_paths,
            ..
        } => {
            for resolved_dir in resolved_directory_paths {
                if !allow_same_for_keep_both && to_path == resolved_dir {
                    return Err(McBrowserError::BadRequest(
                        "Source and destination paths must be different".to_string(),
                    ));
                }
                let resolved_prefix = format!("{resolved_dir}/");
                if to_path.starts_with(&resolved_prefix) {
                    return Err(McBrowserError::BadRequest(
                        "Cannot copy a directory into itself".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn authorize_destination_tree_for_copy(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: Option<&AuthUser>,
    source_plan: &CopySourcePlan,
    target_to: &str,
    require_modify_on_existing: bool,
) -> Result<(), McBrowserError> {
    authorize_copy_permission_if_user(
        conn,
        auth_user,
        crate::mcbrowser::policy::Permission::Create,
        target_to,
    )?;
    if require_modify_on_existing {
        authorize_copy_permission_if_user(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Modify,
            target_to,
        )?;
    }

    if let CopySourcePlan::Directory { descendants, .. } = source_plan {
        for child in descendants {
            let dst_descendant = format!("{target_to}/{}", child.rel_suffix());
            authorize_copy_permission_if_user(
                conn,
                auth_user,
                crate::mcbrowser::policy::Permission::Create,
                &dst_descendant,
            )?;
            if require_modify_on_existing && bfs.metadata(&dst_descendant).is_ok() {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    crate::mcbrowser::policy::Permission::Modify,
                    &dst_descendant,
                )?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_copy_core_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
    auth_user: Option<&AuthUser>,
) -> Result<String, McBrowserError> {
    let from_prefix = validate_conflict_destination(from_path, to_path, "copy", conflict_policy)?;
    let mut source_plan = prepare_copy_source_plan(conn, bfs, from_path, &from_prefix, auth_user)?;
    validate_resolved_source_against_destination(
        &source_plan,
        from_path,
        to_path,
        conflict_policy,
    )?;

    let dst_meta_opt = match bfs.metadata(to_path) {
        Ok(entry) => Some(entry),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(map_fs_io_error(error, "Failed to inspect copy destination")),
    };

    match (conflict_policy, dst_meta_opt) {
        (_, None) => {
            authorize_destination_tree_for_copy(
                conn,
                bfs,
                auth_user,
                &source_plan,
                to_path,
                false,
            )?;
            match &mut source_plan {
                CopySourcePlan::File { file, size, .. } => {
                    copy_pinned_file_new_with_quota(
                        conn,
                        bfs,
                        file,
                        to_path,
                        *size,
                        user_id,
                        accounting_complete,
                    )?;
                }
                CopySourcePlan::Directory { descendants, .. } => {
                    copy_planned_directory_new_with_quota(
                        conn,
                        bfs,
                        descendants,
                        to_path,
                        user_id,
                        accounting_complete,
                    )?;
                }
            }
            Ok(to_path.to_string())
        }
        (OperationConflictPolicy::Error, Some(_)) => {
            authorize_destination_tree_for_copy(
                conn,
                bfs,
                auth_user,
                &source_plan,
                to_path,
                false,
            )?;
            Err(McBrowserError::Conflict(
                "Failed to copy entry: destination path already exists".to_string(),
            ))
        }
        (OperationConflictPolicy::KeepBoth, Some(_)) => {
            let mut next_index = 1usize;
            for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
                let (candidate_to, allocated_index) =
                    allocate_version_suffix_path(bfs, to_path, next_index)?;
                let _ = validate_distinct_non_nested_paths(from_path, &candidate_to, "copy")?;
                validate_resolved_source_against_destination(
                    &source_plan,
                    from_path,
                    &candidate_to,
                    OperationConflictPolicy::Error,
                )?;
                authorize_destination_tree_for_copy(
                    conn,
                    bfs,
                    auth_user,
                    &source_plan,
                    &candidate_to,
                    false,
                )?;
                let copy_result = match &mut source_plan {
                    CopySourcePlan::File { file, size, .. } => copy_pinned_file_new_with_quota(
                        conn,
                        bfs,
                        file,
                        &candidate_to,
                        *size,
                        user_id,
                        accounting_complete,
                    ),
                    CopySourcePlan::Directory { descendants, .. } => {
                        copy_planned_directory_new_with_quota(
                            conn,
                            bfs,
                            descendants,
                            &candidate_to,
                            user_id,
                            accounting_complete,
                        )
                    }
                };
                match copy_result {
                    Ok(()) => return Ok(candidate_to),
                    Err(McBrowserError::Conflict(_)) => {
                        next_index = allocated_index.saturating_add(1);
                        continue;
                    }
                    Err(other_err) => return Err(other_err),
                }
            }
            Err(McBrowserError::Conflict(
                "Failed to allocate a unique versioned destination filename".to_string(),
            ))
        }
        (OperationConflictPolicy::Overwrite, Some(dst_meta)) => {
            authorize_destination_tree_for_copy(conn, bfs, auth_user, &source_plan, to_path, true)?;

            if dst_meta.kind != "file" && dst_meta.kind != "directory" {
                return Err(McBrowserError::Forbidden(
                    "Cannot overwrite symlinks or special files".to_string(),
                ));
            }
            if source_plan.kind_str() != dst_meta.kind {
                return Err(McBrowserError::Conflict(
                    "Cannot overwrite destination entry with a different entry type".to_string(),
                ));
            }

            match &mut source_plan {
                CopySourcePlan::File { file, .. } => {
                    copy_pinned_file_overwrite_with_quota(
                        conn,
                        bfs,
                        file,
                        to_path,
                        user_id,
                        accounting_complete,
                    )?;
                    Ok(to_path.to_string())
                }
                CopySourcePlan::Directory { descendants, .. } => {
                    for child in descendants.iter() {
                        let dst_child_path = format!("{to_path}/{}", child.rel_suffix());
                        match bfs.metadata(&dst_child_path) {
                            Ok(existing_dst_child) => {
                                if existing_dst_child.kind != "file"
                                    && existing_dst_child.kind != "directory"
                                {
                                    return Err(McBrowserError::Forbidden(
                                        "Cannot overwrite symlinks or special files".to_string(),
                                    ));
                                }
                                if existing_dst_child.kind != child.kind_str() {
                                    return Err(McBrowserError::Conflict(format!(
                                        "Cannot overwrite destination descendant '{dst_child_path}' with a different entry type"
                                    )));
                                }
                            }
                            Err(error) if error.kind() == ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(map_fs_io_error(
                                    error,
                                    "Failed to inspect destination descendant",
                                ));
                            }
                        }
                    }

                    load_active_quota_conn(conn, user_id, 0)?;

                    for child in descendants.iter_mut() {
                        let dst_child_path = format!("{to_path}/{}", child.rel_suffix());
                        match child {
                            PlannedCopyDescendant::Directory { .. } => {
                                match bfs.metadata(&dst_child_path) {
                                    Ok(existing) if existing.kind == "directory" => {}
                                    Ok(existing)
                                        if existing.kind != "file"
                                            && existing.kind != "directory" =>
                                    {
                                        return Err(McBrowserError::Forbidden(
                                            "Cannot overwrite symlinks or special files"
                                                .to_string(),
                                        ));
                                    }
                                    Ok(_) => {
                                        return Err(McBrowserError::Conflict(format!(
                                            "Cannot overwrite non-directory '{dst_child_path}' with a directory"
                                        )));
                                    }
                                    Err(error) if error.kind() == ErrorKind::NotFound => {
                                        bfs.create_directory(&dst_child_path).map_err(|err| {
                                            map_fs_io_error(
                                                err,
                                                "Failed to create destination subdirectory",
                                            )
                                        })?;
                                    }
                                    Err(error) => {
                                        return Err(map_fs_io_error(
                                            error,
                                            "Failed to inspect destination subdirectory",
                                        ));
                                    }
                                }
                            }
                            PlannedCopyDescendant::File { file, size, .. } => {
                                match bfs.metadata(&dst_child_path) {
                                    Ok(existing) if existing.kind == "file" => {
                                        copy_pinned_file_overwrite_with_quota(
                                            conn,
                                            bfs,
                                            file,
                                            &dst_child_path,
                                            user_id,
                                            accounting_complete,
                                        )?;
                                    }
                                    Ok(existing)
                                        if existing.kind != "file"
                                            && existing.kind != "directory" =>
                                    {
                                        return Err(McBrowserError::Forbidden(
                                            "Cannot overwrite symlinks or special files"
                                                .to_string(),
                                        ));
                                    }
                                    Ok(_) => {
                                        return Err(McBrowserError::Conflict(format!(
                                            "Cannot overwrite non-file '{dst_child_path}' with a file"
                                        )));
                                    }
                                    Err(error) if error.kind() == ErrorKind::NotFound => {
                                        copy_pinned_file_new_with_quota(
                                            conn,
                                            bfs,
                                            file,
                                            &dst_child_path,
                                            *size,
                                            user_id,
                                            accounting_complete,
                                        )?;
                                    }
                                    Err(error) => {
                                        return Err(map_fs_io_error(
                                            error,
                                            "Failed to inspect destination file during directory copy",
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    Ok(to_path.to_string())
                }
            }
        }
    }
}

#[cfg(test)]
pub fn execute_copy_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    user_id: i64,
) -> Result<(), McBrowserError> {
    let _ = execute_copy_with_policy_conn(
        conn,
        bfs,
        from_path,
        to_path,
        OperationConflictPolicy::Error,
        user_id,
    )?;
    Ok(())
}

#[cfg(test)]
pub fn execute_copy_with_policy_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
) -> Result<String, McBrowserError> {
    execute_copy_with_accounting_conn(
        conn,
        bfs,
        from_path,
        to_path,
        conflict_policy,
        user_id,
        &mut true,
    )
}

#[cfg(test)]
pub(super) fn execute_copy_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    execute_copy_core_with_accounting_conn(
        conn,
        bfs,
        from_path,
        to_path,
        conflict_policy,
        user_id,
        accounting_complete,
        None,
    )
}

#[cfg(test)]
pub fn execute_copy_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    execute_copy_for_user_with_accounting_conn(
        conn,
        bfs,
        auth_user,
        from_path,
        to_path,
        conflict_policy,
        &mut true,
    )
}

pub(super) fn execute_copy_for_user_with_accounting_conn(
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
    execute_copy_core_with_accounting_conn(
        conn,
        bfs,
        &normalized_from,
        &normalized_to,
        conflict_policy,
        user_id,
        accounting_complete,
        Some(auth_user),
    )
}

pub(super) async fn copy_entry(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CopyRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let from_path = match normalize_relative_path(&req.from, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let to_path = match normalize_relative_path(&req.to, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let conflict_policy = match req.resolved_conflict_policy() {
        Ok(policy) => policy,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = validate_conflict_destination(&from_path, &to_path, "copy", conflict_policy)
    {
        return error.into_response();
    }

    let from_for_task = from_path.clone();
    let to_for_task = to_path;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<(String, bool), McBrowserError> {
        let _guard = user_mutation_stripe(user_id).blocking_lock_owned();
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for copy quota check".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let previous_usage = load_active_quota_conn(&conn, user_id, 0)?.used_bytes;
        let audit = crate::mcbrowser::events::record_pending_intent_with_conn(
            &conn,
            &user_for_task,
            crate::mcbrowser::events::McBrowserEventTrigger::EntryCopied,
            &from_for_task,
            Some(&to_for_task),
            0,
        )?;
        let mut accounting_complete = true;
        let final_to = execute_copy_for_user_with_accounting_conn(
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

    match res {
        Ok(Ok((final_to, accounting_pending))) => Json(CopyMoveResponse {
            success: true,
            path: final_to.clone(),
            from: from_path,
            to: final_to,
            accounting_pending,
        })
        .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Copy task failed".to_string()).into_response(),
    }
}
