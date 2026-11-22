use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Low-Level Safe Filesystem & Inode Verification Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TargetStatInfo {
    pub(super) is_directory: bool,
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) size: u64,
    pub(super) mtime_rfc3339: Option<i64>,
}

pub(super) fn openat_no_symlinks(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u64,
        mode: if (flags & libc::O_CREAT) != 0 {
            mode as u64
        } else {
            0
        },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if rc >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(rc as libc::c_int) });
    }
    let err = Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {}
        _ => return Err(err),
    }

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(super) fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(st)
}

pub(super) struct VerifiedScopedUserRoot {
    pub(super) bfs: BrowserFs,
    pub(super) scope: String,
    pub(super) scope_dev: u64,
    pub(super) scope_ino: u64,
}

/// Opens the owner's configured scoped tenant root directory as both a `BrowserFs` and an
/// `OwnedFd` using the active `Connection` (`crate::mcbrowser::policy::effective_scope_with_conn`) and
/// descriptor-confined traversal (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`),
/// never string canonicalization.
pub(super) fn open_verified_user_root_fd(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let raw_scope = crate::mcbrowser::policy::effective_scope_with_conn(conn, user_id)?;
    let normalized_scope = crate::mcbrowser::policy::normalize_scope_path(&raw_scope)?;

    // Provision and validate the raw user root (`base_root/user-{user_id}`).
    let _raw_bfs = open_user_browser_fs_at(base_root, user_id)?;

    let base_c = CString::new(base_root.as_os_str().as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid McBrowser storage root path".to_string()))?;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let base_fd_raw = unsafe { libc::open(base_c.as_ptr(), dir_flags) };
    if base_fd_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to open McBrowser storage root descriptor".to_string(),
        ));
    }
    let base_fd = unsafe { OwnedFd::from_raw_fd(base_fd_raw) };
    let base_st = fstat_fd(base_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat McBrowser storage root descriptor".to_string())
    })?;
    if (base_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || base_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "McBrowser storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    let child_name = format!("user-{user_id}");
    let child_c = CString::new(child_name.as_bytes()).map_err(|_| {
        McBrowserError::Internal("Failed to construct user storage directory name".to_string())
    })?;
    let mut current_fd = openat_no_symlinks(base_fd.as_raw_fd(), child_c.as_c_str(), dir_flags, 0)
        .map_err(|_| {
            McBrowserError::Internal("Failed to open user storage root descriptor".to_string())
        })?;
    let user_st = fstat_fd(current_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat user storage root descriptor".to_string())
    })?;
    if (user_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || user_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "User storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    for seg in normalized_scope.split('/').filter(|s| !s.is_empty()) {
        let c_seg = CString::new(seg).map_err(|_| {
            McBrowserError::BadRequest("Invalid configured policy scope segment".to_string())
        })?;
        current_fd = openat_no_symlinks(current_fd.as_raw_fd(), c_seg.as_c_str(), dir_flags, 0)
            .map_err(|e| map_fs_io_error(e, "Failed to open configured policy scope"))?;
    }

    let scope_st = fstat_fd(current_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat scoped user storage root descriptor".to_string())
    })?;
    if (scope_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || scope_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "Scoped user storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    let dup_raw = unsafe { libc::fcntl(current_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to duplicate scoped user root descriptor".to_string(),
        ));
    }
    let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
    let scoped_bfs = BrowserFs::from_directory(dup_fd).map_err(|_| {
        McBrowserError::Internal("Failed to initialize scoped user filesystem".to_string())
    })?;

    Ok(VerifiedScopedUserRoot {
        bfs: scoped_bfs,
        scope: normalized_scope,
        scope_dev: scope_st.st_dev as u64,
        scope_ino: scope_st.st_ino as u64,
    })
}

/// Ensures an existing share remains bound to the exact policy scope and scoped-root
/// directory inode `(scope_root_dev, scope_root_ino)` under which it was created.
pub(super) fn verify_share_scope_matches(
    share: &StoredShareRow,
    scoped_root: &VerifiedScopedUserRoot,
) -> Result<(), McBrowserError> {
    if share.owner_scope != scoped_root.scope {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    if (share.scope_root_dev != 0 || share.scope_root_ino != 0)
        && (share.scope_root_dev != scoped_root.scope_dev
            || share.scope_root_ino != scoped_root.scope_ino)
    {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn authorize_share_resolution(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    requested_path: &str,
    resolution_paths: &[String],
    resolved_path: &str,
    require_download: bool,
) -> Result<Vec<String>, McBrowserError> {
    let mut paths = Vec::new();
    for path in std::iter::once(requested_path)
        .chain(resolution_paths.iter().map(String::as_str))
        .chain(std::iter::once(resolved_path))
    {
        if paths.iter().any(|existing| existing == path) {
            continue;
        }
        policy(
            conn,
            owner_user,
            crate::mcbrowser::policy::Permission::Share,
            path,
        )?;
        policy(
            conn,
            owner_user,
            crate::mcbrowser::policy::Permission::Read,
            path,
        )?;
        if require_download {
            policy(
                conn,
                owner_user,
                crate::mcbrowser::policy::Permission::Download,
                path,
            )?;
        }
        paths.push(path.to_string());
    }
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorize_shared_relative_resolution(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    root_paths: &[String],
    requested_path: &str,
    resolution_paths: &[String],
    resolved_path: &str,
    require_download: bool,
) -> Result<(), McBrowserError> {
    for root in root_paths {
        for relative in std::iter::once(requested_path)
            .chain(resolution_paths.iter().map(String::as_str))
            .chain(std::iter::once(resolved_path))
        {
            authorize_owner_share_subpath(
                conn,
                policy,
                owner_user,
                root,
                relative,
                require_download,
            )?;
        }
    }
    Ok(())
}

pub(super) fn inspect_share_target(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    normalized_path: &str,
    require_download: bool,
) -> Result<(TargetStatInfo, String), McBrowserError> {
    let resolved = owner_bfs
        .metadata_resolving_internal_links(normalized_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect share target"))?;
    authorize_share_resolution(
        conn,
        policy,
        owner_user,
        normalized_path,
        &resolved.resolution_paths,
        &resolved.resolved_path,
        require_download,
    )?;
    let is_directory = resolved.entry.kind == "directory";
    let metadata = if is_directory {
        let opened = owner_bfs
            .scoped_resolving_internal_links(normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share directory"))?;
        authorize_share_resolution(
            conn,
            policy,
            owner_user,
            normalized_path,
            &opened.resolution_paths,
            &opened.resolved_path,
            require_download,
        )?;
        opened.fs.directory_metadata()
    } else {
        let opened = owner_bfs
            .open_file_resolving_internal_links(normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share file"))?;
        authorize_share_resolution(
            conn,
            policy,
            owner_user,
            normalized_path,
            &opened.resolution_paths,
            &opened.resolved_path,
            require_download,
        )?;
        opened.file.metadata()
    };
    let metadata =
        metadata.map_err(|error| map_fs_io_error(error, "Failed to stat share target"))?;
    let leaf_name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or(normalized_path)
        .to_string();

    Ok((
        TargetStatInfo {
            is_directory,
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: if is_directory { 0 } else { metadata.len() },
            mtime_rfc3339: Some(metadata.mtime()),
        },
        leaf_name,
    ))
}

pub(super) fn open_verified_shared_directory_fs(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    share: &StoredShareRow,
    require_download: bool,
) -> Result<(BrowserFs, Vec<String>), McBrowserError> {
    if !share.is_directory {
        return Err(McBrowserError::BadRequest(
            "Share is not a directory".to_string(),
        ));
    }
    let opened = owner_bfs
        .scoped_resolving_internal_links(&share.target_path)
        .map_err(|_| {
            McBrowserError::NotFound("Shared directory is no longer available".to_string())
        })?;
    let paths = authorize_share_resolution(
        conn,
        policy,
        owner_user,
        &share.target_path,
        &opened.resolution_paths,
        &opened.resolved_path,
        require_download,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    let metadata = opened.fs.directory_metadata().map_err(|_| {
        McBrowserError::NotFound("Shared directory is no longer available".to_string())
    })?;
    if !metadata.is_dir()
        || metadata.dev() != share.target_dev
        || metadata.ino() != share.target_ino
    {
        return Err(McBrowserError::NotFound(
            "Shared directory was moved or replaced".to_string(),
        ));
    }

    Ok((opened.fs, paths))
}

pub(super) fn open_verified_shared_single_file(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    share: &StoredShareRow,
    require_download: bool,
) -> Result<(File, Entry), McBrowserError> {
    if share.is_directory {
        return Err(McBrowserError::BadRequest(
            "Share is a directory, not a single file".to_string(),
        ));
    }
    let opened = owner_bfs
        .open_file_resolving_internal_links(&share.target_path)
        .map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => {
                McBrowserError::Forbidden("Shared file is not permitted".to_string())
            }
            _ => McBrowserError::NotFound("Shared file is no longer available".to_string()),
        })?;
    authorize_share_resolution(
        conn,
        policy,
        owner_user,
        &share.target_path,
        &opened.resolution_paths,
        &opened.resolved_path,
        require_download,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    let file = opened.file;
    let st = fstat_fd(file.as_raw_fd())
        .map_err(|_| McBrowserError::NotFound("Shared file is no longer available".to_string()))?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (st.st_dev as u64) != share.target_dev
        || (st.st_ino as u64) != share.target_ino
    {
        return Err(McBrowserError::NotFound(
            "Shared file was moved or replaced".to_string(),
        ));
    }
    if st.st_nlink > 1 {
        return Err(McBrowserError::Forbidden(
            "Hardlinked files are not permitted".to_string(),
        ));
    }
    let modified = chrono::Utc
        .timestamp_opt(st.st_mtime, u32::try_from(st.st_mtime_nsec).unwrap_or(0))
        .single()
        .map(|dt| dt.to_rfc3339());
    let entry = Entry {
        name: share.target_name.clone(),
        path: share.target_name.clone(),
        kind: "file".to_string(),
        size: st.st_size.max(0) as u64,
        modified,
    };
    Ok((file, entry))
}
