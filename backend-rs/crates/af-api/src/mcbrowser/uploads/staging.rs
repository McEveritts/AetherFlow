use super::db::{
    discard_unpublished_session_conn, mark_session_completed_conn, mark_session_skipped_conn,
};
use super::protocol::{now_unix_secs, validate_upload_id, ConflictPolicy, UploadSessionRecord};
use super::STAGING_DIR_NAME;
use crate::mcbrowser::{
    check_fd_free_space, map_fs_io_error, open_user_browser_fs_at, McBrowserError,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use uuid::Uuid;

pub(super) const RESOLVE_BENEATH: u64 = 0x08;
pub(super) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(super) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
pub(super) struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability-Oriented Private Staging Filesystem Helpers
// ─────────────────────────────────────────────────────────────────────────────

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
    let err = io::Error::last_os_error();
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
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(super) fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

pub(super) fn ensure_private_dir_child(
    parent_fd: libc::c_int,
    child_name: &str,
) -> Result<OwnedFd, McBrowserError> {
    let child_c = CString::new(child_name.as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid staging directory component".to_string()))?;
    let mkdir_rc = unsafe { libc::mkdirat(parent_fd, child_c.as_ptr(), 0o700) };
    if mkdir_rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::AlreadyExists {
            return Err(McBrowserError::Internal(
                "Failed to provision upload staging directory".to_string(),
            ));
        }
    }
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(parent_fd, child_c.as_c_str(), dir_flags, 0).map_err(|_| {
        McBrowserError::Internal("Failed to open upload staging directory safely".to_string())
    })?;
    let st = fstat_fd(fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat upload staging directory".to_string())
    })?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != unsafe { libc::geteuid() } {
        return Err(McBrowserError::Internal(
            "Upload staging directory has invalid type or ownership".to_string(),
        ));
    }
    if (st.st_mode & 0o777) != 0o700 && unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } < 0 {
        return Err(McBrowserError::Internal(
            "Failed to enforce 0700 permissions on upload staging directory".to_string(),
        ));
    }
    Ok(fd)
}

/// Opens `<base_root>/.af-upload-staging/user-<user_id>` safely using `O_NOFOLLOW` and `0700` permissions.
pub(super) fn open_user_staging_dir_at(
    base_root: &Path,
    user_id: i64,
) -> Result<OwnedFd, McBrowserError> {
    if user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }
    if !base_root.is_absolute() || base_root.parent().is_none() {
        return Err(McBrowserError::Internal(
            "McBrowser storage root is misconfigured".to_string(),
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(base_root) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(McBrowserError::Internal(
                "McBrowser storage root is not a valid directory".to_string(),
            ));
        }
    } else {
        fs::create_dir_all(base_root).map_err(|_| {
            McBrowserError::Internal("Failed to initialize McBrowser storage root".to_string())
        })?;
    }

    let base_c = CString::new(base_root.as_os_str().as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid McBrowser storage root path".to_string()))?;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let base_fd_raw = unsafe { libc::open(base_c.as_ptr(), dir_flags) };
    if base_fd_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to open McBrowser storage root".to_string(),
        ));
    }
    let base_fd = unsafe { OwnedFd::from_raw_fd(base_fd_raw) };
    let base_st = fstat_fd(base_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to inspect McBrowser storage root".to_string())
    })?;
    if (base_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || base_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "Storage root ownership is invalid".to_string(),
        ));
    }
    if (base_st.st_mode & 0o777) != 0o700 && unsafe { libc::fchmod(base_fd.as_raw_fd(), 0o700) } < 0
    {
        return Err(McBrowserError::Internal(
            "Failed to enforce private storage permissions".to_string(),
        ));
    }

    let staging_root_fd = ensure_private_dir_child(base_fd.as_raw_fd(), STAGING_DIR_NAME)?;
    let user_dir_name = format!("user-{user_id}");
    ensure_private_dir_child(staging_root_fd.as_raw_fd(), &user_dir_name)
}

pub(super) struct VerifiedScopedUserRoot {
    pub(super) bfs: af_files::BrowserFs,
    pub(super) scope: String,
    pub(super) scope_dev: u64,
    pub(super) scope_ino: u64,
}

/// Opens a specific normalized policy scope directory under `base_root/user-{user_id}` using
/// descriptor-confined traversal (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
/// / `O_NOFOLLOW`) and records its `(st_dev, st_ino)` identity.
pub(super) fn open_scoped_user_root_with_scope_at(
    base_root: &Path,
    user_id: i64,
    raw_scope: &str,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let clean_scope = if raw_scope == "/" { "" } else { raw_scope };
    let normalized_scope = crate::mcbrowser::policy::normalize_scope_path(clean_scope)?;

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

    let scope_dev = scope_st.st_dev as u64;
    let scope_ino = scope_st.st_ino as u64;
    let scoped_bfs = af_files::BrowserFs::from_directory(current_fd).map_err(|_| {
        McBrowserError::Internal("Failed to initialize scoped user filesystem".to_string())
    })?;

    Ok(VerifiedScopedUserRoot {
        bfs: scoped_bfs,
        scope: normalized_scope,
        scope_dev,
        scope_ino,
    })
}

/// Opens the user's currently configured effective policy scope directory using the caller's
/// existing SQLite `Connection` (`crate::mcbrowser::policy::effective_scope_with_conn`).
pub(super) fn open_verified_user_root_fd(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let raw_scope = crate::mcbrowser::policy::effective_scope_with_conn(conn, user_id)?;
    open_scoped_user_root_with_scope_at(base_root, user_id, &raw_scope)
}

/// Opens the exact bound scoped root directory recorded on an `UploadSessionRecord` and verifies
/// its `(st_dev, st_ino)` identity matches.
pub(super) fn open_bound_scope_browser_fs_at(
    base_root: &Path,
    user_id: i64,
    owner_scope: &str,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<af_files::BrowserFs, McBrowserError> {
    let root = open_scoped_user_root_with_scope_at(base_root, user_id, owner_scope)?;
    if (expected_dev != 0 || expected_ino != 0)
        && (root.scope_dev != expected_dev || root.scope_ino != expected_ino)
    {
        return Err(McBrowserError::Conflict(
            "Upload session scoped root directory was replaced on disk".to_string(),
        ));
    }
    Ok(root.bfs)
}

/// Ensures an upload session remains bound to the exact policy scope and scoped-root directory
/// `(scope_root_dev, scope_root_ino)` under which it was created. Any admin scope remap or
/// directory replacement fails closed with `409 Conflict`.
pub(super) fn verify_session_scope_matches(
    session: &UploadSessionRecord,
    scoped_root: &VerifiedScopedUserRoot,
) -> Result<(), McBrowserError> {
    if session.owner_scope != scoped_root.scope {
        return Err(McBrowserError::Conflict(
            "Upload session scope no longer matches user's active policy scope".to_string(),
        ));
    }
    if (session.scope_root_dev != 0 || session.scope_root_ino != 0)
        && (session.scope_root_dev != scoped_root.scope_dev
            || session.scope_root_ino != scoped_root.scope_ino)
    {
        return Err(McBrowserError::Conflict(
            "Upload session scoped root directory changed on disk".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn staging_file_c_name(upload_id: &str) -> Result<CString, McBrowserError> {
    let valid_id = validate_upload_id(upload_id)?;
    CString::new(format!("{valid_id}.part"))
        .map_err(|_| McBrowserError::Internal("Invalid staging filename".to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum UploadPublicationProof {
    Unpublished {},
    Prepared {
        device: u64,
        inode: u64,
        nonce: Option<String>,
    },
    Published {},
}

pub(super) const PUBLICATION_XATTR: &[u8] = b"user.aetherflow.upload-proof\0";

pub(super) fn publication_proof_name(upload_id: &str) -> Result<CString, McBrowserError> {
    let id = validate_upload_id(upload_id)?;
    CString::new(format!("{id}.publication"))
        .map_err(|_| McBrowserError::Internal("Invalid publication proof filename".to_string()))
}

pub(super) fn write_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    proof: &UploadPublicationProof,
) -> Result<(), McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, session.user_id)?;
    let name = publication_proof_name(&session.id)?;
    let temporary_name = CString::new(format!("{}.{}.tmp", session.id, Uuid::new_v4().simple()))
        .map_err(|_| {
            McBrowserError::Internal("Invalid publication proof temporary name".to_string())
        })?;
    let descriptor = openat_no_symlinks(
        directory.as_raw_fd(),
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|error| map_fs_io_error(error, "Failed to create publication proof"))?;
    let mut file = File::from(descriptor);
    let outcome = (|| {
        let bytes = serde_json::to_vec(proof).map_err(|_| {
            McBrowserError::Internal("Failed to encode publication proof".to_string())
        })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| map_fs_io_error(error, "Failed to persist publication proof"))?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } < 0
        {
            return Err(map_fs_io_error(
                io::Error::last_os_error(),
                "Failed to install publication proof",
            ));
        }
        if unsafe { libc::fsync(directory.as_raw_fd()) } < 0 {
            return Err(map_fs_io_error(
                io::Error::last_os_error(),
                "Failed to sync publication proof directory",
            ));
        }
        Ok(())
    })();
    if outcome.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0);
        }
    }
    outcome
}

pub(super) fn read_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
) -> Result<Option<UploadPublicationProof>, McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, session.user_id)?;
    let name = publication_proof_name(&session.id)?;
    let descriptor = match openat_no_symlinks(
        directory.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_fs_io_error(error, "Failed to open publication proof")),
    };
    let metadata = fstat_fd(descriptor.as_raw_fd())
        .map_err(|error| map_fs_io_error(error, "Failed to inspect publication proof"))?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_size < 0
        || metadata.st_size > 4096
    {
        return Err(McBrowserError::Forbidden(
            "Invalid publication proof file".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| map_fs_io_error(error, "Failed to read publication proof"))?;
    if bytes.len() > 4096 {
        return Err(McBrowserError::Forbidden(
            "Publication proof is oversized".to_string(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| McBrowserError::Internal("Invalid publication proof document".to_string()))
}

pub(super) fn remove_publication_proof_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<(), McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, user_id)?;
    let name = publication_proof_name(upload_id)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::NotFound {
            return Err(map_fs_io_error(error, "Failed to remove publication proof"));
        }
    }
    Ok(())
}

pub(super) fn prepare_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    file: &File,
) -> Result<(), McBrowserError> {
    let metadata = fstat_fd(file.as_raw_fd())
        .map_err(|error| map_fs_io_error(error, "Failed to inspect prepared publication"))?;
    let nonce = Uuid::new_v4().simple().to_string();
    let tagged = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            PUBLICATION_XATTR.as_ptr().cast(),
            nonce.as_ptr().cast(),
            nonce.len(),
            0,
        )
    };
    let nonce = if tagged == 0 {
        file.sync_all()
            .map_err(|error| map_fs_io_error(error, "Failed to sync publication identity"))?;
        Some(nonce)
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EOPNOTSUPP) | Some(libc::EPERM) => None,
            _ => {
                return Err(map_fs_io_error(
                    error,
                    "Failed to bind publication identity",
                ))
            }
        }
    };
    write_publication_proof_at(
        base_root,
        session,
        &UploadPublicationProof::Prepared {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            nonce,
        },
    )
}

pub(super) fn prepared_publication_matches(
    file: &File,
    device: u64,
    inode: u64,
    nonce: Option<&str>,
) -> bool {
    let Some(nonce) = nonce
        .filter(|nonce| nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()))
    else {
        return false;
    };
    let Ok(metadata) = fstat_fd(file.as_raw_fd()) else {
        return false;
    };
    if metadata.st_dev != device || metadata.st_ino != inode || metadata.st_nlink != 1 {
        return false;
    }
    let mut actual = [0_u8; 32];
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            PUBLICATION_XATTR.as_ptr().cast(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    length == 32 && actual.as_slice() == nonce.as_bytes()
}

pub(super) fn commit_proven_upload_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    pending: af_files::PendingUpload,
    expected: Option<&File>,
) -> Result<(), McBrowserError> {
    let file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to open publication handle"))?;
    prepare_publication_proof_at(base_root, session, &file)?;
    let outcome = match expected {
        Some(expected) => pending.commit_replace(expected),
        None => pending.commit(),
    };
    match outcome {
        Ok(()) => {
            if let Err(error) = write_publication_proof_at(
                base_root,
                session,
                &UploadPublicationProof::Published {},
            ) {
                tracing::warn!(?error, upload_id = %session.id, "Published upload retains prepared identity for recovery");
            }
            Ok(())
        }
        Err(error) => {
            write_publication_proof_at(
                base_root,
                session,
                &UploadPublicationProof::Unpublished {},
            )?;
            Err(map_fs_io_error(
                error,
                "Failed to finalize upload publication",
            ))
        }
    }
}

pub(super) fn create_exclusive_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<File, McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(
        user_staging_dir.as_raw_fd(),
        file_name.as_c_str(),
        flags,
        0o600,
    )
    .map_err(|e| map_fs_io_error(e, "Failed to create upload staging file"))?;
    let st = fstat_fd(fd.as_raw_fd())
        .map_err(|_| McBrowserError::Internal("Failed to stat upload staging file".to_string()))?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_nlink != 1
        || st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Forbidden(
            "Staging file failed security validation".to_string(),
        ));
    }
    Ok(File::from(fd))
}

pub(super) fn open_existing_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<File, McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(user_staging_dir.as_raw_fd(), file_name.as_c_str(), flags, 0)
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => {
                McBrowserError::NotFound("Upload staging file is missing".to_string())
            }
            _ => map_fs_io_error(e, "Failed to open upload staging file"),
        })?;
    let st = fstat_fd(fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to inspect upload staging file".to_string())
    })?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_nlink != 1
        || st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Forbidden(
            "Staging file must be a single-link regular file owned by the service".to_string(),
        ));
    }
    Ok(File::from(fd))
}

pub(super) fn remove_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<(), McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let rc = unsafe { libc::unlinkat(user_staging_dir.as_raw_fd(), file_name.as_ptr(), 0) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::NotFound {
            return Err(map_fs_io_error(err, "Failed to remove upload staging file"));
        }
    }
    Ok(())
}

/// Reconciles SQLite `offset_bytes` with the physical staging file on disk after a crash or interrupted PATCH.
/// - If disk size > `session.offset_bytes`, truncates the uncommitted tail on disk back to `session.offset_bytes`.
/// - If disk size < `session.offset_bytes`, updates SQLite `offset_bytes` down to disk size so the client
///   re-uploads any bytes that were not durably persisted.
pub(super) fn reconcile_staging_offset_at(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
) -> Result<File, McBrowserError> {
    let file = open_existing_staging_file_at(base_root, session.user_id, &session.id)?;
    let meta = file.metadata().map_err(|_| {
        McBrowserError::Internal("Failed to read staging file metadata".to_string())
    })?;
    let disk_len = meta.len();

    if disk_len > session.offset_bytes {
        file.set_len(session.offset_bytes).map_err(|e| {
            map_fs_io_error(e, "Failed to truncate uncommitted tail on staging file")
        })?;
        file.sync_data()
            .map_err(|e| map_fs_io_error(e, "Failed to sync truncated staging file"))?;
    } else if disk_len < session.offset_bytes {
        let now = now_unix_secs();
        let disk_i64 = i64::try_from(disk_len).unwrap_or(0);
        conn.execute(
            "UPDATE mcbrowser_uploads SET offset_bytes = ?1, status = 'uploading', updated_at = ?2 WHERE id = ?3 AND status IN ('uploading', 'publishing')",
            params![disk_i64, now, session.id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to reconcile upload offset in database".to_string()))?;
        session.offset_bytes = disk_len;
        session.status = "uploading".to_string();
        session.updated_at = now;
    }

    Ok(file)
}

/// Inspects whether `target_path` currently exists in `bfs`.
/// - If it exists as a single-link regular file, returns `Ok(Some((file, st_dev, st_ino, st_size)))`.
/// - If it is a directory, returns `Err(McBrowserError::BadRequest)`.
/// - If it is a symlink or multi-hardlink file, returns `Err(McBrowserError::Forbidden)`.
/// - If it does not exist (`ErrorKind::NotFound`), returns `Ok(None)`.
pub(super) fn inspect_existing_target_in_bfs(
    bfs: &af_files::BrowserFs,
    target_path: &str,
) -> Result<Option<(File, u64, u64, u64)>, McBrowserError> {
    match bfs.open_file(target_path) {
        Ok(file) => {
            let st = fstat_fd(file.as_raw_fd())
                .map_err(|e| map_fs_io_error(e, "Failed to inspect target file metadata"))?;
            let file_type = st.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFDIR {
                return Err(McBrowserError::BadRequest(
                    "Target path is a directory".to_string(),
                ));
            }
            if file_type != libc::S_IFREG || st.st_nlink != 1 {
                return Err(McBrowserError::Forbidden(
                    "Target file must be a single-link regular file".to_string(),
                ));
            }
            let dev = st.st_dev as u64;
            let ino = st.st_ino as u64;
            let size = u64::try_from(st.st_size.max(0)).unwrap_or(0);
            Ok(Some((file, dev, ino, size)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(map_fs_io_error(e, "Failed to inspect target path")),
    }
}

/// Verifies that the target file in `bfs` still matches the identity and size bound at session creation:
/// - When `session.base_target_exists == true`: requires `target_path` to still exist as a single-link
///   regular file with `(st_dev, st_ino, st_size) == (base_target_dev, base_target_ino, base_target_size)`,
///   returning the opened `File` handle for `PendingUpload::commit_replace(&expected_file)`.
///   Any modification, replacement, or deletion fails closed with `409 Conflict`.
/// - When `session.base_target_exists == false`: for `Error`, `Overwrite`, and `Resume`, verifies that
///   no concurrent file was created at `target_path` since session creation (`409 Conflict` if one appeared).
pub(super) fn verify_bound_target_unchanged(
    bfs: &af_files::BrowserFs,
    session: &UploadSessionRecord,
) -> Result<Option<File>, McBrowserError> {
    if session.base_target_exists {
        let Some((file, dev, ino, size)) =
            inspect_existing_target_in_bfs(bfs, &session.target_path)?
        else {
            return Err(McBrowserError::Conflict(
                "Original target file was removed before upload completed".to_string(),
            ));
        };
        if dev != session.base_target_dev
            || ino != session.base_target_ino
            || size != session.base_target_size
        {
            return Err(McBrowserError::Conflict(
                "Original target file changed since upload session was created".to_string(),
            ));
        }
        Ok(Some(file))
    } else {
        match session.conflict_policy {
            ConflictPolicy::Error | ConflictPolicy::Overwrite | ConflictPolicy::Resume => {
                if inspect_existing_target_in_bfs(bfs, &session.target_path)?.is_some() {
                    return Err(McBrowserError::Conflict(
                        "Target file was created concurrently since upload session started"
                            .to_string(),
                    ));
                }
                Ok(None)
            }
            ConflictPolicy::Skip => Ok(None),
        }
    }
}

/// Copies the existing partial prefix (`0..expected_len`) from `existing_file` into the private
/// staging file for `ConflictPolicy::Resume`, verifying before and after the copy that the source
/// file's `(st_dev, st_ino, st_size, st_nlink)` remained unchanged. Never truncates or mutates the
/// live target file in place.
pub(super) fn copy_existing_prefix_to_staging(
    mut existing_file: File,
    staging_file: &mut File,
    expected_dev: u64,
    expected_ino: u64,
    expected_len: u64,
) -> Result<(), McBrowserError> {
    let pre_st = fstat_fd(existing_file.as_raw_fd())
        .map_err(|e| map_fs_io_error(e, "Failed to stat existing file before resume copy"))?;
    if (pre_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || pre_st.st_nlink != 1
        || (pre_st.st_dev as u64) != expected_dev
        || (pre_st.st_ino as u64) != expected_ino
        || u64::try_from(pre_st.st_size.max(0)).unwrap_or(0) != expected_len
    {
        return Err(McBrowserError::Conflict(
            "Existing target file changed while initializing resume staging".to_string(),
        ));
    }

    if expected_len > 0 {
        check_fd_free_space(staging_file.as_raw_fd(), expected_len)?;
    }

    existing_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind existing file for resume copy"))?;
    staging_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind staging file for resume copy"))?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let n = match existing_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(map_fs_io_error(
                    e,
                    "Failed to read existing partial file during resume staging",
                ))
            }
        };
        copied = copied.saturating_add(n as u64);
        if copied > expected_len {
            return Err(McBrowserError::Conflict(
                "Existing target file grew while initializing resume staging".to_string(),
            ));
        }
        staging_file
            .write_all(&buf[..n])
            .map_err(|e| map_fs_io_error(e, "Failed to write resume prefix to staging file"))?;
    }

    if copied != expected_len {
        return Err(McBrowserError::Conflict(
            "Existing target file shrank while initializing resume staging".to_string(),
        ));
    }

    let post_st = fstat_fd(existing_file.as_raw_fd())
        .map_err(|e| map_fs_io_error(e, "Failed to re-stat existing file after resume copy"))?;
    if (post_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || post_st.st_nlink != 1
        || (post_st.st_dev as u64) != expected_dev
        || (post_st.st_ino as u64) != expected_ino
        || u64::try_from(post_st.st_size.max(0)).unwrap_or(0) != expected_len
    {
        return Err(McBrowserError::Conflict(
            "Existing target file changed while initializing resume staging".to_string(),
        ));
    }

    staging_file
        .sync_data()
        .map_err(|e| map_fs_io_error(e, "Failed to sync resume prefix in staging file"))
}

/// Copies a completed staging file into `BrowserFs::begin_upload` (or `BrowserFs::begin_replace`
/// when `expected_replace_target` is `Some`) and commits it atomically (`commit()` or `commit_replace()`).
pub(super) fn publish_staging_file_to_browser_fs(
    mut staging_file: File,
    bfs: &af_files::BrowserFs,
    target_path: &str,
    expected_length: u64,
    expected_replace_target: Option<&File>,
    base_root: &Path,
    session: &UploadSessionRecord,
) -> Result<(), McBrowserError> {
    staging_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind staging file for publication"))?;

    let mut pending = if expected_replace_target.is_some() {
        bfs.begin_replace(target_path)
            .map_err(|e| map_fs_io_error(e, "Failed to initiate replacement file publication"))?
    } else {
        bfs.begin_upload(target_path)
            .map_err(|e| map_fs_io_error(e, "Failed to initiate target file publication"))?
    };

    if expected_length > 0 {
        let pending_file = pending
            .file()
            .map_err(|e| map_fs_io_error(e, "Failed to access pending upload file handle"))?;
        check_fd_free_space(pending_file.as_raw_fd(), expected_length)?;
    }

    let mut buf = vec![0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let n = match staging_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(map_fs_io_error(
                    e,
                    "Failed to read staging file during publication",
                ))
            }
        };
        copied = copied.saturating_add(n as u64);
        if copied > expected_length {
            return Err(McBrowserError::BadRequest(
                "Staging file exceeded declared Upload-Length during publication".to_string(),
            ));
        }
        pending
            .write_all(&buf[..n])
            .map_err(|e| map_fs_io_error(e, "Failed to write target file during publication"))?;
    }

    if copied != expected_length {
        return Err(McBrowserError::Internal(
            "Staging file length did not match declared Upload-Length during publication"
                .to_string(),
        ));
    }

    commit_proven_upload_at(base_root, session, pending, expected_replace_target)
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Testable Operations (using explicit `&Connection` and `base_root: &Path`)
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn publish_zero_byte_upload_conn(
    conn: &Connection,
    base_root: &Path,
    bfs: &af_files::BrowserFs,
    record: &mut UploadSessionRecord,
    pending: af_files::PendingUpload,
    expected_file: Option<&File>,
    now: i64,
) -> Result<(), McBrowserError> {
    if record.upload_length != 0 || record.offset_bytes != 0 {
        return Err(McBrowserError::Internal(
            "Invalid zero-byte publication session".to_string(),
        ));
    }
    let result = commit_proven_upload_at(base_root, record, pending, expected_file);
    if let Err(error) = result {
        let error = if record.conflict_policy == ConflictPolicy::Skip
            && matches!(error, McBrowserError::Conflict(_))
        {
            match inspect_existing_target_in_bfs(bfs, &record.target_path) {
                Ok(Some(_)) => return mark_session_skipped_conn(conn, record, now),
                Ok(None) => error,
                Err(error) => error,
            }
        } else {
            error
        };
        discard_unpublished_session_conn(conn, record, &error)?;
        let _ = remove_publication_proof_at(base_root, record.user_id, &record.id);
        return Err(error);
    }
    mark_session_completed_conn(conn, record, now)
}
