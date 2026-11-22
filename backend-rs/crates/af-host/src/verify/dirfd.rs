use super::lock::resolve_trusted_service_account_ids;
use super::paths::{reject_if_symlink, validate_no_parent_traversal};
use crate::error::{HostBackupError, HostBackupResult};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

/// Enforces trusted ancestor policy and no-symlink traversal on `dir`, creating missing
/// leaf directories step-by-step using `openat` + `mkdirat` with `O_NOFOLLOW | O_DIRECTORY`
/// on Unix, and returns an open directory `File` handle pinned to the verified leaf directory.
pub fn open_or_create_dir_nofollow(
    dir: &Path,
    create_mode: u32,
    context: &str,
) -> HostBackupResult<File> {
    open_or_create_dir_nofollow_with_trusted_uid(dir, create_mode, None, context)
}

/// Variant of [`open_or_create_dir_nofollow`] that also accepts an explicit trusted service owner
/// UID (`extra_trusted_uid`) for AetherFlow state/data/home/staging directories.
pub fn open_or_create_dir_nofollow_with_trusted_uid(
    dir: &Path,
    create_mode: u32,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<File> {
    open_or_create_dir_nofollow_internal(dir, create_mode, extra_trusted_uid, true, context)
}

/// Opens or creates a protected recovery provenance directory where every ancestor and the leaf
/// directory itself must be owned by `root` (`0`) or the current effective UID (`geteuid()`),
/// never delegating directory ownership trust to an unprivileged service UID when running as `root`.
pub fn open_or_create_provenance_dir_nofollow(dir: &Path, context: &str) -> HostBackupResult<File> {
    let dir_file = open_or_create_dir_nofollow_internal(dir, 0o700, None, false, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let euid = unsafe { libc::geteuid() };
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dir_file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat provenance dir {} ({})", dir.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_uid != euid {
            return Err(HostBackupError::PathValidation {
                path: dir.to_path_buf(),
                reason: format!(
                    "{} must be owned by current executor uid={}, found uid={}",
                    context, euid, st_buf.st_uid
                ),
            });
        }
        if (st_buf.st_mode & 0o777) != 0o700 {
            let chmod_rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!("fchmod 0700 provenance dir {} ({})", dir.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
        }
    }
    Ok(dir_file)
}

/// Opens or creates a maintenance lock parent directory with root-only ancestor ownership
/// enforcement when running as `root` (`euid == 0`) and restricted shared traversal (`0750`, `root:target_gid`)
/// on `/run/aetherflow` (or `.../run/aetherflow`).
#[cfg(unix)]
pub(crate) fn open_or_create_lock_parent_dir_nofollow(
    dir: &Path,
    euid: libc::uid_t,
    target_gid: libc::gid_t,
    context: &str,
) -> HostBackupResult<File> {
    use std::os::unix::io::AsRawFd;

    let allow_service_owner = euid != 0;
    let create_mode = 0o750;
    let dir_file =
        open_or_create_dir_nofollow_internal(dir, create_mode, None, allow_service_owner, context)?;

    if euid == 0 && dir.to_string_lossy().ends_with("run/aetherflow") {
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dir_file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!(
                    "fstat maintenance lock parent {} ({})",
                    dir.display(),
                    context
                ),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_uid != 0 {
            return Err(HostBackupError::PathValidation {
                path: dir.to_path_buf(),
                reason: format!(
                    "shared runtime lock directory '{}' is owned by non-root uid={}",
                    dir.display(),
                    st_buf.st_uid
                ),
            });
        }
        if st_buf.st_gid != target_gid {
            let chown_rc = unsafe { libc::fchown(dir_file.as_raw_fd(), 0, target_gid) };
            if chown_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchown shared runtime lock directory {} ({})",
                        dir.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
        }
        if (st_buf.st_mode & 0o7777) != 0o750 {
            let chmod_rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o750) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchmod shared runtime lock directory {} ({})",
                        dir.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
        }
    }

    Ok(dir_file)
}

fn open_or_create_dir_nofollow_internal(
    dir: &Path,
    create_mode: u32,
    extra_trusted_uid: Option<u32>,
    allow_service_owner: bool,
    context: &str,
) -> HostBackupResult<File> {
    validate_no_parent_traversal(dir, context)?;
    if !dir.is_absolute() {
        return Err(HostBackupError::PathValidation {
            path: dir.to_path_buf(),
            reason: format!("{} must be an absolute path", context),
        });
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let root_c = CString::new("/").unwrap();
        let root_fd = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if root_fd < 0 {
            return Err(HostBackupError::io(
                format!("opening '/' directory descriptor ({})", context),
                std::io::Error::last_os_error(),
            ));
        }
        let mut current_dir = unsafe { File::from_raw_fd(root_fd) };
        let euid = unsafe { libc::geteuid() };
        let service_ids = if allow_service_owner {
            resolve_trusted_service_account_ids()
        } else {
            None
        };
        let service_uid = service_ids.map(|(uid_val, _)| uid_val);
        let mut acc = PathBuf::from("/");
        verify_dir_fd_trusted_owner(
            current_dir.as_raw_fd(),
            &acc,
            euid,
            service_uid,
            extra_trusted_uid,
            context,
        )?;

        let normal_segments: Vec<&std::ffi::OsStr> = dir
            .components()
            .filter_map(|comp| match comp {
                Component::Normal(seg) => Some(seg),
                _ => None,
            })
            .collect();
        for comp in dir.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..' segment", context),
                });
            }
        }

        let total_segments = normal_segments.len();
        for (seg_idx, seg) in normal_segments.into_iter().enumerate() {
            let is_leaf_segment = seg_idx + 1 == total_segments;
            let step_create_mode = if is_leaf_segment {
                create_mode & 0o7777
            } else {
                0o750
            };

            acc.push(seg);
            let seg_c =
                CString::new(seg.as_bytes()).map_err(|_| HostBackupError::PathValidation {
                    path: acc.clone(),
                    reason: "directory component contains interior NUL byte".to_string(),
                })?;

            let mut next_fd = unsafe {
                libc::openat(
                    current_dir.as_raw_fd(),
                    seg_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };

            let mut created_now = false;
            if next_fd < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                        if let Ok(meta) = fs::symlink_metadata(&acc) {
                            if meta.file_type().is_symlink() {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!("{} component is a symbolic link", context),
                                });
                            }
                        }
                        if err.raw_os_error() == Some(libc::ELOOP) {
                            return Err(HostBackupError::SymlinkRejected {
                                path: acc,
                                reason: format!("{} component is a symbolic link (ELOOP)", context),
                            });
                        }
                        return Err(HostBackupError::PathValidation {
                            path: acc,
                            reason: format!("{} component exists and is not a directory", context),
                        });
                    }
                    Some(libc::ENOENT) => {
                        let mk_rc = unsafe {
                            libc::mkdirat(
                                current_dir.as_raw_fd(),
                                seg_c.as_ptr(),
                                step_create_mode as libc::mode_t,
                            )
                        };
                        if mk_rc == 0 {
                            created_now = true;
                        } else {
                            let mk_err = std::io::Error::last_os_error();
                            if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                return Err(HostBackupError::io(
                                    format!("mkdirat {} ({})", acc.display(), context),
                                    mk_err,
                                ));
                            }
                        }
                        current_dir.sync_all().map_err(|sync_err| {
                            HostBackupError::io(
                                format!(
                                    "fsync parent directory after mkdirat {} ({})",
                                    acc.display(),
                                    context
                                ),
                                sync_err,
                            )
                        })?;
                        next_fd = unsafe {
                            libc::openat(
                                current_dir.as_raw_fd(),
                                seg_c.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_CLOEXEC
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW,
                            )
                        };
                        if next_fd < 0 {
                            let open_err = std::io::Error::last_os_error();
                            if open_err.raw_os_error() == Some(libc::ELOOP) {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!(
                                        "{} component is a symbolic link after mkdirat",
                                        context
                                    ),
                                });
                            }
                            return Err(HostBackupError::io(
                                format!("openat created directory {} ({})", acc.display(), context),
                                open_err,
                            ));
                        }
                    }
                    _ => {
                        return Err(HostBackupError::io(
                            format!("openat {} ({})", acc.display(), context),
                            err,
                        ));
                    }
                }
            }

            let next_dir = unsafe { File::from_raw_fd(next_fd) };
            let is_var_lib_aetherflow = acc.to_string_lossy().ends_with("var/lib/aetherflow");
            if created_now && euid == 0 && allow_service_owner && is_var_lib_aetherflow {
                if let Some((_svc_uid, svc_gid)) = service_ids {
                    let chown_rc =
                        unsafe { libc::fchown(next_dir.as_raw_fd(), 0, svc_gid as libc::gid_t) };
                    if chown_rc != 0 {
                        return Err(HostBackupError::io(
                            format!(
                                "fchown shared state directory {} ({})",
                                acc.display(),
                                context
                            ),
                            std::io::Error::last_os_error(),
                        ));
                    }
                    let chmod_rc = unsafe { libc::fchmod(next_dir.as_raw_fd(), 0o1770) };
                    if chmod_rc != 0 {
                        return Err(HostBackupError::io(
                            format!(
                                "fchmod shared state directory {} ({})",
                                acc.display(),
                                context
                            ),
                            std::io::Error::last_os_error(),
                        ));
                    }
                }
            }

            verify_dir_fd_trusted_owner(
                next_dir.as_raw_fd(),
                &acc,
                euid,
                service_uid,
                extra_trusted_uid,
                context,
            )?;
            current_dir = next_dir;
        }

        Ok(current_dir)
    }

    #[cfg(not(unix))]
    {
        let _ = (extra_trusted_uid, allow_service_owner);
        ensure_private_dir_all(dir, context)?;
        File::open(dir).map_err(|err| {
            HostBackupError::io(format!("opening dir {} ({})", dir.display(), context), err)
        })
    }
}

/// Opens an existing directory without creating missing components or following symlinks.
/// Returns `Ok(None)` if any component along `dir` does not exist (`ENOENT`).
#[cfg(unix)]
pub(crate) fn open_existing_dir_nofollow_optional_with_trusted_uid(
    dir: &Path,
    extra_trusted_uid: Option<u32>,
    allow_service_owner: bool,
    context: &str,
) -> HostBackupResult<Option<File>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    validate_no_parent_traversal(dir, context)?;
    if !dir.is_absolute() {
        return Err(HostBackupError::PathValidation {
            path: dir.to_path_buf(),
            reason: format!("{} must be an absolute path", context),
        });
    }

    let root_c = CString::new("/").unwrap();
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(HostBackupError::io(
            format!("opening '/' directory descriptor ({})", context),
            std::io::Error::last_os_error(),
        ));
    }
    let mut current_dir = unsafe { File::from_raw_fd(root_fd) };
    let euid = unsafe { libc::geteuid() };
    let service_uid = if allow_service_owner {
        resolve_trusted_service_account_ids().map(|(uid_val, _)| uid_val)
    } else {
        None
    };
    let mut acc = PathBuf::from("/");
    verify_dir_fd_trusted_owner(
        current_dir.as_raw_fd(),
        &acc,
        euid,
        service_uid,
        extra_trusted_uid,
        context,
    )?;

    for comp in dir.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..' segment", context),
                });
            }
            Component::Normal(seg) => {
                acc.push(seg);
                let seg_c =
                    CString::new(seg.as_bytes()).map_err(|_| HostBackupError::PathValidation {
                        path: acc.clone(),
                        reason: "directory component contains interior NUL byte".to_string(),
                    })?;

                let next_fd = unsafe {
                    libc::openat(
                        current_dir.as_raw_fd(),
                        seg_c.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::ENOENT) => return Ok(None),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                            if let Ok(meta) = fs::symlink_metadata(&acc) {
                                if meta.file_type().is_symlink() {
                                    return Err(HostBackupError::SymlinkRejected {
                                        path: acc,
                                        reason: format!("{} component is a symbolic link", context),
                                    });
                                }
                            }
                            if err.raw_os_error() == Some(libc::ELOOP) {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!(
                                        "{} component is a symbolic link (ELOOP)",
                                        context
                                    ),
                                });
                            }
                            return Err(HostBackupError::PathValidation {
                                path: acc,
                                reason: format!(
                                    "{} component exists and is not a directory",
                                    context
                                ),
                            });
                        }
                        _ => {
                            return Err(HostBackupError::io(
                                format!("openat {} ({})", acc.display(), context),
                                err,
                            ));
                        }
                    }
                }
                let next_dir = unsafe { File::from_raw_fd(next_fd) };
                verify_dir_fd_trusted_owner(
                    next_dir.as_raw_fd(),
                    &acc,
                    euid,
                    service_uid,
                    extra_trusted_uid,
                    context,
                )?;
                current_dir = next_dir;
            }
        }
    }

    Ok(Some(current_dir))
}

/// Opens an existing regular file at `path` without following symlinks on any ancestor or leaf
/// (`O_RDONLY | O_CLOEXEC | O_NOFOLLOW` via pinned parent directory descriptor on Unix),
/// verifies via `fstat(fd)` that the opened descriptor is a regular file (`S_IFREG`),
/// and returns `Ok(Some((file, mode, uid, gid)))`, or `Ok(None)` if the file or an ancestor
/// directory does not exist (`ENOENT`).
pub fn open_existing_regular_file_nofollow(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<Option<(File, u32, u32, u32)>> {
    validate_no_parent_traversal(path, context)?;
    let resolved_path: PathBuf;
    let effective_path = if path.is_absolute() {
        path
    } else {
        reject_if_symlink(path, context)?;
        let cwd = std::env::current_dir().map_err(|err| {
            HostBackupError::io(
                format!(
                    "resolving current working directory for {} ({})",
                    path.display(),
                    context
                ),
                err,
            )
        })?;
        resolved_path = cwd.join(path);
        &resolved_path
    };
    let parent = effective_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has no parent directory", context),
        })?;
    let leaf_name = effective_path
        .file_name()
        .and_then(|os_val| os_val.to_str())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has invalid file name", context),
        })?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let Some(parent_dir) = open_existing_dir_nofollow_optional_with_trusted_uid(
            parent,
            extra_trusted_uid,
            true,
            context,
        )?
        else {
            return Ok(None);
        };
        let parent_dfd = parent_dir.as_raw_fd();
        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: "filename contains NUL byte".to_string(),
        })?;

        let mut pre_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut pre_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc != 0 {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(HostBackupError::io(
                format!("fstatat {} ({})", path.display(), context),
                st_err,
            ));
        }

        let pre_type = pre_st.st_mode & libc::S_IFMT;
        if pre_type == libc::S_IFLNK {
            return Err(HostBackupError::SymlinkRejected {
                path: path.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            });
        }
        if pre_type != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: path.to_path_buf(),
                reason: format!("{} exists and is not a regular file", context),
            });
        }

        let fd = unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let open_err = std::io::Error::last_os_error();
            if open_err.raw_os_error() == Some(libc::ELOOP) {
                return Err(HostBackupError::SymlinkRejected {
                    path: path.to_path_buf(),
                    reason: format!("{} is a symbolic link (ELOOP)", context),
                });
            }
            if open_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(HostBackupError::io(
                format!("openat {} ({})", path.display(), context),
                open_err,
            ));
        }

        let file = unsafe { File::from_raw_fd(fd) };
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut opened_st) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: path.to_path_buf(),
                reason: format!("opened descriptor for {} is not a regular file", context),
            });
        }
        if opened_st.st_dev != pre_st.st_dev || opened_st.st_ino != pre_st.st_ino {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} inode changed during no-follow open", context),
            });
        }

        let euid = unsafe { libc::geteuid() };
        let service_uid = resolve_trusted_service_account_ids().map(|(uid_val, _)| uid_val);
        let mut owner_trusted = opened_st.st_uid == 0 || opened_st.st_uid == euid;
        if !owner_trusted && !is_top_level_system_root(effective_path) {
            if let Some(extra_uid) = extra_trusted_uid {
                if opened_st.st_uid == extra_uid as libc::uid_t {
                    owner_trusted = true;
                }
            }
            if !owner_trusted && is_service_owned_subtree_eligible(effective_path) {
                if let Some(svc_uid) = service_uid {
                    if opened_st.st_uid == svc_uid as libc::uid_t {
                        owner_trusted = true;
                    }
                }
            }
        }
        if !owner_trusted {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "untrusted file owner uid={} on '{}' during {}",
                    opened_st.st_uid,
                    path.display(),
                    context
                ),
            });
        }

        Ok(Some((
            file,
            (opened_st.st_mode as u32) & 0o777,
            opened_st.st_uid as u32,
            opened_st.st_gid as u32,
        )))
    }

    #[cfg(not(unix))]
    {
        let _ = (parent, leaf_name, extra_trusted_uid);
        reject_if_symlink(effective_path, context)?;
        match fs::symlink_metadata(effective_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: format!("{} is a symbolic link", context),
                    });
                }
                if !meta.is_file() {
                    return Err(HostBackupError::UnsafeOverwriteRejected {
                        target: path.to_path_buf(),
                        reason: format!("{} exists and is not a regular file", context),
                    });
                }
                let file = File::open(effective_path).map_err(|err| {
                    HostBackupError::io(format!("opening {} ({})", path.display(), context), err)
                })?;
                Ok(Some((file, 0o600, 0, 0)))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(HostBackupError::io(
                format!("stat {} ({})", path.display(), context),
                err,
            )),
        }
    }
}

#[cfg(unix)]
fn is_top_level_system_root(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    matches!(
        raw.as_ref(),
        "/" | "/var"
            | "/var/lib"
            | "/etc"
            | "/opt"
            | "/home"
            | "/tmp"
            | "/var/tmp"
            | "/usr"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/lib64"
            | "/boot"
            | "/proc"
            | "/sys"
            | "/dev"
            | "/run"
    )
}

#[cfg(unix)]
fn is_service_owned_subtree_eligible(path: &Path) -> bool {
    if is_top_level_system_root(path) {
        return false;
    }
    if path.starts_with("/var/lib/aetherflow")
        || path.starts_with("/run/aetherflow")
        || path.starts_with("/etc/aetherflow")
        || path.starts_with("/etc/AetherFlow")
        || path.starts_with("/opt/AetherFlow")
        || path.starts_with("/home/aetherflow")
        || path.starts_with("/tmp")
        || path.starts_with("/var/tmp")
    {
        return true;
    }
    for env_key in [
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_RESTORE_STAGING_ROOT",
        "AETHERFLOW_BACKUP_DIR",
        "AETHERFLOW_OWNER_HOME",
    ] {
        if let Ok(env_val) = std::env::var(env_key) {
            let trimmed = env_val.trim();
            if !trimmed.is_empty() && path.starts_with(Path::new(trimmed)) {
                return true;
            }
        }
    }
    false
}

#[cfg(unix)]
fn verify_dir_fd_trusted_owner(
    fd: std::os::unix::io::RawFd,
    path: &Path,
    euid: libc::uid_t,
    service_uid: Option<u32>,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(HostBackupError::io(
            format!("fstat directory {} ({})", path.display(), context),
            std::io::Error::last_os_error(),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} descriptor is not a directory", context),
        });
    }
    let is_world_writable = (st.st_mode & 0o002) != 0;
    let is_sticky = (st.st_mode & libc::S_ISVTX) != 0;
    if is_world_writable && !is_sticky {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!(
                "refusing to traverse non-sticky world-writable directory '{}' (mode {:o}) during {}",
                path.display(),
                st.st_mode & 0o7777,
                context
            ),
        });
    }
    if euid == 0 && service_uid.is_none() && extra_trusted_uid.is_none() {
        let is_group_writable = (st.st_mode & 0o020) != 0;
        if is_group_writable && st.st_gid != 0 && !is_sticky {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "refusing to traverse non-sticky group-writable directory '{}' (gid={}, mode {:o}) during {}",
                    path.display(),
                    st.st_gid,
                    st.st_mode & 0o7777,
                    context
                ),
            });
        }
    }

    let mut trusted = st.st_uid == 0 || st.st_uid == euid;
    if !trusted && !is_top_level_system_root(path) {
        if let Some(extra_uid) = extra_trusted_uid {
            if st.st_uid == extra_uid as libc::uid_t {
                trusted = true;
            }
        }
        if !trusted && is_service_owned_subtree_eligible(path) {
            if let Some(svc_uid) = service_uid {
                if st.st_uid == svc_uid as libc::uid_t {
                    trusted = true;
                }
            }
        }
    }

    if !trusted {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!(
                "untrusted directory owner uid={} on '{}' (expected root=0, current euid={}, or trusted AetherFlow service owner {:?}/{:?})",
                st.st_uid,
                path.display(),
                euid,
                service_uid,
                extra_trusted_uid
            ),
        });
    }
    Ok(())
}
