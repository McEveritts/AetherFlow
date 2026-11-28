//! Hardened filesystem primitives for `af-release`.
//!
//! Provides symlink-free descriptor-based ancestor traversal, exclusive private directory
//! creation (`0700`), exclusive private file creation (`0600` before any bytes hit disk),
//! same-filesystem private `0700` staging with FD-based `fchown`/`fchmod` before `sync_all()`,
//! `dirfd` `renameat` publication with parent directory `fsync`, and Unix `aetherflow` service
//! user ownership resolution/preservation.

use crate::error::{ReleaseError, ReleaseResult};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(not(unix))]
use std::io::Write;

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Ownership policy applied on the open staged file descriptor prior to `sync_all()` and `renameat`.
#[derive(Debug, Clone, Copy)]
enum TargetOwnership<'a> {
    /// Leave ownership as created by the current effective UID/GID (no `fchown`).
    CurrentUser,
    /// Preserve `(uid, gid)` from `OwnershipMetadata`, or fall back to `aetherflow:aetherflow`.
    PreserveOrService(Option<&'a OwnershipMetadata>),
    /// Own as `root:aetherflow` (or `root:root` if `aetherflow` is absent) when `geteuid() == 0`.
    RootAetherflow,
    /// Own as `root:root` when `geteuid() == 0`.
    RootOwned,
}

#[cfg(unix)]
fn path_cstr(os: &std::ffi::OsStr, full_path: &Path) -> ReleaseResult<CString> {
    CString::new(os.as_bytes()).map_err(|_| ReleaseError::PathValidation {
        path: full_path.to_path_buf(),
        reason: "path component contains NUL byte".to_string(),
    })
}

#[cfg(unix)]
fn fstat_fd(fd: RawFd, path: &Path, context: &str) -> ReleaseResult<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(ReleaseError::io(
            format!("{} {}", context, path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(st)
}

#[cfg(unix)]
fn fstatat_nofollow(dfd: RawFd, name: &CStr) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

#[cfg(unix)]
pub(crate) fn sync_dir_fd(dfd: RawFd, dir_display: &Path) -> ReleaseResult<()> {
    if unsafe { libc::fsync(dfd) } != 0 {
        let err = std::io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::EROFS)) {
            return Err(ReleaseError::io(
                format!("fsync directory {}", dir_display.display()),
                err,
            ));
        }
    }
    Ok(())
}

/// Walks every component of `dir` without following symlinks (`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`)
/// and returns a pinned directory `File` descriptor for `dir`.
#[cfg(unix)]
pub(crate) fn open_dir_nofollow(dir: &Path) -> ReleaseResult<File> {
    crate::config::validate_no_parent_traversal(dir, "directory path")?;
    let mut cur_dir: Option<File> = None;
    let mut accum = PathBuf::new();

    for comp in dir.components() {
        accum.push(comp);
        match comp {
            Component::Prefix(_) | Component::ParentDir => {
                return Err(ReleaseError::PathValidation {
                    path: dir.to_path_buf(),
                    reason: "unsupported or parent traversal component in directory path"
                        .to_string(),
                });
            }
            Component::RootDir => {
                let c_root = CString::new("/").expect("static path");
                let fd = unsafe {
                    libc::open(
                        c_root.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(ReleaseError::io(
                        "opening root directory /",
                        std::io::Error::last_os_error(),
                    ));
                }
                cur_dir = Some(unsafe { File::from_raw_fd(fd) });
            }
            Component::CurDir => {
                if cur_dir.is_none() {
                    let c_dot = CString::new(".").expect("static path");
                    let fd = unsafe {
                        libc::open(
                            c_dot.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(ReleaseError::io(
                            "opening current directory .",
                            std::io::Error::last_os_error(),
                        ));
                    }
                    cur_dir = Some(unsafe { File::from_raw_fd(fd) });
                }
            }
            Component::Normal(seg) => {
                let c_seg = path_cstr(seg, &accum)?;
                let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
                let fd = unsafe {
                    libc::openat(
                        dirfd,
                        c_seg.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let err = std::io::Error::last_os_error();
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
                        return Err(ReleaseError::PathValidation {
                            path: accum,
                            reason: format!(
                                "refusing symlinked or non-directory component while opening '{}'",
                                dir.display()
                            ),
                        });
                    }
                    return Err(ReleaseError::io(
                        format!("opening directory component {}", accum.display()),
                        err,
                    ));
                }
                cur_dir = Some(unsafe { File::from_raw_fd(fd) });
            }
        }
    }

    cur_dir.ok_or_else(|| ReleaseError::PathValidation {
        path: dir.to_path_buf(),
        reason: "directory path resolved to no components".to_string(),
    })
}

/// Walks every component of `dir` without following symlinks, creating any missing directory
/// components with `create_mode` (applied via `fchmod` on the newly created directory FD only,
/// preserving permissions of any pre-existing ancestor directories such as sticky `/tmp`).
#[cfg(unix)]
pub(crate) fn open_or_create_dir_nofollow(dir: &Path, create_mode: u32) -> ReleaseResult<File> {
    crate::config::validate_no_parent_traversal(dir, "directory path")?;
    let mut cur_dir: Option<File> = None;
    let mut accum = PathBuf::new();

    for comp in dir.components() {
        accum.push(comp);
        match comp {
            Component::Prefix(_) | Component::ParentDir => {
                return Err(ReleaseError::PathValidation {
                    path: dir.to_path_buf(),
                    reason: "unsupported or parent traversal component in directory path"
                        .to_string(),
                });
            }
            Component::RootDir => {
                let c_root = CString::new("/").expect("static path");
                let fd = unsafe {
                    libc::open(
                        c_root.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(ReleaseError::io(
                        "opening root directory /",
                        std::io::Error::last_os_error(),
                    ));
                }
                cur_dir = Some(unsafe { File::from_raw_fd(fd) });
            }
            Component::CurDir => {
                if cur_dir.is_none() {
                    let c_dot = CString::new(".").expect("static path");
                    let fd = unsafe {
                        libc::open(
                            c_dot.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(ReleaseError::io(
                            "opening current directory .",
                            std::io::Error::last_os_error(),
                        ));
                    }
                    cur_dir = Some(unsafe { File::from_raw_fd(fd) });
                }
            }
            Component::Normal(seg) => {
                let c_seg = path_cstr(seg, &accum)?;
                let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
                let mut created_now = false;
                let mut fd = unsafe {
                    libc::openat(
                        dirfd,
                        c_seg.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    let mk_rc = unsafe {
                        libc::mkdirat(dirfd, c_seg.as_ptr(), (create_mode & 0o777) as libc::mode_t)
                    };
                    if mk_rc == 0 {
                        created_now = true;
                    } else {
                        let mk_err = std::io::Error::last_os_error();
                        if mk_err.raw_os_error() != Some(libc::EEXIST) {
                            return Err(ReleaseError::io(
                                format!("creating directory {}", accum.display()),
                                mk_err,
                            ));
                        }
                    }
                    fd = unsafe {
                        libc::openat(
                            dirfd,
                            c_seg.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                }
                if fd < 0 {
                    let err = std::io::Error::last_os_error();
                    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
                        return Err(ReleaseError::PathValidation {
                            path: accum,
                            reason: "symlinked or non-directory component rejected".to_string(),
                        });
                    }
                    return Err(ReleaseError::io(
                        format!("opening directory component {}", accum.display()),
                        err,
                    ));
                }
                let next_dir = unsafe { File::from_raw_fd(fd) };
                if created_now
                    && unsafe {
                        libc::fchmod(next_dir.as_raw_fd(), (create_mode & 0o777) as libc::mode_t)
                    } != 0
                {
                    return Err(ReleaseError::io(
                        format!(
                            "setting permissions {:o} on {}",
                            create_mode & 0o777,
                            accum.display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
                cur_dir = Some(next_dir);
            }
        }
    }

    cur_dir.ok_or_else(|| ReleaseError::PathValidation {
        path: dir.to_path_buf(),
        reason: "directory path resolved to no components".to_string(),
    })
}

#[cfg(unix)]
fn split_parent_and_leaf(path: &Path) -> ReleaseResult<(&Path, &std::ffi::OsStr)> {
    crate::config::validate_no_parent_traversal(path, "filesystem path")?;
    let leaf = path
        .file_name()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: "path has no final file component".to_string(),
        })?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Ok((parent, leaf))
}

#[cfg(unix)]
fn open_existing_regular_file_nofollow(path: &Path) -> ReleaseResult<File> {
    let (parent, leaf) = split_parent_and_leaf(path)?;
    let parent_dir = open_dir_nofollow(parent)?;
    let leaf_c = path_cstr(leaf, path)?;
    let fd = unsafe {
        libc::openat(
            parent_dir.as_raw_fd(),
            leaf_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ELOOP) {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing symlinked file".to_string(),
            });
        }
        return Err(ReleaseError::io(
            format!("opening file {}", path.display()),
            err,
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let st = fstat_fd(file.as_raw_fd(), path, "fstat file")?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: "path is not a regular file".to_string(),
        });
    }
    Ok(file)
}

#[cfg(unix)]
fn apply_fd_ownership_and_mode(
    fd: RawFd,
    display_path: &Path,
    ownership: TargetOwnership<'_>,
    mode: u32,
) -> ReleaseResult<()> {
    let euid = unsafe { libc::geteuid() };

    let target_ugid: Option<(libc::uid_t, libc::gid_t)> = match ownership {
        TargetOwnership::CurrentUser => None,
        TargetOwnership::PreserveOrService(preserve_from) => preserve_from
            .map(|m| (m.uid as libc::uid_t, m.gid as libc::gid_t))
            .or_else(|| {
                lookup_aetherflow_ugid().map(|(u, g)| (u as libc::uid_t, g as libc::gid_t))
            }),
        TargetOwnership::RootAetherflow => {
            if euid == 0 {
                let gid = lookup_aetherflow_ugid()
                    .map(|(_, g)| g as libc::gid_t)
                    .unwrap_or(0);
                Some((0, gid))
            } else {
                None
            }
        }
        TargetOwnership::RootOwned => {
            if euid == 0 {
                Some((0, 0))
            } else {
                None
            }
        }
    };

    if let Some((uid, gid)) = target_ugid {
        if unsafe { libc::fchown(fd, uid, gid) } != 0 {
            let err = std::io::Error::last_os_error();
            let is_perm_err = matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES));
            if euid == 0 || !is_perm_err {
                return Err(ReleaseError::io(
                    format!("fchown {}:{} on {}", uid, gid, display_path.display()),
                    err,
                ));
            }
        }
    }

    if unsafe { libc::fchmod(fd, (mode & 0o777) as libc::mode_t) } != 0 {
        return Err(ReleaseError::io(
            format!("fchmod {:o} on {}", mode & 0o777, display_path.display()),
            std::io::Error::last_os_error(),
        ));
    }

    Ok(())
}

/// Maximum cumulative bytes copied from an untrusted SQLite DB + sidecars into root scratch (`2 GiB`).
pub(crate) const MAX_SQLITE_SCRATCH_COPY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Returns `true` when `dir` and every ancestor from `/` down to `dir` is a real non-symlink
/// directory owned by `root` (`uid == 0`) that cannot be modified or renamed by non-root users.
///
/// When `allow_sticky` is `true`, root-owned sticky directories (e.g., `/tmp` `01777`) are
/// accepted because POSIX sticky semantics prevent non-root users from renaming or unlinking
/// root-owned subdirectories created inside them. When `allow_sticky` is `false` (used when
/// validating a *source* directory containing existing files), group/world write bits are
/// rejected unconditionally.
#[cfg(unix)]
pub fn is_trusted_root_path_dir(dir: &Path, allow_sticky: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    if !dir.is_absolute() || dir.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let mut accum = PathBuf::new();
    for comp in dir.components() {
        accum.push(comp);
        let Ok(meta) = fs::symlink_metadata(&accum) else {
            return false;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return false;
        }
        if meta.uid() != 0 {
            return false;
        }
        let mode = meta.mode();
        let writable_by_non_root = (mode & 0o022) != 0;
        #[allow(clippy::unnecessary_cast)]
        let sticky = (mode & (libc::S_ISVTX as u32)) != 0;
        if writable_by_non_root && !(allow_sticky && sticky) {
            return false;
        }
    }
    true
}

/// Validates that a directory inside a root-invoked dry-run tree is a real directory strictly
/// owned by `root` (`uid == 0`) with no group or world write bits (`(mode & 0o022) == 0`).
pub(crate) fn validate_root_dry_run_dir_stat(
    uid: u32,
    mode: u32,
    is_dir: bool,
) -> Result<(), String> {
    if !is_dir {
        return Err("dry-run directory component is not a directory".to_string());
    }
    if uid != 0 {
        return Err(format!(
            "refusing non-root-owned dry-run directory (uid={uid}, mode={:o})",
            mode & 0o7777
        ));
    }
    if (mode & 0o022) != 0 {
        return Err(format!(
            "refusing group/world-writable root dry-run directory (uid={uid}, mode={:o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

/// Ensures `target_dir` inside `dry_run_root` exists without traversing symlinks, and when
/// running as `root` (`euid == 0`) fails closed if `dry_run_root` (or any subdirectory from
/// `dry_run_root` down to `target_dir`) was pre-created by a non-root user or has group/world
/// write permissions.
#[cfg(unix)]
pub fn ensure_trusted_dry_run_dir(
    dry_run_root: &Path,
    target_dir: &Path,
    create_mode: u32,
    isolated_root: Option<&Path>,
) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(dry_run_root)?;
    ensure_no_symlink_ancestors(target_dir)?;

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        create_dir_all_no_symlinks(target_dir, create_mode)?;
        return Ok(());
    }

    if isolated_root.is_none() {
        let Some(parent) = dry_run_root.parent() else {
            return Err(ReleaseError::PathValidation {
                path: dry_run_root.to_path_buf(),
                reason: "dry_run_root must have a valid parent directory".to_string(),
            });
        };
        if !is_trusted_root_path_dir(parent, true) {
            return Err(ReleaseError::PathValidation {
                path: parent.to_path_buf(),
                reason: "refusing root dry-run under untrusted parent directory".to_string(),
            });
        }
    }

    let root_fd = open_or_create_dir_nofollow(dry_run_root, 0o700)?;
    let root_st = fstat_fd(
        root_fd.as_raw_fd(),
        dry_run_root,
        "fstat dry-run root directory",
    )?;
    validate_root_dry_run_dir_stat(
        root_st.st_uid,
        root_st.st_mode,
        (root_st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
    )
    .map_err(|reason| ReleaseError::PathValidation {
        path: dry_run_root.to_path_buf(),
        reason,
    })?;

    let rel = target_dir
        .strip_prefix(dry_run_root)
        .map_err(|_| ReleaseError::PathValidation {
            path: target_dir.to_path_buf(),
            reason: format!(
                "dry-run directory escapes dry_run_root '{}'",
                dry_run_root.display()
            ),
        })?;

    let mut cur_dir = root_fd;
    let mut accum = dry_run_root.to_path_buf();
    for comp in rel.components() {
        let std::path::Component::Normal(seg) = comp else {
            return Err(ReleaseError::PathValidation {
                path: target_dir.to_path_buf(),
                reason: "unexpected non-normal path component in dry-run directory".to_string(),
            });
        };
        accum.push(seg);
        let c_seg = CString::new(seg.as_bytes()).map_err(|_| ReleaseError::PathValidation {
            path: accum.clone(),
            reason: "directory component contains interior NUL byte".to_string(),
        })?;
        let dirfd = cur_dir.as_raw_fd();
        let mut created_now = false;
        let mut fd = unsafe {
            libc::openat(
                dirfd,
                c_seg.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            let mk_rc = unsafe {
                libc::mkdirat(dirfd, c_seg.as_ptr(), (create_mode & 0o755) as libc::mode_t)
            };
            if mk_rc == 0 {
                created_now = true;
            } else {
                let mk_err = std::io::Error::last_os_error();
                if mk_err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(ReleaseError::io(
                        format!("creating dry-run directory {}", accum.display()),
                        mk_err,
                    ));
                }
            }
            fd = unsafe {
                libc::openat(
                    dirfd,
                    c_seg.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
                return Err(ReleaseError::PathValidation {
                    path: accum,
                    reason: "symlinked or non-directory dry-run component rejected".to_string(),
                });
            }
            return Err(ReleaseError::io(
                format!("opening dry-run directory {}", accum.display()),
                err,
            ));
        }
        let next_dir = unsafe { File::from_raw_fd(fd) };
        if created_now
            && unsafe { libc::fchmod(next_dir.as_raw_fd(), (create_mode & 0o755) as libc::mode_t) }
                != 0
        {
            return Err(ReleaseError::io(
                format!(
                    "setting permissions {:o} on {}",
                    create_mode & 0o755,
                    accum.display()
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let st = fstat_fd(next_dir.as_raw_fd(), &accum, "fstat dry-run directory")?;
        validate_root_dry_run_dir_stat(
            st.st_uid,
            st.st_mode,
            (st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
        )
        .map_err(|reason| ReleaseError::PathValidation {
            path: accum.clone(),
            reason,
        })?;
        cur_dir = next_dir;
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_trusted_dry_run_dir(
    _dry_run_root: &Path,
    target_dir: &Path,
    create_mode: u32,
    _isolated_root: Option<&Path>,
) -> ReleaseResult<()> {
    create_dir_all_no_symlinks(target_dir, create_mode)
}

/// Private `0o700` scratch directory rooted strictly under a trusted root-owned base
/// (preferring disk-backed `/var/tmp`, then `/tmp`, then `/run` when `euid == 0`;
/// `std::env::temp_dir()` when unprivileged) with `fstatvfs` free-space verification so
/// path-based tools such as SQLite NEVER operate on paths inside an unprivileged user's
/// writable directory or exhaust small RAM-backed `/run` tmpfs mounts.
#[cfg(unix)]
pub(crate) struct TrustedRootScratchDir {
    base_dir: File,
    scratch_dir: File,
    dir_name: CString,
    identity: (libc::dev_t, libc::ino_t),
    dir_path: PathBuf,
    tracked_files: Vec<CString>,
}

#[cfg(unix)]
fn dir_available_bytes(dfd: RawFd) -> Option<u128> {
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(dfd, &mut vfs) } != 0 {
        return None;
    }
    let block_size = if vfs.f_frsize > 0 {
        vfs.f_frsize as u128
    } else {
        vfs.f_bsize as u128
    };
    Some((vfs.f_bavail as u128).saturating_mul(block_size))
}

#[cfg(unix)]
impl TrustedRootScratchDir {
    pub(crate) fn create_with_min_free(min_free_bytes: u64) -> ReleaseResult<Self> {
        let euid = unsafe { libc::geteuid() };
        let dir_str = format!(
            ".af-root-stage.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let dir_name = CString::new(dir_str.as_str()).expect("UUID scratch name has no NUL");

        let candidates: Vec<PathBuf> = if euid == 0 {
            vec![
                PathBuf::from("/var/tmp"),
                PathBuf::from("/tmp"),
                PathBuf::from("/run"),
            ]
        } else {
            vec![std::env::temp_dir()]
        };

        let mut chosen: Option<(File, PathBuf)> = None;
        for cand in candidates {
            if euid == 0 && !is_trusted_root_path_dir(&cand, true) {
                continue;
            }
            let Ok(base_dir) = open_dir_nofollow(&cand) else {
                continue;
            };
            if min_free_bytes > 0 {
                if let Some(avail) = dir_available_bytes(base_dir.as_raw_fd()) {
                    if avail < min_free_bytes as u128 {
                        continue;
                    }
                }
            }
            if unsafe { libc::mkdirat(base_dir.as_raw_fd(), dir_name.as_ptr(), 0o700) } == 0 {
                chosen = Some((base_dir, cand));
                break;
            }
        }

        let (base_dir, base_path) = chosen.ok_or_else(|| ReleaseError::PathValidation {
            path: PathBuf::from("/var/tmp"),
            reason: format!(
                "failed to create trusted root-owned 0700 scratch directory with at least {} bytes free",
                min_free_bytes
            ),
        })?;
        let dir_path = base_path.join(&dir_str);

        let fd = unsafe {
            libc::openat(
                base_dir.as_raw_fd(),
                dir_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
            }
            return Err(ReleaseError::io(
                format!("opening trusted scratch directory {}", dir_path.display()),
                err,
            ));
        }
        let scratch_dir = unsafe { File::from_raw_fd(fd) };

        let st = match fstat_fd(scratch_dir.as_raw_fd(), &dir_path, "fstat scratch dir") {
            Ok(st) => st,
            Err(err) => {
                drop(scratch_dir);
                unsafe {
                    libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(err);
            }
        };
        let expected_uid = if euid == 0 { 0 } else { euid };
        if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != expected_uid {
            drop(scratch_dir);
            unsafe {
                libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
            }
            return Err(ReleaseError::PathValidation {
                path: dir_path,
                reason: "trusted scratch directory failed owner/type invariant".to_string(),
            });
        }
        if unsafe { libc::fchmod(scratch_dir.as_raw_fd(), 0o700) } != 0 {
            let err = std::io::Error::last_os_error();
            drop(scratch_dir);
            unsafe {
                libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
            }
            return Err(ReleaseError::io(
                format!("fchmod 0700 on scratch directory {}", dir_path.display()),
                err,
            ));
        }
        let st = match fstat_fd(scratch_dir.as_raw_fd(), &dir_path, "fstat scratch dir") {
            Ok(st) => st,
            Err(err) => {
                drop(scratch_dir);
                unsafe {
                    libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(err);
            }
        };
        if (st.st_mode & 0o077) != 0 {
            drop(scratch_dir);
            unsafe {
                libc::unlinkat(base_dir.as_raw_fd(), dir_name.as_ptr(), libc::AT_REMOVEDIR);
            }
            return Err(ReleaseError::PathValidation {
                path: dir_path,
                reason: "trusted scratch directory failed 0700 privacy invariant".to_string(),
            });
        }

        Ok(Self {
            base_dir,
            scratch_dir,
            dir_name,
            identity: (st.st_dev, st.st_ino),
            dir_path,
            tracked_files: Vec::new(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir_path
    }

    pub(crate) fn dir_fd(&self) -> RawFd {
        self.scratch_dir.as_raw_fd()
    }

    pub(crate) fn track_file(&mut self, name: &str) {
        if let Ok(c) = CString::new(name) {
            self.tracked_files.push(c);
        }
    }
}

#[cfg(unix)]
impl Drop for TrustedRootScratchDir {
    fn drop(&mut self) {
        for name in &self.tracked_files {
            unsafe {
                libc::unlinkat(self.scratch_dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        unsafe {
            if let Ok(st) = fstatat_nofollow(self.base_dir.as_raw_fd(), &self.dir_name) {
                if (st.st_dev, st.st_ino) == self.identity {
                    libc::unlinkat(
                        self.base_dir.as_raw_fd(),
                        self.dir_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
            }
        }
    }
}

/// Same-filesystem private `0o700` staging directory used for TOCTOU-free atomic file publication.
///
/// When running as root (`geteuid() == 0`) targeting a directory owned by a non-root user
/// (such as `aetherflow`-owned `/var/lib/aetherflow`), prefers creating the `0o700` staging
/// directory inside the nearest root-owned, non-group/world-writable ancestor on the **exact
/// same filesystem** (`st_dev`) so the non-root user can neither traverse nor rename the staging
/// directory; falls back cleanly to a private `0o700` root-owned directory pinned by open FD
/// inside the target parent directory when the target is its own mountpoint or ancestors are
/// read-only (e.g. systemd `ReadWritePaths`). Callers performing **path-based** writes (such as
/// SQLite) MUST check `path_safe_for_root` and stage via [`TrustedRootScratchDir`] followed by
/// pure FD-only copying into `staging_dir` whenever `path_safe_for_root` is `false`.
#[cfg(unix)]
struct PrivateStagingDir {
    base_dir: File,
    staging_dir: File,
    stage_name: CString,
    tmp_name: CString,
    identity: (libc::dev_t, libc::ino_t),
    stage_path: PathBuf,
    path_safe_for_root: bool,
}

#[cfg(unix)]
impl PrivateStagingDir {
    fn create(parent_dir: &File, parent_path: &Path, tmp_name: &CString) -> ReleaseResult<Self> {
        let parent_st = fstat_fd(parent_dir.as_raw_fd(), parent_path, "fstat parent")?;
        let euid = unsafe { libc::geteuid() };
        let stage_str = format!(".af-stage.{}.{}", std::process::id(), uuid::Uuid::new_v4());
        let stage_name = CString::new(stage_str.as_str()).expect("UUID staging name has no NUL");

        let mut chosen_base: Option<(File, PathBuf)> = None;

        // When root writes into a non-root-owned directory (e.g. /var/lib/aetherflow),
        // prefer the nearest same-FS root-owned non-group/world-writable ancestor directory.
        if euid == 0 && parent_st.st_uid != 0 {
            let mut cur_anc = parent_path.parent();
            while let Some(anc) = cur_anc {
                if anc.as_os_str().is_empty() {
                    break;
                }
                let Ok(anc_dir) = open_dir_nofollow(anc) else {
                    break;
                };
                let Ok(anc_st) = fstat_fd(anc_dir.as_raw_fd(), anc, "fstat ancestor") else {
                    break;
                };
                if anc_st.st_dev != parent_st.st_dev {
                    // Mount boundary crossed — stop immediately to avoid EXDEV.
                    break;
                }
                if anc_st.st_uid == 0
                    && (anc_st.st_mode & 0o022) == 0
                    && unsafe { libc::mkdirat(anc_dir.as_raw_fd(), stage_name.as_ptr(), 0o700) }
                        == 0
                {
                    chosen_base = Some((anc_dir, anc.to_path_buf()));
                    break;
                }
                cur_anc = anc.parent();
            }
        }

        let (base_dir, base_path) = match chosen_base {
            Some(pair) => pair,
            None => {
                if unsafe { libc::mkdirat(parent_dir.as_raw_fd(), stage_name.as_ptr(), 0o700) } != 0
                {
                    return Err(ReleaseError::io(
                        format!(
                            "creating private staging directory in {}",
                            parent_path.display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
                let cloned_parent = parent_dir.try_clone().map_err(|err| {
                    unsafe {
                        libc::unlinkat(
                            parent_dir.as_raw_fd(),
                            stage_name.as_ptr(),
                            libc::AT_REMOVEDIR,
                        );
                    }
                    ReleaseError::io(
                        format!("cloning parent dir descriptor {}", parent_path.display()),
                        err,
                    )
                })?;
                (cloned_parent, parent_path.to_path_buf())
            }
        };

        let stage_path = base_path.join(&stage_str);
        let stage_fd = unsafe {
            libc::openat(
                base_dir.as_raw_fd(),
                stage_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if stage_fd < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::unlinkat(
                    base_dir.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
            return Err(ReleaseError::io(
                format!("opening private staging directory {}", stage_path.display()),
                err,
            ));
        }
        let staging_dir = unsafe { File::from_raw_fd(stage_fd) };

        let stage_st = match fstat_fd(staging_dir.as_raw_fd(), &stage_path, "fstat staging dir") {
            Ok(st) => st,
            Err(err) => {
                drop(staging_dir);
                unsafe {
                    libc::unlinkat(
                        base_dir.as_raw_fd(),
                        stage_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
                return Err(err);
            }
        };

        let owner_ok = if euid == 0 {
            stage_st.st_uid == 0
        } else {
            stage_st.st_uid == euid
        };
        if (stage_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || stage_st.st_dev != parent_st.st_dev
            || !owner_ok
        {
            drop(staging_dir);
            unsafe {
                libc::unlinkat(
                    base_dir.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
            return Err(ReleaseError::PathValidation {
                path: stage_path,
                reason: "staging directory failed same-FS or owner privacy invariants".to_string(),
            });
        }

        if unsafe { libc::fchmod(staging_dir.as_raw_fd(), 0o700) } != 0 {
            let err = std::io::Error::last_os_error();
            drop(staging_dir);
            unsafe {
                libc::unlinkat(
                    base_dir.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
            return Err(ReleaseError::io(
                format!(
                    "enforcing mode 0700 on staging directory {}",
                    stage_path.display()
                ),
                err,
            ));
        }

        let stage_st = match fstat_fd(staging_dir.as_raw_fd(), &stage_path, "fstat staging dir") {
            Ok(st) => st,
            Err(err) => {
                drop(staging_dir);
                unsafe {
                    libc::unlinkat(
                        base_dir.as_raw_fd(),
                        stage_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
                return Err(err);
            }
        };
        if (stage_st.st_mode & 0o077) != 0 {
            drop(staging_dir);
            unsafe {
                libc::unlinkat(
                    base_dir.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
            return Err(ReleaseError::PathValidation {
                path: stage_path,
                reason: "staging directory failed 0700 privacy invariant".to_string(),
            });
        }

        let path_safe_for_root = euid != 0 || is_trusted_root_path_dir(&base_path, true);
        Ok(Self {
            base_dir,
            staging_dir,
            stage_name,
            tmp_name: tmp_name.clone(),
            identity: (stage_st.st_dev, stage_st.st_ino),
            stage_path,
            path_safe_for_root,
        })
    }
}

#[cfg(unix)]
impl Drop for PrivateStagingDir {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.staging_dir.as_raw_fd(), self.tmp_name.as_ptr(), 0);
            if let Ok(st) = fstatat_nofollow(self.base_dir.as_raw_fd(), &self.stage_name) {
                if (st.st_dev, st.st_ino) == self.identity {
                    libc::unlinkat(
                        self.base_dir.as_raw_fd(),
                        self.stage_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
            }
        }
    }
}

#[cfg(unix)]
fn atomic_publish_from_reader_unix<R: Read>(
    reader: &mut R,
    dest: &Path,
    mode: u32,
    ownership: TargetOwnership<'_>,
) -> ReleaseResult<()> {
    atomic_publish_from_reader_unix_inner(reader, dest, mode, ownership, false)
}

#[cfg(unix)]
fn atomic_publish_from_reader_unix_inner<R: Read>(
    reader: &mut R,
    dest: &Path,
    mode: u32,
    ownership: TargetOwnership<'_>,
    allow_replace_symlink_leaf: bool,
) -> ReleaseResult<()> {
    let (parent, leaf) = split_parent_and_leaf(dest)?;
    let parent_dir = open_or_create_dir_nofollow(parent, 0o755)?;
    let parent_dfd = parent_dir.as_raw_fd();
    let leaf_c = path_cstr(leaf, dest)?;

    match fstatat_nofollow(parent_dfd, &leaf_c) {
        Ok(existing_st) => {
            let ftype = existing_st.st_mode & libc::S_IFMT;
            if ftype == libc::S_IFLNK {
                if !allow_replace_symlink_leaf {
                    return Err(ReleaseError::PathValidation {
                        path: dest.to_path_buf(),
                        reason: "refusing atomic overwrite of symlink destination".to_string(),
                    });
                }
            } else if ftype != libc::S_IFREG {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "refusing atomic overwrite of non-regular destination".to_string(),
                });
            }
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting destination {}", dest.display()),
                err,
            ));
        }
    }

    let file_name = leaf.to_string_lossy();
    let tmp_str = format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp_c = CString::new(tmp_str.as_bytes()).map_err(|_| ReleaseError::PathValidation {
        path: dest.to_path_buf(),
        reason: "temporary filename contains NUL byte".to_string(),
    })?;

    let staging = PrivateStagingDir::create(&parent_dir, parent, &tmp_c)?;
    let staging_dfd = staging.staging_dir.as_raw_fd();

    let tmp_fd = unsafe {
        libc::openat(
            staging_dfd,
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if tmp_fd < 0 {
        return Err(ReleaseError::io(
            format!("creating exclusive staged file for {}", dest.display()),
            std::io::Error::last_os_error(),
        ));
    }
    let mut tmp_file = unsafe { File::from_raw_fd(tmp_fd) };

    let stage_res: ReleaseResult<()> = (|| {
        std::io::copy(reader, &mut tmp_file).map_err(|err| {
            ReleaseError::io(format!("writing staged file for {}", dest.display()), err)
        })?;
        apply_fd_ownership_and_mode(tmp_file.as_raw_fd(), dest, ownership, mode)?;
        tmp_file.sync_all().map_err(|err| {
            ReleaseError::io(format!("fsync staged file for {}", dest.display()), err)
        })?;
        let tmp_st = fstat_fd(tmp_file.as_raw_fd(), dest, "fstat staged file")?;
        if (tmp_st.st_mode & libc::S_IFMT) != libc::S_IFREG || tmp_st.st_nlink != 1 {
            return Err(ReleaseError::PathValidation {
                path: dest.to_path_buf(),
                reason: "staged file failed regular-file or link-count invariant".to_string(),
            });
        }
        Ok(())
    })();

    // Close write descriptor before renameat so concurrent execve never observes ETXTBSY.
    drop(tmp_file);
    stage_res?;

    match fstatat_nofollow(parent_dfd, &leaf_c) {
        Ok(existing_st) => {
            let ftype = existing_st.st_mode & libc::S_IFMT;
            let allowed =
                ftype == libc::S_IFREG || (allow_replace_symlink_leaf && ftype == libc::S_IFLNK);
            if !allowed {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "destination changed to symlink or non-regular entry before renameat"
                        .to_string(),
                });
            }
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
        Err(err) => {
            return Err(ReleaseError::io(
                format!("re-verifying destination {}", dest.display()),
                err,
            ));
        }
    }

    if unsafe { libc::renameat(staging_dfd, tmp_c.as_ptr(), parent_dfd, leaf_c.as_ptr()) } != 0 {
        return Err(ReleaseError::io(
            format!("atomically publishing staged file to {}", dest.display()),
            std::io::Error::last_os_error(),
        ));
    }

    sync_dir_fd(parent_dfd, parent)?;
    drop(staging);
    Ok(())
}

/// Verifies that no existing ancestor component of `path` (up to and including `path` itself
/// if it already exists) is a symbolic link (`lstat` / `fs::symlink_metadata`).
///
/// Rejects pre-planted directory symlinks or ancestor symlinks that could redirect directory
/// creation or file extraction outside the intended root.
pub fn ensure_no_symlink_ancestors(path: &Path) -> ReleaseResult<()> {
    crate::config::validate_no_parent_traversal(path, "filesystem path")?;
    let mut accum = PathBuf::new();
    for comp in path.components() {
        accum.push(comp);
        match fs::symlink_metadata(&accum) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(ReleaseError::PathValidation {
                    path: accum,
                    reason: format!(
                        "refusing operation through symlink while checking '{}'",
                        path.display()
                    ),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ReleaseError::io(
                    format!("inspecting {}", accum.display()),
                    error,
                ))
            }
        }
    }
    Ok(())
}

pub fn ensure_no_symlink_in_relative_chain(base_dir: &Path, rel_path: &Path) -> ReleaseResult<()> {
    if rel_path.is_absolute() {
        return Err(ReleaseError::PathValidation {
            path: rel_path.to_path_buf(),
            reason: "release member path must be relative".to_string(),
        });
    }
    crate::config::validate_no_parent_traversal(rel_path, "release member path")?;
    ensure_no_symlink_ancestors(&base_dir.join(rel_path))
}

/// Ensures `dir` and all missing parents exist without traversing any symlinked ancestor,
/// applying `mode` (on Unix) to newly created target directories while preserving existing
/// ancestor directory permissions.
pub fn create_dir_all_no_symlinks(dir: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let _ = open_or_create_dir_nofollow(dir, mode)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(dir)?;

        let mut accum = PathBuf::new();
        for comp in dir.components() {
            accum.push(comp);
            if matches!(
                comp,
                Component::Prefix(_) | Component::RootDir | Component::CurDir
            ) {
                continue;
            }
            match fs::symlink_metadata(&accum) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(ReleaseError::PathValidation {
                            path: accum,
                            reason: "symlinked directory component rejected".to_string(),
                        });
                    }
                    if !meta.is_dir() {
                        return Err(ReleaseError::PathValidation {
                            path: accum,
                            reason: "path component exists and is not a directory".to_string(),
                        });
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    create_single_dir_with_mode(&accum, mode)?;
                }
                Err(err) => {
                    return Err(ReleaseError::io(
                        format!("inspecting directory component {}", accum.display()),
                        err,
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Creates a brand-new directory exclusively (`mkdirat` / `create_dir`, failing if `dir` already
/// exists as a file, symlink, or directory) after validating all parent ancestors are symlink-free
/// and created. Sets Unix mode `mode` (e.g. `0o700` or `0o755`) via `fchmod` on creation.
pub fn create_new_dir_exclusive(dir: &Path, parent_mode: u32, dir_mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let (parent, leaf) = split_parent_and_leaf(dir)?;
        let parent_dir = open_or_create_dir_nofollow(parent, parent_mode)?;
        let leaf_c = path_cstr(leaf, dir)?;
        if unsafe {
            libc::mkdirat(
                parent_dir.as_raw_fd(),
                leaf_c.as_ptr(),
                (dir_mode & 0o777) as libc::mode_t,
            )
        } != 0
        {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Err(ReleaseError::PathValidation {
                    path: dir.to_path_buf(),
                    reason: "target directory or pre-planted entry already exists".to_string(),
                });
            }
            return Err(ReleaseError::io(
                format!("creating directory {}", dir.display()),
                err,
            ));
        }
        let fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(ReleaseError::PathValidation {
                path: dir.to_path_buf(),
                reason: "created directory path resolved to a non-directory or symlink".to_string(),
            });
        }
        let created_dir = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fchmod(created_dir.as_raw_fd(), (dir_mode & 0o777) as libc::mode_t) } != 0
        {
            return Err(ReleaseError::io(
                format!("setting permissions {:o} on {}", dir_mode, dir.display()),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(dir)?;
        if let Some(parent) = dir.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_all_no_symlinks(parent, parent_mode)?;
            }
        }
        if fs::symlink_metadata(dir).is_ok() {
            return Err(ReleaseError::PathValidation {
                path: dir.to_path_buf(),
                reason: "target directory or pre-planted entry already exists".to_string(),
            });
        }
        create_single_dir_with_mode(dir, dir_mode)?;
        Ok(())
    }
}

#[cfg(not(unix))]
fn create_single_dir_with_mode(dir: &Path, mode: u32) -> ReleaseResult<()> {
    let _ = mode;
    fs::create_dir(dir)
        .map_err(|e| ReleaseError::io(format!("creating directory {}", dir.display()), e))?;
    Ok(())
}

/// Enforces explicit Unix permissions `mode` on `dir` via FD-based `fchmod` without following symlinks.
pub fn set_dir_mode(dir: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let dir_file = open_dir_nofollow(dir)?;
        if unsafe { libc::fchmod(dir_file.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
            return Err(ReleaseError::io(
                format!("setting directory mode {:o} on {}", mode, dir.display()),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(dir)
            .map_err(|e| ReleaseError::io(format!("stat directory {}", dir.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: dir.to_path_buf(),
                reason: "refusing to chmod symlinked directory".to_string(),
            });
        }
        let _ = mode;
        Ok(())
    }
}

/// Enforces explicit Unix permissions `mode` on `file_path` via FD-based `openat(O_NOFOLLOW | O_NONBLOCK)`
/// + `fstat(S_IFREG)` + `fchmod`, eliminating path-based symlink TOCTOU races.
pub fn set_file_mode(file_path: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let file = open_existing_regular_file_nofollow(file_path)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
            return Err(ReleaseError::io(
                format!("setting file mode {:o} on {}", mode, file_path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(file_path)
            .map_err(|e| ReleaseError::io(format!("stat file {}", file_path.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: file_path.to_path_buf(),
                reason: "refusing to chmod symlinked file".to_string(),
            });
        }
        let _ = mode;
        Ok(())
    }
}

/// Opens a brand-new file exclusively (`O_CREAT | O_EXCL` / `create_new(true)`) with Unix
/// permissions set to `mode` (e.g., `0o600`) **before** any bytes are written, bypassing
/// permissive process `umask` defaults and rejecting pre-existing files or symlinks.
pub fn open_exclusive_private_file(path: &Path, mode: u32) -> ReleaseResult<File> {
    #[cfg(unix)]
    {
        let (parent, leaf) = split_parent_and_leaf(path)?;
        let parent_dir = open_dir_nofollow(parent)?;
        let leaf_c = path_cstr(leaf, path)?;
        let fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                (mode & 0o777) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(ReleaseError::io(
                format!(
                    "creating exclusive file {} (mode {:o})",
                    path.display(),
                    mode
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
            let err = std::io::Error::last_os_error();
            drop(file);
            unsafe {
                libc::unlinkat(parent_dir.as_raw_fd(), leaf_c.as_ptr(), 0);
            }
            return Err(ReleaseError::io(
                format!("enforcing mode {:o} on {}", mode, path.display()),
                err,
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(path)?;
        let mut opts = OpenOptions::new();
        opts.write(true).read(true).create_new(true);
        let file = opts.open(path).map_err(|e| {
            ReleaseError::io(
                format!(
                    "creating exclusive file {} (mode {:o})",
                    path.display(),
                    mode
                ),
                e,
            )
        })?;
        let _ = mode;
        Ok(file)
    }
}

/// Atomically writes `contents` to `target` via a same-filesystem private `0o700` staging
/// directory, `fchmod` on the open FD before `sync_all()`, `dirfd` `renameat`, and parent
/// directory `fsync`.
pub fn atomic_write_bytes_with_mode(
    target: &Path,
    contents: &[u8],
    mode: u32,
) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let mut slice = contents;
        atomic_publish_from_reader_unix(&mut slice, target, mode, TargetOwnership::CurrentUser)
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(target)?;
        let parent = target
            .parent()
            .ok_or_else(|| ReleaseError::PathValidation {
                path: target.to_path_buf(),
                reason: "target file has no parent directory".to_string(),
            })?;
        if !parent.try_exists().map_err(|error| {
            ReleaseError::io(format!("inspecting parent {}", parent.display()), error)
        })? {
            create_dir_all_no_symlinks(parent, 0o755)?;
        }

        let file_name = target.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
        let tmp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));

        let mut tmp_file = open_exclusive_private_file(&tmp_path, mode)?;
        if let Err(e) = tmp_file
            .write_all(contents)
            .and_then(|()| tmp_file.sync_all())
        {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(ReleaseError::io(
                format!("writing and syncing temporary file {}", tmp_path.display()),
                e,
            ));
        }
        drop(tmp_file);

        fs::rename(&tmp_path, target).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ReleaseError::io(
                format!(
                    "atomically renaming {} -> {}",
                    tmp_path.display(),
                    target.display()
                ),
                e,
            )
        })?;
        Ok(())
    }
}

/// Stages a freshly built file (e.g. SQLite online backup) inside a same-filesystem
/// root-owned `0700` [`PrivateStagingDir`] (or [`TrustedRootScratchDir`] + pure FD streaming when
/// `root` publishes into an unprivileged mountpoint/directory), applies FD-based `fchown` and
/// `fchmod` + `sync_all()` before closing, atomically publishes the file via `dirfd` `renameat`,
/// removes stale `-wal`/`-shm`/`-journal` sidecars in the destination directory via `unlinkat`
/// after the rename succeeds, and `fsync`s the parent directory.
#[allow(clippy::too_many_arguments)]
pub(crate) fn atomic_publish_staged_file_with_mode<F>(
    dest: &Path,
    mode: u32,
    preserve_from: Option<&OwnershipMetadata>,
    root_owned_override: bool,
    allow_replace_symlink_leaf: bool,
    remove_sqlite_sidecars: bool,
    min_scratch_free_bytes: u64,
    build_staged: F,
) -> ReleaseResult<()>
where
    F: FnOnce(&Path) -> ReleaseResult<()>,
{
    #[cfg(not(unix))]
    let _ = min_scratch_free_bytes;
    let parent = dest.parent().ok_or_else(|| ReleaseError::PathValidation {
        path: dest.to_path_buf(),
        reason: "destination file has no parent directory".to_string(),
    })?;
    ensure_no_symlink_ancestors(parent)?;
    if !parent.try_exists().map_err(|error| {
        ReleaseError::io(format!("inspecting parent {}", parent.display()), error)
    })? {
        create_dir_all_no_symlinks(parent, 0o700)?;
    }

    #[cfg(unix)]
    {
        let target_ownership = if root_owned_override {
            TargetOwnership::RootOwned
        } else {
            TargetOwnership::PreserveOrService(preserve_from)
        };
        let dest_str = dest.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            ReleaseError::PathValidation {
                path: dest.to_path_buf(),
                reason: "destination file name is missing or non-UTF-8".to_string(),
            }
        })?;
        let dest_name = CString::new(dest_str).map_err(|_| ReleaseError::PathValidation {
            path: dest.to_path_buf(),
            reason: "destination file name contains interior NUL byte".to_string(),
        })?;
        let parent_dir = open_dir_nofollow(parent)?;

        if let Ok(existing_st) = fstatat_nofollow(parent_dir.as_raw_fd(), &dest_name) {
            let ftype = existing_st.st_mode & libc::S_IFMT;
            if ftype == libc::S_IFDIR {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "refusing to overwrite directory at destination file path".to_string(),
                });
            }
            if ftype == libc::S_IFLNK && !allow_replace_symlink_leaf {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "refusing to overwrite symlink destination".to_string(),
                });
            }
        }

        let tmp_str = format!(
            ".{}.tmp.{}.{}",
            dest_str,
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let tmp_name =
            CString::new(tmp_str.as_str()).map_err(|_| ReleaseError::PathValidation {
                path: dest.to_path_buf(),
                reason: "staging file name contains interior NUL byte".to_string(),
            })?;
        let staging = PrivateStagingDir::create(&parent_dir, parent, &tmp_name)?;
        let staged_path = staging.stage_path.join(&tmp_str);

        if staging.path_safe_for_root {
            // Same-FS staging directory is guaranteed untouchable by non-root users; build directly.
            let init_fd = unsafe {
                libc::openat(
                    staging.staging_dir.as_raw_fd(),
                    tmp_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if init_fd < 0 {
                return Err(ReleaseError::io(
                    format!("creating staged file {}", staged_path.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            drop(unsafe { File::from_raw_fd(init_fd) });

            let build_res = build_staged(&staged_path);
            // Always clean up any SQLite sidecars created inside the private staging dir so rmdir succeeds.
            if remove_sqlite_sidecars {
                for suffix in ["-wal", "-shm", "-journal"] {
                    if let Ok(sc) = CString::new(format!("{tmp_str}{suffix}")) {
                        unsafe {
                            libc::unlinkat(staging.staging_dir.as_raw_fd(), sc.as_ptr(), 0);
                        }
                    }
                }
            }
            build_res?;

            let staged_fd = unsafe {
                libc::openat(
                    staging.staging_dir.as_raw_fd(),
                    tmp_name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if staged_fd < 0 {
                return Err(ReleaseError::io(
                    format!("reopening staged file {}", staged_path.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            let mut staged_file = unsafe { File::from_raw_fd(staged_fd) };
            let st = fstat_fd(staged_file.as_raw_fd(), &staged_path, "fstat staged file")?;
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 1 {
                return Err(ReleaseError::PathValidation {
                    path: staged_path,
                    reason: "staged file is not an exclusive regular file".to_string(),
                });
            }
            if remove_sqlite_sidecars {
                verify_staged_sqlite_header_fd(&mut staged_file, st.st_size, &staged_path)?;
            }
            apply_fd_ownership_and_mode(staged_file.as_raw_fd(), dest, target_ownership, mode)?;
            staged_file.sync_all().map_err(|err| {
                ReleaseError::io(
                    format!("syncing staged file {}", staged_path.display()),
                    err,
                )
            })?;
            drop(staged_file);
        } else {
            // Root is publishing into a non-root-owned mountpoint/directory whose ancestors are
            // not writable on the same filesystem. NEVER pass a path inside `parent` to SQLite:
            // build inside a guaranteed root-owned 0700 scratch directory (/run or /tmp), verify
            // the staged FD, and stream-copy strictly via open FDs into `staging.staging_dir`.
            let mut scratch = TrustedRootScratchDir::create_with_min_free(min_scratch_free_bytes)?;
            let scratch_name_str = "staged.sqlite";
            let scratch_name =
                CString::new(scratch_name_str).expect("static scratch filename has no NUL");
            scratch.track_file(scratch_name_str);
            scratch.track_file("staged.sqlite-wal");
            scratch.track_file("staged.sqlite-shm");
            scratch.track_file("staged.sqlite-journal");
            let scratch_staged_path = scratch.path().join(scratch_name_str);

            let init_fd = unsafe {
                libc::openat(
                    scratch.dir_fd(),
                    scratch_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if init_fd < 0 {
                return Err(ReleaseError::io(
                    format!(
                        "creating root scratch staged file {}",
                        scratch_staged_path.display()
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
            drop(unsafe { File::from_raw_fd(init_fd) });

            let build_res = build_staged(&scratch_staged_path);
            if remove_sqlite_sidecars {
                for suffix in ["-wal", "-shm", "-journal"] {
                    if let Ok(sc) = CString::new(format!("{scratch_name_str}{suffix}")) {
                        unsafe {
                            libc::unlinkat(scratch.dir_fd(), sc.as_ptr(), 0);
                        }
                    }
                }
            }
            build_res?;

            let scratch_fd = unsafe {
                libc::openat(
                    scratch.dir_fd(),
                    scratch_name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if scratch_fd < 0 {
                return Err(ReleaseError::io(
                    format!(
                        "reopening root scratch staged file {}",
                        scratch_staged_path.display()
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
            let mut scratch_file = unsafe { File::from_raw_fd(scratch_fd) };
            let sst = fstat_fd(
                scratch_file.as_raw_fd(),
                &scratch_staged_path,
                "fstat scratch staged file",
            )?;
            if (sst.st_mode & libc::S_IFMT) != libc::S_IFREG || sst.st_nlink != 1 {
                return Err(ReleaseError::PathValidation {
                    path: scratch_staged_path,
                    reason: "scratch staged file is not an exclusive regular file".to_string(),
                });
            }
            if remove_sqlite_sidecars {
                verify_staged_sqlite_header_fd(
                    &mut scratch_file,
                    sst.st_size,
                    &scratch_staged_path,
                )?;
            }

            // Stream-copy strictly by open FDs into the same-FS PrivateStagingDir.
            let out_fd = unsafe {
                libc::openat(
                    staging.staging_dir.as_raw_fd(),
                    tmp_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if out_fd < 0 {
                return Err(ReleaseError::io(
                    format!("creating same-FS staged file for {}", dest.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            let mut out_file = unsafe { File::from_raw_fd(out_fd) };
            std::io::copy(&mut scratch_file, &mut out_file).map_err(|err| {
                ReleaseError::io(
                    format!("streaming verified backup into {}", dest.display()),
                    err,
                )
            })?;
            let out_st = fstat_fd(out_file.as_raw_fd(), dest, "fstat copied staged file")?;
            if (out_st.st_mode & libc::S_IFMT) != libc::S_IFREG || out_st.st_nlink != 1 {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "copied staged file failed regular-file or link-count invariant"
                        .to_string(),
                });
            }
            apply_fd_ownership_and_mode(out_file.as_raw_fd(), dest, target_ownership, mode)?;
            out_file.sync_all().map_err(|err| {
                ReleaseError::io(format!("syncing staged file for {}", dest.display()), err)
            })?;
            drop(out_file);
        }

        if unsafe {
            libc::renameat(
                staging.staging_dir.as_raw_fd(),
                tmp_name.as_ptr(),
                parent_dir.as_raw_fd(),
                dest_name.as_ptr(),
            )
        } != 0
        {
            return Err(ReleaseError::io(
                format!(
                    "atomically renaming staged file {} -> {}",
                    staged_path.display(),
                    dest.display()
                ),
                std::io::Error::last_os_error(),
            ));
        }
        // Unlink stale SQLite sidecars ONLY after the atomic rename succeeds so a failed rename
        // never destroys uncheckpointed WAL/journal state for the previous live database.
        if remove_sqlite_sidecars {
            for suffix in ["-wal", "-shm", "-journal"] {
                if let Ok(sc) = CString::new(format!("{dest_str}{suffix}")) {
                    unsafe {
                        libc::unlinkat(parent_dir.as_raw_fd(), sc.as_ptr(), 0);
                    }
                }
            }
        }
        sync_dir_fd(parent_dir.as_raw_fd(), parent)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (
            root_owned_override,
            allow_replace_symlink_leaf,
            remove_sqlite_sidecars,
        );
        let dest_str = dest
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("staged.db");
        let tmp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            dest_str,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let f = open_exclusive_private_file(&tmp_path, mode)?;
        drop(f);
        if let Err(err) = build_staged(&tmp_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Ok(f) = File::open(&tmp_path) {
            let _ = f.sync_all();
        }
        fs::rename(&tmp_path, dest).map_err(|err| {
            let _ = fs::remove_file(&tmp_path);
            ReleaseError::io(
                format!("renaming {} -> {}", tmp_path.display(), dest.display()),
                err,
            )
        })?;
        apply_service_ownership(dest, preserve_from, mode)?;
        Ok(())
    }
}

/// Verifies a staged SQLite file descriptor is non-empty (`>= 100` bytes — the SQLite file
/// header size) and begins with the canonical 16-byte `SQLite format 3\0` magic header, then
/// rewinds the descriptor to offset `0` so callers can stream-copy from it cleanly.
#[cfg(unix)]
fn verify_staged_sqlite_header_fd(
    file: &mut File,
    st_size: libc::off_t,
    display_path: &Path,
) -> ReleaseResult<()> {
    use std::io::{Seek, SeekFrom};

    if st_size < 100 {
        return Err(ReleaseError::Snapshot {
            db_path: display_path.to_path_buf(),
            reason: format!(
                "staged SQLite backup is unexpectedly truncated ({} bytes < 100-byte header)",
                st_size
            ),
        });
    }
    let mut header = [0_u8; 16];
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        ReleaseError::io(
            format!("seeking staged SQLite file {}", display_path.display()),
            err,
        )
    })?;
    file.read_exact(&mut header).map_err(|err| {
        ReleaseError::io(
            format!("reading staged SQLite header {}", display_path.display()),
            err,
        )
    })?;
    if &header != b"SQLite format 3\0" {
        return Err(ReleaseError::Snapshot {
            db_path: display_path.to_path_buf(),
            reason: "staged SQLite backup failed SQLite format 3 header verification".to_string(),
        });
    }
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        ReleaseError::io(
            format!("rewinding staged SQLite file {}", display_path.display()),
            err,
        )
    })?;
    Ok(())
}

/// Validates `db_path` and any present SQLite sidecar files (`-wal`, `-shm`, `-journal`)
/// via component-wise `open_dir_nofollow`, `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`,
/// and `fstat(S_IFREG && nlink == 1)`, eliminating symlink traversal, hardlink tricks, and FIFO
/// hangs before SQLite touches the database path. Returns `Ok(None)` when `db_path` does not exist.
/// SQLite rollback journal header/super-journal trailer magic (`aJournalMagic` in `sqlite3.c`).
pub(crate) const SQLITE_JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

/// Rejects any SQLite rollback `-journal` containing a super-journal (`zSuper`) trailer.
/// Single-DB AetherFlow / `*arr` transactions never emit multi-DB `ATTACH` super-journals; a
/// crafted trailer causes SQLite `pager_playback()` -> `pager_delsuper()` to `open()` arbitrary
/// host paths without `O_NONBLOCK` or directory confinement.
#[cfg(unix)]
pub(crate) fn reject_sqlite_super_journal_trailer_fd(
    file: &mut File,
    display_path: &Path,
) -> ReleaseResult<()> {
    use std::io::{Read, Seek, SeekFrom};
    let len = file
        .metadata()
        .map_err(|err| {
            ReleaseError::io(
                format!("fstat SQLite journal {}", display_path.display()),
                err,
            )
        })?
        .len();
    if len >= 16 {
        file.seek(SeekFrom::End(-8)).map_err(|err| {
            ReleaseError::io(
                format!("seeking SQLite journal {}", display_path.display()),
                err,
            )
        })?;
        let mut tail = [0u8; 8];
        file.read_exact(&mut tail).map_err(|err| {
            ReleaseError::io(
                format!("reading SQLite journal trailer {}", display_path.display()),
                err,
            )
        })?;
        let _ = file.seek(SeekFrom::Start(0));
        if tail == SQLITE_JOURNAL_MAGIC {
            return Err(ReleaseError::PathValidation {
                path: display_path.to_path_buf(),
                reason:
                    "refusing SQLite rollback journal containing forbidden super-journal trailer"
                        .to_string(),
            });
        }
    }
    Ok(())
}

pub fn validate_sqlite_file_and_sidecars_nofollow(db_path: &Path) -> ReleaseResult<Option<File>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let (parent, leaf) = split_parent_and_leaf(db_path)?;
        let parent_dir = match open_dir_nofollow(parent) {
            Ok(dir) => dir,
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let leaf_c = path_cstr(leaf, db_path)?;
        let db_fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if db_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(ReleaseError::PathValidation {
                    path: db_path.to_path_buf(),
                    reason: "refusing symlinked SQLite database file".to_string(),
                });
            }
            return Err(ReleaseError::io(
                format!("opening SQLite database {}", db_path.display()),
                err,
            ));
        }
        let db_file = unsafe { File::from_raw_fd(db_fd) };
        let st = fstat_fd(db_file.as_raw_fd(), db_path, "fstat SQLite database")?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 1 {
            return Err(ReleaseError::PathValidation {
                path: db_path.to_path_buf(),
                reason: "SQLite database must be an exclusive regular non-symlink file".to_string(),
            });
        }
        for suffix in [
            b"-wal".as_slice(),
            b"-shm".as_slice(),
            b"-journal".as_slice(),
        ] {
            let mut sc_bytes = leaf.as_bytes().to_vec();
            sc_bytes.extend_from_slice(suffix);
            let sc_c = CString::new(sc_bytes).map_err(|_| ReleaseError::PathValidation {
                path: db_path.to_path_buf(),
                reason: "SQLite sidecar filename contains NUL byte".to_string(),
            })?;
            let sc_fd = unsafe {
                libc::openat(
                    parent_dir.as_raw_fd(),
                    sc_c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if sc_fd >= 0 {
                let mut sc_file = unsafe { File::from_raw_fd(sc_fd) };
                let sc_st = fstat_fd(sc_file.as_raw_fd(), db_path, "fstat SQLite sidecar")?;
                if (sc_st.st_mode & libc::S_IFMT) != libc::S_IFREG || sc_st.st_nlink != 1 {
                    return Err(ReleaseError::PathValidation {
                        path: db_path.to_path_buf(),
                        reason: "SQLite sidecar must be an exclusive regular non-symlink file"
                            .to_string(),
                    });
                }
                if suffix == b"-journal" {
                    reject_sqlite_super_journal_trailer_fd(&mut sc_file, db_path)?;
                }
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                if err.raw_os_error() == Some(libc::ELOOP) {
                    return Err(ReleaseError::PathValidation {
                        path: db_path.to_path_buf(),
                        reason: "refusing symlinked SQLite sidecar file".to_string(),
                    });
                }
                return Err(ReleaseError::io(
                    format!("inspecting SQLite sidecar for {}", db_path.display()),
                    err,
                ));
            }
        }
        Ok(Some(db_file))
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(db_path)?;
        match File::open(db_path) {
            Ok(f) => Ok(Some(f)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(ReleaseError::io(
                format!("opening SQLite database {}", db_path.display()),
                err,
            )),
        }
    }
}

/// Opens an existing regular non-symlink file via component-wise `O_DIRECTORY | O_NOFOLLOW`
/// traversal (anchored at `anchor_root` when `path` lies inside it so host OS symlinks above an
/// isolated test root such as `/var/run -> /run` do not cause false rejections), opening the leaf
/// with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and verifying `S_IFREG`.
#[cfg(unix)]
pub(crate) fn open_regular_file_nofollow_anchored(
    path: &Path,
    anchor_root: Option<&Path>,
) -> ReleaseResult<File> {
    let (parent, leaf) = split_parent_and_leaf(path)?;
    let parent_dir = match anchor_root {
        Some(root) if parent.starts_with(root) => {
            let root_c = path_cstr(root.as_os_str(), root)?;
            let anchor_fd = unsafe {
                libc::open(
                    root_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if anchor_fd < 0 {
                return Err(ReleaseError::io(
                    format!("opening anchor root {}", root.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            let mut cur_dir = unsafe { File::from_raw_fd(anchor_fd) };
            let mut accum = root.to_path_buf();
            if let Ok(rel) = parent.strip_prefix(root) {
                for comp in rel.components() {
                    match comp {
                        Component::CurDir => {}
                        Component::Normal(seg) => {
                            accum.push(seg);
                            let c_seg = path_cstr(seg, &accum)?;
                            let fd = unsafe {
                                libc::openat(
                                    cur_dir.as_raw_fd(),
                                    c_seg.as_ptr(),
                                    libc::O_RDONLY
                                        | libc::O_DIRECTORY
                                        | libc::O_NOFOLLOW
                                        | libc::O_CLOEXEC,
                                )
                            };
                            if fd < 0 {
                                let err = std::io::Error::last_os_error();
                                if matches!(
                                    err.raw_os_error(),
                                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                                ) {
                                    return Err(ReleaseError::PathValidation {
                                        path: accum,
                                        reason: format!(
                                            "refusing symlinked or non-directory component while opening '{}'",
                                            path.display()
                                        ),
                                    });
                                }
                                return Err(ReleaseError::io(
                                    format!("opening directory component {}", accum.display()),
                                    err,
                                ));
                            }
                            cur_dir = unsafe { File::from_raw_fd(fd) };
                        }
                        _ => {
                            return Err(ReleaseError::PathValidation {
                                path: path.to_path_buf(),
                                reason: "unsupported path component in anchored file open"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
            cur_dir
        }
        _ => open_dir_nofollow(parent)?,
    };

    let leaf_c = path_cstr(leaf, path)?;
    let fd = unsafe {
        libc::openat(
            parent_dir.as_raw_fd(),
            leaf_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ELOOP) {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing symlinked file".to_string(),
            });
        }
        return Err(ReleaseError::io(
            format!("opening file {}", path.display()),
            err,
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let st = fstat_fd(file.as_raw_fd(), path, "fstat file")?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(ReleaseError::PathValidation {
            path: path.to_path_buf(),
            reason: "path is not a regular file".to_string(),
        });
    }
    Ok(file)
}

/// Reads an exclusive regular non-symlink file (`O_DIRECTORY | O_NOFOLLOW` ancestor walk,
/// `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, `S_IFREG && st_nlink == 1`) with an
/// explicit upper bound `max_bytes`.
pub fn read_regular_file_bounded_nofollow(path: &Path, max_bytes: u64) -> ReleaseResult<Vec<u8>> {
    #[cfg(unix)]
    {
        let file = open_existing_regular_file_nofollow(path)?;
        let st = fstat_fd(file.as_raw_fd(), path, "fstat file")?;
        if st.st_nlink != 1 {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing file with multiple hard links".to_string(),
            });
        }
        if st.st_size < 0 || (st.st_size as u64) > max_bytes {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("file exceeds maximum allowed size ({} bytes)", max_bytes),
            });
        }
        let mut raw = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|err| ReleaseError::io(format!("reading file {}", path.display()), err))?;
        if (raw.len() as u64) > max_bytes {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("file exceeds maximum allowed size ({} bytes)", max_bytes),
            });
        }
        Ok(raw)
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(path)?;
        let meta = fs::symlink_metadata(path)
            .map_err(|err| ReleaseError::io(format!("stat file {}", path.display()), err))?;
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max_bytes {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "file must be a bounded regular non-symlink file".to_string(),
            });
        }
        let file = File::open(path)
            .map_err(|err| ReleaseError::io(format!("opening file {}", path.display()), err))?;
        let mut raw = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|err| ReleaseError::io(format!("reading file {}", path.display()), err))?;
        if (raw.len() as u64) > max_bytes {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("file exceeds maximum allowed size ({} bytes)", max_bytes),
            });
        }
        Ok(raw)
    }
}

/// Hardened SQLite connection wrapper that holds an optional private `0700` root-owned scratch
/// directory alive for the duration of the connection and closes the SQLite connection **before**
/// deleting the scratch replica so `-wal`/`-shm` sidecars are always cleaned up cleanly.
pub struct IsolatedSqliteReplica {
    conn: Option<rusqlite::Connection>,
    #[cfg(unix)]
    _scratch: Option<TrustedRootScratchDir>,
}

impl std::ops::Deref for IsolatedSqliteReplica {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        self.conn
            .as_ref()
            .expect("IsolatedSqliteReplica connection present until Drop")
    }
}

impl std::ops::DerefMut for IsolatedSqliteReplica {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn
            .as_mut()
            .expect("IsolatedSqliteReplica connection present until Drop")
    }
}

impl Drop for IsolatedSqliteReplica {
    fn drop(&mut self) {
        // Explicitly close SQLite before `_scratch` drops so `-wal`/`-shm` unlinks succeed.
        drop(self.conn.take());
    }
}

#[cfg(unix)]
fn copy_fd_bounded_to_scratch(
    reader: &mut File,
    scratch: &TrustedRootScratchDir,
    name: &str,
    remaining_cap: &mut u64,
    display_path: &Path,
) -> ReleaseResult<()> {
    use std::io::Write;
    let c_name = CString::new(name).expect("static scratch filename has no NUL");
    let out_fd = unsafe {
        libc::openat(
            scratch.dir_fd(),
            c_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if out_fd < 0 {
        return Err(ReleaseError::io(
            format!(
                "creating scratch file {} for {}",
                name,
                display_path.display()
            ),
            std::io::Error::last_os_error(),
        ));
    }
    let mut out = unsafe { File::from_raw_fd(out_fd) };
    let cap = *remaining_cap;
    let mut copied: u64 = 0;
    let mut tail8 = [0u8; 8];
    let mut tail_len: usize = 0;
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf).map_err(|err| {
            ReleaseError::io(
                format!("reading {} for root scratch", display_path.display()),
                err,
            )
        })?;
        if n == 0 {
            break;
        }
        copied = copied.saturating_add(n as u64);
        if copied > cap {
            return Err(ReleaseError::Snapshot {
                db_path: display_path.to_path_buf(),
                reason: format!(
                    "SQLite database and sidecars exceed root scratch copy cap ({} bytes)",
                    MAX_SQLITE_SCRATCH_COPY_BYTES
                ),
            });
        }
        out.write_all(&buf[..n]).map_err(|err| {
            ReleaseError::io(
                format!("copying {} into root scratch", display_path.display()),
                err,
            )
        })?;
        if n >= 8 {
            tail8.copy_from_slice(&buf[n - 8..n]);
            tail_len = 8;
        } else {
            let keep = (tail_len + n).min(8);
            let shift = (tail_len + n).saturating_sub(8);
            if shift < tail_len {
                tail8.copy_within(shift..tail_len, 0);
            }
            let dst_start = keep - n;
            tail8[dst_start..keep].copy_from_slice(&buf[..n]);
            tail_len = keep;
        }
    }
    if name.ends_with("-journal") && copied >= 16 && tail_len == 8 && tail8 == SQLITE_JOURNAL_MAGIC
    {
        return Err(ReleaseError::PathValidation {
            path: display_path.to_path_buf(),
            reason: "refusing SQLite rollback journal containing forbidden super-journal trailer"
                .to_string(),
        });
    }
    *remaining_cap = cap.saturating_sub(copied);
    Ok(())
}

#[cfg(unix)]
fn open_sqlite_in_root_scratch(db_path: &Path) -> ReleaseResult<IsolatedSqliteReplica> {
    let (parent, leaf) = split_parent_and_leaf(db_path)?;
    let leaf_c = path_cstr(leaf, db_path)?;
    let build_sidecar_c = |suffix: &[u8]| -> ReleaseResult<CString> {
        let mut bytes = leaf.as_bytes().to_vec();
        bytes.extend_from_slice(suffix);
        CString::new(bytes).map_err(|_| ReleaseError::PathValidation {
            path: db_path.to_path_buf(),
            reason: "SQLite sidecar filename contains NUL byte".to_string(),
        })
    };
    let wal_c = build_sidecar_c(b"-wal")?;
    let shm_c = build_sidecar_c(b"-shm")?;
    let journal_c = build_sidecar_c(b"-journal")?;

    let mut last_err: Option<ReleaseError> = None;
    for attempt in 0..3_u8 {
        let parent_dir = open_dir_nofollow(parent)?;
        let db_fd = unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if db_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(ReleaseError::PathValidation {
                    path: db_path.to_path_buf(),
                    reason: "refusing symlinked SQLite database file".to_string(),
                });
            }
            return Err(ReleaseError::io(
                format!("opening SQLite database {}", db_path.display()),
                err,
            ));
        }
        let mut db_file = unsafe { File::from_raw_fd(db_fd) };
        let db_st = fstat_fd(db_file.as_raw_fd(), db_path, "fstat SQLite database")?;
        if (db_st.st_mode & libc::S_IFMT) != libc::S_IFREG || db_st.st_nlink != 1 {
            return Err(ReleaseError::PathValidation {
                path: db_path.to_path_buf(),
                reason: "SQLite database must be an exclusive regular non-symlink file".to_string(),
            });
        }

        let open_opt_sidecar =
            |sc_c: &CString, label: &str| -> ReleaseResult<Option<(File, u64)>> {
                let fd = unsafe {
                    libc::openat(
                        parent_dir.as_raw_fd(),
                        sc_c.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOENT) {
                        return Ok(None);
                    }
                    if err.raw_os_error() == Some(libc::ELOOP) {
                        return Err(ReleaseError::PathValidation {
                            path: db_path.to_path_buf(),
                            reason: format!("refusing symlinked SQLite {} sidecar", label),
                        });
                    }
                    return Err(ReleaseError::io(
                        format!("opening SQLite {} sidecar for {}", label, db_path.display()),
                        err,
                    ));
                }
                let f = unsafe { File::from_raw_fd(fd) };
                let st = fstat_fd(f.as_raw_fd(), db_path, "fstat SQLite sidecar")?;
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 1 {
                    return Err(ReleaseError::PathValidation {
                        path: db_path.to_path_buf(),
                        reason: format!(
                            "SQLite {} sidecar must be an exclusive regular non-symlink file",
                            label
                        ),
                    });
                }
                let size = u64::try_from(st.st_size).unwrap_or(0);
                Ok(Some((f, size)))
            };

        let mut wal_opt = open_opt_sidecar(&wal_c, "WAL")?;
        let _shm_check = open_opt_sidecar(&shm_c, "SHM")?;
        let mut journal_opt = open_opt_sidecar(&journal_c, "journal")?;

        let db_size = u64::try_from(db_st.st_size).unwrap_or(0);
        let wal_size = wal_opt.as_ref().map_or(0, |(_, sz)| *sz);
        let journal_size = journal_opt.as_ref().map_or(0, |(_, sz)| *sz);
        let total_declared = db_size
            .saturating_add(wal_size)
            .saturating_add(journal_size);
        if total_declared > MAX_SQLITE_SCRATCH_COPY_BYTES {
            return Err(ReleaseError::Snapshot {
                db_path: db_path.to_path_buf(),
                reason: format!(
                    "SQLite database and sidecars ({} bytes) exceed root scratch copy cap ({} bytes)",
                    total_declared, MAX_SQLITE_SCRATCH_COPY_BYTES
                ),
            });
        }

        let min_free = total_declared
            .saturating_mul(2)
            .saturating_add(16 * 1024 * 1024);
        let mut scratch = TrustedRootScratchDir::create_with_min_free(min_free)?;
        scratch.track_file("replica.sqlite");
        scratch.track_file("replica.sqlite-wal");
        scratch.track_file("replica.sqlite-shm");
        scratch.track_file("replica.sqlite-journal");
        let scratch_db = scratch.path().join("replica.sqlite");

        let mut remaining_cap = MAX_SQLITE_SCRATCH_COPY_BYTES;
        copy_fd_bounded_to_scratch(
            &mut db_file,
            &scratch,
            "replica.sqlite",
            &mut remaining_cap,
            db_path,
        )?;
        if let Some((ref mut wf, _)) = wal_opt {
            copy_fd_bounded_to_scratch(
                wf,
                &scratch,
                "replica.sqlite-wal",
                &mut remaining_cap,
                db_path,
            )?;
        }
        if let Some((ref mut jf, _)) = journal_opt {
            copy_fd_bounded_to_scratch(
                jf,
                &scratch,
                "replica.sqlite-journal",
                &mut remaining_cap,
                db_path,
            )?;
        }

        // Open our private root-owned scratch replica RW so SQLite recovers any copied `-wal` or
        // `-journal` frames strictly inside the private 0700 directory (never touching live files).
        let open_attempt = rusqlite::Connection::open(&scratch_db).and_then(|conn| {
            let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
            conn.pragma_update(None, "trusted_schema", "OFF")?;
            let _: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
            Ok(conn)
        });
        match open_attempt {
            Ok(conn) => {
                return Ok(IsolatedSqliteReplica {
                    conn: Some(conn),
                    _scratch: Some(scratch),
                });
            }
            Err(err) => {
                last_err = Some(ReleaseError::Snapshot {
                    db_path: db_path.to_path_buf(),
                    reason: format!("failed to open isolated SQLite replica: {}", err),
                });
                if attempt + 1 < 3 {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| ReleaseError::Snapshot {
        db_path: db_path.to_path_buf(),
        reason: "failed to open isolated SQLite replica after retries".to_string(),
    }))
}

/// Opens `db_path` safely for read-only inspection.
///
/// Because `SQLITE_OPEN_NOFOLLOW` applies `O_NOFOLLOW` only to the primary DB file and NOT to
/// `-wal`/`-shm`/`-journal` sidecars, whenever `root` (`euid == 0`) inspects a database inside a
/// non-root-owned or non-root-writable directory (such as `aetherflow`-owned `/var/lib/aetherflow`),
/// this copies pinned `O_NOFOLLOW | O_NONBLOCK` FDs of `db`, optional `-wal`, and optional `-journal`
/// into a private `0700` [`TrustedRootScratchDir`] (preferring disk-backed `/var/tmp` with `statvfs`
/// free-space check and 2 GiB cap, retrying up to 3 times on torn WAL reads) so `root` NEVER opens
/// live SQLite sidecars in an unprivileged directory.
#[cfg(unix)]
pub(crate) fn is_trusted_root_sqlite_files(db_path: &Path) -> bool {
    let Some(parent) = db_path.parent() else {
        return false;
    };
    if !is_trusted_root_path_dir(parent, false) {
        return false;
    }
    let Some(leaf) = db_path.file_name() else {
        return false;
    };
    let Ok(parent_dir) = open_dir_nofollow(parent) else {
        return false;
    };
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name_os = leaf.to_os_string();
        name_os.push(suffix);
        let Ok(c_name) = CString::new(name_os.as_bytes()) else {
            return false;
        };
        match fstatat_nofollow(parent_dir.as_raw_fd(), &c_name) {
            Ok(st) => {
                if st.st_uid != 0 || (st.st_mode & 0o022) != 0 {
                    return false;
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
            Err(_) => return false,
        }
    }
    true
}

pub fn open_sqlite_isolated_readonly(db_path: &Path) -> ReleaseResult<IsolatedSqliteReplica> {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 && !is_trusted_root_sqlite_files(db_path) {
            return open_sqlite_in_root_scratch(db_path);
        }
    }
    let conn = open_sqlite_nofollow_hardened(db_path, false)?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    Ok(IsolatedSqliteReplica {
        conn: Some(conn),
        #[cfg(unix)]
        _scratch: None,
    })
}

/// Opens `db_path` for lifecycle reservation reconciliation:
/// - When `root` (`euid == 0`) inspects an untrusted/unprivileged DB directory, returns a private
///   RW scratch replica (`is_scratch = true`) so `reconcile_jobs_with_options(&replica, db_path, false)`
///   evaluates live `.lifecycle-owners` locks and marks stale rows `interrupted` strictly in-scratch
///   without EVER opening or mutating `/var/lib/aetherflow/aetherflow.sqlite` as `root`.
/// - When unprivileged or in a trusted root directory, opens the live DB RW with
///   `open_sqlite_nofollow_hardened(db_path, true)` (`is_scratch = false`).
pub fn open_sqlite_isolated_for_reconcile(
    db_path: &Path,
) -> ReleaseResult<(IsolatedSqliteReplica, bool)> {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 && !is_trusted_root_sqlite_files(db_path) {
            return Ok((open_sqlite_in_root_scratch(db_path)?, true));
        }
    }
    let conn = open_sqlite_nofollow_hardened(db_path, true)?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    Ok((
        IsolatedSqliteReplica {
            conn: Some(conn),
            #[cfg(unix)]
            _scratch: None,
        },
        false,
    ))
}

/// Runs a synchronous closure with Linux per-thread `fsuid`/`fsgid` lowered to the owner of
/// `path`'s parent directory whenever `geteuid() == 0` and the parent directory is owned by a
/// non-root user (non-sticky).
///
/// Per Linux `capabilities(7)` / `setfsuid(2)`, transitioning `fsuid` from `0 -> non-zero` clears
/// `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, and `CAP_FSETID` on the current thread
/// only, ensuring SQLite sidecar opens/creations (`-wal`, `-shm`, `-journal`) inside an unprivileged
/// directory cannot write through symlinks into root-owned paths and are created owned by the
/// service user rather than `root`. The RAII guard unconditionally restores `fsuid=0`/`fsgid=0` on
/// return or panic.
/// Determines per-thread `fsuid`/`fsgid` policy when `euid == 0` accesses a SQLite DB inside
/// `parent`. Never falls back to running as `root` inside an unprivileged or untrusted directory:
/// - Non-root parent (`parent_uid != 0`): rejects world-writable directories (`0o002`), and
///   unconditionally drops to `(parent_uid, parent_gid)` regardless of sticky bit (`S_ISVTX`).
/// - Root parent (`parent_uid == 0`): permits root execution ONLY when `trusted_root_dir` is true
///   (every ancestor is `uid == 0` and non-group/world-writable); otherwise fails closed.
pub(crate) fn classify_fsuid_policy(
    parent_uid: u32,
    parent_gid: u32,
    parent_mode: u32,
    trusted_root_dir: bool,
) -> Result<Option<(u32, u32)>, String> {
    if parent_uid != 0 {
        if (parent_mode & 0o002) != 0 {
            return Err(format!(
                "refusing world-writable non-root parent directory (uid={parent_uid}, mode={:o})",
                parent_mode & 0o7777
            ));
        }
        return Ok(Some((parent_uid, parent_gid)));
    }
    if trusted_root_dir {
        Ok(None)
    } else {
        Err(format!(
            "refusing root SQLite access in untrusted root-owned parent directory (mode={:o})",
            parent_mode & 0o7777
        ))
    }
}

/// Runs `f` with Linux per-thread `fsuid`/`fsgid` set to `(target_uid, target_gid)` (and clears
/// per-thread supplementary groups via raw `SYS_setgroups` when lowering to a non-root `uid`)
/// when running as `root` (`euid == 0`), verifying the observed thread credentials and
/// unconditionally restoring the previous `fsuid`/`fsgid` and supplementary groups on return or
/// panic.
pub fn with_uid_gid_fsuid<T, F>(target_uid: u32, target_gid: u32, f: F) -> ReleaseResult<T>
where
    F: FnOnce() -> ReleaseResult<T>,
{
    #[cfg(target_os = "linux")]
    {
        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
        const SYS_SETGROUPS_NUM: libc::c_long = libc::SYS_setgroups32;
        #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
        const SYS_SETGROUPS_NUM: libc::c_long = libc::SYS_setgroups;

        struct FsuidGuard {
            prev_uid: libc::uid_t,
            prev_gid: libc::gid_t,
            restore_groups: Option<Vec<libc::gid_t>>,
        }
        impl Drop for FsuidGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::setfsuid(self.prev_uid);
                    libc::setfsgid(self.prev_gid);
                    if let Some(ref saved) = self.restore_groups {
                        let ptr = if saved.is_empty() {
                            std::ptr::null::<libc::gid_t>()
                        } else {
                            saved.as_ptr()
                        };
                        libc::syscall(SYS_SETGROUPS_NUM, saved.len(), ptr);
                    }
                }
            }
        }

        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            let mut restore_groups: Option<Vec<libc::gid_t>> = None;
            if target_uid != 0 {
                let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
                if count < 0 {
                    return Err(ReleaseError::io(
                        "querying thread supplementary group count before fsuid drop",
                        std::io::Error::last_os_error(),
                    ));
                }
                if count > 0 {
                    let mut saved = vec![0 as libc::gid_t; count as usize];
                    let got = unsafe { libc::getgroups(count, saved.as_mut_ptr()) };
                    if got < 0 {
                        return Err(ReleaseError::io(
                            "reading thread supplementary groups before fsuid drop",
                            std::io::Error::last_os_error(),
                        ));
                    }
                    saved.truncate(got as usize);
                    if !saved.is_empty() {
                        // Use raw SYS_setgroups so ONLY this thread's kernel cred->group_info is
                        // cleared (never glibc's process-wide SIGSETXID setgroups wrapper).
                        let rc = unsafe {
                            libc::syscall(
                                SYS_SETGROUPS_NUM,
                                0usize,
                                std::ptr::null::<libc::gid_t>(),
                            )
                        };
                        if rc != 0 {
                            return Err(ReleaseError::io(
                                format!(
                                    "clearing per-thread supplementary groups before fsuid drop to {target_uid}:{target_gid}"
                                ),
                                std::io::Error::last_os_error(),
                            ));
                        }
                        restore_groups = Some(saved);
                    }
                }
            }

            let prev_gid = unsafe { libc::setfsgid(target_gid as libc::gid_t) } as libc::gid_t;
            let prev_uid = unsafe { libc::setfsuid(target_uid as libc::uid_t) } as libc::uid_t;
            let _guard = FsuidGuard {
                prev_uid,
                prev_gid,
                restore_groups,
            };
            let observed_uid = unsafe { libc::setfsuid(libc::uid_t::MAX) } as libc::uid_t;
            let observed_gid = unsafe { libc::setfsgid(libc::gid_t::MAX) } as libc::gid_t;
            if observed_uid != target_uid as libc::uid_t
                || observed_gid != target_gid as libc::gid_t
            {
                return Err(ReleaseError::PathValidation {
                    path: PathBuf::from("/"),
                    reason: format!(
                        "failed to set per-thread fsuid/fsgid to {target_uid}:{target_gid} (observed {observed_uid}:{observed_gid})"
                    ),
                });
            }
            return f();
        }
        f()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target_uid, target_gid);
        f()
    }
}

/// Runs `f` with Linux per-thread `fsuid`/`fsgid` restored to the process effective credentials
/// (`geteuid()`/`getegid()`), restoring the prior thread `fsuid`/`fsgid` on return or panic.
/// Used by FD-confined root operations (such as `OwnerLease` migration/scratch cleanup) that may
/// be invoked from inside a lowered-`fsuid` SQLite scope.
pub fn with_effective_fsuid<T, F>(f: F) -> ReleaseResult<T>
where
    F: FnOnce() -> ReleaseResult<T>,
{
    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        with_uid_gid_fsuid(euid, egid, f)
    }
    #[cfg(not(target_os = "linux"))]
    {
        f()
    }
}

/// Resolves the target per-thread `fsuid`/`fsgid` required to safely access `path` when running as
/// `root` (`euid == 0`), enforcing `classify_fsuid_policy`:
/// - Returns `Ok(Some((uid, gid)))` for a valid non-root parent directory.
/// - Returns `Ok(None)` when not running as root OR when `parent` is a verified trusted root dir.
/// - Returns `Err(ReleaseError::PathValidation)` on symlinks, world-writable non-root dirs, or
///   untrusted root-owned dirs.
pub fn resolve_path_owner_fsuid(path: &Path) -> ReleaseResult<Option<(u32, u32)>> {
    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Ok(None);
        }
        let (parent, leaf) = split_parent_and_leaf(path)?;
        let parent_dir = open_dir_nofollow(parent)?;
        let st = fstat_fd(parent_dir.as_raw_fd(), parent, "fstat parent directory")?;
        if st.st_uid == 0 {
            if !is_trusted_root_path_dir(parent, false) {
                return Err(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "refusing root SQLite access in untrusted root-owned directory"
                        .to_string(),
                });
            }
            if is_trusted_root_sqlite_files(path) {
                return Ok(None);
            }
            // Root-owned trusted parent contains non-root or group/world-writable DB/sidecar
            // files: never keep fsuid=0. Drop to a single consistent non-root owner if safe,
            // otherwise fail closed.
            let mut single_owner: Option<(u32, u32)> = None;
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let mut name_os = leaf.to_os_string();
                name_os.push(suffix);
                let c_name =
                    CString::new(name_os.as_bytes()).map_err(|_| ReleaseError::PathValidation {
                        path: path.to_path_buf(),
                        reason: "SQLite filename contains interior NUL byte".to_string(),
                    })?;
                match fstatat_nofollow(parent_dir.as_raw_fd(), &c_name) {
                    Ok(fst) => {
                        if (fst.st_mode & libc::S_IFMT) != libc::S_IFREG
                            || fst.st_nlink != 1
                            || (fst.st_mode & 0o002) != 0
                        {
                            return Err(ReleaseError::PathValidation {
                                path: path.to_path_buf(),
                                reason: "refusing root SQLite access on non-regular, hardlinked, or world-writable DB/sidecar file".to_string(),
                            });
                        }
                        if fst.st_uid == 0 {
                            if (fst.st_mode & 0o022) != 0 {
                                return Err(ReleaseError::PathValidation {
                                    path: path.to_path_buf(),
                                    reason: "refusing root SQLite access on group/world-writable root-owned DB/sidecar file".to_string(),
                                });
                            }
                        } else {
                            let owner = (fst.st_uid, fst.st_gid);
                            match single_owner {
                                None => single_owner = Some(owner),
                                Some(existing) if existing == owner => {}
                                Some(_) => {
                                    return Err(ReleaseError::PathValidation {
                                        path: path.to_path_buf(),
                                        reason: "refusing root SQLite access on DB/sidecars with mixed non-root owners".to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(err) => {
                        return Err(ReleaseError::io(
                            format!("fstatat SQLite file under {}", parent.display()),
                            err,
                        ));
                    }
                }
            }
            if let Some(owner) = single_owner {
                return Ok(Some(owner));
            }
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing root SQLite access on untrusted DB/sidecar files".to_string(),
            });
        }
        classify_fsuid_policy(st.st_uid, st.st_gid, st.st_mode as u32, false).map_err(|reason| {
            ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason,
            }
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(None)
    }
}

/// Executes `f` while temporarily setting Linux per-thread `fsuid`/`fsgid` to the owner of
/// `path`'s parent directory whenever the process runs as `root` (`euid == 0`).
///
/// Linux `setfsuid(2)` clears filesystem capability bits (`CAP_CHOWN`, `CAP_DAC_OVERRIDE`,
/// `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_FSETID`) on the current thread only, ensuring SQLite
/// sidecar opens/creations (`-wal`, `-shm`, `-journal`) inside an unprivileged directory cannot
/// follow symlinks into root-owned paths and are created owned by the service user rather than
/// `root`. Fails closed on world-writable non-root directories or untrusted root-owned directories
/// rather than silently running as `root`.
pub fn with_path_owner_fsuid<T, F>(path: &Path, f: F) -> ReleaseResult<T>
where
    F: FnOnce() -> ReleaseResult<T>,
{
    match resolve_path_owner_fsuid(path)? {
        Some((uid, gid)) => with_uid_gid_fsuid(uid, gid, f),
        None => f(),
    }
}

/// Hardened SQLite connection opener: validates symlink-free ancestors, regular non-hardlinked DB
/// & `-wal`/`-shm`/`-journal` sidecars (`O_NOFOLLOW | O_NONBLOCK`), and passes
/// `OpenFlags::SQLITE_OPEN_NOFOLLOW` to `rusqlite::Connection::open_with_flags`.
pub fn open_sqlite_nofollow_hardened(
    db_path: &Path,
    read_write: bool,
) -> ReleaseResult<rusqlite::Connection> {
    let Some(_pinned_db) = validate_sqlite_file_and_sidecars_nofollow(db_path)? else {
        return Err(ReleaseError::io(
            format!("opening SQLite database {}", db_path.display()),
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "SQLite database file does not exist",
            ),
        ));
    };
    let flags = if read_write {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let conn = rusqlite::Connection::open_with_flags(db_path, flags).map_err(|err| {
        ReleaseError::Snapshot {
            db_path: db_path.to_path_buf(),
            reason: format!("failed to open SQLite database: {}", err),
        }
    })?;
    conn.pragma_update(None, "trusted_schema", "OFF")
        .map_err(|err| ReleaseError::Snapshot {
            db_path: db_path.to_path_buf(),
            reason: format!("failed to disable SQLite trusted_schema: {}", err),
        })?;
    Ok(conn)
}

/// Atomically copies `src` to `dest` via a same-filesystem private `0o700` staging directory,
/// applying `fchown` and `fchmod` directly on the open FD before `sync_all()`, then publishing
/// atomically via `dirfd` `renameat` + parent directory `fsync`.
pub fn atomic_copy_file_with_mode(
    src: &Path,
    dest: &Path,
    mode: u32,
    preserve_from: Option<&OwnershipMetadata>,
) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let mut src_file = open_existing_regular_file_nofollow(src)?;
        atomic_publish_from_reader_unix(
            &mut src_file,
            dest,
            mode,
            TargetOwnership::PreserveOrService(preserve_from),
        )
    }
    #[cfg(not(unix))]
    {
        ensure_no_symlink_ancestors(src)?;
        ensure_no_symlink_ancestors(dest)?;
        let parent = dest.parent().ok_or_else(|| ReleaseError::PathValidation {
            path: dest.to_path_buf(),
            reason: "destination file has no parent directory".to_string(),
        })?;
        if !parent.try_exists().map_err(|error| {
            ReleaseError::io(format!("inspecting parent {}", parent.display()), error)
        })? {
            create_dir_all_no_symlinks(parent, 0o755)?;
        }

        let file_name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("copy");
        let tmp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));

        let mut src_file = File::open(src)
            .map_err(|e| ReleaseError::io(format!("opening source file {}", src.display()), e))?;
        let mut tmp_file = open_exclusive_private_file(&tmp_path, mode)?;

        if let Err(e) =
            std::io::copy(&mut src_file, &mut tmp_file).and_then(|_| tmp_file.sync_all())
        {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(ReleaseError::io(
                format!("copying {} -> {}", src.display(), tmp_path.display()),
                e,
            ));
        }
        drop(tmp_file);

        if let Err(e) = apply_service_ownership(&tmp_path, preserve_from, mode) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        fs::rename(&tmp_path, dest).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ReleaseError::io(
                format!("renaming {} -> {}", tmp_path.display(), dest.display()),
                e,
            )
        })?;

        sync_parent_dir_best_effort(parent);
        Ok(())
    }
}

/// Atomically copies `src` to `dest` with `root:aetherflow` ownership (when `geteuid() == 0`)
/// and explicit `mode` (e.g., `0o640` for `/etc/aetherflow/aetherflow.env`), staged in a
/// same-filesystem private `0o700` directory with FD-based `fchown`/`fchmod` before `sync_all()`.
pub(crate) fn atomic_copy_file_root_aetherflow(
    src: &Path,
    dest: &Path,
    mode: u32,
) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let mut src_file = open_existing_regular_file_nofollow(src)?;
        atomic_publish_from_reader_unix(&mut src_file, dest, mode, TargetOwnership::RootAetherflow)
    }
    #[cfg(not(unix))]
    {
        atomic_copy_file_with_mode(src, dest, mode, None)
    }
}

/// Atomically copies `src` to `dest` with `root:root` ownership (when `geteuid() == 0`)
/// and explicit `mode` (e.g., `0o755` for synchronized system helpers and packages), staged in a
/// same-filesystem private `0o700` directory with FD-based `fchown`/`fchmod` before `sync_all()`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn atomic_copy_file_root_owned(src: &Path, dest: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let mut src_file = open_existing_regular_file_nofollow(src)?;
        atomic_publish_from_reader_unix(&mut src_file, dest, mode, TargetOwnership::RootOwned)
    }
    #[cfg(not(unix))]
    {
        atomic_copy_file_with_mode(src, dest, mode, None)
    }
}

/// Atomically replaces a synchronized system helper or mirrored package file with `root:root`
/// ownership and `mode`, permitting atomic `renameat` replacement of a legacy leaf symlink
/// (`S_IFLNK`) inside an `O_DIRECTORY | O_NOFOLLOW`-pinned directory without following the
/// symlink target (matching `deploy/release-manager.sh`'s `PIPE-02` helper migration contract).
pub(crate) fn atomic_replace_helper_file_root_owned(
    src: &Path,
    dest: &Path,
    mode: u32,
) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let mut src_file = open_existing_regular_file_nofollow(src)?;
        atomic_publish_from_reader_unix_inner(
            &mut src_file,
            dest,
            mode,
            TargetOwnership::RootOwned,
            true,
        )
    }
    #[cfg(not(unix))]
    {
        atomic_copy_file_with_mode(src, dest, mode, None)
    }
}

/// Stages `src` into a same-filesystem private `0700` staging directory FIRST (`fchown`/`fchmod`
/// + `sync_all` + exclusivity verification), and only after staging succeeds:
/// 1. Quarantines an existing regular `dest` to `corrupted_leaf` via `renameat` (or unlinks a
///    non-regular non-directory leaf; fails closed on a directory);
/// 2. Atomically publishes the staged file to `dest` via `renameat` (restoring `corrupted_leaf`
///    on `renameat` failure while preserving all SQLite sidecars untouched);
/// 3. Unlinks `-wal`, `-shm`, and `-journal` sidecars strictly AFTER `renameat` succeeds, then
///    fsyncs the parent directory.
#[cfg(unix)]
pub(crate) fn atomic_restore_db_with_quarantine(
    src: &Path,
    dest: &Path,
    mode: u32,
    preserve_ownership: Option<&OwnershipMetadata>,
    corrupted_leaf: &str,
) -> ReleaseResult<Option<PathBuf>> {
    let mut src_file = open_existing_regular_file_nofollow(src)?;
    let (parent, leaf) = split_parent_and_leaf(dest)?;
    let parent_dir = open_dir_nofollow(parent)?;
    let parent_dfd = parent_dir.as_raw_fd();
    let leaf_c = path_cstr(leaf, dest)?;
    let leaf_name = leaf.to_string_lossy();
    let c_corrupted =
        CString::new(corrupted_leaf.as_bytes()).map_err(|_| ReleaseError::PathValidation {
            path: dest.to_path_buf(),
            reason: "corrupted quarantine filename contains NUL byte".to_string(),
        })?;

    let tmp_str = format!(
        ".{}.restore.{}.{}",
        leaf_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp_c = CString::new(tmp_str.as_bytes()).map_err(|_| ReleaseError::PathValidation {
        path: dest.to_path_buf(),
        reason: "temporary restore filename contains NUL byte".to_string(),
    })?;

    // Step 1: Stage and fsync verified backup bytes BEFORE mutating live DB or sidecars.
    let staging = PrivateStagingDir::create(&parent_dir, parent, &tmp_c)?;
    let staging_dfd = staging.staging_dir.as_raw_fd();
    let tmp_fd = unsafe {
        libc::openat(
            staging_dfd,
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if tmp_fd < 0 {
        return Err(ReleaseError::io(
            format!(
                "creating exclusive staged restore file for {}",
                dest.display()
            ),
            std::io::Error::last_os_error(),
        ));
    }
    let mut tmp_file = unsafe { File::from_raw_fd(tmp_fd) };
    let ownership = TargetOwnership::PreserveOrService(preserve_ownership);
    let stage_res: ReleaseResult<()> = (|| {
        std::io::copy(&mut src_file, &mut tmp_file).map_err(|err| {
            ReleaseError::io(
                format!(
                    "copying verified backup into staged restore for {}",
                    dest.display()
                ),
                err,
            )
        })?;
        apply_fd_ownership_and_mode(tmp_file.as_raw_fd(), dest, ownership, mode)?;
        tmp_file.sync_all().map_err(|err| {
            ReleaseError::io(
                format!("fsync staged restore file for {}", dest.display()),
                err,
            )
        })?;
        let tmp_st = fstat_fd(tmp_file.as_raw_fd(), dest, "fstat staged restore file")?;
        if (tmp_st.st_mode & libc::S_IFMT) != libc::S_IFREG || tmp_st.st_nlink != 1 {
            return Err(ReleaseError::PathValidation {
                path: dest.to_path_buf(),
                reason: "staged restore file failed regular-file or link-count invariant"
                    .to_string(),
            });
        }
        Ok(())
    })();
    drop(tmp_file);
    stage_res?;

    // Step 2: Quarantine regular `dest` (or unlink non-regular non-dir leaf; reject directory).
    let mut quarantined: Option<PathBuf> = None;
    let mut quarantined_active = false;
    match fstatat_nofollow(parent_dfd, &leaf_c) {
        Ok(st) => {
            let ftype = st.st_mode & libc::S_IFMT;
            if ftype == libc::S_IFREG {
                if unsafe {
                    libc::renameat(
                        parent_dfd,
                        leaf_c.as_ptr(),
                        parent_dfd,
                        c_corrupted.as_ptr(),
                    )
                } != 0
                {
                    return Err(ReleaseError::io(
                        format!(
                            "quarantining corrupted DB {} -> {}",
                            dest.display(),
                            parent.join(corrupted_leaf).display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
                quarantined = Some(parent.join(corrupted_leaf));
                quarantined_active = true;
            } else if ftype == libc::S_IFDIR {
                return Err(ReleaseError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: "refusing to overwrite directory at database path".to_string(),
                });
            } else if unsafe { libc::unlinkat(parent_dfd, leaf_c.as_ptr(), 0) } != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(ReleaseError::io(
                        format!("unlinking untrusted leaf at {}", dest.display()),
                        err,
                    ));
                }
            }
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
        Err(err) => {
            return Err(ReleaseError::io(
                format!("inspecting live database {}", dest.display()),
                err,
            ));
        }
    }

    // Step 3: Publish staged DB atomically via dirfd renameat; revert quarantine on error.
    if unsafe { libc::renameat(staging_dfd, tmp_c.as_ptr(), parent_dfd, leaf_c.as_ptr()) } != 0 {
        let err = std::io::Error::last_os_error();
        if quarantined_active {
            unsafe {
                libc::renameat(
                    parent_dfd,
                    c_corrupted.as_ptr(),
                    parent_dfd,
                    leaf_c.as_ptr(),
                );
            }
        }
        return Err(ReleaseError::io(
            format!(
                "atomically publishing restored database to {}",
                dest.display()
            ),
            err,
        ));
    }

    // Step 4: Clear stale WAL/SHM/journal sidecars strictly AFTER restored DB is published.
    for suffix in ["-wal", "-shm", "-journal"] {
        if let Ok(c_sc) = CString::new(format!("{leaf_name}{suffix}")) {
            unsafe {
                libc::unlinkat(parent_dfd, c_sc.as_ptr(), 0);
            }
        }
    }
    sync_dir_fd(parent_dfd, parent)?;
    drop(staging);
    Ok(quarantined)
}

/// Ensures `dir` exists without symlinks, has mode `mode` (e.g. `0o755`), and when running as
/// `root` (`euid == 0`), owns `dir` as `root:root` via FD-based `fchown`/`fchmod`.
pub(crate) fn apply_root_owned_dir_mode(dir: &Path, mode: u32) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let dir_file = open_or_create_dir_nofollow(dir, mode)?;
        apply_fd_ownership_and_mode(dir_file.as_raw_fd(), dir, TargetOwnership::RootOwned, mode)
    }
    #[cfg(not(unix))]
    {
        create_dir_all_no_symlinks(dir, mode)?;
        set_dir_mode(dir, mode)
    }
}

/// Best-effort `fsync` on a directory after atomic file renames on Unix.
pub fn sync_parent_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(f) = open_dir_nofollow(dir) {
            let _ = sync_dir_fd(f.as_raw_fd(), dir);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Recorded Unix ownership (`uid`, `gid`, and file mode) of an existing database or secret file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl OwnershipMetadata {
    /// Captures ownership metadata from `path` if it exists and is not a symlink.
    pub fn capture(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::symlink_metadata(path).ok()?;
            if meta.file_type().is_symlink() {
                return None;
            }
            Some(Self {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode() & 0o777,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }
}

/// Resolves any named Unix account's `(uid, gid)` via thread-safe `getpwnam_r`.
#[cfg(unix)]
pub(crate) fn lookup_user_ugid(username: &str) -> Option<(u32, u32)> {
    let name = CString::new(username).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        Some((pwd.pw_uid, pwd.pw_gid))
    } else {
        None
    }
}

/// Resolves the `aetherflow` system account `(uid, gid)` via `getpwnam_r` on Unix if present.
#[cfg(unix)]
pub fn lookup_aetherflow_ugid() -> Option<(u32, u32)> {
    lookup_user_ugid("aetherflow")
}

/// Applies preserved `(uid, gid)` (or the `aetherflow` service user's `(uid, gid)` when available)
/// and `mode` directly to the opened regular-file FD of `path` (`O_NOFOLLOW | O_NONBLOCK`,
/// rejecting symlinks, non-regular files, and multi-hardlink files).
///
/// When running as root (`euid == 0`), `fchown` failures are surfaced as errors;
/// when running as an unprivileged test user, `EPERM`/`EACCES` on `fchown` is ignored while
/// `fchmod` is enforced.
pub fn apply_service_ownership(
    path: &Path,
    preserve_from: Option<&OwnershipMetadata>,
    default_mode: u32,
) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let file = open_existing_regular_file_nofollow(path)?;
        let st = fstat_fd(file.as_raw_fd(), path, "fstat service-owned file")?;
        if st.st_nlink > 1 {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing ownership change on file with multiple hard links".to_string(),
            });
        }
        apply_fd_ownership_and_mode(
            file.as_raw_fd(),
            path,
            TargetOwnership::PreserveOrService(preserve_from),
            default_mode,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = preserve_from;
        set_file_mode(path, default_mode)
    }
}

/// Applies `aetherflow:aetherflow` ownership (when the user exists) and `0700` mode to `data_dir`
/// via FD-based `fchown`/`fchmod` during non-dry-run Stage 0 layout verification, matching
/// `ensure_fhs_layout` in `release-manager.sh`.
pub fn apply_data_dir_ownership_and_mode(data_dir: &Path) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let dir_file = open_dir_nofollow(data_dir)?;
        apply_fd_ownership_and_mode(
            dir_file.as_raw_fd(),
            data_dir,
            TargetOwnership::PreserveOrService(None),
            0o700,
        )
    }
    #[cfg(not(unix))]
    {
        set_dir_mode(data_dir, 0o700)
    }
}

/// Ensures `dir` exists without symlinks, has mode `0750`, and when running as `root`
/// (`euid == 0`) with an `aetherflow` account present, owns `dir` as `root:aetherflow`
/// via FD-based `fchown`/`fchmod`.
pub fn apply_root_aetherflow_dir_ownership_and_mode(dir: &Path) -> ReleaseResult<()> {
    #[cfg(unix)]
    {
        let dir_file = open_or_create_dir_nofollow(dir, 0o750)?;
        apply_fd_ownership_and_mode(
            dir_file.as_raw_fd(),
            dir,
            TargetOwnership::RootAetherflow,
            0o750,
        )
    }
    #[cfg(not(unix))]
    {
        create_dir_all_no_symlinks(dir, 0o750)?;
        set_dir_mode(dir, 0o750)
    }
}

#[cfg(all(test, unix))]
mod crate02_tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn test_sandbox(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("af-fs-sec-test-{}-{}", label, uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn crate02_atomic_copy_stages_in_private_same_fs_dir_and_leaves_no_artifacts() {
        let root = test_sandbox("atomic-copy");
        let src = root.join("src.db");
        let dest_dir = root.join("var/lib/aetherflow");
        let dest = dest_dir.join("aetherflow.sqlite");
        fs::write(&src, b"sqlite-payload-v1").unwrap();
        fs::create_dir_all(&dest_dir).unwrap();

        let owner = OwnershipMetadata::capture(&src);
        atomic_copy_file_with_mode(&src, &dest, 0o600, owner.as_ref()).unwrap();

        let meta = fs::symlink_metadata(&dest).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&dest).unwrap(), b"sqlite-payload-v1");

        // Verify staging directory was cleaned up completely.
        let remaining: Vec<String> = fs::read_dir(&dest_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(remaining, vec!["aetherflow.sqlite".to_string()]);

        // Verify overwrite produces a fresh inode (atomic renameat) with new contents.
        let old_ino = meta.ino();
        fs::write(&src, b"sqlite-payload-v2").unwrap();
        atomic_copy_file_with_mode(&src, &dest, 0o640, None).unwrap();
        let meta2 = fs::symlink_metadata(&dest).unwrap();
        assert_ne!(meta2.ino(), old_ino);
        assert_eq!(meta2.permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::read(&dest).unwrap(), b"sqlite-payload-v2");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn crate02_private_staging_dir_is_0700_same_fs_and_auto_cleaned_on_drop() {
        let root = test_sandbox("staging-dir");
        let parent_file = open_dir_nofollow(&root).unwrap();
        let parent_st = fstat_fd(parent_file.as_raw_fd(), &root, "stat").unwrap();
        let tmp_c = CString::new(".probe.tmp").unwrap();

        let stage_path = {
            let staging = PrivateStagingDir::create(&parent_file, &root, &tmp_c).unwrap();
            let stage_st =
                fstat_fd(staging.staging_dir.as_raw_fd(), &staging.stage_path, "stat").unwrap();
            assert_eq!(stage_st.st_dev, parent_st.st_dev);
            assert_eq!(stage_st.st_mode & 0o777, 0o700);
            assert_eq!(stage_st.st_uid, unsafe { libc::geteuid() });
            staging.stage_path.clone()
        };
        assert!(
            !stage_path.exists(),
            "PrivateStagingDir must clean up on drop"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn crate02_rejects_symlinks_and_hardlinks_in_fd_security_ops() {
        let root = test_sandbox("symlinks-hardlinks");
        let victim = root.join("victim");
        fs::write(&victim, b"untouched").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();

        let link_file = root.join("link-file");
        symlink(&victim, &link_file).unwrap();

        // set_file_mode must reject symlink without altering victim.
        let err = set_file_mode(&link_file, 0o600).unwrap_err();
        assert!(matches!(err, ReleaseError::PathValidation { .. }));
        assert_eq!(
            fs::symlink_metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // apply_service_ownership must reject symlink and hardlinked files.
        let err_own_sym = apply_service_ownership(&link_file, None, 0o600).unwrap_err();
        assert!(matches!(err_own_sym, ReleaseError::PathValidation { .. }));

        let hardlink = root.join("hardlink");
        fs::hard_link(&victim, &hardlink).unwrap();
        let err_hl = apply_service_ownership(&hardlink, None, 0o600).unwrap_err();
        assert!(matches!(err_hl, ReleaseError::PathValidation { .. }));

        // atomic_copy_file_with_mode must refuse symlinked destination or source.
        let src = root.join("src");
        fs::write(&src, b"replacement").unwrap();
        let err_dst = atomic_copy_file_with_mode(&src, &link_file, 0o600, None).unwrap_err();
        assert!(matches!(err_dst, ReleaseError::PathValidation { .. }));
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");

        let err_src =
            atomic_copy_file_with_mode(&link_file, &root.join("out"), 0o600, None).unwrap_err();
        assert!(matches!(err_src, ReleaseError::PathValidation { .. }));

        // set_dir_mode must reject symlinked directory.
        let real_dir = root.join("real-dir");
        fs::create_dir(&real_dir).unwrap();
        let link_dir = root.join("link-dir");
        symlink(&real_dir, &link_dir).unwrap();
        let err_dir = set_dir_mode(&link_dir, 0o700).unwrap_err();
        assert!(matches!(err_dir, ReleaseError::PathValidation { .. }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn crate02_root_aetherflow_and_root_owned_atomic_copies_enforce_modes() {
        let root = test_sandbox("modes");
        let src = root.join("src.env");
        fs::write(&src, b"SECRET=1\n").unwrap();

        let env_dst = root.join("etc/aetherflow/aetherflow.env");
        atomic_copy_file_root_aetherflow(&src, &env_dst, 0o640).unwrap();
        assert_eq!(
            fs::symlink_metadata(&env_dst).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let helper_dst = root.join("usr/bin/af-certbot-sync");
        atomic_copy_file_root_owned(&src, &helper_dst, 0o755).unwrap();
        assert_eq!(
            fs::symlink_metadata(&helper_dst)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wave1b_r7_classify_fsuid_policy_blocks_sticky_and_untrusted_root_bypass() {
        // Non-root owner MUST drop fsuid/fsgid even when sticky bit (S_ISVTX) is set.
        assert_eq!(
            classify_fsuid_policy(1000, 1000, 0o1700, false).unwrap(),
            Some((1000, 1000))
        );
        assert_eq!(
            classify_fsuid_policy(999, 999, 0o0750, false).unwrap(),
            Some((999, 999))
        );
        // World-writable non-root parent must fail closed.
        assert!(classify_fsuid_policy(1000, 1000, 0o0777, false).is_err());
        assert!(classify_fsuid_policy(1000, 1000, 0o1777, false).is_err());
        // Root-owned parent requires trusted_root_dir == true; untrusted root dirs fail closed.
        assert_eq!(classify_fsuid_policy(0, 0, 0o0755, true).unwrap(), None);
        assert!(classify_fsuid_policy(0, 0, 0o1777, false).is_err());
        assert!(classify_fsuid_policy(0, 0, 0o0770, false).is_err());
    }

    #[test]
    fn wave1b_r8_rejects_sqlite_hot_journal_with_super_journal_trailer() {
        let root = test_sandbox("super-journal");
        let db_path = root.join("test.sqlite");
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        // Craft a rollback journal with a trailing super-journal magic (`aJournalMagic`).
        let journal_path = root.join("test.sqlite-journal");
        let mut crafted = vec![0u8; 64];
        crafted[..8].copy_from_slice(&SQLITE_JOURNAL_MAGIC);
        let tail_start = crafted.len() - 8;
        crafted[tail_start..].copy_from_slice(&SQLITE_JOURNAL_MAGIC);
        fs::write(&journal_path, &crafted).unwrap();

        let err_direct = open_sqlite_nofollow_hardened(&db_path, false).unwrap_err();
        assert!(
            matches!(err_direct, ReleaseError::PathValidation { .. }),
            "expected PathValidation on direct open with super-journal trailer, got: {err_direct:?}"
        );

        let err_scratch = open_sqlite_in_root_scratch(&db_path).err().unwrap();
        assert!(
            matches!(err_scratch, ReleaseError::PathValidation { .. }),
            "expected PathValidation on scratch open with super-journal trailer, got: {err_scratch:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wave1b_r9_validate_root_dry_run_dir_stat_rejects_non_root_and_writable_dirs() {
        assert!(validate_root_dry_run_dir_stat(0, 0o040700, true).is_ok());
        assert!(validate_root_dry_run_dir_stat(0, 0o040755, true).is_ok());
        assert!(validate_root_dry_run_dir_stat(1000, 0o040700, true).is_err());
        assert!(validate_root_dry_run_dir_stat(999, 0o040755, true).is_err());
        assert!(validate_root_dry_run_dir_stat(0, 0o040770, true).is_err());
        assert!(validate_root_dry_run_dir_stat(0, 0o040777, true).is_err());
        assert!(validate_root_dry_run_dir_stat(0, 0o041777, true).is_err());
        assert!(validate_root_dry_run_dir_stat(0, 0o100600, false).is_err());
    }
}
