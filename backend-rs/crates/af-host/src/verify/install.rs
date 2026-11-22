use super::dirfd::{
    open_existing_dir_nofollow_optional_with_trusted_uid, open_existing_regular_file_nofollow,
    open_or_create_dir_nofollow_with_trusted_uid,
};
use super::paths::reject_if_symlink;
use crate::error::{HostBackupError, HostBackupResult};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

#[cfg(unix)]
struct PrivateInstallDirectory {
    parent: File,
    directory: File,
    name: std::ffi::CString,
    temporary: std::ffi::CString,
    identity: (u64, u64),
    #[cfg(test)]
    path: PathBuf,
}

#[cfg(unix)]
impl PrivateInstallDirectory {
    fn create(parent: &File, path: &Path, temporary: &std::ffi::CString) -> HostBackupResult<Self> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(format!(".af-install.{}", uuid::Uuid::new_v4())).unwrap();
        let staging_path = path.join(name.to_str().unwrap());
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(HostBackupError::io(
                "creating private install directory",
                std::io::Error::last_os_error(),
            ));
        }
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(HostBackupError::io(
                "opening private install directory",
                std::io::Error::last_os_error(),
            ));
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory
            .metadata()
            .map_err(|error| HostBackupError::io("verifying private install directory", error))?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(HostBackupError::PathValidation {
                path: staging_path,
                reason: "install staging directory is not executor-owned and private".to_string(),
            });
        }
        Ok(Self {
            parent: parent
                .try_clone()
                .map_err(|error| HostBackupError::io("pinning install parent", error))?,
            directory,
            name,
            temporary: temporary.clone(),
            identity: (metadata.dev(), metadata.ino()),
            #[cfg(test)]
            path: staging_path,
        })
    }
}

#[cfg(unix)]
impl Drop for PrivateInstallDirectory {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.temporary.as_ptr(), 0);
            let mut metadata: libc::stat = std::mem::zeroed();
            if libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
                && (metadata.st_dev as u64, metadata.st_ino as u64) == self.identity
            {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
    }
}

#[cfg(test)]
type PreRenameInstallHook = Box<dyn Fn(&Path, &Path, &str) + Send + Sync>;

#[cfg(test)]
static PRE_RENAME_INSTALL_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<PreRenameInstallHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_pre_rename_install_hook(hook: Option<PreRenameInstallHook>) {
    let lock = PRE_RENAME_INSTALL_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = hook;
    }
}

#[cfg(test)]
fn invoke_pre_rename_install_hook(dest: &Path, parent: &Path, tmp_name: &str) {
    if let Some(lock) = PRE_RENAME_INSTALL_HOOK.get() {
        if let Ok(guard) = lock.lock() {
            if let Some(ref hook) = *guard {
                hook(dest, parent, tmp_name);
            }
        }
    }
}

/// Atomically copies `src` into `dest` using dirfd-relative `openat(..., O_CREAT | O_EXCL | O_NOFOLLOW)`,
/// `fchmod`, optional `fchown` (preserving `uid`/`gid`), `fsync` on the temporary file,
/// `renameat(parent_dfd, tmp, parent_dfd, dest_leaf)` (after verifying the destination leaf is not
/// an existing directory or symlink via `fstatat(..., AT_SYMLINK_NOFOLLOW)`), and `fsync(parent_dfd)`.
pub fn atomic_install_file_at_destination(
    src: &Path,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    atomic_install_file_at_destination_with_trusted_ancestor_uid(
        src, dest, mode, uid, gid, None, context,
    )
}

/// Variant of [`atomic_install_file_at_destination`] that accepts an independently supplied
/// caller/service `trusted_ancestor_uid` (never derived from archive headers or manifest entries).
pub fn atomic_install_file_at_destination_with_trusted_ancestor_uid(
    src: &Path,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    atomic_install_file_at_destination_with_verification(
        src,
        None,
        None,
        None,
        dest,
        mode,
        uid,
        gid,
        trusted_ancestor_uid,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn atomic_install_file_at_destination_with_verification(
    src: &Path,
    expected_dev_ino: Option<(u64, u64)>,
    expected_sha256: Option<&str>,
    expected_size: Option<u64>,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let mut src_file = if src.is_absolute() {
        let (file, _, _, _) =
            open_existing_regular_file_nofollow(src, trusted_ancestor_uid, context)?.ok_or_else(
                || HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!("{} staged source does not exist", context),
                },
            )?;
        file
    } else {
        reject_if_symlink(src, context)?;
        let mut src_opts = OpenOptions::new();
        src_opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            src_opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        src_opts.open(src).map_err(|err| {
            HostBackupError::io(
                format!("opening staged source {} ({})", src.display(), context),
                err,
            )
        })?
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let mut src_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(src_file.as_raw_fd(), &mut src_st) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat staged source {} ({})", src.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (src_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source is not a regular file", context),
            });
        }
        if src_st.st_nlink == 0 {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source was unlinked before installation", context),
            });
        }
        if src_st.st_nlink > 1 {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source has multiple hard links", context),
            });
        }
        if let Some((exp_dev, exp_ino)) = expected_dev_ino {
            let euid = unsafe { libc::geteuid() };
            if src_st.st_uid != euid {
                return Err(HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!(
                        "{} source owner uid={} does not match effective uid={}",
                        context, src_st.st_uid, euid
                    ),
                });
            }
            if src_st.st_dev as u64 != exp_dev || src_st.st_ino as u64 != exp_ino {
                return Err(HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!(
                        "{} source inode changed before installation (expected dev={} ino={}, actual dev={} ino={})",
                        context, exp_dev, exp_ino, src_st.st_dev, src_st.st_ino
                    ),
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = expected_dev_ino;
    }

    atomic_install_verified_reader_at_destination(
        &mut src_file,
        expected_sha256,
        expected_size,
        dest,
        mode,
        uid,
        gid,
        trusted_ancestor_uid,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn atomic_install_verified_reader_at_destination<R: Read>(
    src_reader: &mut R,
    expected_sha256: Option<&str>,
    expected_size: Option<u64>,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: format!("{} has no parent directory", context),
        })?;
    let leaf_name = dest
        .file_name()
        .and_then(|os_val| os_val.to_str())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: format!("{} has invalid file name", context),
        })?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let parent_dir = open_or_create_dir_nofollow_with_trusted_uid(
            parent,
            0o755,
            trusted_ancestor_uid,
            context,
        )?;
        let parent_dfd = parent_dir.as_raw_fd();

        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: "destination filename contains NUL byte".to_string(),
        })?;

        let mut existing_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut existing_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc == 0 {
            let ftype = existing_st.st_mode & libc::S_IFMT;
            if ftype == libc::S_IFLNK {
                return Err(HostBackupError::SymlinkRejected {
                    path: dest.to_path_buf(),
                    reason: format!("{} destination leaf is a symbolic link", context),
                });
            }
            if ftype != libc::S_IFREG {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest.to_path_buf(),
                    reason: format!(
                        "{} destination leaf exists and is not a regular file",
                        context
                    ),
                });
            }
        } else {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() != Some(libc::ENOENT) {
                return Err(HostBackupError::io(
                    format!("fstatat {} ({})", dest.display(), context),
                    st_err,
                ));
            }
        }

        let tmp_name = format!(
            ".{}.af-atomic.{}.{}",
            leaf_name,
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let tmp_c =
            CString::new(tmp_name.as_str()).map_err(|_| HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: "temporary filename contains NUL byte".to_string(),
            })?;

        let staging = PrivateInstallDirectory::create(&parent_dir, parent, &tmp_c)?;
        let staging_dfd = staging.directory.as_raw_fd();
        let tmp_fd = unsafe {
            libc::openat(
                staging_dfd,
                tmp_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                (mode & 0o7777) as libc::c_uint,
            )
        };
        if tmp_fd < 0 {
            return Err(HostBackupError::io(
                format!(
                    "openat temporary file in {} ({})",
                    parent.display(),
                    context
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let mut tmp_file = unsafe { File::from_raw_fd(tmp_fd) };

        let write_res: HostBackupResult<libc::stat> = (|| {
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut copied_bytes = 0u64;
            loop {
                let count = src_reader.read(&mut buf).map_err(|err| {
                    HostBackupError::io(
                        format!("reading payload for {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                if count == 0 {
                    break;
                }
                tmp_file.write_all(&buf[..count]).map_err(|err| {
                    HostBackupError::io(
                        format!("writing payload to {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                hasher.update(&buf[..count]);
                copied_bytes += count as u64;
            }

            if let Some(exp_sz) = expected_size {
                if copied_bytes != exp_sz {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: format!("size={}", exp_sz),
                        actual: format!("size={}", copied_bytes),
                    });
                }
            }
            if let Some(exp_sha) = expected_sha256 {
                let exp_clean = exp_sha.trim().to_ascii_lowercase();
                let actual_sha = hex::encode(hasher.finalize());
                if actual_sha != exp_clean {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: exp_clean,
                        actual: actual_sha,
                    });
                }
            }

            if uid.is_some() || gid.is_some() {
                let target_uid = uid
                    .map(|uid_val| uid_val as libc::uid_t)
                    .unwrap_or(u32::MAX as libc::uid_t);
                let target_gid = gid
                    .map(|gid_val| gid_val as libc::gid_t)
                    .unwrap_or(u32::MAX as libc::gid_t);
                let chown_rc =
                    unsafe { libc::fchown(tmp_file.as_raw_fd(), target_uid, target_gid) };
                if chown_rc != 0 {
                    let chown_err = std::io::Error::last_os_error();
                    let euid = unsafe { libc::geteuid() };
                    let mut actual_st: libc::stat = unsafe { std::mem::zeroed() };
                    let stat_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut actual_st) } == 0;
                    let uid_satisfied = stat_ok
                        && uid
                            .map(|req_uid| actual_st.st_uid == req_uid as libc::uid_t)
                            .unwrap_or(true);
                    let gid_satisfied = stat_ok
                        && gid
                            .map(|req_gid| actual_st.st_gid == req_gid as libc::gid_t)
                            .unwrap_or(true);
                    let is_perm_err = matches!(
                        chown_err.raw_os_error(),
                        Some(libc::EPERM) | Some(libc::EACCES)
                    );
                    if euid == 0 || !is_perm_err || !uid_satisfied || !gid_satisfied {
                        return Err(HostBackupError::io(
                            format!(
                                "fchown uid={:?} gid={:?} on {} ({})",
                                uid,
                                gid,
                                dest.display(),
                                context
                            ),
                            chown_err,
                        ));
                    }
                }
            }

            let chmod_rc =
                unsafe { libc::fchmod(tmp_file.as_raw_fd(), (mode & 0o7777) as libc::mode_t) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchmod {:o} on {} ({})",
                        mode & 0o7777,
                        dest.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }

            tmp_file.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!("fsync temporary file for {} ({})", dest.display(), context),
                    err,
                )
            })?;

            let mut tmp_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut tmp_st) } != 0 {
                return Err(HostBackupError::io(
                    format!("fstat temporary file for {} ({})", dest.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
            if (tmp_st.st_mode & libc::S_IFMT) != libc::S_IFREG || tmp_st.st_nlink != 1 {
                return Err(HostBackupError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: format!(
                        "{} temporary file has unexpected link count or type before rename",
                        context
                    ),
                });
            }
            Ok(tmp_st)
        })();

        let tmp_st = match write_res {
            Ok(stat_val) => stat_val,
            Err(err) => {
                drop(tmp_file);
                unsafe {
                    let _ = libc::unlinkat(staging_dfd, tmp_c.as_ptr(), 0);
                }
                return Err(err);
            }
        };

        #[cfg(test)]
        invoke_pre_rename_install_hook(dest, &staging.path, &tmp_name);

        let mut pre_rename_fd_st: libc::stat = unsafe { std::mem::zeroed() };
        let mut pre_rename_dir_st: libc::stat = unsafe { std::mem::zeroed() };
        let pre_fd_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut pre_rename_fd_st) } == 0;
        let pre_dir_ok = unsafe {
            libc::fstatat(
                staging_dfd,
                tmp_c.as_ptr(),
                &mut pre_rename_dir_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if !pre_fd_ok
            || !pre_dir_ok
            || (pre_rename_dir_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || pre_rename_fd_st.st_nlink != 1
            || pre_rename_dir_st.st_nlink != 1
            || pre_rename_dir_st.st_dev != tmp_st.st_dev
            || pre_rename_dir_st.st_ino != tmp_st.st_ino
        {
            drop(tmp_file);
            return Err(HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: format!(
                    "{} temporary file at '{}' was replaced, unlinked, or hard-linked before rename",
                    context,
                    parent.join(&tmp_name).display()
                ),
            });
        }

        let rename_rc =
            unsafe { libc::renameat(staging_dfd, tmp_c.as_ptr(), parent_dfd, leaf_c.as_ptr()) };
        if rename_rc != 0 {
            let ren_err = std::io::Error::last_os_error();
            drop(tmp_file);
            return Err(HostBackupError::io(
                format!("renameat -> {} ({})", dest.display(), context),
                ren_err,
            ));
        }

        let mut post_rename_dir_st: libc::stat = unsafe { std::mem::zeroed() };
        let mut post_rename_fd_st: libc::stat = unsafe { std::mem::zeroed() };
        let post_dir_ok = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut post_rename_dir_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        let post_fd_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut post_rename_fd_st) } == 0;
        drop(tmp_file);
        if !post_dir_ok
            || !post_fd_ok
            || (post_rename_dir_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || post_rename_dir_st.st_dev != tmp_st.st_dev
            || post_rename_dir_st.st_ino != tmp_st.st_ino
            || post_rename_dir_st.st_size != tmp_st.st_size
            || (post_rename_dir_st.st_mode & 0o7777) != (tmp_st.st_mode & 0o7777)
            || post_rename_dir_st.st_uid != tmp_st.st_uid
            || post_rename_dir_st.st_gid != tmp_st.st_gid
            || post_rename_fd_st.st_nlink != 1
        {
            return Err(HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: format!(
                    "{} destination '{}' failed post-rename inode/metadata verification",
                    context,
                    dest.display()
                ),
            });
        }

        parent_dir.sync_all().map_err(|err| {
            HostBackupError::io(
                format!("fsync parent directory {} ({})", parent.display(), context),
                err,
            )
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (uid, gid, trusted_ancestor_uid);
        ensure_private_dir_all(parent, context)?;
        let (tmp_path, mut tmp_file) =
            create_unique_private_temp_file(dest, "atomic-install", context)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut copied_bytes = 0u64;
        let copy_res: HostBackupResult<()> = (|| {
            loop {
                let count = src_reader.read(&mut buf).map_err(|err| {
                    HostBackupError::io(
                        format!("reading payload for {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                if count == 0 {
                    break;
                }
                tmp_file.write_all(&buf[..count]).map_err(|err| {
                    HostBackupError::io(
                        format!(
                            "writing temporary install file {} ({})",
                            tmp_path.display(),
                            context
                        ),
                        err,
                    )
                })?;
                hasher.update(&buf[..count]);
                copied_bytes += count as u64;
            }
            if let Some(exp_sz) = expected_size {
                if copied_bytes != exp_sz {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: format!("size={}", exp_sz),
                        actual: format!("size={}", copied_bytes),
                    });
                }
            }
            if let Some(exp_sha) = expected_sha256 {
                let exp_clean = exp_sha.trim().to_ascii_lowercase();
                let actual_sha = hex::encode(hasher.finalize());
                if actual_sha != exp_clean {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: exp_clean,
                        actual: actual_sha,
                    });
                }
            }
            tmp_file.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!(
                        "syncing temporary install file {} ({})",
                        tmp_path.display(),
                        context
                    ),
                    err,
                )
            })?;
            Ok(())
        })();
        drop(tmp_file);
        if let Err(err) = copy_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Err(err) = fs::rename(&tmp_path, dest) {
            let _ = fs::remove_file(&tmp_path);
            return Err(HostBackupError::io(
                format!(
                    "renaming {} -> {} ({})",
                    tmp_path.display(),
                    dest.display(),
                    context
                ),
                err,
            ));
        }
        Ok(())
    }
}

/// Removes a regular file at `target` using dirfd-relative `unlinkat(parent_dfd, leaf, 0)` on Unix
/// after verifying `parent` is free of symlinks and owned by a trusted user. Ignores `ENOENT`.
pub fn unlink_file_at_destination(target: &Path, context: &str) -> HostBackupResult<()> {
    unlink_file_at_destination_with_trusted_ancestor_uid(target, None, context)
}

/// Variant of [`unlink_file_at_destination`] that accepts an independently supplied
/// caller/service `trusted_ancestor_uid`.
pub fn unlink_file_at_destination_with_trusted_ancestor_uid(
    target: &Path,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let Some(parent) = target.parent() else {
        return Ok(());
    };
    let Some(leaf_name) = target.file_name().and_then(|os_val| os_val.to_str()) else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let Some(parent_dir) = open_existing_dir_nofollow_optional_with_trusted_uid(
            parent,
            trusted_ancestor_uid,
            true,
            context,
        )?
        else {
            return Ok(());
        };
        let parent_dfd = parent_dir.as_raw_fd();
        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: target.to_path_buf(),
            reason: "filename contains NUL byte".to_string(),
        })?;
        let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut leaf_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc != 0 {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(HostBackupError::io(
                format!("fstatat {} ({})", target.display(), context),
                st_err,
            ));
        }
        let leaf_type = leaf_st.st_mode & libc::S_IFMT;
        if leaf_type == libc::S_IFLNK {
            return Err(HostBackupError::SymlinkRejected {
                path: target.to_path_buf(),
                reason: format!("{} target leaf is a symbolic link", context),
            });
        }
        if leaf_type != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: target.to_path_buf(),
                reason: format!("{} target leaf exists and is not a regular file", context),
            });
        }
        let rc = unsafe { libc::unlinkat(parent_dfd, leaf_c.as_ptr(), 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(HostBackupError::io(
                    format!("unlinkat {} ({})", target.display(), context),
                    err,
                ));
            }
        } else {
            parent_dir.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!(
                        "fsync parent directory {} after unlinkat ({})",
                        parent.display(),
                        context
                    ),
                    err,
                )
            })?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (leaf_name, trusted_ancestor_uid);
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(HostBackupError::io(
                format!("removing {} ({})", target.display(), context),
                err,
            )),
        }
    }
}
