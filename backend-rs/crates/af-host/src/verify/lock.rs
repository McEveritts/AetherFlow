use super::dirfd::{
    open_existing_dir_nofollow_optional_with_trusted_uid, open_or_create_lock_parent_dir_nofollow,
};
use super::paths::{reject_if_symlink, validate_no_parent_traversal};
use crate::error::{HostBackupError, HostBackupResult};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Default system-wide maintenance lockfile path shared across `af-runner`, `af-api`,
/// `af-services`, `af-release`, `af-cli`, `deploy/release-manager.sh`, and `af-backup`.
pub const DEFAULT_MAINTENANCE_LOCK_PATH: &str = "/run/aetherflow/.snapshot.lock";

fn normalize_maintenance_lock_fallback_dir(candidate_dir: &Path) -> PathBuf {
    let mut current = candidate_dir;
    if current.file_name().and_then(|os_val| os_val.to_str()) == Some(".snapshot.lock") {
        if let Some(parent) = current.parent() {
            if !parent.as_os_str().is_empty() {
                current = parent;
            }
        }
    }
    if current
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "sqlite" | "db" | "sqlite3" | "gz" | "json"
            )
        })
        .unwrap_or(false)
    {
        if let Some(parent) = current.parent() {
            if !parent.as_os_str().is_empty() {
                current = parent;
            }
        }
    }

    let comps: Vec<Component<'_>> = current.components().collect();
    if comps.len() >= 3 {
        for idx in 0..=(comps.len() - 3) {
            if comps[idx].as_os_str() == "var"
                && comps[idx + 1].as_os_str() == "lib"
                && comps[idx + 2].as_os_str() == "aetherflow"
            {
                let mut state_dir = PathBuf::new();
                for seg in &comps[..=(idx + 2)] {
                    state_dir.push(seg.as_os_str());
                }
                return state_dir;
            }
        }
    }

    if comps.len() >= 2 {
        for idx in 0..=(comps.len() - 2) {
            let first_seg = comps[idx].as_os_str().to_string_lossy();
            let second_seg = comps[idx + 1].as_os_str().to_string_lossy();
            if (first_seg.eq_ignore_ascii_case("etc") || first_seg.eq_ignore_ascii_case("opt"))
                && second_seg.eq_ignore_ascii_case("aetherflow")
            {
                let mut prefix_root = PathBuf::new();
                for seg in &comps[..idx] {
                    prefix_root.push(seg.as_os_str());
                }
                if prefix_root.as_os_str().is_empty() {
                    prefix_root.push("/");
                }
                return prefix_root.join("var/lib/aetherflow");
            }
        }
    }

    while let Some(leaf) = current.file_name().and_then(|os_val| os_val.to_str()) {
        let is_sub_dir = matches!(
            leaf,
            "backups"
                | "restore-staging"
                | ".restore-provenance"
                | ".self-update-jobs"
                | "releases"
        ) || leaf.starts_with(".staging-")
            || leaf.starts_with(".rollback-restore.");
        if is_sub_dir {
            if let Some(parent) = current.parent() {
                if !parent.as_os_str().is_empty() {
                    current = parent;
                    continue;
                }
            }
        }
        break;
    }

    current.to_path_buf()
}

/// Resolves the shared cross-process maintenance lockfile path.
pub fn resolve_maintenance_lock_path(fallback_dir: Option<&Path>) -> PathBuf {
    if let Ok(raw) = std::env::var("AETHERFLOW_MAINTENANCE_LOCK_PATH") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let has_explicit_db_or_root_env = [
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_RESTORE_STAGING_ROOT",
        "AETHERFLOW_DB_PATH",
        "DB_PATH",
        "DATA_DIR",
    ]
    .iter()
    .any(|env_key| {
        std::env::var(env_key)
            .ok()
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false)
    });

    let normalized_fallback = fallback_dir
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(normalize_maintenance_lock_fallback_dir);

    if has_explicit_db_or_root_env {
        if let Ok(resolved) = af_models::try_resolve_canonical_maintenance_lock_path_with_env(
            None,
            None,
            normalized_fallback.as_deref(),
            |env_key| std::env::var(env_key).ok(),
        ) {
            return resolved;
        }
    }

    if let Some(state_dir) = normalized_fallback {
        if state_dir == Path::new("/var/lib/aetherflow") {
            return PathBuf::from(DEFAULT_MAINTENANCE_LOCK_PATH);
        }
        let comps: Vec<Component<'_>> = state_dir.components().collect();
        if comps.len() >= 3
            && comps[comps.len() - 3].as_os_str() == "var"
            && comps[comps.len() - 2].as_os_str() == "lib"
            && comps[comps.len() - 1].as_os_str() == "aetherflow"
        {
            let mut prefix_root = PathBuf::new();
            for seg in &comps[..(comps.len() - 3)] {
                prefix_root.push(seg.as_os_str());
            }
            if !prefix_root.as_os_str().is_empty() && prefix_root != Path::new("/") {
                let candidate_run_dir = prefix_root.join("run/aetherflow");
                let mut map_to_run = candidate_run_dir.exists();
                #[cfg(unix)]
                if !map_to_run {
                    use std::os::unix::fs::MetadataExt;
                    if let (Ok(root_meta), Ok(var_meta)) = (
                        fs::symlink_metadata(&prefix_root),
                        fs::symlink_metadata(&state_dir),
                    ) {
                        if root_meta.uid() == 0 && var_meta.uid() != 0 {
                            map_to_run = true;
                        }
                    }
                }
                if map_to_run {
                    return candidate_run_dir.join(".snapshot.lock");
                }
            }
        }
        return state_dir.join(".snapshot.lock");
    }

    if let Ok(resolved) =
        af_models::try_resolve_canonical_maintenance_lock_path_from_env(None, None, None)
    {
        return resolved;
    }
    PathBuf::from(DEFAULT_MAINTENANCE_LOCK_PATH)
}

/// Resolves the UID and primary GID of the packaged `aetherflow` service user on Unix
/// (or an explicit numeric override via `AETHERFLOW_SERVICE_UID` / `AETHERFLOW_SERVICE_GID`
/// or account name override via `AETHERFLOW_SERVICE_USER`).
#[cfg(unix)]
pub fn resolve_trusted_service_account_ids() -> Option<(u32, u32)> {
    let uid_override = std::env::var("AETHERFLOW_SERVICE_UID")
        .ok()
        .and_then(|val| val.trim().parse::<u32>().ok());
    let gid_override = std::env::var("AETHERFLOW_SERVICE_GID")
        .ok()
        .and_then(|val| val.trim().parse::<u32>().ok());
    if let (Some(uid_val), Some(gid_val)) = (uid_override, gid_override) {
        return Some((uid_val, gid_val));
    }

    let account_name = std::env::var("AETHERFLOW_SERVICE_USER")
        .ok()
        .map(|val| val.trim().to_string())
        .filter(|val| !val.is_empty())
        .unwrap_or_else(|| "aetherflow".to_string());

    let account_c = std::ffi::CString::new(account_name).ok()?;
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0u8; 4096];
        let rc = libc::getpwnam_r(
            account_c.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() {
            let resolved_uid = uid_override.unwrap_or(pwd.pw_uid);
            let resolved_gid = gid_override.unwrap_or(pwd.pw_gid);
            return Some((resolved_uid, resolved_gid));
        }
    }
    uid_override.map(|uid_val| (uid_val, gid_override.unwrap_or(uid_val)))
}

#[cfg(not(unix))]
pub fn resolve_trusted_service_account_ids() -> Option<(u32, u32)> {
    None
}

/// Exclusive cross-process maintenance lock guard backed by `flock(LOCK_EX)` on Unix
/// (and an exclusive lockfile on non-Unix).
///
/// Serializes all mutating backup, restore, retention prune, and release self-update
/// operations across processes (`af-api`, `af-runner`, `af-services`, `af-cli`, `af-release`).
#[derive(Debug)]
pub struct HostMaintenanceLockGuard {
    lock_path: PathBuf,
    _file: File,
    #[cfg(unix)]
    parent_dir: File,
    #[cfg(unix)]
    leaf_name: String,
    #[cfg(unix)]
    locked_dev: u64,
    #[cfg(unix)]
    locked_ino: u64,
}

impl HostMaintenanceLockGuard {
    /// Acquires the exclusive maintenance lock at `lock_path`, waiting up to `timeout`.
    pub fn acquire(
        lock_path: impl AsRef<Path>,
        timeout: std::time::Duration,
    ) -> HostBackupResult<Self> {
        let path = lock_path.as_ref().to_path_buf();
        validate_no_parent_traversal(&path, "maintenance lock path")?;
        reject_if_symlink(&path, "maintenance lockfile")?;

        let start = std::time::Instant::now();
        loop {
            match Self::try_acquire_once(&path) {
                Ok(guard) => return Ok(guard),
                Err(AcquireAttemptError::Fatal(err)) => return Err(err),
                Err(AcquireAttemptError::Busy(reason)) => {
                    if start.elapsed() >= timeout {
                        return Err(HostBackupError::InvalidConfig(format!(
                            "maintenance lock busy at '{}': {}",
                            path.display(),
                            reason
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    /// Acquires the default shared maintenance lock (resolving via [`resolve_maintenance_lock_path`]).
    pub fn acquire_default(
        fallback_dir: Option<&Path>,
        timeout: std::time::Duration,
    ) -> HostBackupResult<Self> {
        let primary = resolve_maintenance_lock_path(fallback_dir);
        Self::acquire(&primary, timeout)
    }

    /// Verifies that the held lock descriptor is still linked at `self.lock_path` under the
    /// pinned parent directory descriptor with the exact `(st_dev, st_ino)` acquired, and has
    /// not been unlinked, renamed, or replaced during the guarded maintenance operation.
    pub fn verify_still_active(&self) -> HostBackupResult<()> {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::io::AsRawFd;

            let euid = unsafe { libc::geteuid() };
            let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(self._file.as_raw_fd(), &mut fd_st) } != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fstat active maintenance lockfile {}",
                        self.lock_path.display()
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
            if fd_st.st_nlink == 0 {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile was unlinked while lock guard was held"
                        .to_string(),
                });
            }
            if fd_st.st_nlink > 1 {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile has multiple hard links while held".to_string(),
                });
            }

            let leaf_c = CString::new(self.leaf_name.as_str()).map_err(|_| {
                HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock filename contains NUL byte".to_string(),
                }
            })?;
            let mut dir_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.parent_dir.as_raw_fd(),
                    leaf_c.as_ptr(),
                    &mut dir_leaf_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile disappeared from parent directory while held"
                        .to_string(),
                });
            }
            if (dir_leaf_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || dir_leaf_st.st_dev as u64 != self.locked_dev
                || dir_leaf_st.st_ino as u64 != self.locked_ino
                || fd_st.st_dev as u64 != self.locked_dev
                || fd_st.st_ino as u64 != self.locked_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason:
                        "maintenance lockfile inode was substituted in parent directory while held"
                            .to_string(),
                });
            }

            let parent_path = self.lock_path.parent().unwrap_or_else(|| Path::new("/"));
            let verified_parent_opt = open_existing_dir_nofollow_optional_with_trusted_uid(
                parent_path,
                None,
                euid != 0,
                "active maintenance lock parent",
            )?;
            let Some(verified_parent_dir) = verified_parent_opt else {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock parent directory disappeared while held".to_string(),
                });
            };
            let mut verified_parent_st: libc::stat = unsafe { std::mem::zeroed() };
            let mut parent_fd_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(verified_parent_dir.as_raw_fd(), &mut verified_parent_st) } != 0
                || unsafe { libc::fstat(self.parent_dir.as_raw_fd(), &mut parent_fd_st) } != 0
                || verified_parent_st.st_dev != parent_fd_st.st_dev
                || verified_parent_st.st_ino != parent_fd_st.st_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock parent directory was renamed or replaced while held"
                        .to_string(),
                });
            }
            let mut active_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    verified_parent_dir.as_raw_fd(),
                    leaf_c.as_ptr(),
                    &mut active_leaf_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
                || active_leaf_st.st_dev as u64 != self.locked_dev
                || active_leaf_st.st_ino as u64 != self.locked_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile path no longer resolves to held lock inode"
                        .to_string(),
                });
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn try_acquire_once(path: &Path) -> Result<Self, AcquireAttemptError> {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let parent = path.parent().ok_or_else(|| {
            AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "maintenance lock path must have a parent directory".to_string(),
            })
        })?;
        let leaf_name = path
            .file_name()
            .and_then(|os_val| os_val.to_str())
            .ok_or_else(|| {
                AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "maintenance lock path must have a valid file name".to_string(),
                })
            })?;

        let service_ids = resolve_trusted_service_account_ids();
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let (_target_uid, target_gid) = if let Some((svc_uid, svc_gid)) = service_ids {
            (svc_uid as libc::uid_t, svc_gid as libc::gid_t)
        } else {
            (euid, egid)
        };

        let parent_dir = open_or_create_lock_parent_dir_nofollow(
            parent,
            euid,
            target_gid,
            "maintenance lock parent",
        )
        .map_err(AcquireAttemptError::Fatal)?;
        let parent_dfd = parent_dir.as_raw_fd();

        let mut parent_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(parent_dfd, &mut parent_st) } != 0 {
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("fstat maintenance lock parent {}", parent.display()),
                std::io::Error::last_os_error(),
            )));
        }

        if euid == 0 {
            if parent_st.st_uid != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: parent.to_path_buf(),
                    reason: format!(
                        "maintenance lock parent '{}' is owned by non-root uid={} while acquiring lock as root; refusing replaceable lock parent",
                        parent.display(),
                        parent_st.st_uid
                    ),
                }));
            }
            if (parent_st.st_mode & 0o020) != 0
                && parent_st.st_gid != 0
                && (parent_st.st_mode & libc::S_ISVTX) == 0
            {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: parent.to_path_buf(),
                    reason: format!(
                        "maintenance lock parent '{}' is group-writable without sticky bit (mode {:o})",
                        parent.display(),
                        parent_st.st_mode & 0o7777
                    ),
                }));
            }
        }

        let leaf_c = CString::new(leaf_name).map_err(|_| {
            AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "maintenance lock filename contains NUL byte".to_string(),
            })
        })?;

        let mut lock_fd = unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if lock_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            lock_fd = unsafe {
                libc::openat(
                    parent_dfd,
                    leaf_c.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o660 as libc::c_uint,
                )
            };
            if lock_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                return Err(AcquireAttemptError::Busy(
                    "maintenance lockfile created concurrently during openat".to_string(),
                ));
            }
            if lock_fd >= 0 {
                // Ensure group-writable permissions even under restrictive runner UMask=0077
                if unsafe { libc::fchmod(lock_fd, 0o660) } != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe { libc::close(lock_fd) };
                    return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                        format!("fchmod maintenance lockfile {}", path.display()),
                        err,
                    )));
                }
            }
        }
        if lock_fd < 0 {
            let open_err = std::io::Error::last_os_error();
            let mut err_st: libc::stat = unsafe { std::mem::zeroed() };
            let st_rc = unsafe {
                libc::fstatat(
                    parent_dfd,
                    leaf_c.as_ptr(),
                    &mut err_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if st_rc == 0 && (err_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile is a symbolic link".to_string(),
                    },
                ));
            }
            if open_err.raw_os_error() == Some(libc::ELOOP) {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile is a symbolic link (ELOOP)".to_string(),
                    },
                ));
            }
            if open_err.raw_os_error() == Some(libc::EISDIR)
                || (st_rc == 0 && (err_st.st_mode & libc::S_IFMT) != libc::S_IFREG)
            {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile exists and is not a regular file".to_string(),
                    },
                ));
            }
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("opening maintenance lockfile {}", path.display()),
                open_err,
            )));
        }

        let mut file = unsafe { File::from_raw_fd(lock_fd) };
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut opened_st) } != 0 {
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("fstat opened maintenance lockfile {}", path.display()),
                std::io::Error::last_os_error(),
            )));
        }
        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "opened maintenance lockfile is not a regular file".to_string(),
                },
            ));
        }
        if opened_st.st_nlink > 1 {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "opened maintenance lockfile has multiple hard links".to_string(),
                },
            ));
        }
        let allowed_owner = opened_st.st_uid == 0
            || opened_st.st_uid == euid
            || service_ids
                .map(|(svc_uid, _)| opened_st.st_uid == svc_uid as libc::uid_t)
                .unwrap_or(false);
        if !allowed_owner {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' has untrusted owner uid={}",
                        path.display(),
                        opened_st.st_uid
                    ),
                },
            ));
        }
        if (opened_st.st_mode & 0o002) != 0 {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' has unsafe world-writable permissions {:o}",
                        path.display(),
                        opened_st.st_mode & 0o777
                    ),
                },
            ));
        }

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AcquireAttemptError::Busy(format!(
                "flock(LOCK_EX | LOCK_NB) busy: {}",
                err
            )));
        }

        let mut verify_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut verify_leaf_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || verify_leaf_st.st_dev != opened_st.st_dev
            || verify_leaf_st.st_ino != opened_st.st_ino
            || opened_st.st_nlink == 0
        {
            return Err(AcquireAttemptError::Busy(
                "lockfile inode changed during acquisition".to_string(),
            ));
        }

        if euid == 0 {
            if opened_st.st_uid != 0 || opened_st.st_gid != target_gid {
                let chown_rc = unsafe { libc::fchown(file.as_raw_fd(), 0, target_gid) };
                if chown_rc != 0 {
                    return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                        format!("fchown maintenance lockfile {}", path.display()),
                        std::io::Error::last_os_error(),
                    )));
                }
            }
            let chmod_rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o660) };
            if chmod_rc != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                    format!("fchmod maintenance lockfile {}", path.display()),
                    std::io::Error::last_os_error(),
                )));
            }
            let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
            let mut post_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &mut post_st) } != 0
                || unsafe {
                    libc::fstatat(
                        parent_dfd,
                        leaf_c.as_ptr(),
                        &mut post_leaf_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                || post_st.st_uid != 0
                || post_st.st_gid != target_gid
                || (post_st.st_mode & 0o777) != 0o660
                || post_st.st_nlink != 1
                || post_leaf_st.st_dev != opened_st.st_dev
                || post_leaf_st.st_ino != opened_st.st_ino
            {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' metadata after root normalization is incompatible",
                        path.display()
                    ),
                }));
            }
        } else {
            let explicit_gid_override = std::env::var("AETHERFLOW_SERVICE_GID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            let explicit_uid_override = std::env::var("AETHERFLOW_SERVICE_UID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            let explicit_user_override = std::env::var("AETHERFLOW_SERVICE_USER")
                .ok()
                .map(|val| !val.trim().is_empty())
                .unwrap_or(false);
            let is_service_context = explicit_gid_override.is_some()
                || explicit_uid_override.is_some()
                || explicit_user_override
                || path.starts_with("/var/lib/aetherflow")
                || path.starts_with("/run/aetherflow")
                || service_ids
                    .map(|(svc_uid, svc_gid)| {
                        euid == svc_uid as libc::uid_t
                            || parent_st.st_uid == svc_uid as libc::uid_t
                            || parent_st.st_gid == svc_gid as libc::gid_t
                            || opened_st.st_uid == svc_uid as libc::uid_t
                            || opened_st.st_gid == svc_gid as libc::gid_t
                    })
                    .unwrap_or(false);
            let has_service_target_gid = explicit_gid_override.is_some() || service_ids.is_some();
            let expected_gid = if is_service_context && has_service_target_gid {
                target_gid
            } else {
                egid
            };

            if opened_st.st_uid == euid {
                if opened_st.st_gid != expected_gid {
                    let chown_rc = unsafe {
                        libc::fchown(file.as_raw_fd(), u32::MAX as libc::uid_t, expected_gid)
                    };
                    if chown_rc != 0 {
                        let chown_err = std::io::Error::last_os_error();
                        return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                            format!(
                                "fchown maintenance lockfile {} to expected gid={}",
                                path.display(),
                                expected_gid
                            ),
                            chown_err,
                        )));
                    }
                }
                if (opened_st.st_mode & 0o777) != 0o660 {
                    let chmod_rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o660) };
                    if chmod_rc != 0 {
                        return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                            format!("fchmod maintenance lockfile {}", path.display()),
                            std::io::Error::last_os_error(),
                        )));
                    }
                }
            }

            let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &mut post_st) } != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                    format!(
                        "fstat maintenance lockfile {} after metadata check",
                        path.display()
                    ),
                    std::io::Error::last_os_error(),
                )));
            }
            if (post_st.st_mode & 0o777) != 0o660 {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: format!(
                        "maintenance lockfile '{}' has incompatible mode {:04o} (expected 0660)",
                        path.display(),
                        post_st.st_mode & 0o777
                    ),
                    },
                ));
            }
            let gid_compatible = post_st.st_gid == expected_gid
                || (!is_service_context
                    && (parent_st.st_mode & libc::S_ISGID) != 0
                    && post_st.st_gid == parent_st.st_gid);
            if !gid_compatible {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: format!(
                        "maintenance lockfile '{}' resulting gid={} does not match expected gid={}",
                        path.display(),
                        post_st.st_gid,
                        expected_gid
                    ),
                    },
                ));
            }
        }

        let _ = file.set_len(0);
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        let guard = Self {
            lock_path: path.to_path_buf(),
            _file: file,
            parent_dir,
            leaf_name: leaf_name.to_string(),
            locked_dev: opened_st.st_dev as u64,
            locked_ino: opened_st.st_ino as u64,
        };
        guard
            .verify_still_active()
            .map_err(AcquireAttemptError::Fatal)?;
        Ok(guard)
    }

    #[cfg(not(unix))]
    fn try_acquire_once(path: &Path) -> Result<Self, AcquireAttemptError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| AcquireAttemptError::Busy(format!("lockfile already held: {}", err)))?;

        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        Ok(Self {
            lock_path: path.to_path_buf(),
            _file: file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.lock_path
    }
}

enum AcquireAttemptError {
    Busy(String),
    Fatal(HostBackupError),
}

impl Drop for HostMaintenanceLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}
