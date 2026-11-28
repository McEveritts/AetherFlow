//! Release serialization and locking (`flock` on Unix + cross-platform lockfile guard)
//! and persistent crash-recovery journal (`.recovery_state.json`).

use crate::config::{ReleaseChannel, ReleaseCommand};
use crate::error::{ReleaseError, ReleaseResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::io::{Seek, SeekFrom};

enum AcquireAttemptError {
    Busy(String),
    Fatal(ReleaseError),
}

/// Exclusive file-backed lock guard preventing concurrent `deploy`, `rollback`, `cleanup`,
/// or `migrate-systemd` operations from colliding on `/opt/AetherFlow/releases` or SQLite snapshots.
#[derive(Debug)]
pub struct ReleaseLockGuard {
    lock_path: PathBuf,
    _file: File,
    #[cfg(unix)]
    parent_dir: File,
    #[cfg(unix)]
    leaf_name: String,
    #[cfg(unix)]
    locked_dev: libc::dev_t,
    #[cfg(unix)]
    locked_ino: libc::ino_t,
}

impl ReleaseLockGuard {
    pub fn acquire(lock_path: impl AsRef<Path>, timeout: Duration) -> ReleaseResult<Self> {
        let path = lock_path.as_ref().to_path_buf();
        crate::config::validate_no_parent_traversal(&path, "release lock path")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::fs_security::create_dir_all_no_symlinks(parent, 0o750)?;
            }
        }

        let start = Instant::now();
        loop {
            match Self::try_acquire_once(&path) {
                Ok(guard) => return Ok(guard),
                Err(AcquireAttemptError::Fatal(err)) => return Err(err),
                Err(AcquireAttemptError::Busy(reason)) => {
                    if start.elapsed() >= timeout {
                        return Err(ReleaseError::LockBusy {
                            lock_path: path,
                            reason,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// Verifies that the held lock descriptor is still linked at `self.lock_path` under the
    /// pinned parent directory descriptor with the exact `(st_dev, st_ino)` acquired and
    /// remains a single-link regular file.
    pub fn verify_still_active(&self) -> ReleaseResult<()> {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::io::AsRawFd;

            let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(self._file.as_raw_fd(), &mut fd_st) } != 0 {
                return Err(ReleaseError::io(
                    format!("fstat active release lockfile {}", self.lock_path.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            if (fd_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "active release lockfile is not a regular file".to_string(),
                });
            }
            if fd_st.st_nlink == 0 {
                return Err(ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "release lockfile was unlinked while lock guard was held".to_string(),
                });
            }
            if fd_st.st_nlink > 1 {
                return Err(ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "release lockfile has multiple hard links while held".to_string(),
                });
            }

            let leaf_c = CString::new(self.leaf_name.as_str()).map_err(|_| {
                ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "release lock filename contains NUL byte".to_string(),
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
                return Err(ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "release lockfile disappeared from parent directory while held"
                        .to_string(),
                });
            }
            if (dir_leaf_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || dir_leaf_st.st_dev != self.locked_dev
                || dir_leaf_st.st_ino != self.locked_ino
                || fd_st.st_dev != self.locked_dev
                || fd_st.st_ino != self.locked_ino
            {
                return Err(ReleaseError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "release lockfile inode was substituted in parent directory while held"
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

        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let leaf_name = path
            .file_name()
            .and_then(|os_val| os_val.to_str())
            .ok_or_else(|| {
                AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "release lock path must have a valid file name".to_string(),
                })
            })?;
        let leaf_c = CString::new(leaf_name).map_err(|_| {
            AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "release lock filename contains NUL byte".to_string(),
            })
        })?;

        let parent_dir = crate::fs_security::open_or_create_dir_nofollow(parent, 0o750)
            .map_err(AcquireAttemptError::Fatal)?;
        let parent_dfd = parent_dir.as_raw_fd();

        // Open with O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC so pre-planted FIFOs never hang and
        // symlink leaves fail immediately with ELOOP.
        let mut lock_fd = unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
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
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK,
                    0o660 as libc::c_uint,
                )
            };
            if lock_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                return Err(AcquireAttemptError::Busy(
                    "lockfile created concurrently during openat".to_string(),
                ));
            }
            if lock_fd >= 0 && unsafe { libc::fchmod(lock_fd, 0o660) } != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(lock_fd) };
                return Err(AcquireAttemptError::Fatal(ReleaseError::io(
                    format!("fchmod lockfile {}", path.display()),
                    err,
                )));
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
            if open_err.raw_os_error() == Some(libc::ELOOP)
                || (st_rc == 0 && (err_st.st_mode & libc::S_IFMT) == libc::S_IFLNK)
            {
                return Err(AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "release lockfile is a symbolic link".to_string(),
                }));
            }
            if open_err.raw_os_error() == Some(libc::EISDIR)
                || (st_rc == 0 && (err_st.st_mode & libc::S_IFMT) != libc::S_IFREG)
            {
                return Err(AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "release lockfile exists and is not a regular file".to_string(),
                }));
            }
            return Err(AcquireAttemptError::Fatal(ReleaseError::io(
                format!("failed to open lockfile {}", path.display()),
                open_err,
            )));
        }

        let mut file = unsafe { File::from_raw_fd(lock_fd) };
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut opened_st) } != 0 {
            return Err(AcquireAttemptError::Fatal(ReleaseError::io(
                format!("fstat opened lockfile {}", path.display()),
                std::io::Error::last_os_error(),
            )));
        }
        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "opened release lockfile is not a regular file".to_string(),
            }));
        }
        if opened_st.st_nlink > 1 {
            return Err(AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "opened release lockfile has multiple hard links".to_string(),
            }));
        }

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AcquireAttemptError::Busy(format!(
                "flock(LOCK_EX | LOCK_NB) busy: {}",
                err
            )));
        }

        // Re-verify regular-file type, link count, and exact (st_dev, st_ino) after flock
        // so unlink/rename races between openat and flock cannot split locks across two inodes.
        let mut post_fd_st: libc::stat = unsafe { std::mem::zeroed() };
        let mut verify_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut post_fd_st) } != 0
            || unsafe {
                libc::fstatat(
                    parent_dfd,
                    leaf_c.as_ptr(),
                    &mut verify_leaf_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            || (post_fd_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || (verify_leaf_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || post_fd_st.st_nlink == 0
            || verify_leaf_st.st_dev != opened_st.st_dev
            || verify_leaf_st.st_ino != opened_st.st_ino
            || post_fd_st.st_dev != opened_st.st_dev
            || post_fd_st.st_ino != opened_st.st_ino
        {
            return Err(AcquireAttemptError::Busy(
                "lockfile inode changed during acquisition".to_string(),
            ));
        }
        if post_fd_st.st_nlink > 1 || verify_leaf_st.st_nlink > 1 {
            return Err(AcquireAttemptError::Fatal(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "release lockfile gained multiple hard links during acquisition"
                    .to_string(),
            }));
        }

        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        Ok(Self {
            lock_path: path.to_path_buf(),
            _file: file,
            parent_dir,
            leaf_name: leaf_name.to_string(),
            locked_dev: opened_st.st_dev,
            locked_ino: opened_st.st_ino,
        })
    }

    #[cfg(not(unix))]
    fn try_acquire_once(path: &Path) -> Result<Self, AcquireAttemptError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| AcquireAttemptError::Busy(format!("lockfile already held: {}", e)))?;

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

    #[cfg(unix)]
    pub fn file_identity(&self) -> std::io::Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self._file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other(
                "maintenance lock is not a regular file",
            ));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    #[cfg(unix)]
    pub fn preserve_in_child(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let file = self._file.try_clone()?;
        let descriptor = file.as_raw_fd();
        command.env("AF_MAINTENANCE_GUARD_FD", descriptor.to_string());
        unsafe {
            command.pre_exec(move || {
                let descriptor = file.as_raw_fd();
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags == -1
                    || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(descriptor)
    }
}

#[cfg(not(unix))]
impl Drop for ReleaseLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Lifecycle phase recorded in `.recovery_state.json` during a release transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePhase {
    Stage0FhsLayout,
    Stage1Scaffold,
    Stage1_5Snapshot,
    Stage2SymlinkSwap,
    Stage3HealthProbe,
    Stage4Rollback,
    Stage5Cleanup,
    Stage6MigrateSystemd,
    #[serde(alias = "completed")]
    Complete,
    Failed,
}

/// Persistent recovery state persisted at `${RELEASES_DIR}/.recovery_state.json`
/// so interrupted deployments or administrative health checks can inspect exact stage state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryState {
    pub operation_id: String,
    pub command: ReleaseCommand,
    pub channel: ReleaseChannel,
    pub dry_run: bool,
    pub phase: ReleasePhase,
    pub candidate_release: Option<PathBuf>,
    pub previous_release: Option<PathBuf>,
    pub resolved_db_path: Option<PathBuf>,
    pub resolved_db_source: Option<String>,
    pub snapshot_path: Option<PathBuf>,
    pub started_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_error: Option<String>,
}

impl RecoveryState {
    pub fn new(command: ReleaseCommand, channel: ReleaseChannel, dry_run: bool) -> Self {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Self {
            operation_id: std::env::var("AETHERFLOW_UPDATE_OPERATION_ID")
                .ok()
                .and_then(|value| uuid::Uuid::parse_str(&value).ok())
                .unwrap_or_else(uuid::Uuid::new_v4)
                .to_string(),
            command,
            channel,
            dry_run,
            phase: ReleasePhase::Stage0FhsLayout,
            candidate_release: None,
            previous_release: None,
            resolved_db_path: None,
            resolved_db_source: None,
            snapshot_path: None,
            started_at: now.clone(),
            updated_at: now,
            last_error: None,
        }
    }

    /// Returns the canonical recovery state file path under `releases_dir`.
    pub fn state_file_path(releases_dir: &Path) -> PathBuf {
        releases_dir.join(".recovery_state.json")
    }

    /// Returns `true` if this recovery state represents an interrupted/in-flight mutating operation
    /// that did not reach a terminal (`Complete` or pre-swap `Failed`) state.
    pub fn is_unfinished(&self) -> bool {
        !matches!(self.phase, ReleasePhase::Complete | ReleasePhase::Failed)
    }

    /// Returns `true` if this recovery state indicates a previous deployment or rollback already
    /// swapped `current` (or entered Stage 3 / Stage 4) without completing cleanly, meaning `current`
    /// may point to an unhealthy release while `.previous_release` holds the last known-good release.
    pub fn has_unhealthy_or_interrupted_post_swap_deploy(&self) -> bool {
        !self.dry_run
            && (self.phase == ReleasePhase::Stage4Rollback
                || (self.command == ReleaseCommand::Deploy
                    && matches!(
                        self.phase,
                        ReleasePhase::Stage2SymlinkSwap | ReleasePhase::Stage3HealthProbe
                    )))
    }

    /// Atomically persists the recovery state to `${RELEASES_DIR}/.recovery_state.json`
    /// using a same-filesystem private staging file with `0600` permissions before `sync_all()`,
    /// atomic `renameat`, and parent directory `fsync`.
    pub fn save(&mut self, releases_dir: &Path) -> ReleaseResult<()> {
        crate::fs_security::create_dir_all_no_symlinks(releases_dir, 0o755)?;
        self.updated_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let target = Self::state_file_path(releases_dir);
        let payload = serde_json::to_vec_pretty(self).map_err(|e| {
            ReleaseError::Config(format!("failed to serialize recovery state: {}", e))
        })?;
        crate::fs_security::atomic_write_bytes_with_mode(&target, &payload, 0o600)?;
        crate::fs_security::sync_parent_dir_best_effort(releases_dir);
        Ok(())
    }

    /// Loads the recovery state from `${RELEASES_DIR}/.recovery_state.json` if present.
    pub fn load(releases_dir: &Path) -> ReleaseResult<Option<Self>> {
        use std::io::Read;

        let path = Self::state_file_path(releases_dir);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(ReleaseError::PathValidation {
                        path,
                        reason: "refusing to read symlinked or non-regular .recovery_state.json"
                            .to_string(),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(ReleaseError::io(
                    format!("inspecting {}", path.display()),
                    err,
                ));
            }
        }
        let mut opts = fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = opts
            .open(&path)
            .map_err(|e| ReleaseError::io(format!("reading {}", path.display()), e))?;
        let fmeta = file
            .metadata()
            .map_err(|e| ReleaseError::io(format!("stat {}", path.display()), e))?;
        if !fmeta.is_file() {
            return Err(ReleaseError::PathValidation {
                path,
                reason: "refusing to read non-regular .recovery_state.json".to_string(),
            });
        }
        let mut raw = String::new();
        file.take(65_537)
            .read_to_string(&mut raw)
            .map_err(|e| ReleaseError::io(format!("reading {}", path.display()), e))?;
        if raw.len() > 65_536 {
            return Err(ReleaseError::PathValidation {
                path,
                reason: ".recovery_state.json exceeds 64 KiB cap".to_string(),
            });
        }
        let parsed: Self = serde_json::from_str(&raw)
            .or_else(|original_error| {
                let mut legacy: serde_json::Value = serde_json::from_str(&raw)?;
                if legacy["phase"] != "completed"
                    || legacy["command"] != "deploy"
                    || legacy["dry_run"] != false
                    || legacy.get("started_at").is_some()
                {
                    return Err(original_error);
                }
                let Some(updated_at) = legacy["updated_at"]
                    .as_str()
                    .filter(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).is_ok())
                    .map(str::to_owned)
                else {
                    return Err(original_error);
                };
                legacy["started_at"] = serde_json::Value::String(updated_at);
                serde_json::from_value(legacy)
            })
            .map_err(|error| {
                ReleaseError::Config(format!(
                    "corrupted recovery state file {}: {}",
                    path.display(),
                    error
                ))
            })?;
        Ok(Some(parsed))
    }
}

#[cfg(all(test, unix))]
mod crate09_lock_tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    fn lock_sandbox(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("af-lock-test-{}-{}", label, uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn crate09_release_lock_rejects_fifo_without_blocking_and_rejects_symlinks_and_hardlinks() {
        let root = lock_sandbox("fifo-sym-hl");

        // 1. Pre-planted FIFO must fail immediately without blocking (O_NONBLOCK + S_IFREG).
        let fifo_path = root.join(".fifo.lock");
        let fifo_c = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        let fifo_err = ReleaseLockGuard::acquire(&fifo_path, Duration::from_secs(5)).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO open must fail fast without hanging or spinning"
        );
        assert!(
            matches!(fifo_err, ReleaseError::PathValidation { .. }),
            "expected PathValidation on FIFO, got: {fifo_err:?}"
        );

        // 2. Symlink lockfile fails fast with PathValidation.
        let target = root.join("real-target");
        fs::write(&target, b"x").unwrap();
        let sym_lock = root.join(".sym.lock");
        symlink(&target, &sym_lock).unwrap();
        let sym_err = ReleaseLockGuard::acquire(&sym_lock, Duration::from_secs(5)).unwrap_err();
        assert!(matches!(sym_err, ReleaseError::PathValidation { .. }));

        // 3. Multi-hardlink lockfile fails fast with PathValidation.
        let hl_lock = root.join(".hl.lock");
        fs::hard_link(&target, &hl_lock).unwrap();
        let hl_err = ReleaseLockGuard::acquire(&hl_lock, Duration::from_secs(5)).unwrap_err();
        assert!(matches!(hl_err, ReleaseError::PathValidation { .. }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn crate09_release_lock_detects_unlinked_or_substituted_inode() {
        let root = lock_sandbox("inode-recheck");
        let lock_path = root.join(".release.lock");

        let guard = ReleaseLockGuard::acquire(&lock_path, Duration::from_millis(100)).unwrap();
        guard.verify_still_active().unwrap();

        // Replace the lockfile path with a new inode while the old guard is held.
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, b"substituted").unwrap();

        let err = guard.verify_still_active().unwrap_err();
        assert!(
            matches!(err, ReleaseError::PathValidation { .. }),
            "expected inode substitution failure, got: {err:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
