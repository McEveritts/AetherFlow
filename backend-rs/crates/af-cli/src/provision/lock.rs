use super::fs_helpers::{ensure_no_symlink_ancestors, open_exclusive_private_file};
use crate::error::{CliError, CliResult};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

/// RAII crash-safe PID lockfile guard compatible with `_acquire_lock` / `_release_lock`
/// in `setup/modules/06-state.sh`.
#[derive(Debug)]
pub struct ProvisionLockGuard {
    lock_path: PathBuf,
    owner_pid: u32,
    _serialization_guard: af_release::ReleaseLockGuard,
}

impl ProvisionLockGuard {
    /// Atomically acquires `lock_path` using an exclusive temporary lockfile + hard-link/create_new
    /// publish and stale-PID crash recovery.
    pub fn acquire(lock_path: impl Into<PathBuf>) -> CliResult<Self> {
        let lock_path = lock_path.into();
        ensure_no_symlink_ancestors(&lock_path, "provision lockfile")?;

        let parent = lock_path.parent().ok_or_else(|| {
            CliError::Validation(format!(
                "lockfile path '{}' has no parent directory",
                lock_path.display()
            ))
        })?;
        if !parent.as_os_str().is_empty() {
            ensure_no_symlink_ancestors(parent, "provision lockfile parent")?;
            fs::create_dir_all(parent).map_err(|e| {
                CliError::io(format!("creating lockfile dir {}", parent.display()), e)
            })?;
            ensure_no_symlink_ancestors(parent, "provision lockfile parent")?;
        }

        let guard_path = parent.join(format!(
            ".{}.rust-guard",
            lock_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        ensure_no_symlink_ancestors(&guard_path, "provision serialization guard")?;
        let serialization_guard =
            af_release::ReleaseLockGuard::acquire(&guard_path, std::time::Duration::ZERO).map_err(
                |error| {
                    CliError::PreflightOrIntegrity(format!(
                        "another provisioning operation holds {}: {}",
                        guard_path.display(),
                        error
                    ))
                },
            )?;

        let my_pid = std::process::id();
        let pid_payload = format!("{}\n", my_pid);
        let tmp_lock = parent.join(format!(".af-lock-tmp-{}-{}", my_pid, Uuid::new_v4()));

        let mut tmp_file = open_exclusive_private_file(&tmp_lock, 0o600, "temporary lockfile")?;
        if let Err(e) = tmp_file
            .write_all(pid_payload.as_bytes())
            .and_then(|()| tmp_file.sync_all())
        {
            let _ = fs::remove_file(&tmp_lock);
            return Err(CliError::io(
                format!("writing temporary lockfile {}", tmp_lock.display()),
                e,
            ));
        }
        drop(tmp_file);

        for _attempt in 0..3 {
            ensure_no_symlink_ancestors(&lock_path, "provision lockfile")?;
            let link_res = fs::hard_link(&tmp_lock, &lock_path).or_else(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(err)
                } else {
                    // Fallback for filesystems that disallow hard links: exclusive `create_new(true)`
                    let mut options = OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                    }
                    let mut f = options.open(&lock_path)?;
                    f.write_all(pid_payload.as_bytes())?;
                    f.sync_all()
                }
            });

            match link_res {
                Ok(()) => {
                    let _ = fs::remove_file(&tmp_lock);
                    return Ok(Self {
                        lock_path,
                        owner_pid: my_pid,
                        _serialization_guard: serialization_guard,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Err(sym_err) =
                        ensure_no_symlink_ancestors(&lock_path, "provision lockfile")
                    {
                        let _ = fs::remove_file(&tmp_lock);
                        return Err(sym_err);
                    }
                    let raw_pid = fs::read_to_string(&lock_path).unwrap_or_default();
                    if let Ok(existing_pid) = raw_pid.trim().parse::<u32>() {
                        if is_pid_alive(existing_pid) {
                            let _ = fs::remove_file(&tmp_lock);
                            return Err(CliError::PreflightOrIntegrity(format!(
                                "another AetherFlow setup/provision process is running (PID {} in {})",
                                existing_pid,
                                lock_path.display()
                            )));
                        }
                    }
                    // Stale lockfile from crashed/non-running PID or corrupt PID file: remove and retry
                    let _ = fs::remove_file(&lock_path);
                }
                Err(err) => {
                    let _ = fs::remove_file(&tmp_lock);
                    return Err(CliError::io(
                        format!("acquiring lockfile {}", lock_path.display()),
                        err,
                    ));
                }
            }
        }

        let _ = fs::remove_file(&tmp_lock);
        Err(CliError::PreflightOrIntegrity(format!(
            "failed to acquire provisioning lockfile {} due to concurrent contention",
            lock_path.display()
        )))
    }
}

impl Drop for ProvisionLockGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.lock_path) {
            if !meta.file_type().is_symlink() {
                if let Ok(raw) = fs::read_to_string(&self.lock_path) {
                    if raw.trim().parse::<u32>().ok() == Some(self.owner_pid) {
                        let _ = fs::remove_file(&self.lock_path);
                    }
                }
            }
        }
    }
}

pub(super) fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid == 0 {
            return false;
        }
        if pid == std::process::id() {
            return true;
        }
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(stat_raw) = fs::read_to_string(&stat_path) {
            // In `/proc/<pid>/stat`, state character follows the last `)` of `comm`
            if let Some(rparen) = stat_raw.rfind(')') {
                let after = stat_raw[rparen + 1..].trim_start();
                return !(after.starts_with('Z') || after.starts_with('X'));
            }
        }
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if raw_pid <= 0 {
            return false;
        }
        let rc = unsafe { libc::kill(raw_pid, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        pid == std::process::id()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
