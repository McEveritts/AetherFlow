//! Release serialization and locking (`flock` on Unix + cross-platform lockfile guard)
//! and persistent crash-recovery journal (`.recovery_state.json`).

use crate::config::{ReleaseChannel, ReleaseCommand};
use crate::error::{ReleaseError, ReleaseResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Exclusive file-backed lock guard preventing concurrent `deploy`, `rollback`, `cleanup`,
/// or `migrate-systemd` operations from colliding on `/opt/AetherFlow/releases` or SQLite snapshots.
#[derive(Debug)]
pub struct ReleaseLockGuard {
    lock_path: PathBuf,
    _file: File,
}

impl ReleaseLockGuard {
    pub fn acquire(lock_path: impl AsRef<Path>, timeout: Duration) -> ReleaseResult<Self> {
        let path = lock_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::fs_security::create_dir_all_no_symlinks(parent, 0o750)?;
            }
        }

        let start = Instant::now();
        loop {
            match Self::try_acquire_once(&path) {
                Ok(guard) => return Ok(guard),
                Err(reason) => {
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

    #[cfg(unix)]
    fn try_acquire_once(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o660)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| format!("failed to open lockfile: {}", err))?;

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("flock(LOCK_EX | LOCK_NB) busy: {}", err));
        }

        let _ = file.set_len(0);
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        Ok(Self {
            lock_path: path.to_path_buf(),
            _file: file,
        })
    }

    #[cfg(not(unix))]
    fn try_acquire_once(path: &Path) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("lockfile already held: {}", e))?;

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

impl Drop for ReleaseLockGuard {
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

    /// Returns `true` if this recovery state indicates a previous deployment already swapped `current`
    /// (or entered Stage 3 / Stage 4) without completing cleanly, meaning `current` may point to an
    /// unhealthy candidate release while `.previous_release` holds the last known-good release.
    pub fn has_unhealthy_or_interrupted_post_swap_deploy(&self) -> bool {
        self.command == ReleaseCommand::Deploy
            && !self.dry_run
            && matches!(
                self.phase,
                ReleasePhase::Stage2SymlinkSwap
                    | ReleasePhase::Stage3HealthProbe
                    | ReleasePhase::Stage4Rollback
            )
    }

    /// Atomically persists the recovery state to `${RELEASES_DIR}/.recovery_state.json`
    /// using a globally unique (`UUIDv4` + PID) exclusive (`create_new`) temporary file
    /// created with `0600` permissions before writing, `sync_all()`, and atomic `fs::rename`.
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
        let path = Self::state_file_path(releases_dir);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(ReleaseError::PathValidation {
                    path,
                    reason: "refusing to read symlinked .recovery_state.json".to_string(),
                });
            }
        } else {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)
            .map_err(|e| ReleaseError::io(format!("reading {}", path.display()), e))?;
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
