//! Safe, WAL-consistent SQLite snapshot capture and integrity verification for `af-host`.
//!
//! # Invariant: Never Plain-Copy a Live SQLite Database
//! Copying a live SQLite database file with `std::fs::copy` or `cp`/`tar` while writers or
//! WAL frames (`-wal` / `-shm`) are active risks torn pages and uncheckpointed transactions.
//!
//! All snapshots in `af-host` are produced exclusively via:
//! 1. `VACUUM INTO '<staging_path>'` inside an exclusive `0700` staging directory on a
//!    busy-timeout-configured SQLite connection, or
//! 2. SQLite's online `rusqlite::backup::Backup` page-copy API into an exclusively created
//!    `0600` staging file, followed by:
//! - Enforcing `0600` file permissions on the staged snapshot before moving out of private staging,
//! - `PRAGMA quick_check` on the resulting snapshot before activation,
//! - Atomic rename into the destination path, and
//! - Immediate `.sha256` sidecar generation after all database handles are closed.

use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::SqliteSnapshotMetadata;
use crate::verify::{
    create_unique_private_staging_dir, create_unique_private_temp_file, ensure_private_dir_all,
    open_existing_regular_file_nofollow, open_verified_regular_file_for_read, reject_if_symlink,
    reject_symlink_chain, set_private_file_permissions, sync_parent_directory,
    validate_no_parent_traversal, validate_relative_backup_path, write_sha256_sidecar,
};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug)]
struct PinnedRegularFile {
    file: File,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

#[derive(Debug)]
struct SqliteVerifiedSourceGuard {
    db_path: PathBuf,
    trusted_source_uid: Option<u32>,
    db_pinned: Option<PinnedRegularFile>,
    wal_pinned: Option<PinnedRegularFile>,
    shm_pinned: Option<PinnedRegularFile>,
    #[cfg(target_os = "linux")]
    pre_open_fds: std::collections::BTreeSet<libc::c_int>,
    #[cfg(target_os = "linux")]
    bound_conn_fd: Option<libc::c_int>,
}

fn verify_sqlite_connection_identity(connection: &Connection, path: &Path) -> HostBackupResult<()> {
    let connection_path = connection
        .path()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: "SQLite connection is not backed by the configured database".to_string(),
        })?;
    let expected = std::path::absolute(path)
        .map_err(|error| HostBackupError::io("resolving configured SQLite path", error))?;
    let actual = std::path::absolute(connection_path)
        .map_err(|error| HostBackupError::io("resolving SQLite connection path", error))?;
    if actual != expected {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: "SQLite connection names a different database".to_string(),
        });
    }
    #[cfg(unix)]
    {
        let mut moved: libc::c_int = 0;
        let result = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
                (&mut moved as *mut libc::c_int).cast(),
            )
        };
        if result != rusqlite::ffi::SQLITE_OK || moved != 0 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "SQLite connection identity could not be verified (VFS result={}, moved={})",
                    result, moved
                ),
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn snapshot_process_fd_numbers() -> std::collections::BTreeSet<libc::c_int> {
    let mut fd_set = std::collections::BTreeSet::new();
    if let Ok(entries) = fs::read_dir("/proc/self/fd") {
        for entry_res in entries.flatten() {
            if let Some(fd_num) = entry_res
                .file_name()
                .to_str()
                .and_then(|name_str| name_str.parse::<libc::c_int>().ok())
            {
                let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd_num, &mut fd_st) } == 0
                    && (fd_st.st_mode & libc::S_IFMT) == libc::S_IFREG
                {
                    fd_set.insert(fd_num);
                }
            }
        }
    }
    fd_set
}

#[cfg(test)]
type PreSqliteConnectHook = Box<dyn Fn(&Path) + Send + Sync>;

#[cfg(test)]
thread_local! {
    static PRE_SQLITE_CONNECT_HOOK: std::cell::RefCell<Option<PreSqliteConnectHook>> = const { std::cell::RefCell::new(None) };
    static POST_SQLITE_CONNECT_HOOK: std::cell::RefCell<Option<PreSqliteConnectHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_post_sqlite_connect_hook(hook: Option<PreSqliteConnectHook>) {
    POST_SQLITE_CONNECT_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(test)]
fn invoke_post_sqlite_connect_hook(path: &Path) {
    POST_SQLITE_CONNECT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow().as_ref() {
            hook(path);
        }
    });
}

#[cfg(test)]
pub(crate) fn set_pre_sqlite_connect_hook(hook: Option<PreSqliteConnectHook>) {
    PRE_SQLITE_CONNECT_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(test)]
fn invoke_pre_sqlite_connect_hook(path: &Path) {
    PRE_SQLITE_CONNECT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow().as_ref() {
            hook(path);
        }
    });
}

impl SqliteVerifiedSourceGuard {
    fn open_single_pinned(
        path: &Path,
        trusted_source_uid: Option<u32>,
        context: &str,
        for_integrity: bool,
    ) -> HostBackupResult<Option<PinnedRegularFile>> {
        let map_snapshot_err = |err: HostBackupError| -> HostBackupError {
            match err {
                HostBackupError::UnsafeOverwriteRejected { reason, .. } => {
                    if for_integrity {
                        HostBackupError::SqliteIntegrity {
                            db_path: path.to_path_buf(),
                            detail: reason,
                        }
                    } else {
                        HostBackupError::SqliteSnapshot {
                            db_path: path.to_path_buf(),
                            reason,
                        }
                    }
                }
                other_err => other_err,
            }
        };

        let opened_opt = if path.is_absolute() {
            open_existing_regular_file_nofollow(path, trusted_source_uid, context)
                .map_err(map_snapshot_err)?
                .map(|(file_handle, _, _, _)| file_handle)
        } else {
            open_verified_regular_file_for_read(path, trusted_source_uid, context)
                .map_err(map_snapshot_err)?
                .map(|(file_handle, _)| file_handle)
        };

        let Some(file_handle) = opened_opt else {
            return Ok(None);
        };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file_handle.as_raw_fd(), &mut st_buf) } != 0 {
                return Err(HostBackupError::io(
                    format!("fstat {} ({})", path.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
            if (st_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(map_snapshot_err(HostBackupError::UnsafeOverwriteRejected {
                    target: path.to_path_buf(),
                    reason: format!("{} is not a regular file", context),
                }));
            }
            if st_buf.st_nlink == 0 {
                return Err(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!("{} was unlinked during open", context),
                });
            }
            if st_buf.st_nlink > 1 {
                return Err(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "{} has multiple hard links (nlink={})",
                        context, st_buf.st_nlink
                    ),
                });
            }
            Ok(Some(PinnedRegularFile {
                file: file_handle,
                dev: st_buf.st_dev as u64,
                ino: st_buf.st_ino as u64,
            }))
        }

        #[cfg(not(unix))]
        {
            let _ = for_integrity;
            Ok(Some(PinnedRegularFile { file: file_handle }))
        }
    }

    fn open_and_pin(
        source_db_path: &Path,
        require_db_exists: bool,
        trusted_source_uid: Option<u32>,
        for_integrity: bool,
    ) -> HostBackupResult<Self> {
        let db_pinned = Self::open_single_pinned(
            source_db_path,
            trusted_source_uid,
            "source SQLite database",
            for_integrity,
        )?;
        if require_db_exists && db_pinned.is_none() {
            if for_integrity {
                return Err(HostBackupError::SqliteIntegrity {
                    db_path: source_db_path.to_path_buf(),
                    detail: "snapshot file does not exist".to_string(),
                });
            }
            return Err(HostBackupError::SqliteSnapshot {
                db_path: source_db_path.to_path_buf(),
                reason: "source SQLite database file does not exist".to_string(),
            });
        }

        let wal_path = PathBuf::from(format!("{}-wal", source_db_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", source_db_path.display()));
        let wal_pinned = Self::open_single_pinned(
            &wal_path,
            trusted_source_uid,
            "source SQLite WAL sidecar",
            for_integrity,
        )?;
        let shm_pinned = Self::open_single_pinned(
            &shm_path,
            trusted_source_uid,
            "source SQLite SHM sidecar",
            for_integrity,
        )?;

        #[cfg(target_os = "linux")]
        let pre_open_fds = snapshot_process_fd_numbers();

        Ok(Self {
            db_path: source_db_path.to_path_buf(),
            trusted_source_uid,
            db_pinned,
            wal_pinned,
            shm_pinned,
            #[cfg(target_os = "linux")]
            pre_open_fds,
            #[cfg(target_os = "linux")]
            bound_conn_fd: None,
        })
    }

    #[cfg(target_os = "linux")]
    fn refresh_pre_open_fds(&mut self) {
        self.pre_open_fds = snapshot_process_fd_numbers();
    }

    #[cfg(not(target_os = "linux"))]
    fn refresh_pre_open_fds(&mut self) {}

    fn bind_opened_connection(
        &mut self,
        conn: &Connection,
        for_integrity: bool,
    ) -> HostBackupResult<()> {
        verify_sqlite_connection_identity(conn, &self.db_path)?;
        let _: i64 = conn
            .query_row("PRAGMA schema_version;", [], |row| row.get(0))
            .map_err(|err| {
                if for_integrity {
                    HostBackupError::SqliteIntegrity {
                        db_path: self.db_path.clone(),
                        detail: format!("failed to read SQLite schema_version: {}", err),
                    }
                } else {
                    HostBackupError::SqliteSnapshot {
                        db_path: self.db_path.clone(),
                        reason: format!("failed to read SQLite schema_version: {}", err),
                    }
                }
            })?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            if let Some(ref pinned_db) = self.db_pinned {
                let guard_db_fd = pinned_db.file.as_raw_fd();
                let guard_wal_fd = self.wal_pinned.as_ref().map(|pin| pin.file.as_raw_fd());
                let guard_shm_fd = self.shm_pinned.as_ref().map(|pin| pin.file.as_raw_fd());
                let wal_str = format!("{}-wal", self.db_path.display());
                let shm_str = format!("{}-shm", self.db_path.display());
                let db_str = self.db_path.to_string_lossy().into_owned();
                let db_parent_str = self
                    .db_path
                    .parent()
                    .map(|parent_dir| parent_dir.to_string_lossy().into_owned())
                    .unwrap_or_default();

                let mut matched_new_fd: Option<libc::c_int> = None;
                let mut reusable_existing_fd: Option<libc::c_int> = None;
                if let Ok(entries) = fs::read_dir("/proc/self/fd") {
                    for entry_res in entries.flatten() {
                        let Some(fd_num) = entry_res
                            .file_name()
                            .to_str()
                            .and_then(|name_str| name_str.parse::<libc::c_int>().ok())
                        else {
                            continue;
                        };
                        if fd_num == guard_db_fd
                            || Some(fd_num) == guard_wal_fd
                            || Some(fd_num) == guard_shm_fd
                        {
                            continue;
                        }
                        let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(fd_num, &mut fd_st) } != 0 {
                            continue;
                        }
                        if (fd_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                            continue;
                        }
                        if let Ok(link_target) = fs::read_link(entry_res.path()) {
                            let target_str = link_target.to_string_lossy();
                            let clean_target =
                                target_str.strip_suffix(" (deleted)").unwrap_or(&target_str);
                            let _ = &db_parent_str;
                            if clean_target == db_str
                                && (fd_st.st_dev as u64 != pinned_db.dev
                                    || fd_st.st_ino as u64 != pinned_db.ino)
                            {
                                return Err(HostBackupError::PathValidation {
                                    path: self.db_path.clone(),
                                    reason: "newly opened SQLite connection descriptor points to substituted database inode".to_string(),
                                });
                            }
                            if clean_target == wal_str {
                                if let Some(ref pinned_wal) = self.wal_pinned {
                                    if fd_st.st_dev as u64 != pinned_wal.dev
                                        || fd_st.st_ino as u64 != pinned_wal.ino
                                    {
                                        return Err(HostBackupError::PathValidation {
                                            path: PathBuf::from(&wal_str),
                                            reason: "newly opened SQLite WAL descriptor does not match authenticated no-follow WAL inode".to_string(),
                                        });
                                    }
                                }
                            } else if clean_target == shm_str {
                                if let Some(ref pinned_shm) = self.shm_pinned {
                                    if fd_st.st_dev as u64 != pinned_shm.dev
                                        || fd_st.st_ino as u64 != pinned_shm.ino
                                    {
                                        return Err(HostBackupError::PathValidation {
                                            path: PathBuf::from(&shm_str),
                                            reason: "newly opened SQLite SHM descriptor does not match authenticated no-follow SHM inode".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                        if self.pre_open_fds.contains(&fd_num) {
                            if fd_st.st_dev as u64 == pinned_db.dev
                                && fd_st.st_ino as u64 == pinned_db.ino
                                && fd_st.st_nlink == 1
                            {
                                reusable_existing_fd = Some(fd_num);
                            }
                            continue;
                        }
                        if fd_st.st_dev as u64 == pinned_db.dev
                            && fd_st.st_ino as u64 == pinned_db.ino
                        {
                            matched_new_fd = Some(fd_num);
                        }
                    }
                }
                let Some(bound_fd) = matched_new_fd.or(reusable_existing_fd) else {
                    return Err(HostBackupError::PathValidation {
                        path: self.db_path.clone(),
                        reason: "newly opened SQLite connection descriptor does not match authenticated no-follow database inode".to_string(),
                    });
                };
                self.bound_conn_fd = Some(bound_fd);
            }
        }
        Ok(())
    }

    fn verify_unchanged_and_consistent(
        &mut self,
        require_db_exists: bool,
        require_process_conn_fd: bool,
        for_integrity: bool,
    ) -> HostBackupResult<()> {
        let current_db = Self::open_single_pinned(
            &self.db_path,
            self.trusted_source_uid,
            "source SQLite database",
            for_integrity,
        )?;
        match (&self.db_pinned, current_db) {
            (Some(prev_db), Some(curr_db)) => {
                #[cfg(unix)]
                if prev_db.dev != curr_db.dev || prev_db.ino != curr_db.ino {
                    return Err(HostBackupError::PathValidation {
                        path: self.db_path.clone(),
                        reason:
                            "SQLite database inode was substituted during snapshot/verification"
                                .to_string(),
                    });
                }
                #[cfg(not(unix))]
                let _ = (prev_db, curr_db);
            }
            (Some(_), None) => {
                return Err(HostBackupError::PathValidation {
                    path: self.db_path.clone(),
                    reason: "SQLite database file disappeared during snapshot/verification"
                        .to_string(),
                });
            }
            (None, Some(curr_db)) => {
                self.db_pinned = Some(curr_db);
            }
            (None, None) => {
                if require_db_exists {
                    return Err(HostBackupError::SqliteSnapshot {
                        db_path: self.db_path.clone(),
                        reason: "source SQLite database file does not exist".to_string(),
                    });
                }
            }
        }

        let wal_path = PathBuf::from(format!("{}-wal", self.db_path.display()));
        let current_wal = Self::open_single_pinned(
            &wal_path,
            self.trusted_source_uid,
            "source SQLite WAL sidecar",
            for_integrity,
        )?;
        match (&self.wal_pinned, current_wal) {
            (Some(prev_wal), Some(curr_wal)) => {
                #[cfg(unix)]
                if prev_wal.dev != curr_wal.dev || prev_wal.ino != curr_wal.ino {
                    return Err(HostBackupError::PathValidation {
                        path: wal_path,
                        reason:
                            "SQLite WAL sidecar inode was substituted during snapshot/verification"
                                .to_string(),
                    });
                }
                #[cfg(not(unix))]
                let _ = (prev_wal, curr_wal);
            }
            (None, Some(curr_wal)) => {
                self.wal_pinned = Some(curr_wal);
            }
            (_, None) => {}
        }

        let shm_path = PathBuf::from(format!("{}-shm", self.db_path.display()));
        let current_shm = Self::open_single_pinned(
            &shm_path,
            self.trusted_source_uid,
            "source SQLite SHM sidecar",
            for_integrity,
        )?;
        match (&self.shm_pinned, current_shm) {
            (Some(prev_shm), Some(curr_shm)) => {
                #[cfg(unix)]
                if prev_shm.dev != curr_shm.dev || prev_shm.ino != curr_shm.ino {
                    return Err(HostBackupError::PathValidation {
                        path: shm_path,
                        reason:
                            "SQLite SHM sidecar inode was substituted during snapshot/verification"
                                .to_string(),
                    });
                }
                #[cfg(not(unix))]
                let _ = (prev_shm, curr_shm);
            }
            (None, Some(curr_shm)) => {
                self.shm_pinned = Some(curr_shm);
            }
            (_, None) => {}
        }

        #[cfg(target_os = "linux")]
        if require_process_conn_fd {
            use std::os::unix::io::AsRawFd;
            if let Some(ref pinned_db) = self.db_pinned {
                if let Some(bound_fd) = self.bound_conn_fd {
                    let mut bound_st: libc::stat = unsafe { std::mem::zeroed() };
                    if unsafe { libc::fstat(bound_fd, &mut bound_st) } != 0
                        || bound_st.st_dev as u64 != pinned_db.dev
                        || bound_st.st_ino as u64 != pinned_db.ino
                        || bound_st.st_nlink != 1
                    {
                        return Err(HostBackupError::PathValidation {
                            path: self.db_path.clone(),
                            reason: "bound SQLite connection descriptor no longer matches authenticated no-follow database inode".to_string(),
                        });
                    }
                }
                let guard_db_fd = pinned_db.file.as_raw_fd();
                let guard_wal_fd = self.wal_pinned.as_ref().map(|pin| pin.file.as_raw_fd());
                let guard_shm_fd = self.shm_pinned.as_ref().map(|pin| pin.file.as_raw_fd());
                let wal_str = format!("{}-wal", self.db_path.display());
                let shm_str = format!("{}-shm", self.db_path.display());
                let mut found_conn_db_fd = self.bound_conn_fd.is_some();
                if let Ok(entries) = fs::read_dir("/proc/self/fd") {
                    for entry_res in entries.flatten() {
                        let Some(fd_num) = entry_res
                            .file_name()
                            .to_str()
                            .and_then(|name_str| name_str.parse::<libc::c_int>().ok())
                        else {
                            continue;
                        };
                        if fd_num == guard_db_fd
                            || Some(fd_num) == guard_wal_fd
                            || Some(fd_num) == guard_shm_fd
                        {
                            continue;
                        }
                        let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(fd_num, &mut fd_st) } == 0 {
                            if self.bound_conn_fd.is_none()
                                && fd_st.st_dev as u64 == pinned_db.dev
                                && fd_st.st_ino as u64 == pinned_db.ino
                            {
                                found_conn_db_fd = true;
                            }
                            if let Ok(link_target) = fs::read_link(entry_res.path()) {
                                let target_str = link_target.to_string_lossy();
                                let clean_target =
                                    target_str.strip_suffix(" (deleted)").unwrap_or(&target_str);
                                if clean_target == wal_str {
                                    if let Some(ref pinned_wal) = self.wal_pinned {
                                        if fd_st.st_dev as u64 != pinned_wal.dev
                                            || fd_st.st_ino as u64 != pinned_wal.ino
                                        {
                                            return Err(HostBackupError::PathValidation {
                                                path: PathBuf::from(&wal_str),
                                                reason: "open SQLite WAL descriptor does not match authenticated no-follow WAL inode".to_string(),
                                            });
                                        }
                                    }
                                } else if clean_target == shm_str {
                                    if let Some(ref pinned_shm) = self.shm_pinned {
                                        if fd_st.st_dev as u64 != pinned_shm.dev
                                            || fd_st.st_ino as u64 != pinned_shm.ino
                                        {
                                            return Err(HostBackupError::PathValidation {
                                                path: PathBuf::from(&shm_str),
                                                reason: "open SQLite SHM descriptor does not match authenticated no-follow SHM inode".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !found_conn_db_fd {
                    return Err(HostBackupError::PathValidation {
                        path: self.db_path.clone(),
                        reason: "open SQLite connection descriptor does not match authenticated no-follow database inode".to_string(),
                    });
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = require_process_conn_fd;

        Ok(())
    }
}

/// Strategy used to capture a consistent SQLite snapshot without plain file copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMethod {
    /// Uses SQLite `VACUUM INTO '<path>'` to produce a defragmented, standalone, WAL-consistent database.
    #[default]
    VacuumInto,
    /// Uses SQLite's Online Backup API (`sqlite3_backup_init` / `rusqlite::backup::Backup`).
    OnlineBackupApi,
}

impl SnapshotMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            SnapshotMethod::VacuumInto => "vacuum_into",
            SnapshotMethod::OnlineBackupApi => "online_backup_api",
        }
    }
}

/// Configuration options for capturing a consistent SQLite snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotOptions {
    /// Snapshot capture mechanism (`VacuumInto` by default).
    pub method: SnapshotMethod,
    /// Busy timeout waiting for concurrent writers/locks on the source database (`30s` default).
    pub busy_timeout: Duration,
    /// Pages copied per step when using `OnlineBackupApi` (`256` default).
    pub pages_per_step: i32,
    /// Pause between step batches when using `OnlineBackupApi` (`10ms` default).
    pub step_pause: Duration,
    /// Optional caller-configured trusted owner UID for custom database/sidecar paths.
    #[serde(default)]
    pub trusted_source_uid: Option<u32>,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            method: SnapshotMethod::VacuumInto,
            busy_timeout: Duration::from_secs(30),
            pages_per_step: 256,
            step_pause: Duration::from_millis(10),
            trusted_source_uid: None,
        }
    }
}

/// Completed, integrity-verified SQLite snapshot artifact and its `.sha256` sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteSnapshotReceipt {
    pub source_db_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub sidecar_path: PathBuf,
    pub metadata: SqliteSnapshotMetadata,
}

/// Captures a WAL-consistent snapshot of an open [`rusqlite::Connection`] into `dest_path`
/// using `VACUUM INTO` inside an exclusive `0700` staging directory, sets `0600` permissions,
/// verifies `PRAGMA quick_check` on the snapshot, atomically activates `dest_path`, and writes
/// `<dest_path>.sha256`.
///
/// Callers holding a pooled connection (`max_size(1)` in `af-db`) can pass `&conn` directly
/// so no second pool checkout is attempted.
pub fn snapshot_sqlite_with_conn(
    source_conn: &Connection,
    source_label_path: &Path,
    dest_path: &Path,
    relative_manifest_path: &str,
    busy_timeout: Duration,
) -> HostBackupResult<SqliteSnapshotReceipt> {
    snapshot_sqlite_with_conn_and_trusted_uid(
        source_conn,
        source_label_path,
        dest_path,
        relative_manifest_path,
        busy_timeout,
        None,
    )
}

/// Variant of [`snapshot_sqlite_with_conn`] that accepts an explicit caller-configured
/// `trusted_source_uid` for custom SQLite source and WAL/SHM sidecar ownership validation.
pub fn snapshot_sqlite_with_conn_and_trusted_uid(
    source_conn: &Connection,
    source_label_path: &Path,
    dest_path: &Path,
    relative_manifest_path: &str,
    busy_timeout: Duration,
    trusted_source_uid: Option<u32>,
) -> HostBackupResult<SqliteSnapshotReceipt> {
    let _ = validate_relative_backup_path(relative_manifest_path)?;
    validate_no_parent_traversal(source_label_path, "source SQLite database path")?;
    reject_if_symlink(source_label_path, "source SQLite database")?;
    let conn_has_disk_path = source_conn
        .path()
        .map(|conn_path| !conn_path.is_empty())
        .unwrap_or(false);
    if conn_has_disk_path {
        verify_sqlite_connection_identity(source_conn, source_label_path)?;
    }
    let mut source_guard = if source_label_path
        .parent()
        .is_some_and(|parent_dir| !parent_dir.as_os_str().is_empty())
    {
        let mut guard = SqliteVerifiedSourceGuard::open_and_pin(
            source_label_path,
            conn_has_disk_path,
            trusted_source_uid,
            false,
        )?;
        let has_on_disk_db = conn_has_disk_path || guard.db_pinned.is_some();
        if has_on_disk_db {
            let _: i64 = source_conn
                .query_row("PRAGMA schema_version;", [], |row| row.get(0))
                .map_err(|err| HostBackupError::SqliteSnapshot {
                    db_path: source_label_path.to_path_buf(),
                    reason: format!("failed to read SQLite schema_version: {}", err),
                })?;
        }
        guard.verify_unchanged_and_consistent(conn_has_disk_path, has_on_disk_db, false)?;
        Some(guard)
    } else {
        None
    };

    validate_no_parent_traversal(dest_path, "snapshot destination path")?;
    reject_if_symlink(dest_path, "snapshot destination path")?;

    let parent = dest_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest_path.to_path_buf(),
            reason: "snapshot destination path must have a parent directory".to_string(),
        })?;
    if !parent.as_os_str().is_empty() {
        ensure_private_dir_all(parent, "snapshot destination directory")?;
        reject_symlink_chain(parent, dest_path)?;
    }

    let _ = source_conn.busy_timeout(busy_timeout);

    let staging_dir =
        create_unique_private_staging_dir(parent, "vacuum", "SQLite VACUUM INTO staging dir")?;
    let base_name = dest_path
        .file_name()
        .and_then(|file_str| file_str.to_str())
        .unwrap_or("snapshot.sqlite");
    let staging_path = staging_dir.join(format!(
        "{}.vacuum.{}.{}",
        base_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let vacuum_res: HostBackupResult<SqliteSnapshotReceipt> = (|| {
        reject_symlink_chain(&staging_dir, &staging_path)?;
        let escaped_staging = staging_path.to_string_lossy().replace('\'', "''");
        source_conn
            .execute_batch(&format!("VACUUM INTO '{}';", escaped_staging))
            .map_err(|err| HostBackupError::SqliteSnapshot {
                db_path: source_label_path.to_path_buf(),
                reason: format!("VACUUM INTO failed: {}", err),
            })?;

        if let Some(ref mut guard) = source_guard {
            if conn_has_disk_path {
                verify_sqlite_connection_identity(source_conn, source_label_path)?;
            }
            let has_on_disk_db = conn_has_disk_path || guard.db_pinned.is_some();
            guard.verify_unchanged_and_consistent(conn_has_disk_path, has_on_disk_db, false)?;
        }

        set_private_file_permissions(&staging_path, "staged SQLite VACUUM INTO snapshot")?;

        finalize_staged_snapshot(
            source_label_path,
            &staging_path,
            dest_path,
            relative_manifest_path,
            SnapshotMethod::VacuumInto,
        )
    })();

    drop(source_guard);
    let _ = fs::remove_file(&staging_path);
    let _ = fs::remove_dir_all(&staging_dir);
    vacuum_res
}

/// Captures a WAL-consistent snapshot from `source_db_path` on disk into `dest_path`
/// without ever performing a raw filesystem copy of the live database.
pub fn snapshot_sqlite_database(
    source_db_path: &Path,
    dest_path: &Path,
    relative_manifest_path: &str,
    options: &SnapshotOptions,
) -> HostBackupResult<SqliteSnapshotReceipt> {
    let _ = validate_relative_backup_path(relative_manifest_path)?;
    validate_no_parent_traversal(source_db_path, "source SQLite database path")?;
    validate_no_parent_traversal(dest_path, "snapshot destination path")?;
    reject_if_symlink(source_db_path, "source SQLite database")?;
    reject_if_symlink(dest_path, "snapshot destination")?;

    let mut source_guard = SqliteVerifiedSourceGuard::open_and_pin(
        source_db_path,
        true,
        options.trusted_source_uid,
        false,
    )?;

    if source_db_path == dest_path {
        return Err(HostBackupError::SqliteSnapshot {
            db_path: source_db_path.to_path_buf(),
            reason: "source and destination SQLite paths must not be identical".to_string(),
        });
    }

    let parent = dest_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest_path.to_path_buf(),
            reason: "snapshot destination path must have a parent directory".to_string(),
        })?;
    if !parent.as_os_str().is_empty() {
        ensure_private_dir_all(parent, "snapshot destination directory")?;
        reject_symlink_chain(parent, dest_path)?;
    }

    source_guard.refresh_pre_open_fds();
    #[cfg(test)]
    invoke_pre_sqlite_connect_hook(source_db_path);

    let src_conn = Connection::open_with_flags(
        source_db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .or_else(|_| {
        Connection::open_with_flags(
            source_db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
    })
    .map_err(|err| HostBackupError::SqliteSnapshot {
        db_path: source_db_path.to_path_buf(),
        reason: format!("failed to open source database: {}", err),
    })?;

    #[cfg(test)]
    invoke_post_sqlite_connect_hook(source_db_path);

    src_conn
        .busy_timeout(options.busy_timeout)
        .map_err(|err| HostBackupError::SqliteSnapshot {
            db_path: source_db_path.to_path_buf(),
            reason: format!("failed to configure busy_timeout: {}", err),
        })?;

    source_guard.bind_opened_connection(&src_conn, false)?;
    source_guard.verify_unchanged_and_consistent(true, true, false)?;

    match options.method {
        SnapshotMethod::VacuumInto => {
            let receipt = snapshot_sqlite_with_conn_and_trusted_uid(
                &src_conn,
                source_db_path,
                dest_path,
                relative_manifest_path,
                options.busy_timeout,
                options.trusted_source_uid,
            );
            let verify_res = verify_sqlite_connection_identity(&src_conn, source_db_path)
                .and_then(|()| source_guard.verify_unchanged_and_consistent(true, true, false));
            drop(src_conn);
            drop(source_guard);
            verify_res?;
            receipt
        }
        SnapshotMethod::OnlineBackupApi => {
            let (staging_path, staging_file) = create_unique_private_temp_file(
                dest_path,
                "sqlite-staging",
                "temporary snapshot staging file",
            )?;
            drop(staging_file);

            let backup_res: HostBackupResult<()> = (|| {
                let mut dst_conn = Connection::open_with_flags(
                    &staging_path,
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_CREATE
                        | OpenFlags::SQLITE_OPEN_NO_MUTEX
                        | OpenFlags::SQLITE_OPEN_NOFOLLOW,
                )
                .map_err(|open_err| HostBackupError::SqliteSnapshot {
                    db_path: staging_path.clone(),
                    reason: format!("failed to open staging database: {}", open_err),
                })?;
                let _ = dst_conn.busy_timeout(options.busy_timeout);
                {
                    let backup = Backup::new(&src_conn, &mut dst_conn).map_err(|init_err| {
                        HostBackupError::SqliteSnapshot {
                            db_path: source_db_path.to_path_buf(),
                            reason: format!("sqlite3_backup_init failed: {}", init_err),
                        }
                    })?;
                    let pages = options.pages_per_step.max(1);
                    backup
                        .run_to_completion(pages, options.step_pause, None)
                        .map_err(|step_err| HostBackupError::SqliteSnapshot {
                            db_path: source_db_path.to_path_buf(),
                            reason: format!("online backup page transfer failed: {}", step_err),
                        })?;
                }
                let _ = dst_conn.execute_batch(
                    "PRAGMA journal_mode = DELETE; PRAGMA wal_checkpoint(TRUNCATE);",
                );
                verify_sqlite_connection_identity(&src_conn, source_db_path)?;
                source_guard.verify_unchanged_and_consistent(true, true, false)?;
                Ok(())
            })();
            drop(src_conn);
            drop(source_guard);

            if let Err(err) = backup_res {
                let _ = fs::remove_file(&staging_path);
                return Err(err);
            }

            if let Err(err) =
                set_private_file_permissions(&staging_path, "staged OnlineBackupApi snapshot")
            {
                let _ = fs::remove_file(&staging_path);
                return Err(err);
            }

            finalize_staged_snapshot(
                source_db_path,
                &staging_path,
                dest_path,
                relative_manifest_path,
                SnapshotMethod::OnlineBackupApi,
            )
        }
    }
}

/// Runs `PRAGMA quick_check`, queries `user_version` and `journal_mode` on a standalone
/// SQLite snapshot file, and returns `(user_version, journal_mode, integrity_result)`.
pub fn verify_sqlite_snapshot_integrity(
    snapshot_path: &Path,
) -> HostBackupResult<(i64, String, String)> {
    verify_sqlite_snapshot_integrity_with_trusted_uid(snapshot_path, None)
}

/// Variant of [`verify_sqlite_snapshot_integrity`] that accepts an explicit caller-configured
/// `trusted_source_uid` and enforces that a standalone snapshot file has no unverified `-wal`/`-shm` sidecars.
pub fn verify_sqlite_snapshot_integrity_with_trusted_uid(
    snapshot_path: &Path,
    trusted_source_uid: Option<u32>,
) -> HostBackupResult<(i64, String, String)> {
    validate_no_parent_traversal(snapshot_path, "SQLite snapshot file")?;
    reject_if_symlink(snapshot_path, "SQLite snapshot file")?;

    let mut snapshot_guard =
        SqliteVerifiedSourceGuard::open_and_pin(snapshot_path, true, trusted_source_uid, true)?;
    if snapshot_guard.wal_pinned.is_some() || snapshot_guard.shm_pinned.is_some() {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: "standalone SQLite snapshot must not have active WAL or SHM sidecar files"
                .to_string(),
        });
    }

    snapshot_guard.refresh_pre_open_fds();
    #[cfg(test)]
    invoke_pre_sqlite_connect_hook(snapshot_path);

    let conn = Connection::open_with_flags(
        snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|open_err| HostBackupError::SqliteIntegrity {
        db_path: snapshot_path.to_path_buf(),
        detail: format!("failed to open snapshot for verification: {}", open_err),
    })?;

    snapshot_guard.bind_opened_connection(&conn, true)?;
    verify_sqlite_connection_identity(&conn, snapshot_path)?;
    snapshot_guard.verify_unchanged_and_consistent(true, true, true)?;
    if snapshot_guard.wal_pinned.is_some() || snapshot_guard.shm_pinned.is_some() {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail:
                "unexpected WAL or SHM sidecar appeared during standalone snapshot verification"
                    .to_string(),
        });
    }

    let quick_check: String = conn
        .query_row("PRAGMA quick_check;", [], |row| row.get(0))
        .map_err(|query_err| HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: format!("PRAGMA quick_check query failed: {}", query_err),
        })?;

    if !quick_check.eq_ignore_ascii_case("ok") {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: quick_check,
        });
    }

    let full_integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
        .map_err(|query_err| HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: format!("PRAGMA integrity_check query failed: {}", query_err),
        })?;

    if !full_integrity.eq_ignore_ascii_case("ok") {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: full_integrity,
        });
    }

    let user_version: i64 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .unwrap_or(0);
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .unwrap_or_else(|_| "delete".to_string());

    snapshot_guard.verify_unchanged_and_consistent(true, true, true)?;
    if snapshot_guard.wal_pinned.is_some() || snapshot_guard.shm_pinned.is_some() {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail:
                "unexpected WAL or SHM sidecar appeared during standalone snapshot verification"
                    .to_string(),
        });
    }
    drop(conn);
    drop(snapshot_guard);

    Ok((user_version, journal_mode, quick_check))
}

fn finalize_staged_snapshot(
    source_db_path: &Path,
    staging_path: &Path,
    dest_path: &Path,
    relative_manifest_path: &str,
    method: SnapshotMethod,
) -> HostBackupResult<SqliteSnapshotReceipt> {
    let (user_version, journal_mode, integrity_check) =
        match verify_sqlite_snapshot_integrity(staging_path) {
            Ok(res) => res,
            Err(err) => {
                let _ = fs::remove_file(staging_path);
                return Err(err);
            }
        };

    if let Err(err) = set_private_file_permissions(staging_path, "verified staged SQLite snapshot")
    {
        let _ = fs::remove_file(staging_path);
        return Err(err);
    }

    if let Err(err) = reject_if_symlink(dest_path, "snapshot destination") {
        let _ = fs::remove_file(staging_path);
        return Err(err);
    }

    if let Err(rename_err) = fs::rename(staging_path, dest_path) {
        let _ = fs::remove_file(staging_path);
        return Err(HostBackupError::io(
            format!(
                "activating staged SQLite snapshot {} -> {}",
                staging_path.display(),
                dest_path.display()
            ),
            rename_err,
        ));
    }

    if let Some(dest_parent) = dest_path.parent() {
        sync_parent_directory(dest_parent, "activating staged SQLite snapshot")?;
    }

    let (sidecar_path, sha256, size_bytes) = write_sha256_sidecar(dest_path)?;

    let metadata = SqliteSnapshotMetadata {
        snapshot_relative_path: relative_manifest_path.to_string(),
        capture_method: method.as_str().to_string(),
        sqlite_user_version: user_version,
        journal_mode,
        integrity_check,
        size_bytes,
        sha256,
    };

    Ok(SqliteSnapshotReceipt {
        source_db_path: source_db_path.to_path_buf(),
        snapshot_path: dest_path.to_path_buf(),
        sidecar_path,
        metadata,
    })
}
