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
    reject_if_symlink, reject_symlink_chain, set_private_file_permissions,
    validate_no_parent_traversal, validate_relative_backup_path, write_sha256_sidecar,
};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            method: SnapshotMethod::VacuumInto,
            busy_timeout: Duration::from_secs(30),
            pages_per_step: 256,
            step_pause: Duration::from_millis(10),
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
    let _ = validate_relative_backup_path(relative_manifest_path)?;
    validate_no_parent_traversal(source_label_path, "source SQLite database path")?;
    reject_if_symlink(source_label_path, "source SQLite database")?;
    validate_no_parent_traversal(dest_path, "snapshot destination path")?;
    reject_if_symlink(dest_path, "snapshot destination path")?;

    let parent = dest_path.parent().ok_or_else(|| HostBackupError::PathValidation {
        path: dest_path.to_path_buf(),
        reason: "snapshot destination path must have a parent directory".to_string(),
    })?;
    if !parent.as_os_str().is_empty() {
        ensure_private_dir_all(parent, "snapshot destination directory")?;
        reject_symlink_chain(parent, dest_path)?;
    }

    let _ = source_conn.busy_timeout(busy_timeout);

    // Because SQLite `VACUUM INTO` requires its target file not to exist yet and creates it
    // using process umask, execute `VACUUM INTO` inside a freshly created `0700` private
    // staging subdirectory and tighten the resulting snapshot file to `0600` before moving.
    let staging_dir =
        create_unique_private_staging_dir(parent, "vacuum", "SQLite VACUUM INTO staging dir")?;
    let base_name = dest_path
        .file_name()
        .and_then(|s| s.to_str())
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
            .map_err(|e| HostBackupError::SqliteSnapshot {
                db_path: source_label_path.to_path_buf(),
                reason: format!("VACUUM INTO failed: {}", e),
            })?;

        set_private_file_permissions(&staging_path, "staged SQLite VACUUM INTO snapshot")?;

        finalize_staged_snapshot(
            source_label_path,
            &staging_path,
            dest_path,
            relative_manifest_path,
            SnapshotMethod::VacuumInto,
        )
    })();

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

    let src_meta = match fs::symlink_metadata(source_db_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostBackupError::SqliteSnapshot {
                db_path: source_db_path.to_path_buf(),
                reason: "source SQLite database file does not exist".to_string(),
            });
        }
        Err(e) => {
            return Err(HostBackupError::io(
                format!("stat source SQLite database {}", source_db_path.display()),
                e,
            ));
        }
    };
    if src_meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: source_db_path.to_path_buf(),
            reason: "source SQLite database is a symbolic link".to_string(),
        });
    }
    if !src_meta.is_file() {
        return Err(HostBackupError::SqliteSnapshot {
            db_path: source_db_path.to_path_buf(),
            reason: "source SQLite database path is not a regular file".to_string(),
        });
    }

    if source_db_path == dest_path {
        return Err(HostBackupError::SqliteSnapshot {
            db_path: source_db_path.to_path_buf(),
            reason: "source and destination SQLite paths must not be identical".to_string(),
        });
    }

    let parent = dest_path.parent().ok_or_else(|| HostBackupError::PathValidation {
        path: dest_path.to_path_buf(),
        reason: "snapshot destination path must have a parent directory".to_string(),
    })?;
    if !parent.as_os_str().is_empty() {
        ensure_private_dir_all(parent, "snapshot destination directory")?;
        reject_symlink_chain(parent, dest_path)?;
    }

    let src_conn = Connection::open_with_flags(
        source_db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .or_else(|_| {
        Connection::open_with_flags(
            source_db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    })
    .map_err(|e| HostBackupError::SqliteSnapshot {
        db_path: source_db_path.to_path_buf(),
        reason: format!("failed to open source database: {}", e),
    })?;

    src_conn
        .busy_timeout(options.busy_timeout)
        .map_err(|e| HostBackupError::SqliteSnapshot {
            db_path: source_db_path.to_path_buf(),
            reason: format!("failed to configure busy_timeout: {}", e),
        })?;

    match options.method {
        SnapshotMethod::VacuumInto => {
            let receipt = snapshot_sqlite_with_conn(
                &src_conn,
                source_db_path,
                dest_path,
                relative_manifest_path,
                options.busy_timeout,
            );
            drop(src_conn);
            receipt
        }
        SnapshotMethod::OnlineBackupApi => {
            // Exclusively create the staging file with 0600 permissions BEFORE SQLite writes pages to it
            let (staging_path, staging_file) = create_unique_private_temp_file(
                dest_path,
                "sqlite-staging",
                "temporary snapshot staging file",
            )?;
            drop(staging_file);

            let backup_res: HostBackupResult<()> = (|| {
                let mut dst_conn = Connection::open(&staging_path).map_err(|e| {
                    HostBackupError::SqliteSnapshot {
                        db_path: staging_path.clone(),
                        reason: format!("failed to open staging database: {}", e),
                    }
                })?;
                let _ = dst_conn.busy_timeout(options.busy_timeout);
                {
                    let backup = Backup::new(&src_conn, &mut dst_conn).map_err(|e| {
                        HostBackupError::SqliteSnapshot {
                            db_path: source_db_path.to_path_buf(),
                            reason: format!("sqlite3_backup_init failed: {}", e),
                        }
                    })?;
                    let pages = options.pages_per_step.max(1);
                    backup
                        .run_to_completion(pages, options.step_pause, None)
                        .map_err(|e| HostBackupError::SqliteSnapshot {
                            db_path: source_db_path.to_path_buf(),
                            reason: format!("online backup page transfer failed: {}", e),
                        })?;
                }
                Ok(())
            })();
            drop(src_conn);

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
    validate_no_parent_traversal(snapshot_path, "SQLite snapshot file")?;
    reject_if_symlink(snapshot_path, "SQLite snapshot file")?;
    let meta = match fs::symlink_metadata(snapshot_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostBackupError::SqliteIntegrity {
                db_path: snapshot_path.to_path_buf(),
                detail: "snapshot file does not exist".to_string(),
            });
        }
        Err(e) => {
            return Err(HostBackupError::io(
                format!("stat SQLite snapshot {}", snapshot_path.display()),
                e,
            ));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: snapshot_path.to_path_buf(),
            reason: "SQLite snapshot file is a symbolic link".to_string(),
        });
    }
    if !meta.is_file() {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: "snapshot path is not a regular file".to_string(),
        });
    }

    let conn = Connection::open_with_flags(
        snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| HostBackupError::SqliteIntegrity {
        db_path: snapshot_path.to_path_buf(),
        detail: format!("failed to open snapshot for verification: {}", e),
    })?;

    let quick_check: String = conn
        .query_row("PRAGMA quick_check;", [], |r| r.get(0))
        .map_err(|e| HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: format!("PRAGMA quick_check query failed: {}", e),
        })?;

    if !quick_check.eq_ignore_ascii_case("ok") {
        return Err(HostBackupError::SqliteIntegrity {
            db_path: snapshot_path.to_path_buf(),
            detail: quick_check,
        });
    }

    let user_version: i64 = conn
        .query_row("PRAGMA user_version;", [], |r| r.get(0))
        .unwrap_or(0);
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .unwrap_or_else(|_| "delete".to_string());

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
