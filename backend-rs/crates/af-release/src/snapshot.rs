//! Stage 1.5 & Stage 4: WAL-safe online SQLite backups (`rusqlite::backup::Backup`),
//! `PRAGMA integrity_check` verification, `MANIFEST.sha256` generation, and corruption recovery.

use crate::artifact::{compute_file_sha256, parse_sha256_manifest};
use crate::config::{ReleaseConfig, ResolvedDbPath};
use crate::error::{ReleaseError, ReleaseResult};
use crate::fs_security::{
    apply_service_ownership, atomic_copy_file_with_mode, atomic_write_bytes_with_mode,
    create_dir_all_no_symlinks, ensure_no_symlink_ancestors, open_exclusive_private_file,
    sync_parent_dir_best_effort, OwnershipMetadata,
};
use crate::lock::ReleaseLockGuard;
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Outcome of Stage 1.5 State Snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReport {
    /// Whether a snapshot file was actually written (`false` when no live DB exists on a real deploy).
    pub created: bool,
    /// Path to the source SQLite database that was backed up.
    pub source_db: PathBuf,
    /// Path to the `.bak` snapshot inside `${RELEASE_DIR}/data-snapshot/`.
    pub backup_path: Option<PathBuf>,
    /// Path to `${RELEASE_DIR}/data-snapshot/MANIFEST.sha256`.
    pub manifest_path: Option<PathBuf>,
    /// Lowercase SHA-256 digest of the `.bak` snapshot.
    pub sha256: Option<String>,
}

/// Executes a WAL-safe online SQLite backup from `src` (opened read-only so a hot WAL is never
/// checkpointed by a dry-run or snapshot) into `dest` using SQLite's online backup API.
///
/// Writes into a fresh exclusive sibling temporary file created with `0600` permissions **before**
/// any database pages are copied, verifies `sync_all()`, removes any destination `-wal`/`-shm`
/// sidecars, and atomically renames the temporary file to `dest`.
pub fn sqlite_online_backup(src: &Path, dest: &Path) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(src)?;
    ensure_no_symlink_ancestors(dest)?;

    if !src.is_file() {
        return Err(ReleaseError::Snapshot {
            db_path: src.to_path_buf(),
            reason: "source database file does not exist".to_string(),
        });
    }
    let parent = dest.parent().ok_or_else(|| ReleaseError::PathValidation {
        path: dest.to_path_buf(),
        reason: "backup destination has no parent directory".to_string(),
    })?;
    create_dir_all_no_symlinks(parent, 0o700)?;

    let dest_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sqlite.bak");
    let tmp_dest = parent.join(format!(
        ".{}.tmp.{}.{}",
        dest_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    // Pre-create the temporary destination file exclusively with 0600 permissions BEFORE opening
    // it with rusqlite so database secrets are never exposed to a permissive default umask.
    let tmp_file = open_exclusive_private_file(&tmp_dest, 0o600)?;
    drop(tmp_file);

    let backup_result = (|| -> ReleaseResult<()> {
        let src_conn = Connection::open_with_flags(
            src,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ReleaseError::Snapshot {
            db_path: src.to_path_buf(),
            reason: format!("failed to open source DB read-only: {}", e),
        })?;
        let _ = src_conn.busy_timeout(Duration::from_secs(10));

        let mut dst_conn = Connection::open(&tmp_dest).map_err(|e| ReleaseError::Snapshot {
            db_path: dest.to_path_buf(),
            reason: format!("failed to open destination DB {}: {}", tmp_dest.display(), e),
        })?;
        let _ = dst_conn.busy_timeout(Duration::from_secs(10));

        {
            let backup =
                Backup::new(&src_conn, &mut dst_conn).map_err(|e| ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: format!("failed to initialize online backup: {}", e),
                })?;
            backup
                .run_to_completion(256, Duration::from_millis(10), None)
                .map_err(|e| ReleaseError::Snapshot {
                    db_path: src.to_path_buf(),
                    reason: format!("online backup copy failed: {}", e),
                })?;
        }
        Ok(())
    })();

    if let Err(err) = backup_result {
        let _ = fs::remove_file(&tmp_dest);
        let _ = fs::remove_file(format!("{}-wal", tmp_dest.display()));
        let _ = fs::remove_file(format!("{}-shm", tmp_dest.display()));
        return Err(err);
    }

    if let Ok(f) = fs::File::open(&tmp_dest) {
        let _ = f.sync_all();
    }

    // Remove any pre-existing destination sidecars and atomically rename the 0600 backup into place
    let _ = fs::remove_file(format!("{}-wal", dest.display()));
    let _ = fs::remove_file(format!("{}-shm", dest.display()));
    fs::rename(&tmp_dest, dest).map_err(|e| {
        let _ = fs::remove_file(&tmp_dest);
        ReleaseError::io(
            format!(
                "renaming online backup {} -> {}",
                tmp_dest.display(),
                dest.display()
            ),
            e,
        )
    })?;
    let _ = fs::remove_file(format!("{}-wal", tmp_dest.display()));
    let _ = fs::remove_file(format!("{}-shm", tmp_dest.display()));
    sync_parent_dir_best_effort(parent);

    Ok(())
}

/// Runs `PRAGMA integrity_check;` against `db_path` (opened read-only) and returns the normalized
/// first-line status (`"ok"` when healthy, or `"error"` / diagnostic string on corruption).
pub fn sqlite_integrity(db_path: &Path) -> String {
    if let Ok(meta) = fs::symlink_metadata(db_path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return "error".to_string();
        }
    } else {
        return "missing".to_string();
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(db_path, flags) else {
        return "error".to_string();
    };
    let _ = conn.busy_timeout(Duration::from_secs(5));
    let res: Result<String, _> =
        conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0));
    match res {
        Ok(raw) => {
            let first_line = raw.lines().next().unwrap_or("");
            let cleaned: String = first_line.chars().filter(|c| !c.is_whitespace()).collect();
            if cleaned.is_empty() {
                "error".to_string()
            } else {
                cleaned
            }
        }
        Err(_) => "error".to_string(),
    }
}

/// Creates a minimal dry-run placeholder SQLite database at `db_path` with `0600` permissions
/// enforced before writing, matching:
/// `CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');`
pub fn create_dry_run_placeholder_db(db_path: &Path) -> ReleaseResult<()> {
    ensure_no_symlink_ancestors(db_path)?;
    if let Some(parent) = db_path.parent() {
        create_dir_all_no_symlinks(parent, 0o700)?;
    }
    if !db_path.exists() {
        let f = open_exclusive_private_file(db_path, 0o600)?;
        drop(f);
    }
    let conn = Connection::open(db_path).map_err(|e| ReleaseError::Snapshot {
        db_path: db_path.to_path_buf(),
        reason: format!("failed to create dry-run placeholder DB: {}", e),
    })?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); \
         INSERT INTO _meta VALUES ('version','dryrun');",
    )
    .map_err(|e| ReleaseError::Snapshot {
        db_path: db_path.to_path_buf(),
        reason: format!("failed to seed dry-run placeholder DB: {}", e),
    })?;
    Ok(())
}

/// Executes Stage 1.5 State Snapshot into `${RELEASE_DIR}/data-snapshot/${SQLITE_DB}.bak`,
/// verifies `PRAGMA integrity_check == "ok"`, and writes `MANIFEST.sha256` (all with private
/// `0700` directory and `0600` file permissions before writing).
///
/// Preserves the exact dry-run vs live-deploy guarantees of `state_snapshot` in `deploy/release-manager.sh`:
/// - During `--dry-run`, if `resolved.path` exists and differs from `${DATA_DIR}/${SQLITE_DB}`,
///   it is first copied via read-only online backup into `${DATA_DIR}/${SQLITE_DB}`. If that copy fails,
///   any partial copy/WAL/SHM files are removed and Stage 1.5 returns an error without falling through
///   to a placeholder database.
/// - During `--dry-run`, if no live DB exists, a placeholder DB is created at `${DATA_DIR}/${SQLITE_DB}`.
/// - During a real deploy (`dry_run == false`), if `resolved.path` does not exist, the snapshot is skipped
///   cleanly (`created: false`).
pub fn create_state_snapshot(
    config: &ReleaseConfig,
    resolved: &ResolvedDbPath,
    release_dir: &Path,
    dry_run: bool,
) -> ReleaseResult<SnapshotReport> {
    ensure_no_symlink_ancestors(release_dir)?;
    let mut snapshot_db = resolved.path.clone();

    if dry_run {
        let copy = config.data_dir.join(&config.sqlite_db);
        create_dir_all_no_symlinks(&config.data_dir, 0o700)?;

        if resolved.path.is_file() && resolved.path != copy {
            if let Err(err) = sqlite_online_backup(&resolved.path, &copy) {
                let _ = fs::remove_file(&copy);
                let _ = fs::remove_file(format!("{}-wal", copy.display()));
                let _ = fs::remove_file(format!("{}-shm", copy.display()));
                return Err(ReleaseError::Snapshot {
                    db_path: resolved.path.clone(),
                    reason: format!(
                        "[DRY-RUN] Failed to copy live database from {} (source: {}): {}",
                        resolved.path.display(),
                        resolved.source,
                        err
                    ),
                });
            }
        }
        snapshot_db = copy;
    }

    if !snapshot_db.is_file() {
        if dry_run {
            create_dry_run_placeholder_db(&snapshot_db)?;
        } else {
            return Ok(SnapshotReport {
                created: false,
                source_db: resolved.path.clone(),
                backup_path: None,
                manifest_path: None,
                sha256: None,
            });
        }
    }

    let snapshot_dir = release_dir.join("data-snapshot");
    create_dir_all_no_symlinks(&snapshot_dir, 0o700)?;

    let bak_filename = format!("{}.bak", config.sqlite_db);
    let bak_path = snapshot_dir.join(&bak_filename);
    let lock_file = snapshot_dir.join(".snapshot.lock");

    {
        let _lock = ReleaseLockGuard::acquire(&lock_file, config.snapshot_timeout)?;
        sqlite_online_backup(&snapshot_db, &bak_path)?;
    }

    let integrity = sqlite_integrity(&bak_path);
    if integrity != "ok" {
        return Err(ReleaseError::IntegrityFailed {
            db_path: bak_path,
            result: integrity,
        });
    }

    let sha256 = compute_file_sha256(&bak_path)?;
    let manifest_path = snapshot_dir.join("MANIFEST.sha256");
    let manifest_line = format!("{}  {}\n", sha256, bak_filename);
    atomic_write_bytes_with_mode(&manifest_path, manifest_line.as_bytes(), 0o600)?;

    Ok(SnapshotReport {
        created: true,
        source_db: snapshot_db,
        backup_path: Some(bak_path),
        manifest_path: Some(manifest_path),
        sha256: Some(sha256),
    })
}
/// Verifies that `${snapshot_dir}/${bak_filename}` matches the SHA-256 digest recorded in
/// `${snapshot_dir}/MANIFEST.sha256` and is not a symlink.
pub fn verify_snapshot_manifest(snapshot_dir: &Path, bak_filename: &str) -> ReleaseResult<String> {
    ensure_no_symlink_ancestors(snapshot_dir)?;
    let bak_path = snapshot_dir.join(bak_filename);
    let manifest_path = snapshot_dir.join("MANIFEST.sha256");

    let bak_meta = fs::symlink_metadata(&bak_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "missing snapshot backup {}: {}",
            bak_path.display(),
            e
        ))
    })?;
    if bak_meta.file_type().is_symlink() || !bak_meta.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "snapshot backup {} is a symlink or non-regular file",
            bak_path.display()
        )));
    }

    let manifest_meta = fs::symlink_metadata(&manifest_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "missing snapshot MANIFEST.sha256 at {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    if manifest_meta.file_type().is_symlink() || !manifest_meta.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "snapshot manifest {} is a symlink or non-regular file",
            manifest_path.display()
        )));
    }

    let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "failed to read snapshot manifest {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    let expected = parse_sha256_manifest(&manifest_content, bak_filename).map_err(|e| {
        ReleaseError::Rollback(format!(
            "invalid snapshot manifest {}: {}",
            manifest_path.display(),
            e
        ))
    })?;
    let actual = compute_file_sha256(&bak_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "failed to hash snapshot {}: {}",
            bak_path.display(),
            e
        ))
    })?;
    if actual != expected {
        return Err(ReleaseError::Rollback(format!(
            "snapshot SHA-256 mismatch for {}: expected {}, got {}",
            bak_path.display(),
            expected,
            actual
        )));
    }
    Ok(actual)
}

/// Outcome of Stage 4 SQLite Integrity Check & Snapshot Restore (`state_restore`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    /// Whether the live database was already healthy (`PRAGMA integrity_check == "ok"`).
    pub live_db_healthy: bool,
    /// Whether the snapshot `.bak` was restored over a corrupted or missing live database.
    pub restored_from_snapshot: bool,
    /// If a corrupted live database was quarantined, its `.corrupted.<epoch>` path.
    pub quarantined_corrupted_path: Option<PathBuf>,
}

/// Checks the integrity of the resolved live database and restores `${target_release}/data-snapshot/${SQLITE_DB}.bak`
/// if and only if the live database fails `PRAGMA integrity_check`, the snapshot passes both
/// `MANIFEST.sha256` digest verification and `PRAGMA integrity_check == "ok"`, and `stop_services` succeeds.
///
/// Before replacing the database file:
/// 1. Verifies `MANIFEST.sha256` and `PRAGMA integrity_check == "ok"` on `.bak`.
/// 2. Requires `stop_services(db_path)` to succeed (`?`) so `aetherflow-api` and `aetherflow-runner`
///    cannot continue writing or recreate a WAL over the restored file.
/// 3. Captures ownership (`uid`, `gid`, `mode`) from the existing `db_path` (or parent directory)
///    before quarantining.
/// 4. Copies `.bak` into an exclusive `0600` sibling temporary file in `db_path`'s parent directory,
///    runs `sync_all()`, verifies `PRAGMA integrity_check == "ok"` on the staged temp file, and applies
///    preserved ownership (or `aetherflow:aetherflow` service user ownership).
/// 5. Quarantines `${db_path}` to `${db_path}.corrupted.<epoch>.<uuid>`, removes `-wal`/`-shm` sidecars,
///    atomically renames the verified temp file to `${db_path}`, and removes `-wal`/`-shm` again.
pub fn restore_state_if_corrupted<F>(
    config: &ReleaseConfig,
    resolved: &ResolvedDbPath,
    target_release: &Path,
    dry_run: bool,
    mut stop_services: F,
) -> ReleaseResult<RestoreReport>
where
    F: FnMut(&Path) -> ReleaseResult<()>,
{
    let db_path = &resolved.path;
    let snapshot_dir = target_release.join("data-snapshot");
    let bak_filename = format!("{}.bak", config.sqlite_db);
    let bak_path = snapshot_dir.join(&bak_filename);

    if dry_run {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    ensure_no_symlink_ancestors(db_path)?;

    if !db_path.is_file() && !bak_path.is_file() {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    let integrity = if db_path.is_file() {
        sqlite_integrity(db_path)
    } else {
        "missing".to_string()
    };

    if integrity == "ok" {
        return Ok(RestoreReport {
            live_db_healthy: true,
            restored_from_snapshot: false,
            quarantined_corrupted_path: None,
        });
    }

    if !bak_path.is_file() {
        return Err(ReleaseError::Rollback(format!(
            "live database at {} failed integrity check ({}) and no snapshot exists at {}",
            db_path.display(),
            integrity,
            bak_path.display()
        )));
    }

    // 1. Verify MANIFEST.sha256 digest and SQLite integrity of the backup BEFORE stopping services or touching live DB
    verify_snapshot_manifest(&snapshot_dir, &bak_filename)?;

    let bak_integrity = sqlite_integrity(&bak_path);
    if bak_integrity != "ok" {
        return Err(ReleaseError::Rollback(format!(
            "refusing to restore corrupted snapshot {} (integrity={})",
            bak_path.display(),
            bak_integrity
        )));
    }

    // 2. Require service stop to succeed before touching WAL/SHM sidecars or live database
    stop_services(db_path).map_err(|e| {
        ReleaseError::Rollback(format!(
            "refusing to restore database {} because stopping services failed: {}",
            db_path.display(),
            e
        ))
    })?;

    // 3. Capture ownership/permissions from existing DB (or parent dir) before quarantine
    let preserved_ownership = OwnershipMetadata::capture(db_path)
        .or_else(|| db_path.parent().and_then(OwnershipMetadata::capture))
        .map(|mut m| {
            // Ensure restored DB is never group/world-accessible while preserving user read/write
            m.mode = 0o600;
            m
        });

    let parent = db_path.parent().ok_or_else(|| {
        ReleaseError::Rollback(format!(
            "database path {} has no parent directory",
            db_path.display()
        ))
    })?;
    create_dir_all_no_symlinks(parent, 0o700)?;

    // 4. Stage .bak into an exclusive 0600 sibling temp file, fsync, verify integrity, and set ownership
    let db_filename = db_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("aetherflow.sqlite");
    let staged_tmp = parent.join(format!(
        ".{}.restore.{}.{}",
        db_filename,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    atomic_copy_file_with_mode(
        &bak_path,
        &staged_tmp,
        0o600,
        preserved_ownership.as_ref(),
    )?;

    let staged_integrity = sqlite_integrity(&staged_tmp);
    if staged_integrity != "ok" {
        let _ = fs::remove_file(&staged_tmp);
        return Err(ReleaseError::Rollback(format!(
            "staged restore temp file {} failed integrity check ({})",
            staged_tmp.display(),
            staged_integrity
        )));
    }

    // 5. Quarantine corrupted DB first, remove WAL/SHM sidecars, then atomically rename staged_tmp -> db_path
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));

    let mut quarantined = None;
    if db_path.is_file() {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let corrupted_path = PathBuf::from(format!(
            "{}.corrupted.{}.{}",
            db_path.display(),
            epoch,
            uuid::Uuid::new_v4()
        ));
        if let Err(e) = fs::rename(db_path, &corrupted_path) {
            let _ = fs::remove_file(&staged_tmp);
            return Err(ReleaseError::io(
                format!(
                    "quarantining corrupted DB {} -> {}",
                    db_path.display(),
                    corrupted_path.display()
                ),
                e,
            ));
        }
        quarantined = Some(corrupted_path);
    }

    let _ = fs::remove_file(&wal_path);
    let _ = fs::remove_file(&shm_path);

    if let Err(e) = fs::rename(&staged_tmp, db_path) {
        let _ = fs::remove_file(&staged_tmp);
        // Attempt to restore quarantined file if rename failed
        if let Some(ref q) = quarantined {
            let _ = fs::rename(q, db_path);
        }
        return Err(ReleaseError::io(
            format!(
                "atomically renaming restored DB {} -> {}",
                staged_tmp.display(),
                db_path.display()
            ),
            e,
        ));
    }

    // Ensure no stale sidecars exist after the atomic swap
    let _ = fs::remove_file(&wal_path);
    let _ = fs::remove_file(&shm_path);

    apply_service_ownership(db_path, preserved_ownership.as_ref(), 0o600)?;
    sync_parent_dir_best_effort(parent);

    Ok(RestoreReport {
        live_db_healthy: false,
        restored_from_snapshot: true,
        quarantined_corrupted_path: quarantined,
    })
}
