//! Non-destructive restore planning, preflight inspection, and archive verification for `af-host`.
//!
//! # Security & Non-Destructive Invariants
//! 1. **Non-Destructive Planning & Preflight Only:** `plan_restore`, `preflight_restore_directory`,
//!    and `preflight_tar_gz_archive` never overwrite, delete, or mutate live host files.
//! 2. **Explicitly Unsupported Destructive Execution:** `execute_destructive_restore` always fails
//!    closed with [`HostBackupError::DestructiveRestoreUnsupported`] rather than performing an
//!    unsafe or uncoordinated live overwrite while `aetherflow-api` or systemd services hold open
//!    SQLite/configuration descriptors.
//! 3. **Path Traversal Rejection:** Any manifest or archive entry containing `..`, `.`, leading
//!    `/`, `\`, drive prefixes, or NUL bytes is rejected immediately.
//! 4. **Symlink & Link Rejection:** Symbolic links (`EntryType::Symlink`), hard links (`EntryType::Link`),
//!    FIFOs, character/block devices, and existing destination symlinks along any ancestor chain
//!    under `target_root` (including ancestors of `target_root` itself) are rejected.
//! 5. **Unsafe Overwrite Rejection:** Direct system roots (`/`, `/etc`, `/var`, `/usr`, `C:\`, etc.),
//!    relative roots, or paths with fewer than two normal components are unconditionally rejected as
//!    `target_root`. Under `OverwritePolicy::RejectExisting` (the default), any existing file or
//!    directory collision under `target_root` is rejected unless the caller explicitly opts into
//!    `OverwritePolicy::AllowRegularFilesInStaging` on a non-production staging root.

use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupManifest, BackupTargetKind, CompatibilityReport, SqliteSnapshotMetadata};
use crate::snapshot::verify_sqlite_snapshot_integrity;
use crate::verify::{
    compute_file_sha256, ensure_private_dir_all, reject_if_symlink, reject_symlink_chain,
    validate_no_parent_traversal, validate_relative_backup_path, verify_file_sha256,
    verify_file_with_sidecar,
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Policy governing how restore planning handles existing files under `target_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicy {
    /// Fail closed with [`HostBackupError::UnsafeOverwriteRejected`] if any planned destination
    /// file already exists on disk.
    #[default]
    RejectExisting,
    /// Allow overwriting existing regular files only when planning against an isolated staging root
    /// (still rejects overwriting directories, symlinks, or special files).
    AllowRegularFilesInStaging,
}

/// Planned action for an individual verified backup entry during non-destructive restore preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedRestoreAction {
    /// Target file does not exist and would be created under `target_root`.
    CreateNew,
    /// Target regular file exists and `OverwritePolicy::AllowRegularFilesInStaging` permitted replacement.
    ReplaceExistingRegularFile,
}

/// Single validated item inside a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlanItem {
    pub relative_path: String,
    pub destination_path: PathBuf,
    pub kind: BackupTargetKind,
    pub sha256: String,
    pub size_bytes: u64,
    pub action: PlannedRestoreAction,
}

/// Non-destructive restore plan and preflight verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePlan {
    pub backup_id: String,
    pub target_root: PathBuf,
    pub overwrite_policy: OverwritePolicy,
    pub compatibility: CompatibilityReport,
    pub items: Vec<RestorePlanItem>,
    pub total_bytes: u64,
    /// `true` only when a standalone SQLite snapshot file on disk has passed `PRAGMA quick_check`
    /// (`preflight_restore_directory`). Streaming `.tar.gz` archive preflight (`preflight_tar_gz_archive`)
    /// verifies the snapshot member's SHA-256 and byte length without extracting to disk, so this
    /// field remains `false` for `.tar.gz` preflight.
    pub sqlite_integrity_verified: bool,
    pub non_destructive_only: bool,
}

/// Options for computing and validating a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePreflightOptions {
    /// Current host AetherFlow version (e.g., `"v4.0.0"`).
    pub host_app_version: String,
    /// Optional maximum SQLite `PRAGMA user_version` supported by the host binary.
    pub max_supported_sqlite_user_version: Option<i64>,
    /// Overwrite behavior when a planned destination file already exists.
    pub overwrite_policy: OverwritePolicy,
    /// Whether to require `.sha256` sidecars on the primary archive/snapshot before planning.
    pub require_artifact_sidecar: bool,
}

impl Default for RestorePreflightOptions {
    fn default() -> Self {
        Self {
            host_app_version: "4.0.0".to_string(),
            max_supported_sqlite_user_version: None,
            overwrite_policy: OverwritePolicy::RejectExisting,
            require_artifact_sidecar: true,
        }
    }
}

/// Validates and normalizes `target_root`, requiring:
/// - No empty string, NUL byte, `.` or `..` raw path segments
/// - An absolute path (`target_root.is_absolute()`)
/// - At least two `Component::Normal` segments (so `/` and top-level system directories like
///   `/etc`, `//etc`, `/var`, `/usr`, `/tmp`, `C:\Windows` are rejected)
/// - Not located at or directly targeting forbidden system hierarchies (`/etc`, `/proc`, `/sys`,
///   `/dev`, `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr`, `C:\Windows`, `C:\System32`)
/// - Every existing ancestor and `target_root` itself is free of symbolic links
fn validate_safe_target_root(target_root: &Path) -> HostBackupResult<PathBuf> {
    validate_no_parent_traversal(target_root, "restore target_root")?;

    if !target_root.is_absolute() {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "restore target_root '{}' must be an absolute path",
                target_root.display()
            ),
        });
    }

    let mut normalized = PathBuf::new();
    let mut normal_segments: Vec<String> = Vec::new();
    for comp in target_root.components() {
        match comp {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: target_root.to_string_lossy().into_owned(),
                    reason: "restore target_root must not contain '.' or '..' segments".to_string(),
                });
            }
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." {
                    return Err(HostBackupError::TraversalRejected {
                        path: target_root.to_string_lossy().into_owned(),
                        reason: "restore target_root must not contain '.' or '..' segments"
                            .to_string(),
                    });
                }
                normalized.push(seg);
                normal_segments.push(s.into_owned());
            }
        }
    }

    // Require at least two normal path components so root (`/`) and single-component
    // top-level directories (`/etc`, `//etc`, `/var`, `/usr`, `/tmp`, `C:\Windows`) can never
    // be used directly as `target_root`.
    if normal_segments.len() < 2 {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "refusing to plan restore directly onto root or top-level system directory '{}' (at least two normal path components required)",
                target_root.display()
            ),
        });
    }

    let first_lower = normal_segments[0].to_ascii_lowercase();
    let second_lower = normal_segments[1].to_ascii_lowercase();
    let forbidden_top = matches!(
        first_lower.as_str(),
        "etc"
            | "proc"
            | "sys"
            | "dev"
            | "boot"
            | "bin"
            | "sbin"
            | "lib"
            | "lib64"
            | "usr"
            | "windows"
            | "system32"
    );
    let forbidden_var_or_run = (first_lower == "var"
        && matches!(
            second_lower.as_str(),
            "lib" | "www" | "log" | "mail" | "spool" | "backups"
        )
        && normal_segments.len() == 2)
        || (first_lower == "home" && normal_segments.len() == 2);

    if forbidden_top || forbidden_var_or_run {
        return Err(HostBackupError::UnsafeOverwriteRejected {
            target: target_root.to_path_buf(),
            reason: format!(
                "refusing to plan restore onto protected system directory '{}'",
                target_root.display()
            ),
        });
    }

    // Check every existing ancestor and target_root itself for symlinks
    reject_if_symlink(&normalized, "restore target_root")?;

    match fs::symlink_metadata(&normalized) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: normalized,
                    reason: "restore target_root is a symbolic link".to_string(),
                });
            }
            if !meta.is_dir() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: normalized,
                    reason: "restore target_root exists and is not a directory".to_string(),
                });
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(HostBackupError::io(
                format!("inspecting target_root {}", normalized.display()),
                err,
            ));
        }
    }

    Ok(normalized)
}

/// Validates a single destination path under `target_root` against traversal, symlinks,
/// and the configured [`OverwritePolicy`].
fn plan_single_destination(
    target_root: &Path,
    relative_path: &str,
    overwrite_policy: OverwritePolicy,
) -> HostBackupResult<(PathBuf, PlannedRestoreAction)> {
    let rel_buf = validate_relative_backup_path(relative_path)?;
    let dest = target_root.join(&rel_buf);

    // Ensure every existing path component (including ancestors of target_root and between target_root and dest) is free of symlinks
    reject_symlink_chain(target_root, &dest)?;

    match fs::symlink_metadata(&dest) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: dest,
                    reason: "destination path is a symbolic link".to_string(),
                });
            }
            if meta.is_dir() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "cannot overwrite an existing directory with a file entry".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "cannot overwrite special non-regular file".to_string(),
                });
            }
            match overwrite_policy {
                OverwritePolicy::RejectExisting => Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest,
                    reason: "destination file already exists and OverwritePolicy::RejectExisting is active".to_string(),
                }),
                OverwritePolicy::AllowRegularFilesInStaging => {
                    Ok((dest, PlannedRestoreAction::ReplaceExistingRegularFile))
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok((dest, PlannedRestoreAction::CreateNew))
        }
        Err(err) => Err(HostBackupError::io(
            format!("inspecting destination {}", dest.display()),
            err,
        )),
    }
}

/// Computes a purely non-destructive [`RestorePlan`] from a validated [`BackupManifest`]
/// without touching any files under `target_root`.
pub fn plan_restore_from_manifest(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    let normalized_root = validate_safe_target_root(target_root)?;
    let compatibility = manifest.check_compatibility(
        &options.host_app_version,
        options.max_supported_sqlite_user_version,
    )?;

    let mut items = Vec::with_capacity(manifest.entries.len());
    let mut total_bytes = 0u64;

    for entry in &manifest.entries {
        let (dest, action) = plan_single_destination(
            &normalized_root,
            &entry.relative_path,
            options.overwrite_policy,
        )?;
        total_bytes = total_bytes.saturating_add(entry.size_bytes);
        items.push(RestorePlanItem {
            relative_path: entry.relative_path.clone(),
            destination_path: dest,
            kind: entry.kind,
            sha256: entry.sha256.clone(),
            size_bytes: entry.size_bytes,
            action,
        });
    }

    Ok(RestorePlan {
        backup_id: manifest.backup_id.clone(),
        target_root: normalized_root,
        overwrite_policy: options.overwrite_policy,
        compatibility,
        items,
        total_bytes,
        sqlite_integrity_verified: false,
        non_destructive_only: true,
    })
}

/// Runs a full non-destructive preflight over a backup staging directory containing a
/// [`BackupManifest`] and its referenced files on disk:
/// 1. Validates `manifest` compatibility and schema version.
/// 2. Rejects any path traversal or symlink inside `backup_source_dir` AND `target_root` (including ancestors).
/// 3. Verifies every file's SHA-256 digest and byte length against `manifest.entries`.
/// 4. If `manifest.sqlite_snapshot` is present, verifies its `.sha256` sidecar (when requested)
///    and runs `PRAGMA quick_check` read-only on the snapshot file.
/// 5. Produces a non-destructive [`RestorePlan`] without modifying `target_root`.
pub fn preflight_restore_directory(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(backup_source_dir, "backup_source_dir")?;
    reject_if_symlink(backup_source_dir, "backup_source_dir")?;

    let mut plan = plan_restore_from_manifest(manifest, target_root, options)?;

    for entry in &manifest.entries {
        let rel = validate_relative_backup_path(&entry.relative_path)?;
        let src_path = backup_source_dir.join(&rel);
        reject_symlink_chain(backup_source_dir, &src_path)?;

        if !src_path.is_file() {
            if entry.required {
                return Err(HostBackupError::PathValidation {
                    path: src_path,
                    reason: format!(
                        "required backup entry '{}' is missing from backup directory",
                        entry.relative_path
                    ),
                });
            }
            continue;
        }

        let verification = verify_file_sha256(&src_path, &entry.sha256)?;
        if verification.size_bytes != entry.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "size mismatch for '{}': manifest declared {} bytes, actual {} bytes",
                entry.relative_path, entry.size_bytes, verification.size_bytes
            )));
        }
    }

    if let Some(ref snap) = manifest.sqlite_snapshot {
        let snap_rel = validate_relative_backup_path(&snap.snapshot_relative_path)?;
        let snap_path = backup_source_dir.join(&snap_rel);
        reject_symlink_chain(backup_source_dir, &snap_path)?;

        if options.require_artifact_sidecar {
            verify_file_with_sidecar(&snap_path)?;
        }
        let verification = verify_file_sha256(&snap_path, &snap.sha256)?;
        if verification.size_bytes != snap.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "SQLite snapshot size mismatch for '{}': expected {}, got {}",
                snap.snapshot_relative_path, snap.size_bytes, verification.size_bytes
            )));
        }
        let (uv, _, _) = verify_sqlite_snapshot_integrity(&snap_path)?;
        if uv != snap.sqlite_user_version {
            return Err(HostBackupError::InvalidManifest(format!(
                "SQLite snapshot user_version mismatch for '{}': manifest declared {}, actual {}",
                snap.snapshot_relative_path, snap.sqlite_user_version, uv
            )));
        }
        if let Some(max_uv) = options.max_supported_sqlite_user_version {
            if uv > max_uv {
                return Err(HostBackupError::IncompatibleVersion {
                    backup_version: format!("sqlite_user_version={}", uv),
                    host_version: format!("max_sqlite_user_version={}", max_uv),
                    reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                });
            }
        }
        plan.sqlite_integrity_verified = true;
    }

    Ok(plan)
}

/// Inspects a `.tar.gz` backup archive completely in-memory (streaming without extracting to disk),
/// verifying:
/// 1. The archive's `.sha256` sidecar (if `options.require_artifact_sidecar` is `true`).
/// 2. Every tar header has a safe relative path (no leading `/`, no `..`, no `.`, no `\`, no NUL).
/// 3. No tar entry is a symlink (`EntryType::Symlink`), hardlink (`EntryType::Link`), device, or FIFO.
/// 4. Every file entry's streamed SHA-256 and byte count matches `manifest.entries` (and `sqlite_snapshot`
///    when present).
/// 5. All required manifest entries are present in the archive.
/// 6. Destination paths under `target_root` satisfy `options.overwrite_policy` and contain no symlinks.
///
/// Note: Because `preflight_tar_gz_archive` streams archive members in-memory without writing files
/// to disk, live SQLite `PRAGMA quick_check` is not executed on embedded tar members and
/// `RestorePlan::sqlite_integrity_verified` remains `false`.
pub fn preflight_tar_gz_archive(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    if options.require_artifact_sidecar {
        verify_file_with_sidecar(archive_path)?;
    }

    let plan = plan_restore_from_manifest(manifest, target_root, options)?;

    verify_tar_gz_against_manifest(
        archive_path,
        manifest,
        Some((&plan.target_root, options.overwrite_policy)),
    )?;

    Ok(plan)
}

/// Streams a `.tar.gz` archive in-memory and verifies that all tar members are safe regular/directory
/// entries matching `manifest.entries` (and `manifest.sqlite_snapshot` if present) in path, SHA-256,
/// and byte size, and that all required entries are present.
pub(crate) fn verify_tar_gz_against_manifest(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root_check: Option<(&Path, OverwritePolicy)>,
) -> HostBackupResult<()> {
    manifest.validate()?;
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    let expected_by_path: HashMap<String, &crate::manifest::BackupManifestEntry> = manifest
        .entries
        .iter()
        .filter(|e| e.kind != BackupTargetKind::TarGzArchive)
        .map(|e| (e.relative_path.replace('\\', "/"), e))
        .collect();

    let file = File::open(archive_path).map_err(|e| {
        HostBackupError::io(format!("opening archive {}", archive_path.display()), e)
    })?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut seen_entries = HashSet::new();
    let entries_iter = archive.entries().map_err(|e| HostBackupError::Archive {
        archive: archive_path.to_path_buf(),
        reason: format!("failed to read tar header stream: {}", e),
    })?;

    for entry_result in entries_iter {
        let mut entry = entry_result.map_err(|e| HostBackupError::Archive {
            archive: archive_path.to_path_buf(),
            reason: format!("corrupt tar entry header: {}", e),
        })?;

        let entry_type = entry.header().entry_type();
        let raw_path_bytes = entry.path_bytes();
        let raw_path_str = String::from_utf8_lossy(&raw_path_bytes).into_owned();

        // Reject symlink or hardlink tar entries BEFORE path normalization
        if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
            return Err(HostBackupError::SymlinkRejected {
                path: PathBuf::from(&raw_path_str),
                reason: format!(
                    "tar archive '{}' contains forbidden {:?} entry '{}'",
                    archive_path.display(),
                    entry_type,
                    raw_path_str
                ),
            });
        }

        let norm_rel = validate_relative_backup_path(&raw_path_str)?;
        let key = norm_rel.to_string_lossy().replace('\\', "/");

        if entry_type == EntryType::Directory {
            if let Some((target_root, _)) = target_root_check {
                let dir_dest = target_root.join(&norm_rel);
                reject_symlink_chain(target_root, &dir_dest)?;
            }
            continue;
        }

        if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "tar archive contains unsupported special entry type {:?} at '{}'",
                    entry_type, key
                ),
            });
        }

        if !seen_entries.insert(key.clone()) {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("duplicate tar entry '{}' in archive", key),
            });
        }

        if let Some((target_root, overwrite_policy)) = target_root_check {
            // Verify destination safety for every archive member, even if unlisted
            let _ = plan_single_destination(target_root, &key, overwrite_policy)?;
        }

        let Some(expected) = expected_by_path.get(&key) else {
            return Err(HostBackupError::InvalidManifest(format!(
                "tar archive contains undeclared file '{}' not present in BackupManifest",
                key
            )));
        };

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            let n = entry.read(&mut buf).map_err(|e| HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("failed reading tar payload for '{}': {}", key, e),
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            read_bytes += n as u64;
        }

        let actual_sha = hex::encode(hasher.finalize());
        if !actual_sha.eq_ignore_ascii_case(&expected.sha256) {
            return Err(HostBackupError::ChecksumMismatch {
                artifact: format!("{}:{}", archive_path.display(), key),
                expected: expected.sha256.clone(),
                actual: actual_sha,
            });
        }
        if read_bytes != expected.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "tar entry '{}' byte size mismatch: manifest expected {}, got {}",
                key, expected.size_bytes, read_bytes
            )));
        }
    }

    for (key, expected) in &expected_by_path {
        if expected.required && !seen_entries.contains(key) {
            return Err(HostBackupError::Archive {
                archive: archive_path.to_path_buf(),
                reason: format!("required manifest entry '{}' is missing from tar archive", key),
            });
        }
    }

    Ok(())
}

/// Explicitly unsupported destructive live-host restore entry point.
///
/// Attempting to destructively overwrite `/etc/AetherFlow`, `/var/lib/aetherflow/aetherflow.sqlite`,
/// or user home configs in-place without stopping writers and coordinating service rollback is
/// unsafe. Callers must use [`plan_restore_from_manifest`], [`preflight_restore_directory`], or
/// [`preflight_tar_gz_archive`] for non-destructive verification, and rely on `af-release` /
/// operator-controlled maintenance windows for service-stopped state replacement.
pub fn execute_destructive_restore(
    _plan: &RestorePlan,
) -> HostBackupResult<()> {
    Err(HostBackupError::DestructiveRestoreUnsupported {
        reason: "in-place destructive host/database overwrite is disabled by design; run preflight verification and perform state replacement only under an offline maintenance window".to_string(),
    })
}

/// Detailed receipt produced after a safe, manifest-verified staged restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReceipt {
    pub backup_id: String,
    pub target_root: PathBuf,
    pub restored_files: Vec<PathBuf>,
    pub total_bytes: u64,
    pub sqlite_verified: bool,
    pub manifest: BackupManifest,
}

/// Executes a safe, manifest-verified staged restore into an explicit `target_root` directory.
///
/// Security and Integrity guarantees:
/// 1. Rejects unsafe system roots (`/`, `/etc`, `/var`, etc.) and ancestor symlinks on `target_root`.
/// 2. Verifies `.sha256` sidecars and `.manifest.json` compatibility.
/// 3. Rejects path traversal and symlinks within the backup payload.
/// 4. Extracts files atomically with private permissions (`0600` for files, `0700` for directories).
/// 5. Automatically detects and purges stale `-wal` and `-shm` write-ahead logs next to restored SQLite DBs.
/// 6. Executes `PRAGMA quick_check` integrity verification on restored SQLite databases.
pub fn execute_coordinated_restore(
    archive_or_dir: &Path,
    target_root: &Path,
    options: RestorePreflightOptions,
) -> HostBackupResult<RestoreReceipt> {
    validate_no_parent_traversal(archive_or_dir, "archive_or_dir")?;
    reject_if_symlink(archive_or_dir, "archive_or_dir")?;

    let normalized_root = validate_safe_target_root(target_root)?;
    reject_symlink_chain(target_root, &normalized_root)?;

    if archive_or_dir.is_file() {
        let filename = archive_or_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if filename.ends_with(".tar.gz") {
            if options.require_artifact_sidecar {
                verify_file_with_sidecar(archive_or_dir)?;
            }

            let manifest_path = archive_or_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!("{}.manifest.json", filename));

            let manifest = if manifest_path.is_file() {
                BackupManifest::load_from_path(&manifest_path, true)?
            } else {
                // Search inside tar archive for manifest
                let f = File::open(archive_or_dir).map_err(|e| {
                    HostBackupError::io(format!("opening archive {}", archive_or_dir.display()), e)
                })?;
                let mut ar = Archive::new(GzDecoder::new(f));
                let mut found_manifest: Option<BackupManifest> = None;
                if let Ok(entries) = ar.entries() {
                    for entry in entries.flatten() {
                        let p = entry.path_bytes();
                        let p_str = String::from_utf8_lossy(&p);
                        if p_str.ends_with(".manifest.json") || p_str == "manifest.json" {
                            let mut bytes = Vec::new();
                            let mut r = entry;
                            if r.read_to_end(&mut bytes).is_ok() {
                                if let Ok(m) = serde_json::from_slice::<BackupManifest>(&bytes) {
                                    found_manifest = Some(m);
                                    break;
                                }
                            }
                        }
                    }
                }
                found_manifest.ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!(
                        "missing required backup manifest for archive '{}'",
                        archive_or_dir.display()
                    ))
                })?
            };

            manifest.validate()?;
            manifest.check_compatibility(
                &options.host_app_version,
                options.max_supported_sqlite_user_version,
            )?;
            preflight_tar_gz_archive(archive_or_dir, &manifest, &normalized_root, &options)?;

            ensure_private_dir_all(&normalized_root, "target_root")?;

            let file = File::open(archive_or_dir).map_err(|e| {
                HostBackupError::io(format!("opening archive {}", archive_or_dir.display()), e)
            })?;
            let mut archive = Archive::new(GzDecoder::new(file));

            let mut restored_files = Vec::new();
            let mut total_bytes = 0u64;

            let entries = archive.entries().map_err(|e| HostBackupError::Archive {
                archive: archive_or_dir.to_path_buf(),
                reason: format!("failed to read tar entries: {}", e),
            })?;

            for entry_res in entries {
                let mut entry = entry_res.map_err(|e| HostBackupError::Archive {
                    archive: archive_or_dir.to_path_buf(),
                    reason: format!("failed reading tar entry: {}", e),
                })?;

                let entry_type = entry.header().entry_type();
                let raw_path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();

                if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
                    return Err(HostBackupError::SymlinkRejected {
                        path: PathBuf::from(&raw_path),
                        reason: "symlinks are forbidden in staged restore".to_string(),
                    });
                }

                let norm_rel = validate_relative_backup_path(&raw_path)?;

                if entry_type == EntryType::Directory {
                    let dir_dest = normalized_root.join(&norm_rel);
                    ensure_private_dir_all(&dir_dest, "target_dir")?;
                    continue;
                }

                if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
                    continue;
                }

                let (dest_path, _) = plan_single_destination(
                    &normalized_root,
                    &raw_path,
                    options.overwrite_policy,
                )?;
                let parent = dest_path.parent().ok_or_else(|| {
                    HostBackupError::InvalidConfig(format!(
                        "invalid parent for destination {}",
                        dest_path.display()
                    ))
                })?;
                ensure_private_dir_all(parent, "destination_parent")?;

                let temp_file_path = parent.join(format!(
                    ".tmp_restore_{}_{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                let mut hasher = Sha256::new();
                let mut written = 0u64;

                {
                    let mut out = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&temp_file_path)
                        .map_err(|e| {
                            HostBackupError::io(
                                format!("creating temp file {}", temp_file_path.display()),
                                e,
                            )
                        })?;

                    #[cfg(unix)]
                    {
                        let mut p = out
                            .metadata()
                            .map_err(|e| HostBackupError::io("temp file metadata", e))?
                            .permissions();
                        p.set_mode(0o600);
                        let _ = out.set_permissions(p);
                    }

                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = entry.read(&mut buf).map_err(|e| HostBackupError::Archive {
                            archive: archive_or_dir.to_path_buf(),
                            reason: format!("reading tar entry {}: {}", raw_path, e),
                        })?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        out.write_all(&buf[..n])
                            .map_err(|e| HostBackupError::io("writing restored entry", e))?;
                        written += n as u64;
                    }
                    out.sync_all()
                        .map_err(|e| HostBackupError::io("syncing restored file", e))?;
                }

                let actual_sha = hex::encode(hasher.finalize());
                let key = norm_rel.to_string_lossy().replace('\\', "/");
                let exp = manifest
                    .entries
                    .iter()
                    .find(|e| e.relative_path.replace('\\', "/") == key)
                    .ok_or_else(|| {
                        let _ = fs::remove_file(&temp_file_path);
                        HostBackupError::Archive {
                            archive: archive_or_dir.to_path_buf(),
                            reason: format!(
                                "archive entry '{}' is not registered in backup manifest",
                                raw_path
                            ),
                        }
                    })?;

                if !actual_sha.eq_ignore_ascii_case(&exp.sha256) {
                    let _ = fs::remove_file(&temp_file_path);
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest_path.display().to_string(),
                        expected: exp.sha256.clone(),
                        actual: actual_sha,
                    });
                }

                fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                    let _ = fs::remove_file(&temp_file_path);
                    HostBackupError::io(
                        format!(
                            "atomic rename {} -> {}",
                            temp_file_path.display(),
                            dest_path.display()
                        ),
                        e,
                    )
                })?;

                restored_files.push(dest_path);
                total_bytes += written;
            }

            let mut sqlite_verified = false;
            for rf in &restored_files {
                let rf_name = rf.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if rf_name.ends_with(".sqlite") {
                    let wal = rf.with_file_name(format!("{}-wal", rf_name));
                    let shm = rf.with_file_name(format!("{}-shm", rf_name));
                    if wal.exists() {
                        let _ = fs::remove_file(&wal);
                    }
                    if shm.exists() {
                        let _ = fs::remove_file(&shm);
                    }

                    let (uv, _, _) = verify_sqlite_snapshot_integrity(rf)?;
                    if let Some(max_uv) = options.max_supported_sqlite_user_version {
                        if uv > max_uv {
                            return Err(HostBackupError::IncompatibleVersion {
                                backup_version: format!("sqlite_user_version={}", uv),
                                host_version: format!("max_sqlite_user_version={}", max_uv),
                                reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                            });
                        }
                    }
                    sqlite_verified = true;
                }
            }

            Ok(RestoreReceipt {
                backup_id: manifest.backup_id.clone(),
                target_root: normalized_root,
                restored_files,
                total_bytes,
                sqlite_verified,
                manifest,
            })
        } else if filename.ends_with(".sqlite") {
            if options.require_artifact_sidecar {
                verify_file_with_sidecar(archive_or_dir)?;
            }

            let manifest_path = archive_or_dir
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!("{}.manifest.json", filename));

            let manifest = if manifest_path.is_file() {
                BackupManifest::load_from_path(&manifest_path, true)?
            } else {
                let (uv, jm, ic) = verify_sqlite_snapshot_integrity(archive_or_dir)?;
                let (sha, size) = compute_file_sha256(archive_or_dir)?;

                let mut m = BackupManifest::new(&options.host_app_version, filename)?;
                m.entries.push(crate::manifest::BackupManifestEntry {
                    relative_path: filename.to_string(),
                    logical_target_path: None,
                    kind: BackupTargetKind::SqliteSnapshot,
                    sha256: sha.clone(),
                    size_bytes: size,
                    unix_mode: Some(0o600),
                    required: true,
                });
                m.sqlite_snapshot = Some(SqliteSnapshotMetadata {
                    snapshot_relative_path: filename.to_string(),
                    capture_method: "sqlite_snapshot".to_string(),
                    sqlite_user_version: uv,
                    journal_mode: jm,
                    integrity_check: ic,
                    size_bytes: size,
                    sha256: sha,
                });
                m
            };

            manifest.validate()?;
            manifest.check_compatibility(
                &options.host_app_version,
                options.max_supported_sqlite_user_version,
            )?;

            ensure_private_dir_all(&normalized_root, "target_root")?;
            let (dest_path, _) = plan_single_destination(
                &normalized_root,
                filename,
                options.overwrite_policy,
            )?;

            let parent = dest_path.parent().unwrap();
            ensure_private_dir_all(parent, "destination_parent")?;

            let temp_file_path = parent.join(format!(
                ".tmp_restore_{}_{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));

            let size = {
                let mut src = File::open(archive_or_dir)
                    .map_err(|e| HostBackupError::io("opening source sqlite file", e))?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_file_path)
                    .map_err(|e| HostBackupError::io("creating temp sqlite file", e))?;

                #[cfg(unix)]
                {
                    let mut p = out
                        .metadata()
                        .map_err(|e| HostBackupError::io("temp file metadata", e))?
                        .permissions();
                    p.set_mode(0o600);
                    let _ = out.set_permissions(p);
                }

                let mut hasher = Sha256::new();
                let mut buf = [0u8; 64 * 1024];
                let mut written = 0u64;
                loop {
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| HostBackupError::io("reading sqlite bytes", e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n])
                        .map_err(|e| HostBackupError::io("writing sqlite bytes", e))?;
                    written += n as u64;
                }
                out.sync_all()
                    .map_err(|e| HostBackupError::io("syncing restored sqlite", e))?;

                let actual_sha = hex::encode(hasher.finalize());
                let expected_sha = manifest
                    .entries
                    .iter()
                    .find(|e| e.relative_path == filename || e.kind == BackupTargetKind::SqliteSnapshot)
                    .map(|e| e.sha256.as_str())
                    .or_else(|| manifest.sqlite_snapshot.as_ref().map(|s| s.sha256.as_str()));
                if let Some(exp_sha) = expected_sha {
                    if !actual_sha.eq_ignore_ascii_case(exp_sha) {
                        let _ = fs::remove_file(&temp_file_path);
                        return Err(HostBackupError::ChecksumMismatch {
                            artifact: dest_path.display().to_string(),
                            expected: exp_sha.to_string(),
                            actual: actual_sha,
                        });
                    }
                }
                written
            };

            fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                let _ = fs::remove_file(&temp_file_path);
                HostBackupError::io("renaming restored sqlite file", e)
            })?;

            let wal = dest_path.with_file_name(format!("{}-wal", filename));
            let shm = dest_path.with_file_name(format!("{}-shm", filename));
            if wal.exists() {
                let _ = fs::remove_file(&wal);
            }
            if shm.exists() {
                let _ = fs::remove_file(&shm);
            }

            let (uv, _, _) = verify_sqlite_snapshot_integrity(&dest_path)?;
            if let Some(max_uv) = options.max_supported_sqlite_user_version {
                if uv > max_uv {
                    return Err(HostBackupError::IncompatibleVersion {
                        backup_version: format!("sqlite_user_version={}", uv),
                        host_version: format!("max_sqlite_user_version={}", max_uv),
                        reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                    });
                }
            }

            Ok(RestoreReceipt {
                backup_id: manifest.backup_id.clone(),
                target_root: normalized_root,
                restored_files: vec![dest_path],
                total_bytes: size,
                sqlite_verified: true,
                manifest,
            })
        } else {
            Err(HostBackupError::InvalidConfig(format!(
                "unsupported backup file extension for '{}'; expected .tar.gz or .sqlite",
                filename
            )))
        }
    } else if archive_or_dir.is_dir() {
        let manifest_path = fs::read_dir(archive_or_dir)
            .map_err(|e| HostBackupError::io("reading backup directory", e))?
            .filter_map(|e| e.ok())
            .find(|e| {
                let n = e.file_name();
                let s = n.to_string_lossy();
                s.ends_with(".manifest.json") || s == "manifest.json"
            })
            .map(|e| e.path())
            .ok_or_else(|| {
                HostBackupError::InvalidManifest(format!(
                    "no .manifest.json found in backup directory '{}'",
                    archive_or_dir.display()
                ))
            })?;

        let manifest = BackupManifest::load_from_path(&manifest_path, true)?;
        preflight_restore_directory(archive_or_dir, &manifest, &normalized_root, &options)?;

        ensure_private_dir_all(&normalized_root, "target_root")?;

        let mut restored_files = Vec::new();
        let mut total_bytes = 0u64;

        for entry in &manifest.entries {
            let rel = validate_relative_backup_path(&entry.relative_path)?;
            let src_path = archive_or_dir.join(&rel);
            if !src_path.is_file() {
                if entry.required {
                    return Err(HostBackupError::PathValidation {
                        path: src_path,
                        reason: format!(
                            "required file '{}' missing in backup directory",
                            entry.relative_path
                        ),
                    });
                }
                continue;
            }

            let (dest_path, _) = plan_single_destination(
                &normalized_root,
                &entry.relative_path,
                options.overwrite_policy,
            )?;
            let parent = dest_path.parent().unwrap();
            ensure_private_dir_all(parent, "destination_parent")?;

            let temp_file_path = parent.join(format!(
                ".tmp_restore_{}_{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));

            {
                let mut src = File::open(&src_path)
                    .map_err(|e| HostBackupError::io("opening source file", e))?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_file_path)
                    .map_err(|e| HostBackupError::io("creating temp file", e))?;

                #[cfg(unix)]
                {
                    let mut p = out
                        .metadata()
                        .map_err(|e| HostBackupError::io("temp file metadata", e))?
                        .permissions();
                    p.set_mode(0o600);
                    let _ = out.set_permissions(p);
                }

                let mut hasher = Sha256::new();
                let mut buf = [0u8; 64 * 1024];
                let mut written = 0u64;
                loop {
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| HostBackupError::io("reading file bytes", e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n])
                        .map_err(|e| HostBackupError::io("writing file bytes", e))?;
                    written += n as u64;
                }
                out.sync_all()
                    .map_err(|e| HostBackupError::io("syncing restored file", e))?;

                let actual_sha = hex::encode(hasher.finalize());
                if !actual_sha.eq_ignore_ascii_case(&entry.sha256) {
                    let _ = fs::remove_file(&temp_file_path);
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest_path.display().to_string(),
                        expected: entry.sha256.clone(),
                        actual: actual_sha,
                    });
                }
                total_bytes += written;
            }

            fs::rename(&temp_file_path, &dest_path).map_err(|e| {
                let _ = fs::remove_file(&temp_file_path);
                HostBackupError::io("renaming restored file", e)
            })?;

            restored_files.push(dest_path);
        }

        let mut sqlite_verified = false;
        for rf in &restored_files {
            let rf_name = rf.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if rf_name.ends_with(".sqlite") {
                let wal = rf.with_file_name(format!("{}-wal", rf_name));
                let shm = rf.with_file_name(format!("{}-shm", rf_name));
                if wal.exists() {
                    let _ = fs::remove_file(&wal);
                }
                if shm.exists() {
                    let _ = fs::remove_file(&shm);
                }

                let (uv, _, _) = verify_sqlite_snapshot_integrity(rf)?;
                if let Some(max_uv) = options.max_supported_sqlite_user_version {
                    if uv > max_uv {
                        return Err(HostBackupError::IncompatibleVersion {
                            backup_version: format!("sqlite_user_version={}", uv),
                            host_version: format!("max_sqlite_user_version={}", max_uv),
                            reason: "SQLite snapshot user_version exceeds host maximum".to_string(),
                        });
                    }
                }
                sqlite_verified = true;
            }
        }

        Ok(RestoreReceipt {
            backup_id: manifest.backup_id.clone(),
            target_root: normalized_root,
            restored_files,
            total_bytes,
            sqlite_verified,
            manifest,
        })
    } else {
        Err(HostBackupError::PathValidation {
            path: archive_or_dir.to_path_buf(),
            reason: "backup source must be a regular file or directory".to_string(),
        })
    }
}

/// Convenience alias for [`execute_coordinated_restore`].
pub fn execute_staged_restore(
    archive_or_dir: &Path,
    target_root: &Path,
    options: RestorePreflightOptions,
) -> HostBackupResult<RestoreReceipt> {
    execute_coordinated_restore(archive_or_dir, target_root, options)
}
