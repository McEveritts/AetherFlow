//! High-level backup bundle creation, listing, retention pruning, and system maintenance
//! ownership registry for `af-host`.
//!
//! Bridges `packages/system/af-backup` (multi-target host configuration archive + chunking)
//! with `af-api` / `af-services` (online SQLite `VACUUM INTO` snapshot + `.sha256` sidecar),
//! producing a unified, manifest-backed backup bundle without ever plain-copying a live SQLite DB.

use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupManifest, BackupTargetKind};
use crate::restore::verify_tar_gz_against_manifest;
use crate::snapshot::{
    snapshot_sqlite_database, verify_sqlite_snapshot_integrity, SnapshotOptions,
    SqliteSnapshotReceipt,
};
use crate::verify::{
    checksum_sidecar_path, create_unique_private_staging_dir,
    create_unique_private_temp_file, ensure_private_dir_all, parse_exact_chunk_index,
    reject_if_symlink, reject_symlink_chain, safe_backup_file_path, split_backup_into_chunks,
    validate_backup_filename, validate_no_parent_traversal, validate_relative_backup_path,
    verify_file_with_sidecar, write_sha256_sidecar,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Builder;

/// Default retention limit matching `af-api::storage::MAX_RETAINED_BACKUPS` (`10`).
pub const DEFAULT_MAX_RETAINED_BACKUPS: usize = 10;

/// Default retention age in days matching `af-api::storage::RETENTION_DAYS` (`7`).
pub const DEFAULT_RETENTION_DAYS: i64 = 7;

/// Source target specification for host configuration files/directories included in a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBackupTargetSpec {
    /// Relative path inside the backup archive/manifest (e.g., `"etc/AetherFlow/aetherflow.env"`).
    pub archive_relative_path: String,
    /// Actual source path on the host filesystem (or isolated test root).
    pub source_path: PathBuf,
    /// Optional logical FHS path recorded in the manifest for operator reference.
    pub logical_fhs_path: Option<String>,
    /// Whether missing source path should fail the backup (`false` matches `af-backup`'s `get_valid_targets`).
    pub required: bool,
}

/// Configuration for creating a host backup bundle (SQLite snapshot + optional config tar.gz + manifest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBackupConfig {
    /// Directory where backup artifacts, `.sha256` sidecars, and `.manifest.json` files are stored.
    pub backup_dir: PathBuf,
    /// Current AetherFlow application version recorded in the manifest (e.g., `"v4.0.0"`).
    pub app_version: String,
    /// Optional live SQLite database path to snapshot consistently via `VACUUM INTO` / Online Backup API.
    pub sqlite_db_path: Option<PathBuf>,
    /// Snapshot capture options for SQLite.
    pub snapshot_options: SnapshotOptions,
    /// Optional host configuration targets (matching `packages/system/af-backup` `TARGETS`).
    pub config_targets: Vec<HostBackupTargetSpec>,
    /// Optional chunk split size in bytes (matching `af-backup create [chunk-size]`).
    pub chunk_size_bytes: Option<u64>,
    /// Maximum number of backups retained during pruning (`10`).
    pub max_retained_backups: usize,
    /// Minimum age in days before backups beyond `max_retained_backups` are pruned (`7`).
    pub retention_days: i64,
}

impl HostBackupConfig {
    /// Creates an isolated backup configuration rooted under `root` (ideal for unit tests and staging).
    pub fn for_isolated_root(root: &Path, app_version: impl Into<String>) -> Self {
        let owner_home = root.join("home/aetherflow");
        Self {
            backup_dir: root.join("var/lib/aetherflow/backups"),
            app_version: app_version.into(),
            sqlite_db_path: Some(root.join("var/lib/aetherflow/aetherflow.sqlite")),
            snapshot_options: SnapshotOptions::default(),
            config_targets: default_host_targets_for_root(root, &owner_home),
            chunk_size_bytes: None,
            max_retained_backups: DEFAULT_MAX_RETAINED_BACKUPS,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// Returns the canonical host configuration targets modeled on `packages/system/af-backup`,
/// parameterized by `fs_root` and `owner_home` so tests never touch real `/etc` or `/home`.
pub fn default_host_targets_for_root(
    fs_root: &Path,
    owner_home: &Path,
) -> Vec<HostBackupTargetSpec> {
    vec![
        HostBackupTargetSpec {
            archive_relative_path: "etc/AetherFlow".to_string(),
            source_path: fs_root.join("etc/AetherFlow"),
            logical_fhs_path: Some("/etc/AetherFlow".to_string()),
            required: false,
        },
        HostBackupTargetSpec {
            archive_relative_path: "etc/aetherflow/aetherflow.env".to_string(),
            source_path: fs_root.join("etc/aetherflow/aetherflow.env"),
            logical_fhs_path: Some("/etc/aetherflow/aetherflow.env".to_string()),
            required: false,
        },
        HostBackupTargetSpec {
            archive_relative_path: "var/www/html/dashboard/inc/config.php".to_string(),
            source_path: fs_root.join("var/www/html/dashboard/inc/config.php"),
            logical_fhs_path: Some("/var/www/html/dashboard/inc/config.php".to_string()),
            required: false,
        },
        HostBackupTargetSpec {
            archive_relative_path: "var/www/html/dashboard/custom".to_string(),
            source_path: fs_root.join("var/www/html/dashboard/custom"),
            logical_fhs_path: Some("/var/www/html/dashboard/custom".to_string()),
            required: false,
        },
        HostBackupTargetSpec {
            archive_relative_path: "home/owner/.rtorrent.rc".to_string(),
            source_path: owner_home.join(".rtorrent.rc"),
            logical_fhs_path: Some("~/.rtorrent.rc".to_string()),
            required: false,
        },
    ]
}

/// Summary receipt returned when a host backup operation completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBackupReceipt {
    pub backup_id: String,
    pub primary_artifact_path: PathBuf,
    pub primary_sidecar_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sidecar_path: PathBuf,
    pub sqlite_receipt: Option<SqliteSnapshotReceipt>,
    pub archive_path: Option<PathBuf>,
    pub chunk_paths: Vec<PathBuf>,
    pub manifest: BackupManifest,
}

/// Summary item returned when listing existing backups in `backup_dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInventoryItem {
    pub filename: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_at: String,
    pub checksum_present: bool,
    pub checksum_sha256: Option<String>,
    pub manifest_present: bool,
    pub chunk_count: usize,
}

/// Creates a consistent SQLite snapshot backup (`aetherflow_<timestamp>.sqlite`), its `.sha256`
/// sidecar, and its versioned `.manifest.json` (+ `.manifest.json.sha256`) inside `config.backup_dir`.
///
/// This is the canonical shared implementation for `af-api::storage::perform_system_backup`
/// and `af-services::workers::execute_online_sqlite_backup`.
pub fn create_sqlite_snapshot_backup(
    config: &HostBackupConfig,
    timestamp_slug: Option<&str>,
) -> HostBackupResult<HostBackupReceipt> {
    ensure_private_dir_all(&config.backup_dir, "backup_dir")?;

    let db_source = config.sqlite_db_path.as_ref().ok_or_else(|| {
        HostBackupError::InvalidConfig(
            "sqlite_db_path is required for create_sqlite_snapshot_backup".to_string(),
        )
    })?;

    let ts = timestamp_slug
        .map(|s| s.to_string())
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string());
    let filename = validate_backup_filename(&format!("aetherflow_{}.sqlite", ts))?;
    let snapshot_dest = safe_backup_file_path(&config.backup_dir, &filename)?;

    let sqlite_receipt = snapshot_sqlite_database(
        db_source,
        &snapshot_dest,
        &filename,
        &config.snapshot_options,
    )?;

    let mut manifest = BackupManifest::new(&config.app_version, &filename)?;
    manifest.sqlite_snapshot = Some(sqlite_receipt.metadata.clone());
    manifest.add_file_from_disk(
        &filename,
        &snapshot_dest,
        BackupTargetKind::SqliteSnapshot,
        Some(db_source.to_string_lossy().into_owned()),
        true,
    )?;

    let mut chunk_paths = Vec::new();
    if let Some(chunk_size) = config.chunk_size_bytes {
        chunk_paths = split_backup_into_chunks(&snapshot_dest, chunk_size)?;
        manifest.chunk_count = chunk_paths.len();
        manifest.chunk_size_bytes = Some(chunk_size);
    }

    let manifest_filename = format!("{}.manifest.json", filename);
    let manifest_path = safe_backup_file_path(&config.backup_dir, &manifest_filename)?;
    let manifest_sidecar_path = manifest.save_atomic(&manifest_path)?;

    Ok(HostBackupReceipt {
        backup_id: manifest.backup_id.clone(),
        primary_artifact_path: snapshot_dest,
        primary_sidecar_path: sqlite_receipt.sidecar_path.clone(),
        manifest_path,
        manifest_sidecar_path,
        sqlite_receipt: Some(sqlite_receipt),
        archive_path: None,
        chunk_paths,
        manifest,
    })
}

/// Creates a full host configuration & SQLite snapshot `.tar.gz` backup bundle
/// (`aetherflow-backup-<timestamp>.tar.gz`), its `.sha256` sidecar, and its versioned
/// `.manifest.json` (+ `.manifest.json.sha256`).
///
/// Safe against live SQLite corruption: if `config.sqlite_db_path` is present and exists on disk,
/// it is first snapshotted via `VACUUM INTO` / Online Backup API into a verified staging snapshot
/// inside an exclusive `0700` staging directory and packed into the archive under
/// `var/lib/aetherflow/aetherflow.sqlite` (never plain-copied).
/// All symlinks in `config_targets` (including ancestor symlinks) are rejected.
pub fn create_host_archive_backup(
    config: &HostBackupConfig,
    timestamp_slug: Option<&str>,
) -> HostBackupResult<HostBackupReceipt> {
    ensure_private_dir_all(&config.backup_dir, "backup_dir")?;

    let ts = timestamp_slug
        .map(|s| s.to_string())
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d-%H%M%S").to_string());
    let archive_filename = validate_backup_filename(&format!("aetherflow-backup-{}.tar.gz", ts))?;
    let archive_path = safe_backup_file_path(&config.backup_dir, &archive_filename)?;

    let mut manifest = BackupManifest::new(&config.app_version, &archive_filename)?;

    let (tmp_archive_path, tar_file) = create_unique_private_temp_file(
        &archive_path,
        "archive-tmp",
        "temporary tar.gz archive",
    )?;

    let staging_dir = create_unique_private_staging_dir(
        &config.backup_dir,
        "archive-db",
        "host archive SQLite staging directory",
    )?;
    let staged_sqlite_path = staging_dir.join(format!("staged-db-{}.sqlite", ts));
    let mut sqlite_receipt_opt: Option<SqliteSnapshotReceipt> = None;

    let build_result: HostBackupResult<()> = (|| {
        let enc = GzEncoder::new(tar_file, Compression::fast());
        let mut tar_builder = Builder::new(enc);
        // Never follow symlinks when archiving host configuration directories
        tar_builder.follow_symlinks(false);

        // 1. If a live SQLite database is configured and exists, snapshot it safely first
        if let Some(ref db_src) = config.sqlite_db_path {
            validate_no_parent_traversal(db_src, "sqlite_db_path")?;
            reject_if_symlink(db_src, "sqlite_db_path")?;
            if db_src.exists() {
                let rel_db_in_archive = "var/lib/aetherflow/aetherflow.sqlite";
                let receipt = snapshot_sqlite_database(
                    db_src,
                    &staged_sqlite_path,
                    rel_db_in_archive,
                    &config.snapshot_options,
                )?;
                append_verified_file_to_tar(
                    &mut tar_builder,
                    &staged_sqlite_path,
                    rel_db_in_archive,
                    BackupTargetKind::SqliteSnapshot,
                    Some(db_src.to_string_lossy().into_owned()),
                    true,
                    &mut manifest,
                )?;
                let _ = fs::remove_file(&receipt.sidecar_path);
                let _ = fs::remove_file(&staged_sqlite_path);
                manifest.sqlite_snapshot = Some(receipt.metadata.clone());
                sqlite_receipt_opt = Some(receipt);
            }
        }

        // 2. Walk configured host targets (files and directories)
        for target in &config.config_targets {
            let norm_rel = validate_relative_backup_path(&target.archive_relative_path)?;
            validate_no_parent_traversal(&target.source_path, "target source_path")?;
            reject_if_symlink(&target.source_path, "backup target source_path")?;

            let meta = match fs::symlink_metadata(&target.source_path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if target.required {
                        return Err(HostBackupError::PathValidation {
                            path: target.source_path.clone(),
                            reason: format!(
                                "required backup target '{}' does not exist",
                                target.archive_relative_path
                            ),
                        });
                    }
                    continue;
                }
                Err(e) => {
                    return Err(HostBackupError::io(
                        format!("inspecting target {}", target.source_path.display()),
                        e,
                    ));
                }
            };

            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: target.source_path.clone(),
                    reason: "backup target is a symbolic link".to_string(),
                });
            }

            if meta.is_file() {
                let rel_str = norm_rel.to_string_lossy().replace('\\', "/");
                append_verified_file_to_tar(
                    &mut tar_builder,
                    &target.source_path,
                    &rel_str,
                    BackupTargetKind::ConfigFile,
                    target.logical_fhs_path.clone(),
                    target.required,
                    &mut manifest,
                )?;
            } else if meta.is_dir() {
                append_directory_tree_to_tar(
                    &mut tar_builder,
                    &target.source_path,
                    &target.source_path,
                    &norm_rel,
                    target.logical_fhs_path.as_deref(),
                    &mut manifest,
                )?;
            }
        }

        if manifest.entries.is_empty() {
            return Err(HostBackupError::InvalidConfig(
                "no valid configuration files or SQLite database found to back up".to_string(),
            ));
        }

        let gz_encoder = tar_builder.into_inner().map_err(|e| HostBackupError::Archive {
            archive: archive_path.clone(),
            reason: format!("finalizing tar stream failed: {}", e),
        })?;
        let inner_file = gz_encoder.finish().map_err(|e| HostBackupError::Archive {
            archive: archive_path.clone(),
            reason: format!("finalizing gzip stream failed: {}", e),
        })?;
        inner_file.sync_all().map_err(|e| {
            HostBackupError::io(
                format!("syncing temporary archive {}", tmp_archive_path.display()),
                e,
            )
        })?;

        Ok(())
    })();

    let _ = fs::remove_file(&staged_sqlite_path);
    let _ = fs::remove_file(checksum_sidecar_path(&staged_sqlite_path));
    let _ = fs::remove_dir_all(&staging_dir);

    if let Err(err) = build_result {
        let _ = fs::remove_file(&tmp_archive_path);
        return Err(err);
    }

    if let Err(e) = reject_if_symlink(&archive_path, "backup archive path") {
        let _ = fs::remove_file(&tmp_archive_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_archive_path, &archive_path) {
        let _ = fs::remove_file(&tmp_archive_path);
        return Err(HostBackupError::io(
            format!(
                "activating backup archive {} -> {}",
                tmp_archive_path.display(),
                archive_path.display()
            ),
            e,
        ));
    }

    let (primary_sidecar_path, _, _) = write_sha256_sidecar(&archive_path)?;

    let mut chunk_paths = Vec::new();
    if let Some(chunk_size) = config.chunk_size_bytes {
        chunk_paths = split_backup_into_chunks(&archive_path, chunk_size)?;
        manifest.chunk_count = chunk_paths.len();
        manifest.chunk_size_bytes = Some(chunk_size);
    }

    let manifest_filename = format!("{}.manifest.json", archive_filename);
    let manifest_path = safe_backup_file_path(&config.backup_dir, &manifest_filename)?;
    let manifest_sidecar_path = manifest.save_atomic(&manifest_path)?;

    Ok(HostBackupReceipt {
        backup_id: manifest.backup_id.clone(),
        primary_artifact_path: archive_path.clone(),
        primary_sidecar_path,
        manifest_path,
        manifest_sidecar_path,
        sqlite_receipt: sqlite_receipt_opt,
        archive_path: Some(archive_path),
        chunk_paths,
        manifest,
    })
}

fn append_verified_file_to_tar(
    tar_builder: &mut Builder<GzEncoder<File>>,
    disk_path: &Path,
    archive_rel_path: &str,
    kind: BackupTargetKind,
    logical_target_path: Option<String>,
    required: bool,
    manifest: &mut BackupManifest,
) -> HostBackupResult<()> {
    reject_if_symlink(disk_path, "archive member")?;
    let _ = validate_relative_backup_path(archive_rel_path)?;

    manifest.add_file_from_disk(
        archive_rel_path.to_string(),
        disk_path,
        kind,
        logical_target_path,
        required,
    )?;

    let mut f = File::open(disk_path)
        .map_err(|e| HostBackupError::io(format!("opening {}", disk_path.display()), e))?;
    tar_builder
        .append_file(archive_rel_path, &mut f)
        .map_err(|e| HostBackupError::Archive {
            archive: disk_path.to_path_buf(),
            reason: format!("appending '{}' to tar failed: {}", archive_rel_path, e),
        })?;
    Ok(())
}

fn append_directory_tree_to_tar(
    tar_builder: &mut Builder<GzEncoder<File>>,
    root_dir: &Path,
    current_dir: &Path,
    archive_prefix: &Path,
    logical_fhs_prefix: Option<&str>,
    manifest: &mut BackupManifest,
) -> HostBackupResult<()> {
    reject_symlink_chain(root_dir, current_dir)?;

    let mut entries: Vec<_> = fs::read_dir(current_dir)
        .map_err(|e| HostBackupError::io(format!("reading directory {}", current_dir.display()), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            HostBackupError::io(format!("iterating directory {}", current_dir.display()), e)
        })?;

    // Sort deterministically by filename so archive order and manifests are reproducible
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| HostBackupError::io(format!("stat {}", path.display()), e))?;

        if meta.file_type().is_symlink() {
            return Err(HostBackupError::SymlinkRejected {
                path,
                reason: "symlink inside backed-up configuration directory is forbidden".to_string(),
            });
        }

        let rel_from_root = path.strip_prefix(root_dir).map_err(|_| {
            HostBackupError::PathValidation {
                path: path.clone(),
                reason: "failed to strip directory root prefix".to_string(),
            }
        })?;
        let combined_rel = archive_prefix.join(rel_from_root);
        let rel_str = combined_rel.to_string_lossy().replace('\\', "/");

        if meta.is_dir() {
            append_directory_tree_to_tar(
                tar_builder,
                root_dir,
                &path,
                archive_prefix,
                logical_fhs_prefix,
                manifest,
            )?;
        } else if meta.is_file() {
            let logical = logical_fhs_prefix.map(|prefix| {
                let sub = rel_from_root.to_string_lossy().replace('\\', "/");
                format!("{}/{}", prefix.trim_end_matches('/'), sub)
            });
            append_verified_file_to_tar(
                tar_builder,
                &path,
                &rel_str,
                BackupTargetKind::ConfigDirectoryEntry,
                logical,
                true,
                manifest,
            )?;
        }
    }

    Ok(())
}

/// Lists all `.sqlite` and `.tar.gz` backup artifacts in `backup_dir`, reporting their
/// `.sha256` sidecar status, `.manifest.json` presence, and exact 5-digit `.part.NNNNN`
/// non-symlink regular file chunk counts.
pub fn list_backup_inventory(backup_dir: &Path) -> HostBackupResult<Vec<BackupInventoryItem>> {
    validate_no_parent_traversal(backup_dir, "backup_dir")?;
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }
    reject_if_symlink(backup_dir, "backup_dir")?;

    let mut all_entries = Vec::new();
    for entry in fs::read_dir(backup_dir)
        .map_err(|e| HostBackupError::io(format!("reading {}", backup_dir.display()), e))?
    {
        let entry = entry.map_err(|e| HostBackupError::io("reading dir entry", e))?;
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let is_regular_non_symlink = meta.is_file() && !meta.file_type().is_symlink();
        all_entries.push((
            entry.file_name().to_string_lossy().into_owned(),
            path,
            meta,
            is_regular_non_symlink,
        ));
    }

    let mut items = Vec::new();
    for (name, path, meta, is_regular_non_symlink) in &all_entries {
        if !*is_regular_non_symlink || name.starts_with('.') {
            continue;
        }
        let is_primary = (name.ends_with(".sqlite") || name.ends_with(".tar.gz"))
            && !name.contains(".staging")
            && !name.contains(".tmp")
            && safe_primary_check(name);
        if !is_primary {
            continue;
        }

        let modified_at = meta
            .modified()
            .ok()
            .map(|m| DateTime::<Utc>::from(m).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        let sidecar = checksum_sidecar_path(path);
        let checksum_sha256 = match fs::symlink_metadata(&sidecar) {
            Ok(sc_meta) if sc_meta.is_file() && !sc_meta.file_type().is_symlink() => {
                fs::read_to_string(&sidecar)
                    .ok()
                    .and_then(|s| crate::verify::parse_sha256_sidecar_str(&s).ok())
            }
            _ => None,
        };

        let manifest_path = backup_dir.join(format!("{}.manifest.json", name));
        let manifest_present = match fs::symlink_metadata(&manifest_path) {
            Ok(m_meta) => m_meta.is_file() && !m_meta.file_type().is_symlink(),
            Err(_) => false,
        };

        let chunk_count = all_entries
            .iter()
            .filter(|(other_name, _, _, other_regular)| {
                *other_regular && parse_exact_chunk_index(name, other_name).is_some()
            })
            .count();

        items.push(BackupInventoryItem {
            filename: name.clone(),
            path: path.clone(),
            size_bytes: meta.len(),
            modified_at,
            checksum_present: checksum_sha256.is_some(),
            checksum_sha256,
            manifest_present,
            chunk_count,
        });
    }

    items.sort_by(|a, b| b.modified_at.cmp(&a.modified_at).then_with(|| b.filename.cmp(&a.filename)));
    Ok(items)
}

fn safe_primary_check(name: &str) -> bool {
    validate_backup_filename(name).is_ok()
}

/// Deletes a specific backup artifact along with its `.sha256` sidecar, `.manifest.json`,
/// `.manifest.json.sha256`, and any exact 5-digit `.part.NNNNN` regular non-symlink chunk files
/// inside `backup_dir`. Rejects symlinks if encountered on companion or chunk paths.
pub fn delete_backup_artifacts(backup_dir: &Path, filename: &str) -> HostBackupResult<Vec<PathBuf>> {
    let primary = safe_backup_file_path(backup_dir, filename)?;
    let primary_meta = match fs::symlink_metadata(&primary) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostBackupError::PathValidation {
                path: primary,
                reason: "backup file not found".to_string(),
            });
        }
        Err(e) => {
            return Err(HostBackupError::io(
                format!("stat backup file {}", primary.display()),
                e,
            ));
        }
    };
    if primary_meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: primary,
            reason: "backup file is a symbolic link".to_string(),
        });
    }
    if !primary_meta.is_file() {
        return Err(HostBackupError::PathValidation {
            path: primary,
            reason: "backup path is not a regular file".to_string(),
        });
    }

    let mut to_remove = vec![primary.clone()];
    let companions = [
        checksum_sidecar_path(&primary),
        backup_dir.join(format!("{}.manifest.json", filename)),
        backup_dir.join(format!("{}.manifest.json.sha256", filename)),
    ];

    for c in companions {
        match fs::symlink_metadata(&c) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(HostBackupError::SymlinkRejected {
                        path: c,
                        reason: "backup companion file is a symbolic link".to_string(),
                    });
                }
                if meta.is_file() {
                    to_remove.push(c);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(HostBackupError::io(
                    format!("stat companion file {}", c.display()),
                    e,
                ));
            }
        }
    }

    let mut chunk_candidates: Vec<(usize, PathBuf)> = Vec::new();
    for entry in fs::read_dir(backup_dir)
        .map_err(|e| HostBackupError::io(format!("reading {}", backup_dir.display()), e))?
    {
        let entry = entry.map_err(|e| HostBackupError::io("reading dir entry", e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(idx) = parse_exact_chunk_index(filename, &name) {
            let p = entry.path();
            let meta = fs::symlink_metadata(&p)
                .map_err(|e| HostBackupError::io(format!("stat chunk {}", p.display()), e))?;
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: p,
                    reason: "backup chunk file is a symbolic link".to_string(),
                });
            }
            if meta.is_file() {
                chunk_candidates.push((idx, p));
            }
        }
    }
    chunk_candidates.sort_by_key(|(idx, _)| *idx);
    for (_, p) in chunk_candidates {
        to_remove.push(p);
    }

    let mut removed = Vec::with_capacity(to_remove.len());
    for c in to_remove {
        fs::remove_file(&c)
            .map_err(|e| HostBackupError::io(format!("removing {}", c.display()), e))?;
        removed.push(c);
    }

    Ok(removed)
}

/// Prunes backups in `backup_dir` beyond `max_retained` that are older than `retention_days`,
/// removing their companion `.sha256`, `.manifest.json`, and `.part.NNNNN` files.
pub fn prune_backup_inventory(
    backup_dir: &Path,
    max_retained: usize,
    retention_days: i64,
) -> HostBackupResult<Vec<String>> {
    let items = list_backup_inventory(backup_dir)?;
    if items.len() <= max_retained {
        return Ok(Vec::new());
    }

    let cutoff = Utc::now() - ChronoDuration::days(retention_days.max(0));
    let mut pruned = Vec::new();

    for item in items.into_iter().skip(max_retained) {
        if let Ok(parsed_ts) = DateTime::parse_from_rfc3339(&item.modified_at) {
            if parsed_ts.with_timezone(&Utc) > cutoff {
                continue;
            }
        }
        let _ = delete_backup_artifacts(backup_dir, &item.filename)?;
        pruned.push(item.filename);
    }

    Ok(pruned)
}

/// Verifies an existing backup artifact on disk (`<filename>.sha256` + optional `<filename>.manifest.json`),
/// including:
/// 1. Primary artifact `.sha256` sidecar verification.
/// 2. Manifest `.sha256` sidecar and schema/cross-entry validation (when `<filename>.manifest.json` exists).
/// 3. Primary artifact filename match against `manifest.primary_artifact`.
/// 4. Standalone SQLite snapshot SHA-256, byte size, `PRAGMA quick_check`, and `user_version` verification
///    for `.sqlite` primary artifacts, or full streaming `.tar.gz` member SHA-256/size/entry verification
///    against `manifest` for `.tar.gz` primary artifacts.
/// 5. Exact `.part.00000`..`.part.<N-1>` chunk existence, non-symlink regular file checks, chunk size
///    bounds, total byte size, and concatenated SHA-256 digest matching the primary artifact.
pub fn verify_backup_artifact(
    backup_dir: &Path,
    filename: &str,
) -> HostBackupResult<(crate::verify::ChecksumVerification, Option<BackupManifest>)> {
    let artifact_path = safe_backup_file_path(backup_dir, filename)?;
    let checksum_res = verify_file_with_sidecar(&artifact_path)?;

    let manifest_path = backup_dir.join(format!("{}.manifest.json", filename));
    reject_symlink_chain(backup_dir, &manifest_path)?;
    let manifest_opt = if manifest_path.exists() {
        Some(BackupManifest::load_from_path(&manifest_path, true)?)
    } else {
        None
    };

    // Collect any exact 5-digit `.part.NNNNN` files present in `backup_dir` for `filename`
    let mut disk_chunks: Vec<(usize, PathBuf)> = Vec::new();
    for entry in fs::read_dir(backup_dir)
        .map_err(|e| HostBackupError::io(format!("reading {}", backup_dir.display()), e))?
    {
        let entry = entry.map_err(|e| HostBackupError::io("reading dir entry", e))?;
        let entry_name = entry.file_name().to_string_lossy().into_owned();
        if let Some(idx) = parse_exact_chunk_index(filename, &entry_name) {
            let p = entry.path();
            reject_symlink_chain(backup_dir, &p)?;
            let meta = fs::symlink_metadata(&p)
                .map_err(|e| HostBackupError::io(format!("stat chunk {}", p.display()), e))?;
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: p,
                    reason: "backup chunk file is a symbolic link".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::ChunkError {
                    artifact: artifact_path.clone(),
                    reason: format!("chunk path '{}' is not a regular file", p.display()),
                });
            }
            disk_chunks.push((idx, p));
        }
    }
    disk_chunks.sort_by_key(|(idx, _)| *idx);

    if let Some(ref m) = manifest_opt {
        if m.primary_artifact != filename {
            return Err(HostBackupError::InvalidManifest(format!(
                "manifest primary_artifact '{}' does not match verified filename '{}'",
                m.primary_artifact, filename
            )));
        }

        if filename.ends_with(".tar.gz") {
            verify_tar_gz_against_manifest(&artifact_path, m, None)?;
        } else if filename.ends_with(".sqlite") {
            let Some(ref snap) = m.sqlite_snapshot else {
                return Err(HostBackupError::InvalidManifest(format!(
                    "SQLite backup artifact '{}' is missing sqlite_snapshot metadata in manifest",
                    filename
                )));
            };
            if snap.snapshot_relative_path != filename {
                return Err(HostBackupError::InvalidManifest(format!(
                    "sqlite_snapshot relative_path '{}' does not match SQLite backup filename '{}'",
                    snap.snapshot_relative_path, filename
                )));
            }
            if !checksum_res.actual_sha256.eq_ignore_ascii_case(&snap.sha256) {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: artifact_path.display().to_string(),
                    expected: snap.sha256.clone(),
                    actual: checksum_res.actual_sha256.clone(),
                });
            }
            if checksum_res.size_bytes != snap.size_bytes {
                return Err(HostBackupError::InvalidManifest(format!(
                    "SQLite artifact '{}' size_bytes ({}) does not match manifest ({})",
                    filename, checksum_res.size_bytes, snap.size_bytes
                )));
            }
            let (uv, _, _) = verify_sqlite_snapshot_integrity(&artifact_path)?;
            if uv != snap.sqlite_user_version {
                return Err(HostBackupError::InvalidManifest(format!(
                    "SQLite artifact '{}' user_version ({}) does not match manifest ({})",
                    filename, uv, snap.sqlite_user_version
                )));
            }
        } else if let Some(entry) = m.entries.iter().find(|e| e.relative_path == filename) {
            if !checksum_res
                .actual_sha256
                .eq_ignore_ascii_case(&entry.sha256)
            {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: artifact_path.display().to_string(),
                    expected: entry.sha256.clone(),
                    actual: checksum_res.actual_sha256.clone(),
                });
            }
            if checksum_res.size_bytes != entry.size_bytes {
                return Err(HostBackupError::InvalidManifest(format!(
                    "artifact '{}' size_bytes ({}) does not match manifest entry ({})",
                    filename, checksum_res.size_bytes, entry.size_bytes
                )));
            }
        }

        if m.chunk_count != disk_chunks.len() {
            return Err(HostBackupError::ChunkError {
                artifact: artifact_path.clone(),
                reason: format!(
                    "manifest declared {} chunks, but found {} chunk files on disk",
                    m.chunk_count,
                    disk_chunks.len()
                ),
            });
        }
    } else if filename.ends_with(".sqlite") {
        let _ = verify_sqlite_snapshot_integrity(&artifact_path)?;
    }

    if !disk_chunks.is_empty() {
        let declared_chunk_size = manifest_opt.as_ref().and_then(|m| m.chunk_size_bytes);
        verify_chunks_against_primary(
            &artifact_path,
            &disk_chunks,
            &checksum_res.actual_sha256,
            checksum_res.size_bytes,
            declared_chunk_size,
        )?;
    }

    Ok((checksum_res, manifest_opt))
}

/// Streams all sequential `.part.NNNNN` chunks in order, verifying contiguous indices `0..N`,
/// per-chunk byte size against `declared_chunk_size` (if present), total byte length, and overall
/// SHA-256 digest against the primary artifact.
fn verify_chunks_against_primary(
    artifact_path: &Path,
    disk_chunks: &[(usize, PathBuf)],
    expected_sha256: &str,
    expected_total_size: u64,
    declared_chunk_size: Option<u64>,
) -> HostBackupResult<()> {
    let total_chunks = disk_chunks.len();
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    for (pos, (idx, part_path)) in disk_chunks.iter().enumerate() {
        if *idx != pos {
            return Err(HostBackupError::ChunkError {
                artifact: artifact_path.to_path_buf(),
                reason: format!(
                    "non-contiguous chunk sequence: expected .part.{:05}, found .part.{:05}",
                    pos, idx
                ),
            });
        }
        let mut f = File::open(part_path).map_err(|e| {
            HostBackupError::io(format!("opening chunk {}", part_path.display()), e)
        })?;
        let mut part_bytes = 0u64;
        loop {
            let n = f.read(&mut buf).map_err(|e| {
                HostBackupError::io(format!("reading chunk {}", part_path.display()), e)
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            part_bytes += n as u64;
        }
        if part_bytes == 0 {
            return Err(HostBackupError::ChunkError {
                artifact: artifact_path.to_path_buf(),
                reason: format!("chunk '{}' is empty (0 bytes)", part_path.display()),
            });
        }
        if let Some(chunk_sz) = declared_chunk_size {
            if pos + 1 < total_chunks && part_bytes != chunk_sz {
                return Err(HostBackupError::ChunkError {
                    artifact: artifact_path.to_path_buf(),
                    reason: format!(
                        "non-final chunk '{}' has size {} bytes (expected chunk_size_bytes {})",
                        part_path.display(),
                        part_bytes,
                        chunk_sz
                    ),
                });
            }
            if pos + 1 == total_chunks && part_bytes > chunk_sz {
                return Err(HostBackupError::ChunkError {
                    artifact: artifact_path.to_path_buf(),
                    reason: format!(
                        "final chunk '{}' has size {} bytes exceeding chunk_size_bytes {}",
                        part_path.display(),
                        part_bytes,
                        chunk_sz
                    ),
                });
            }
        }
        total_bytes += part_bytes;
    }

    if total_bytes != expected_total_size {
        return Err(HostBackupError::ChunkError {
            artifact: artifact_path.to_path_buf(),
            reason: format!(
                "chunk total size mismatch: chunks sum to {} bytes, primary artifact is {} bytes",
                total_bytes, expected_total_size
            ),
        });
    }

    let actual_sha = hex::encode(hasher.finalize());
    if !actual_sha.eq_ignore_ascii_case(expected_sha256) {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: format!("{} (chunks)", artifact_path.display()),
            expected: expected_sha256.to_ascii_lowercase(),
            actual: actual_sha,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Maintenance Script Ownership & Classification Registry
// ─────────────────────────────────────────────────────────────────────────────

/// Architectural ownership tier for legacy `packages/system/*` host maintenance scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceOwnerCrate {
    /// Owned by `af-host`: backup/snapshot/manifest/verification/restore preflight foundations.
    AfHost,
    /// Owned by `af-runner`: privileged root socket daemon IPC (`setdisk`, `af-systemd-sandbox`, `/etc/hosts`).
    AfRunner,
    /// Owned by `af-services`: background Tokio workers & config mutators (`af-heal` watchdog, smart backup scheduler).
    AfServices,
    /// Owned by `af-release`: atomic single-binary release deployment & rollback (`release-manager.sh`, `updateAetherFlow`).
    AfRelease,
    /// Retained as an external shell/Python script (legacy interactive CLI or third-party app helper).
    RetainedSystemScript,
}

/// Ownership record documenting how each `packages/system/*` script maps into the Rust workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceHelperOwnership {
    pub script_path: &'static str,
    pub owner: MaintenanceOwnerCrate,
    pub rust_replacement_or_entry: &'static str,
    pub destructive_or_privileged: bool,
    pub rationale: &'static str,
}

/// Returns the canonical ownership table for all `packages/system/*` maintenance helpers.
pub const fn maintenance_helper_ownership_registry() -> &'static [MaintenanceHelperOwnership] {
    &[
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-backup",
            owner: MaintenanceOwnerCrate::AfHost,
            rust_replacement_or_entry: "af_host::{create_sqlite_snapshot_backup, create_host_archive_backup, verify_backup_artifact, preflight_restore_directory, preflight_tar_gz_archive}",
            destructive_or_privileged: true,
            rationale: "Shared backup foundation in af-host provides versioned manifests, WAL-safe SQLite snapshots, SHA-256 sidecars, chunk split/assemble, and non-destructive restore preflight.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-heal",
            owner: MaintenanceOwnerCrate::AfServices,
            rust_replacement_or_entry: "af_services::workers::start_heal_worker",
            destructive_or_privileged: true,
            rationale: "Systemd unit health polling with exponential backoff runs in af-services and dispatches restarts through af-runner.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-systemd-sandbox",
            owner: MaintenanceOwnerCrate::AfRunner,
            rust_replacement_or_entry: "af_runner::{apply_package_sandbox_local, render_systemd_sandbox_dropin}",
            destructive_or_privileged: true,
            rationale: "Privileged systemd drop-in generation and daemon-reload execution belong to the root runner daemon.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/setdisk",
            owner: MaintenanceOwnerCrate::AfRunner,
            rust_replacement_or_entry: "af_runner::{execute_set_quota_local, parse_quota_size_to_1k_blocks}",
            destructive_or_privileged: true,
            rationale: "Linux filesystem quota enforcement (setquota) requires root privileges inside af-runner.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/updateAetherFlow",
            owner: MaintenanceOwnerCrate::AfRelease,
            rust_replacement_or_entry: "af_release + deploy/release-manager.sh",
            destructive_or_privileged: true,
            rationale: "Control-plane upgrades, SQLite pre-upgrade snapshots, and atomic symlink swaps are owned by af-release.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-certbot-sync",
            owner: MaintenanceOwnerCrate::RetainedSystemScript,
            rust_replacement_or_entry: "af_runner::update_hosts_file_local (for /etc/hosts) + systemd timer for certbot",
            destructive_or_privileged: true,
            rationale: "Internal .aether.local hosts reconciliation is handled in af-runner/af-services; certbot webroot expansion remains a timer-driven shell utility.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-tune",
            owner: MaintenanceOwnerCrate::RetainedSystemScript,
            rust_replacement_or_entry: "packages/system/af-tune (host sysctl & .rtorrent.rc heuristic tuner)",
            destructive_or_privileged: true,
            rationale: "Mutates kernel sysctl net.core.rmem_max/wmem_max and user .rtorrent.rc; kept as explicit root maintenance script.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/af-sentinel.py",
            owner: MaintenanceOwnerCrate::RetainedSystemScript,
            rust_replacement_or_entry: "packages/system/af-sentinel.py (auth.log anomaly scanner)",
            destructive_or_privileged: true,
            rationale: "Optional standalone log scanner; firewall bans remain external to the unprivileged API.",
        },
        MaintenanceHelperOwnership {
            script_path: "packages/system/showspace",
            owner: MaintenanceOwnerCrate::RetainedSystemScript,
            rust_replacement_or_entry: "af_hardware::get_system_metrics_core + packages/system/showspace CLI",
            destructive_or_privileged: false,
            rationale: "Read-only CLI formatter for /home/<user> disk usage; API uses af-hardware / repquota.",
        },
    ]
}
