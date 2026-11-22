use super::journal::{sqlite_sidecar_paths, RestoreExecutionOptions};
use super::policy::{
    resolve_trusted_canonical_host_destination_with_sqlite_override,
    validate_destination_not_provenance, validate_safe_target_root,
    validate_trusted_sqlite_db_path, OverwritePolicy, PlannedRestoreAction, RestorePlan,
    RestorePlanItem, RestorePreflightOptions,
};
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::{BackupManifest, BackupTargetKind};
use crate::snapshot::verify_sqlite_snapshot_integrity_with_trusted_uid;
use crate::verify::{
    open_existing_regular_file_nofollow, reject_if_symlink, reject_symlink_chain,
    validate_no_parent_traversal, validate_relative_backup_path,
    verify_file_sha256_with_trusted_uid, verify_file_with_sidecar_and_trusted_uid,
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, EntryType};

pub(super) fn validate_execution_target_root(
    target_root: &Path,
) -> HostBackupResult<(PathBuf, bool)> {
    validate_no_parent_traversal(target_root, "restore target_root")?;
    let raw = target_root.to_string_lossy();
    if raw == "/" {
        reject_if_symlink(Path::new("/"), "canonical host root")?;
        return Ok((PathBuf::from("/"), true));
    }
    let norm = validate_safe_target_root(target_root)?;
    Ok((norm, false))
}

pub(super) fn resolve_effective_relative_destination<'a>(
    relative_path: &'a str,
    entry_kind: Option<BackupTargetKind>,
    sqlite_target_rel_path: Option<&'a str>,
) -> &'a str {
    if entry_kind == Some(BackupTargetKind::SqliteSnapshot) {
        if let Some(custom_rel) = sqlite_target_rel_path
            .map(|raw_rel| raw_rel.trim())
            .filter(|raw_rel| !raw_rel.is_empty())
        {
            custom_rel
        } else {
            "var/lib/aetherflow/aetherflow.sqlite"
        }
    } else {
        relative_path
    }
}

fn split_sqlite_override_path(
    sqlite_override: Option<&Path>,
) -> HostBackupResult<(Option<String>, Option<&Path>)> {
    match sqlite_override {
        None => Ok((None, None)),
        Some(path_val) if path_val.is_absolute() => Ok((None, Some(path_val))),
        Some(path_val) => {
            let rel_str = path_val
                .to_str()
                .ok_or_else(|| HostBackupError::PathValidation {
                    path: path_val.to_path_buf(),
                    reason: "relative sqlite override path must be valid UTF-8".to_string(),
                })?;
            let _ = validate_relative_backup_path(rel_str)?;
            Ok((Some(rel_str.to_string()), None))
        }
    }
}

pub(super) fn plan_single_destination_with_options(
    target_root: &Path,
    relative_path: &str,
    entry_kind: Option<BackupTargetKind>,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    overwrite_policy: OverwritePolicy,
) -> HostBackupResult<(PathBuf, PlannedRestoreAction)> {
    let effective_rel =
        resolve_effective_relative_destination(relative_path, entry_kind, sqlite_target_rel_path);
    let rel_buf = validate_relative_backup_path(effective_rel)?;
    let is_sqlite_entry = entry_kind == Some(BackupTargetKind::SqliteSnapshot);
    let has_explicit_sqlite_rel = sqlite_target_rel_path
        .map(|raw_rel| !raw_rel.trim().is_empty())
        .unwrap_or(false);

    if !is_sqlite_entry {
        let normalized_rel = rel_buf.to_string_lossy().replace('\\', "/");
        if normalized_rel == "var/lib/aetherflow/aetherflow.sqlite"
            || normalized_rel == "var/lib/aetherflow/aetherflow.sqlite-wal"
            || normalized_rel == "var/lib/aetherflow/aetherflow.sqlite-shm"
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "non-SQLite entry '{}' must not target canonical SQLite database or WAL/SHM paths",
                relative_path
            )));
        }
    }

    let dest = if let (true, Some(custom_db)) = (is_sqlite_entry, trusted_sqlite_db_path) {
        let validated_db = validate_trusted_sqlite_db_path(custom_db)?;
        let parent_anchor = validated_db
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| target_root.to_path_buf());
        reject_symlink_chain(&parent_anchor, &validated_db)?;
        validated_db
    } else if target_root == Path::new("/") {
        if is_sqlite_entry && has_explicit_sqlite_rel {
            let candidate_abs = Path::new("/").join(&rel_buf);
            let validated_db = validate_trusted_sqlite_db_path(&candidate_abs)?;
            let parent_anchor = validated_db
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| target_root.to_path_buf());
            reject_symlink_chain(&parent_anchor, &validated_db)?;
            validated_db
        } else {
            let (_anchor, mapped_dest) =
                resolve_trusted_canonical_host_destination_with_sqlite_override(
                    target_root,
                    effective_rel,
                    trusted_sqlite_db_path,
                )?;
            mapped_dest
        }
    } else {
        let dest_under_root = target_root.join(&rel_buf);
        reject_symlink_chain(target_root, &dest_under_root)?;
        dest_under_root
    };

    validate_destination_not_provenance(&dest, target_root, None)?;

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

pub(super) fn validate_unique_resolved_destinations<'a, I>(items: I) -> HostBackupResult<()>
where
    I: IntoIterator<Item = (&'a str, &'a Path, BackupTargetKind)>,
{
    let mut seen_destinations: HashMap<PathBuf, String> = HashMap::new();
    let mut reserved_sidecars: HashMap<PathBuf, String> = HashMap::new();
    let collected: Vec<(&'a str, &'a Path, BackupTargetKind)> = items.into_iter().collect();

    for (rel_label, dest_path, kind) in &collected {
        if let Some(prev_label) =
            seen_destinations.insert(dest_path.to_path_buf(), (*rel_label).to_string())
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "duplicate resolved restore destination '{}' shared by '{}' and '{}'",
                dest_path.display(),
                prev_label,
                rel_label
            )));
        }
        if *kind == BackupTargetKind::SqliteSnapshot {
            let (wal_path, shm_path) = sqlite_sidecar_paths(dest_path);
            reserved_sidecars.insert(wal_path, (*rel_label).to_string());
            reserved_sidecars.insert(shm_path, (*rel_label).to_string());
        }
    }

    for (rel_label, dest_path, _) in &collected {
        if let Some(sqlite_owner) = reserved_sidecars.get(*dest_path) {
            return Err(HostBackupError::InvalidManifest(format!(
                "restore entry '{}' resolves to SQLite WAL/SHM sidecar path '{}' owned by '{}'",
                rel_label,
                dest_path.display(),
                sqlite_owner
            )));
        }
    }

    Ok(())
}

/// Computes a purely non-destructive [`RestorePlan`] from a validated [`BackupManifest`]
/// without touching any files under `target_root`.
pub fn plan_restore_from_manifest(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    plan_restore_from_manifest_with_sqlite_override(manifest, target_root, options, None)
}

/// Computes a purely non-destructive [`RestorePlan`] from a validated [`BackupManifest`]
/// with an optional server-configured trusted SQLite destination override (`trusted_sqlite_db_path`).
/// Accepts either a relative override (`sqlite_target_rel_path`) or an absolute `trusted_sqlite_db_path`.
pub fn plan_restore_from_manifest_with_sqlite_override(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn plan_restore_from_manifest_with_sqlite_overrides(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )
}

pub fn plan_restore_from_manifest_for_execution(
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

pub(super) fn plan_restore_from_manifest_internal(
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (normalized_root, _) = validate_execution_target_root(target_root)?;
    let compatibility = manifest.check_compatibility(
        &options.host_app_version,
        options.max_supported_sqlite_user_version,
    )?;

    let mut items = Vec::with_capacity(manifest.entries.len());
    let mut total_bytes = 0u64;

    for entry in &manifest.entries {
        let (dest, action) = plan_single_destination_with_options(
            &normalized_root,
            &entry.relative_path,
            Some(entry.kind),
            sqlite_target_rel_path,
            trusted_sqlite_db_path,
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

    validate_unique_resolved_destinations(items.iter().map(|item| {
        (
            item.relative_path.as_str(),
            item.destination_path.as_path(),
            item.kind,
        )
    }))?;

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
/// [`BackupManifest`] and its referenced files on disk.
pub fn preflight_restore_directory(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    preflight_restore_directory_with_sqlite_override(
        backup_source_dir,
        manifest,
        target_root,
        options,
        None,
    )
}

/// Runs [`preflight_restore_directory`] with an optional server-configured trusted SQLite destination override.
pub fn preflight_restore_directory_with_sqlite_override(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    preflight_restore_directory_with_sqlite_overrides(
        backup_source_dir,
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn preflight_restore_directory_with_sqlite_overrides(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
        backup_source_dir,
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
        None,
    )
}

pub fn preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    trusted_sqlite_uid: Option<u32>,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(backup_source_dir, "backup_source_dir")?;
    reject_if_symlink(backup_source_dir, "backup_source_dir")?;

    let mut plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )?;

    for entry in &manifest.entries {
        let rel = validate_relative_backup_path(&entry.relative_path)?;
        let src_path = backup_source_dir.join(&rel);
        reject_symlink_chain(backup_source_dir, &src_path)?;

        let entry_trusted_uid = if entry.kind == BackupTargetKind::SqliteSnapshot {
            trusted_sqlite_uid
        } else {
            None
        };

        let opened = open_existing_regular_file_nofollow(
            &src_path,
            entry_trusted_uid,
            "preflight backup entry",
        )?;
        if opened.is_none() {
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
        drop(opened);

        let verification =
            verify_file_sha256_with_trusted_uid(&src_path, &entry.sha256, entry_trusted_uid)?;
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
            verify_file_with_sidecar_and_trusted_uid(&snap_path, trusted_sqlite_uid)?;
        }
        let verification =
            verify_file_sha256_with_trusted_uid(&snap_path, &snap.sha256, trusted_sqlite_uid)?;
        if verification.size_bytes != snap.size_bytes {
            return Err(HostBackupError::InvalidManifest(format!(
                "SQLite snapshot size mismatch for '{}': expected {}, got {}",
                snap.snapshot_relative_path, snap.size_bytes, verification.size_bytes
            )));
        }
        let (uv, _, _) =
            verify_sqlite_snapshot_integrity_with_trusted_uid(&snap_path, trusted_sqlite_uid)?;
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

pub fn preflight_restore_directory_for_execution(
    backup_source_dir: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
        backup_source_dir,
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
        exec_options.trusted_sqlite_uid,
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

/// Inspects a `.tar.gz` backup archive completely in-memory (streaming without extracting to disk).
pub fn preflight_tar_gz_archive(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
) -> HostBackupResult<RestorePlan> {
    preflight_tar_gz_archive_with_sqlite_override(
        archive_path,
        manifest,
        target_root,
        options,
        None,
    )
}

/// Runs [`preflight_tar_gz_archive`] with an optional server-configured trusted SQLite destination override.
pub fn preflight_tar_gz_archive_with_sqlite_override(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    let (sqlite_rel, sqlite_abs) = split_sqlite_override_path(trusted_sqlite_db_path)?;
    preflight_tar_gz_archive_with_sqlite_overrides(
        archive_path,
        manifest,
        target_root,
        options,
        sqlite_rel.as_deref(),
        sqlite_abs,
    )
}

pub fn preflight_tar_gz_archive_with_sqlite_overrides(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<RestorePlan> {
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
        archive_path,
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
        None,
    )
}

pub fn preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    options: &RestorePreflightOptions,
    sqlite_target_rel_path: Option<&str>,
    trusted_sqlite_db_path: Option<&Path>,
    trusted_uid: Option<u32>,
) -> HostBackupResult<RestorePlan> {
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    if options.require_artifact_sidecar {
        verify_file_with_sidecar_and_trusted_uid(archive_path, trusted_uid)?;
    }

    let plan = plan_restore_from_manifest_internal(
        manifest,
        target_root,
        options,
        sqlite_target_rel_path,
        trusted_sqlite_db_path,
    )?;

    verify_tar_gz_against_manifest_with_options_and_uid(
        archive_path,
        manifest,
        Some((
            &plan.target_root,
            options.overwrite_policy,
            sqlite_target_rel_path,
            trusted_sqlite_db_path,
        )),
        trusted_uid,
    )?;

    Ok(plan)
}

pub fn preflight_tar_gz_archive_for_execution(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root: &Path,
    exec_options: &RestoreExecutionOptions,
) -> HostBackupResult<RestorePlan> {
    let overwrite_policy = if exec_options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };
    let preflight_opts = RestorePreflightOptions {
        host_app_version: exec_options.host_app_version.clone(),
        max_supported_sqlite_user_version: exec_options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let plan = preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
        archive_path,
        manifest,
        target_root,
        &preflight_opts,
        exec_options.sqlite_target_rel_path.as_deref(),
        exec_options.trusted_sqlite_db_path.as_deref(),
        exec_options.trusted_sqlite_uid,
    )?;
    for item in &plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &plan.target_root,
            exec_options.provenance_dir.as_deref(),
        )?;
    }
    Ok(plan)
}

pub(crate) fn verify_tar_gz_against_manifest_with_trusted_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    trusted_uid: Option<u32>,
) -> HostBackupResult<()> {
    verify_tar_gz_against_manifest_with_options_and_uid(archive_path, manifest, None, trusted_uid)
}

#[allow(clippy::type_complexity)]
pub(crate) fn verify_tar_gz_against_manifest_with_options_and_uid(
    archive_path: &Path,
    manifest: &BackupManifest,
    target_root_check: Option<(&Path, OverwritePolicy, Option<&str>, Option<&Path>)>,
    trusted_uid: Option<u32>,
) -> HostBackupResult<()> {
    manifest.validate()?;
    validate_no_parent_traversal(archive_path, "archive_path")?;
    reject_if_symlink(archive_path, "backup tar.gz archive")?;

    let expected_by_path: HashMap<String, &crate::manifest::BackupManifestEntry> = manifest
        .entries
        .iter()
        .filter(|entry_item| entry_item.kind != BackupTargetKind::TarGzArchive)
        .map(|entry_item| (entry_item.relative_path.replace('\\', "/"), entry_item))
        .collect();

    let (file, _, _, _) =
        open_existing_regular_file_nofollow(archive_path, trusted_uid, "backup tar.gz archive")?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: archive_path.to_path_buf(),
                reason: "backup tar.gz archive does not exist".to_string(),
            })?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut seen_entries = HashSet::new();
    let mut resolved_for_uniqueness: Vec<(String, PathBuf, BackupTargetKind)> = Vec::new();
    let entries_iter = archive.entries().map_err(|err| HostBackupError::Archive {
        archive: archive_path.to_path_buf(),
        reason: format!("failed to read tar header stream: {}", err),
    })?;

    for entry_result in entries_iter {
        let mut entry = entry_result.map_err(|err| HostBackupError::Archive {
            archive: archive_path.to_path_buf(),
            reason: format!("corrupt tar entry header: {}", err),
        })?;

        let entry_type = entry.header().entry_type();
        let raw_path_bytes = entry.path_bytes();
        let raw_path_str = String::from_utf8_lossy(&raw_path_bytes).into_owned();

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
            if let Some((target_root, _, _, _)) = target_root_check {
                if target_root != Path::new("/") {
                    let dir_dest = target_root.join(&norm_rel);
                    reject_symlink_chain(target_root, &dir_dest)?;
                }
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

        let expected_opt = expected_by_path.get(&key).copied();
        if let Some((target_root, overwrite_policy, sqlite_rel_opt, trusted_sqlite_db_path)) =
            target_root_check
        {
            let (resolved_dest, _) = plan_single_destination_with_options(
                target_root,
                &key,
                expected_opt.map(|item| item.kind),
                sqlite_rel_opt,
                trusted_sqlite_db_path,
                overwrite_policy,
            )?;
            if let Some(expected_entry) = expected_opt {
                resolved_for_uniqueness.push((key.clone(), resolved_dest, expected_entry.kind));
            }
        }

        let Some(expected) = expected_opt else {
            return Err(HostBackupError::InvalidManifest(format!(
                "tar archive contains undeclared file '{}' not present in BackupManifest",
                key
            )));
        };

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            let bytes_read = entry
                .read(&mut buf)
                .map_err(|err| HostBackupError::Archive {
                    archive: archive_path.to_path_buf(),
                    reason: format!("failed reading tar payload for '{}': {}", key, err),
                })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buf[..bytes_read]);
            read_bytes += bytes_read as u64;
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
                reason: format!(
                    "required manifest entry '{}' is missing from tar archive",
                    key
                ),
            });
        }
    }

    if !resolved_for_uniqueness.is_empty() {
        validate_unique_resolved_destinations(
            resolved_for_uniqueness
                .iter()
                .map(|(rel_key, dest_path, kind)| (rel_key.as_str(), dest_path.as_path(), *kind)),
        )?;
    }

    Ok(())
}

/// Explicitly unsupported unconfirmed/in-place destructive live-host restore entry point.
pub fn execute_destructive_restore(_plan: &RestorePlan) -> HostBackupResult<()> {
    Err(HostBackupError::DestructiveRestoreUnsupported {
        reason: "in-place destructive host/database overwrite is disabled by design; run preflight verification and perform state replacement only under an offline maintenance window".to_string(),
    })
}
