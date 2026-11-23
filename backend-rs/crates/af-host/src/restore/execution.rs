use super::journal::{
    persist_committed_journal_snapshot, persist_recovery_journal_snapshot,
    persist_recovery_journal_snapshot_with_fault, remove_recovery_dir_and_provenance_with_fault,
    resolve_restored_entry_mode, sanitize_sqlite_sidecar_mode, sqlite_sidecar_paths,
    write_exclusive_staged_file, write_journal_with_sidecar_and_provenance,
    RestoreExecutionOptions, RestoreExecutionReport, RollbackFailureJournal,
    RollbackFailureJournalEntry, RollbackRecord, StagedRestoreEntry,
    IN_PROGRESS_RECOVERY_JOURNAL_FILENAME, JOURNAL_STATE_ABORTED_CLEAN, JOURNAL_STATE_COMMITTED,
    JOURNAL_STATE_IN_PROGRESS, JOURNAL_STATE_QUIESCING, JOURNAL_STATE_ROLLBACK_FAILED,
    JOURNAL_STATE_ROLLED_BACK,
};
use super::policy::{
    is_service_data_dir_secret_destination, is_service_data_dir_secret_key,
    resolve_effective_quiesce_services, resolve_recovery_provenance_dir,
    validate_destination_not_provenance, validate_quiesce_service_entries,
    validate_trusted_sqlite_db_path, OverwritePolicy, RestorePreflightOptions,
};
use super::preflight::{
    plan_restore_from_manifest_internal, plan_single_destination_with_options,
    resolve_effective_relative_destination, validate_execution_target_root,
    validate_unique_resolved_destinations,
};
use super::quiescence::{stop_services_with_compensation, ServiceQuiescenceController};
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::BackupTargetKind;
use crate::snapshot::{
    verify_sqlite_snapshot_integrity, verify_sqlite_snapshot_integrity_with_trusted_uid,
};
use crate::verify::{
    atomic_install_file_at_destination_with_verification, open_existing_regular_file_nofollow,
    open_or_create_dir_nofollow, reject_symlink_chain, safe_backup_file_path,
    unlink_file_at_destination_with_trusted_ancestor_uid, validate_relative_backup_path,
    verify_file_sha256_with_trusted_uid,
};
use flate2::read::GzDecoder;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tar::{Archive, EntryType};

fn effective_is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn uses_service_data_dir_ownership(
    relative_key: Option<&str>,
    dest: &Path,
    kind: BackupTargetKind,
) -> bool {
    kind == BackupTargetKind::SqliteSnapshot
        || relative_key.is_some_and(is_service_data_dir_secret_key)
        || is_service_data_dir_secret_destination(dest)
}

/// Executes a verified, offline-staged, service-quiesced, rollback-protected restore of a backup
/// artifact (`<filename>` inside `backup_dir`) into `target_root`.
pub fn execute_staged_restore<Q: ServiceQuiescenceController>(
    backup_dir: &Path,
    filename: &str,
    target_root: &Path,
    options: &RestoreExecutionOptions,
    quiescence: &Q,
) -> HostBackupResult<RestoreExecutionReport> {
    if !options.confirm_destructive_restore {
        return Err(HostBackupError::DestructiveRestoreUnsupported {
            reason: "destructive restore requires explicit confirmation (confirm_destructive_restore=true) after non-destructive preflight".to_string(),
        });
    }

    let (normalized_root, is_canonical_root) = validate_execution_target_root(target_root)?;
    if let Some(ref custom_db) = options.trusted_sqlite_db_path {
        let validated_custom_db = validate_trusted_sqlite_db_path(custom_db)?;
        validate_destination_not_provenance(
            &validated_custom_db,
            &normalized_root,
            options.provenance_dir.as_deref(),
        )?;
    }
    let validated_requested = validate_quiesce_service_entries(&options.quiesce_services)?;
    let effective_services = resolve_effective_quiesce_services(&validated_requested);

    let (verification, maybe_manifest) = crate::backup::verify_backup_artifact_with_trusted_uid(
        backup_dir,
        filename,
        options.trusted_sqlite_uid,
    )?;
    if !verification.verified {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: filename.to_string(),
            expected: verification.expected_sha256,
            actual: verification.actual_sha256,
        });
    }

    let manifest = maybe_manifest.ok_or_else(|| {
        HostBackupError::InvalidManifest(format!(
            "backup '{}' does not have a verified .manifest.json sidecar required for safe staged restore",
            filename
        ))
    })?;

    let _compat = manifest.check_compatibility(
        &options.host_app_version,
        options.max_supported_sqlite_user_version,
    )?;

    let overwrite_policy = if options.allow_overwrite {
        OverwritePolicy::AllowRegularFilesInStaging
    } else {
        OverwritePolicy::RejectExisting
    };

    let preflight_opts = RestorePreflightOptions {
        host_app_version: options.host_app_version.clone(),
        max_supported_sqlite_user_version: options.max_supported_sqlite_user_version,
        overwrite_policy,
        require_artifact_sidecar: true,
    };
    let validated_plan = plan_restore_from_manifest_internal(
        &manifest,
        &normalized_root,
        &preflight_opts,
        options.sqlite_target_rel_path.as_deref(),
        options.trusted_sqlite_db_path.as_deref(),
    )?;
    for item in &validated_plan.items {
        validate_destination_not_provenance(
            &item.destination_path,
            &validated_plan.target_root,
            options.provenance_dir.as_deref(),
        )?;
    }

    let artifact_path = safe_backup_file_path(backup_dir, filename)?;
    let provenance_dir =
        resolve_recovery_provenance_dir(&normalized_root, options.provenance_dir.as_deref());

    let run_id = format!("{}.{}", std::process::id(), uuid::Uuid::new_v4());
    let staging_dir = backup_dir.join(format!(".staging-restore.{}", run_id));
    let rollback_dir = backup_dir.join(format!(".rollback-restore.{}", run_id));

    open_or_create_dir_nofollow(&staging_dir, 0o700, "restore staging dir")?;

    let stage_result = (|| -> HostBackupResult<(Vec<StagedRestoreEntry>, Option<i64>, bool)> {
        let mut staged_entries = Vec::new();
        let mut sqlite_uv = None;
        let mut sqlite_verified = false;

        if filename.ends_with(".tar.gz") {
            let expected_by_path: HashMap<String, &crate::manifest::BackupManifestEntry> = manifest
                .entries
                .iter()
                .filter(|entry| entry.kind != BackupTargetKind::TarGzArchive)
                .map(|entry| (entry.relative_path.replace('\\', "/"), entry))
                .collect();

            let (file, _, _, _) = open_existing_regular_file_nofollow(
                &artifact_path,
                options.trusted_sqlite_uid,
                "backup tar.gz archive",
            )?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: "backup tar.gz archive does not exist".to_string(),
            })?;
            let gz = GzDecoder::new(file);
            let mut archive = Archive::new(gz);
            let mut seen = HashSet::new();

            let entries_iter = archive.entries().map_err(|err| HostBackupError::Archive {
                archive: artifact_path.clone(),
                reason: format!("reading tar entries: {}", err),
            })?;

            for entry_res in entries_iter {
                let mut entry = entry_res.map_err(|err| HostBackupError::Archive {
                    archive: artifact_path.clone(),
                    reason: format!("corrupt tar entry: {}", err),
                })?;
                let entry_type = entry.header().entry_type();
                let header_mode = entry.header().mode().ok().map(|mode_val| mode_val & 0o7777);
                let header_uid = entry
                    .header()
                    .uid()
                    .ok()
                    .and_then(|uid_val| u32::try_from(uid_val).ok());
                let header_gid = entry
                    .header()
                    .gid()
                    .ok()
                    .and_then(|gid_val| u32::try_from(gid_val).ok());

                let raw_path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
                if entry_type == EntryType::Symlink || entry_type == EntryType::Link {
                    return Err(HostBackupError::SymlinkRejected {
                        path: PathBuf::from(&raw_path),
                        reason: format!(
                            "tar archive contains forbidden {:?} entry '{}'",
                            entry_type, raw_path
                        ),
                    });
                }
                let norm_rel = validate_relative_backup_path(&raw_path)?;
                let key = norm_rel.to_string_lossy().replace('\\', "/");
                if entry_type == EntryType::Directory {
                    if !is_canonical_root {
                        let dir_dest = normalized_root.join(&norm_rel);
                        reject_symlink_chain(&normalized_root, &dir_dest)?;
                    }
                    continue;
                }
                if entry_type != EntryType::Regular && entry_type != EntryType::Continuous {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("unsupported tar entry type {:?} at '{}'", entry_type, key),
                    });
                }
                if !seen.insert(key.clone()) {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("duplicate tar entry '{}'", key),
                    });
                }

                let expected = expected_by_path.get(&key).ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!("undeclared tar entry '{}'", key))
                })?;

                let (dest_path, _) = plan_single_destination_with_options(
                    &normalized_root,
                    &key,
                    Some(expected.kind),
                    options.sqlite_target_rel_path.as_deref(),
                    options.trusted_sqlite_db_path.as_deref(),
                    overwrite_policy,
                )?;
                validate_destination_not_provenance(
                    &dest_path,
                    &normalized_root,
                    options.provenance_dir.as_deref(),
                )?;
                let staged_path = staging_dir.join(&norm_rel);
                reject_symlink_chain(&staging_dir, &staged_path)?;

                let mode = resolve_restored_entry_mode(
                    expected.unix_mode.or(header_mode),
                    &key,
                    expected.kind,
                    options,
                );
                let is_service_secret = is_service_data_dir_secret_key(&key)
                    || is_service_data_dir_secret_destination(&dest_path);
                let uid = if expected.kind == BackupTargetKind::SqliteSnapshot {
                    options
                        .trusted_sqlite_uid
                        .or(expected.unix_uid)
                        .or(header_uid)
                } else if is_service_secret {
                    if effective_is_root() {
                        options
                            .trusted_sqlite_uid
                            .or(expected.unix_uid)
                            .or(header_uid)
                    } else {
                        None
                    }
                } else {
                    expected.unix_uid.or(header_uid)
                };
                let gid = if expected.kind == BackupTargetKind::SqliteSnapshot {
                    options
                        .trusted_sqlite_gid
                        .or(expected.unix_gid)
                        .or(header_gid)
                } else if is_service_secret {
                    if effective_is_root() {
                        options
                            .trusted_sqlite_gid
                            .or(expected.unix_gid)
                            .or(header_gid)
                    } else {
                        None
                    }
                } else {
                    expected.unix_gid.or(header_gid)
                };

                let (pinned_file, staged_dev_ino, actual_sha, actual_size) =
                    write_exclusive_staged_file(&staged_path, &mut entry, 0o600)?;
                if !actual_sha.eq_ignore_ascii_case(&expected.sha256) {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: format!("{}:{}", filename, key),
                        expected: expected.sha256.clone(),
                        actual: actual_sha,
                    });
                }
                if actual_size != expected.size_bytes {
                    return Err(HostBackupError::InvalidManifest(format!(
                        "size mismatch for '{}': expected {}, got {}",
                        key, expected.size_bytes, actual_size
                    )));
                }

                if expected.kind == BackupTargetKind::SqliteSnapshot {
                    let (uv, _, _) = verify_sqlite_snapshot_integrity(&staged_path)?;
                    if let Some(ref snap_meta) = manifest.sqlite_snapshot {
                        if uv != snap_meta.sqlite_user_version {
                            return Err(HostBackupError::InvalidManifest(format!(
                                "staged SQLite user_version mismatch: manifest declared {}, actual {}",
                                snap_meta.sqlite_user_version, uv
                            )));
                        }
                    }
                    sqlite_uv = Some(uv);
                    sqlite_verified = true;
                }

                staged_entries.push(StagedRestoreEntry {
                    relative_key: key,
                    staged_path,
                    _pinned_file: pinned_file,
                    staged_dev_ino,
                    expected_sha256: actual_sha,
                    expected_size: actual_size,
                    destination_path: dest_path,
                    kind: expected.kind,
                    unix_mode: mode,
                    unix_uid: uid,
                    unix_gid: gid,
                });
            }

            for (key, expected) in &expected_by_path {
                if expected.required && !seen.contains(key) {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!("required manifest entry '{}' missing from archive", key),
                    });
                }
            }
        } else if filename.ends_with(".sqlite") {
            let entry = manifest
                .entries
                .iter()
                .find(|item| item.kind == BackupTargetKind::SqliteSnapshot)
                .ok_or_else(|| {
                    HostBackupError::InvalidManifest(
                        "standalone SQLite backup manifest has no SqliteSnapshot entry".to_string(),
                    )
                })?;

            let rel_dest = resolve_effective_relative_destination(
                &entry.relative_path,
                Some(BackupTargetKind::SqliteSnapshot),
                options.sqlite_target_rel_path.as_deref(),
            );

            let (dest_path, _) = plan_single_destination_with_options(
                &normalized_root,
                rel_dest,
                Some(BackupTargetKind::SqliteSnapshot),
                options.sqlite_target_rel_path.as_deref(),
                options.trusted_sqlite_db_path.as_deref(),
                overwrite_policy,
            )?;
            validate_destination_not_provenance(
                &dest_path,
                &normalized_root,
                options.provenance_dir.as_deref(),
            )?;
            let staged_path = staging_dir.join("staged_snapshot.sqlite");
            let (mut src_file, _, _, _) = open_existing_regular_file_nofollow(
                &artifact_path,
                options.trusted_sqlite_uid,
                "SQLite backup snapshot",
            )?
            .ok_or_else(|| HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: "SQLite backup snapshot does not exist".to_string(),
            })?;
            let (pinned_file, staged_dev_ino, actual_sha, actual_size) =
                write_exclusive_staged_file(&staged_path, &mut src_file, 0o600)?;
            if !actual_sha.eq_ignore_ascii_case(&entry.sha256) {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: filename.to_string(),
                    expected: entry.sha256.clone(),
                    actual: actual_sha,
                });
            }
            if actual_size != entry.size_bytes {
                return Err(HostBackupError::InvalidManifest(format!(
                    "SQLite snapshot size mismatch: expected {}, got {}",
                    entry.size_bytes, actual_size
                )));
            }
            let (uv, _, _) = verify_sqlite_snapshot_integrity(&staged_path)?;
            sqlite_uv = Some(uv);
            sqlite_verified = true;

            staged_entries.push(StagedRestoreEntry {
                relative_key: rel_dest.to_string(),
                staged_path,
                _pinned_file: pinned_file,
                staged_dev_ino,
                expected_sha256: actual_sha,
                expected_size: actual_size,
                destination_path: dest_path,
                kind: BackupTargetKind::SqliteSnapshot,
                unix_mode: resolve_restored_entry_mode(
                    entry.unix_mode,
                    rel_dest,
                    BackupTargetKind::SqliteSnapshot,
                    options,
                ),
                unix_uid: options.trusted_sqlite_uid.or(entry.unix_uid),
                unix_gid: options.trusted_sqlite_gid.or(entry.unix_gid),
            });
        } else {
            return Err(HostBackupError::PathValidation {
                path: artifact_path.clone(),
                reason: format!("unsupported backup artifact extension for '{}'", filename),
            });
        }

        validate_unique_resolved_destinations(staged_entries.iter().map(|staged_item| {
            (
                staged_item.relative_key.as_str(),
                staged_item.destination_path.as_path(),
                staged_item.kind,
            )
        }))?;

        Ok((staged_entries, sqlite_uv, sqlite_verified))
    })();

    let (staged_entries, sqlite_uv, sqlite_verified) = match stage_result {
        Ok(staged_val) => staged_val,
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(err);
        }
    };

    if let Err(err) = open_or_create_dir_nofollow(&rollback_dir, 0o700, "restore rollback dir") {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err);
    }

    let in_progress_journal_path = rollback_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
    let mut rollback_records: Vec<RollbackRecord> = Vec::new();
    let mut journal_generation = 0u64;

    if let Err(err) = persist_recovery_journal_snapshot_with_fault(
        &in_progress_journal_path,
        &provenance_dir,
        &mut journal_generation,
        &manifest.backup_id,
        filename,
        &normalized_root,
        &rollback_dir,
        &effective_services,
        &rollback_records,
        JOURNAL_STATE_QUIESCING,
        options.trusted_sqlite_db_path.as_deref(),
        options.fail_initial_local_journal_write,
    ) {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
            &rollback_dir,
            &provenance_dir,
            options.fail_early_cleanup_remove_rb_dir,
        ) {
            return Err(HostBackupError::InvalidManifest(format!(
                "initial recovery journal persistence failed ({}) and cleanup of '{}' failed ({})",
                err,
                rollback_dir.display(),
                cleanup_err
            )));
        }
        return Err(err);
    }

    if let Err((stop_err, comp_failed)) =
        stop_services_with_compensation(quiescence, &effective_services)
    {
        drop(staged_entries);
        let _ = fs::remove_dir_all(&staging_dir);
        if !comp_failed
            && persist_recovery_journal_snapshot(
                &in_progress_journal_path,
                &provenance_dir,
                &mut journal_generation,
                &manifest.backup_id,
                filename,
                &normalized_root,
                &rollback_dir,
                &effective_services,
                &rollback_records,
                JOURNAL_STATE_ABORTED_CLEAN,
                options.trusted_sqlite_db_path.as_deref(),
            )
            .is_ok()
        {
            if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
                &rollback_dir,
                &provenance_dir,
                options.fail_early_cleanup_remove_rb_dir,
            ) {
                return Err(HostBackupError::InvalidManifest(format!(
                    "service quiescence failed ({}) and cleanup of aborted recovery directory '{}' failed ({})",
                    stop_err,
                    rollback_dir.display(),
                    cleanup_err
                )));
            }
        }
        return Err(stop_err);
    }

    let mut restored_files: Vec<PathBuf> = Vec::new();
    let mut sqlite_restored = false;
    let mut committed_durably = false;

    let apply_result = (|| -> HostBackupResult<()> {
        persist_recovery_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            JOURNAL_STATE_IN_PROGRESS,
            options.trusted_sqlite_db_path.as_deref(),
        )?;

        for (idx, item) in staged_entries.iter().enumerate() {
            if !is_canonical_root {
                reject_symlink_chain(&normalized_root, &item.destination_path)?;
            }

            let trusted_ancestor_uid = if uses_service_data_dir_ownership(
                Some(&item.relative_key),
                &item.destination_path,
                item.kind,
            ) {
                options.trusted_sqlite_uid
            } else {
                None
            };

            let existing_dest = open_existing_regular_file_nofollow(
                &item.destination_path,
                trusted_ancestor_uid,
                "existing restore destination file",
            )?;

            let mut existed_before = false;
            let mut orig_mode = None;
            let mut orig_uid = None;
            let mut orig_gid = None;
            let mut rollback_copy_path = None;
            let mut rollback_copy_file = None;
            let mut rollback_copy_dev_ino = None;
            let mut rollback_copy_sha256 = None;
            let mut rollback_copy_size = None;

            if let Some((mut orig_file, fd_mode, fd_uid, fd_gid)) = existing_dest {
                existed_before = true;
                orig_mode = Some(fd_mode & 0o7777);
                orig_uid = Some(fd_uid);
                orig_gid = Some(fd_gid);
                let rb_file = rollback_dir.join(format!("entry_{}.bak", idx));
                let (copy_file, copy_dev_ino, copy_sha, copy_size) =
                    write_exclusive_staged_file(&rb_file, &mut orig_file, 0o600)?;
                rollback_copy_path = Some(rb_file);
                rollback_copy_file = Some(std::sync::Arc::new(copy_file));
                rollback_copy_dev_ino = copy_dev_ino;
                rollback_copy_sha256 = Some(copy_sha);
                rollback_copy_size = Some(copy_size);
            }

            let mut had_wal_copy = None;
            let mut wal_copy_file = None;
            let mut wal_copy_dev_ino = None;
            let mut wal_copy_sha256 = None;
            let mut wal_copy_size = None;
            let mut had_shm_copy = None;
            let mut shm_copy_file = None;
            let mut shm_copy_dev_ino = None;
            let mut shm_copy_sha256 = None;
            let mut shm_copy_size = None;
            let mut wal_attrs = (None, None, None);
            let mut shm_attrs = (None, None, None);

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&item.destination_path);
                if let Some((mut wal_file, wal_fd_mode, wal_fd_uid, wal_fd_gid)) =
                    open_existing_regular_file_nofollow(
                        &wal_path,
                        trusted_ancestor_uid,
                        "existing SQLite WAL sidecar",
                    )?
                {
                    wal_attrs = (
                        Some(wal_fd_mode & 0o7777),
                        Some(wal_fd_uid),
                        Some(wal_fd_gid),
                    );
                    let rb_wal = rollback_dir.join(format!("entry_{}.wal.bak", idx));
                    let (wal_pinned, wal_dev_ino, wal_sha, wal_sz) =
                        write_exclusive_staged_file(&rb_wal, &mut wal_file, 0o600)?;
                    had_wal_copy = Some(rb_wal);
                    wal_copy_file = Some(std::sync::Arc::new(wal_pinned));
                    wal_copy_dev_ino = wal_dev_ino;
                    wal_copy_sha256 = Some(wal_sha);
                    wal_copy_size = Some(wal_sz);
                }
                if let Some((mut shm_file, shm_fd_mode, shm_fd_uid, shm_fd_gid)) =
                    open_existing_regular_file_nofollow(
                        &shm_path,
                        trusted_ancestor_uid,
                        "existing SQLite SHM sidecar",
                    )?
                {
                    shm_attrs = (
                        Some(shm_fd_mode & 0o7777),
                        Some(shm_fd_uid),
                        Some(shm_fd_gid),
                    );
                    let rb_shm = rollback_dir.join(format!("entry_{}.shm.bak", idx));
                    let (shm_pinned, shm_dev_ino, shm_sha, shm_sz) =
                        write_exclusive_staged_file(&rb_shm, &mut shm_file, 0o600)?;
                    had_shm_copy = Some(rb_shm);
                    shm_copy_file = Some(std::sync::Arc::new(shm_pinned));
                    shm_copy_dev_ino = shm_dev_ino;
                    shm_copy_sha256 = Some(shm_sha);
                    shm_copy_size = Some(shm_sz);
                }
            }

            rollback_records.push(RollbackRecord {
                destination_path: item.destination_path.clone(),
                kind: item.kind,
                existed_before,
                rollback_copy_path,
                _rollback_copy_file: rollback_copy_file,
                rollback_copy_dev_ino,
                rollback_copy_sha256,
                rollback_copy_size,
                had_wal_copy,
                _wal_copy_file: wal_copy_file,
                wal_copy_dev_ino,
                wal_copy_sha256,
                wal_copy_size,
                had_shm_copy,
                _shm_copy_file: shm_copy_file,
                shm_copy_dev_ino,
                shm_copy_sha256,
                shm_copy_size,
                original_mode: orig_mode,
                original_uid: orig_uid,
                original_gid: orig_gid,
                wal_mode: wal_attrs.0,
                wal_uid: wal_attrs.1,
                wal_gid: wal_attrs.2,
                shm_mode: shm_attrs.0,
                shm_uid: shm_attrs.1,
                shm_gid: shm_attrs.2,
            });

            persist_recovery_journal_snapshot(
                &in_progress_journal_path,
                &provenance_dir,
                &mut journal_generation,
                &manifest.backup_id,
                filename,
                &normalized_root,
                &rollback_dir,
                &effective_services,
                &rollback_records,
                JOURNAL_STATE_IN_PROGRESS,
                options.trusted_sqlite_db_path.as_deref(),
            )?;

            if let Some(limit) = options.fail_after_replacements {
                if idx >= limit {
                    return Err(HostBackupError::Archive {
                        archive: artifact_path.clone(),
                        reason: format!(
                            "simulated mid-restore failure triggered after {} file replacement(s)",
                            idx
                        ),
                    });
                }
            }

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&item.destination_path);
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &wal_path,
                    trusted_ancestor_uid,
                    "removing stale WAL before restore",
                )?;
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &shm_path,
                    trusted_ancestor_uid,
                    "removing stale SHM before restore",
                )?;
            }

            let effective_uid = item.unix_uid.or(orig_uid);
            let effective_gid = item.unix_gid.or(orig_gid);
            let effective_mode = item.unix_mode & 0o777;

            atomic_install_file_at_destination_with_verification(
                &item.staged_path,
                item.staged_dev_ino,
                Some(&item.expected_sha256),
                Some(item.expected_size),
                &item.destination_path,
                effective_mode,
                effective_uid,
                effective_gid,
                trusted_ancestor_uid,
                "restoring staged entry to destination",
            )?;

            if item.kind == BackupTargetKind::SqliteSnapshot {
                let _ = verify_sqlite_snapshot_integrity_with_trusted_uid(
                    &item.destination_path,
                    trusted_ancestor_uid,
                )?;
                let post_sqlite_verify = verify_file_sha256_with_trusted_uid(
                    &item.destination_path,
                    &item.expected_sha256,
                    trusted_ancestor_uid,
                )?;
                if post_sqlite_verify.size_bytes != item.expected_size {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: item.destination_path.display().to_string(),
                        expected: format!("size={}", item.expected_size),
                        actual: format!("size={}", post_sqlite_verify.size_bytes),
                    });
                }
                sqlite_restored = true;
            }

            restored_files.push(item.destination_path.clone());
        }

        if let Some(limit) = options.fail_after_replacements {
            if staged_entries.len() <= limit {
                return Err(HostBackupError::Archive {
                    archive: artifact_path.clone(),
                    reason: format!(
                        "simulated post-replacement failure triggered at threshold {}",
                        limit
                    ),
                });
            }
        }

        persist_committed_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            options.trusted_sqlite_db_path.as_deref(),
            options.fail_provenance_on_commit,
            options.fail_provenance_parent_sync_on_commit,
            options.fail_local_journal_on_commit,
            &mut committed_durably,
        )?;

        quiescence.start_and_verify_services(&effective_services)?;
        Ok(())
    })();

    drop(staged_entries);
    let _ = fs::remove_dir_all(&staging_dir);

    if let Err(apply_err) = apply_result {
        if committed_durably {
            if options.fail_local_journal_on_commit || options.fail_provenance_parent_sync_on_commit
            {
                drop(rollback_records);
                return Err(apply_err);
            }
            let committed_entries: Vec<RollbackFailureJournalEntry> = rollback_records
                .iter()
                .map(|rec| RollbackFailureJournalEntry {
                    destination_path: rec.destination_path.clone(),
                    kind: Some(rec.kind),
                    existed_before: rec.existed_before,
                    rollback_copy_path: rec.rollback_copy_path.clone(),
                    rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
                    had_wal_copy: rec.had_wal_copy.clone(),
                    wal_copy_sha256: rec.wal_copy_sha256.clone(),
                    had_shm_copy: rec.had_shm_copy.clone(),
                    shm_copy_sha256: rec.shm_copy_sha256.clone(),
                    original_mode: rec.original_mode,
                    original_uid: rec.original_uid,
                    original_gid: rec.original_gid,
                    wal_mode: rec.wal_mode,
                    wal_uid: rec.wal_uid,
                    wal_gid: rec.wal_gid,
                    shm_mode: rec.shm_mode,
                    shm_uid: rec.shm_uid,
                    shm_gid: rec.shm_gid,
                    restored_during_rollback: true,
                })
                .collect();
            drop(rollback_records);

            let mut committed_journal = RollbackFailureJournal {
                backup_id: manifest.backup_id,
                primary_artifact: filename.to_string(),
                target_root: normalized_root,
                recovery_dir: rollback_dir.clone(),
                apply_failure_reason: apply_err.to_string(),
                rollback_errors: vec![format!(
                    "post-commit service start failed (committed state preserved without rollback): {}",
                    apply_err
                )],
                file_rollback_incomplete: false,
                services_left_stopped: true,
                quiesced_services: effective_services,
                entries: committed_entries,
                journal_state: JOURNAL_STATE_COMMITTED.to_string(),
                trusted_sqlite_db_path: options.trusted_sqlite_db_path.clone(),
                generation: 0,
                journal_digest_sha256: None,
            };
            let _ = write_journal_with_sidecar_and_provenance(
                &in_progress_journal_path,
                &provenance_dir,
                &rollback_dir,
                &mut committed_journal,
                &mut journal_generation,
                "recovery-journal",
                "committed restore journal awaiting service restart",
            );
            return Err(apply_err);
        }

        let mut rollback_errors = Vec::new();
        let mut journal_entries = Vec::with_capacity(rollback_records.len());

        for (rb_idx, rec) in rollback_records.iter().rev().enumerate() {
            let mut rec_ok = true;

            if let Some(rb_limit) = options.fail_rollback_after_restores {
                if rb_idx >= rb_limit {
                    rec_ok = false;
                    rollback_errors.push(format!(
                        "simulated rollback failure triggered at rollback step {} for {}",
                        rb_idx,
                        rec.destination_path.display()
                    ));
                }
            }

            if rec_ok {
                let trusted_ancestor_uid = if uses_service_data_dir_ownership(
                    None,
                    &rec.destination_path,
                    rec.kind,
                ) {
                    options.trusted_sqlite_uid
                } else {
                    None
                };

                if rec.kind == BackupTargetKind::SqliteSnapshot {
                    let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                    if let Err(wal_err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                        &wal_path,
                        trusted_ancestor_uid,
                        "rollback WAL cleanup",
                    ) {
                        rec_ok = false;
                        rollback_errors.push(format!(
                            "unlink WAL {}: {}",
                            wal_path.display(),
                            wal_err
                        ));
                    }
                    if let Err(shm_err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                        &shm_path,
                        trusted_ancestor_uid,
                        "rollback SHM cleanup",
                    ) {
                        rec_ok = false;
                        rollback_errors.push(format!(
                            "unlink SHM {}: {}",
                            shm_path.display(),
                            shm_err
                        ));
                    }
                }

                if rec_ok {
                    if rec.existed_before {
                        if let Some(ref rb_copy) = rec.rollback_copy_path {
                            let rb_mode = rec.original_mode.unwrap_or(0o600);
                            if let Err(err) = atomic_install_file_at_destination_with_verification(
                                rb_copy,
                                rec.rollback_copy_dev_ino,
                                rec.rollback_copy_sha256.as_deref(),
                                rec.rollback_copy_size,
                                &rec.destination_path,
                                rb_mode,
                                rec.original_uid,
                                rec.original_gid,
                                trusted_ancestor_uid,
                                "rolling back destination file",
                            ) {
                                rec_ok = false;
                                rollback_errors.push(format!(
                                    "restore {}: {}",
                                    rec.destination_path.display(),
                                    err
                                ));
                            }
                        } else {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "missing rollback copy for existing file {}",
                                rec.destination_path.display()
                            ));
                        }
                    } else if rec.destination_path.exists() {
                        if let Err(err) = unlink_file_at_destination_with_trusted_ancestor_uid(
                            &rec.destination_path,
                            trusted_ancestor_uid,
                            "rolling back newly created destination file",
                        ) {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "remove new file {}: {}",
                                rec.destination_path.display(),
                                err
                            ));
                        }
                    }
                }

                if rec_ok && rec.kind == BackupTargetKind::SqliteSnapshot {
                    let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                    if let Some(ref rb_wal) = rec.had_wal_copy {
                        if let Err(err) = atomic_install_file_at_destination_with_verification(
                            rb_wal,
                            rec.wal_copy_dev_ino,
                            rec.wal_copy_sha256.as_deref(),
                            rec.wal_copy_size,
                            &wal_path,
                            sanitize_sqlite_sidecar_mode(rec.wal_mode),
                            rec.wal_uid.or(rec.original_uid),
                            rec.wal_gid.or(rec.original_gid),
                            trusted_ancestor_uid,
                            "rolling back SQLite WAL sidecar",
                        ) {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "restore WAL {}: {}",
                                wal_path.display(),
                                err
                            ));
                        }
                    }
                    if let Some(ref rb_shm) = rec.had_shm_copy {
                        if let Err(err) = atomic_install_file_at_destination_with_verification(
                            rb_shm,
                            rec.shm_copy_dev_ino,
                            rec.shm_copy_sha256.as_deref(),
                            rec.shm_copy_size,
                            &shm_path,
                            sanitize_sqlite_sidecar_mode(rec.shm_mode),
                            rec.shm_uid.or(rec.original_uid),
                            rec.shm_gid.or(rec.original_gid),
                            trusted_ancestor_uid,
                            "rolling back SQLite SHM sidecar",
                        ) {
                            rec_ok = false;
                            rollback_errors.push(format!(
                                "restore SHM {}: {}",
                                shm_path.display(),
                                err
                            ));
                        }
                    }
                }
            }

            journal_entries.push(RollbackFailureJournalEntry {
                destination_path: rec.destination_path.clone(),
                kind: Some(rec.kind),
                existed_before: rec.existed_before,
                rollback_copy_path: rec.rollback_copy_path.clone(),
                rollback_copy_sha256: rec.rollback_copy_sha256.clone(),
                had_wal_copy: rec.had_wal_copy.clone(),
                wal_copy_sha256: rec.wal_copy_sha256.clone(),
                had_shm_copy: rec.had_shm_copy.clone(),
                shm_copy_sha256: rec.shm_copy_sha256.clone(),
                original_mode: rec.original_mode,
                original_uid: rec.original_uid,
                original_gid: rec.original_gid,
                wal_mode: rec.wal_mode,
                wal_uid: rec.wal_uid,
                wal_gid: rec.wal_gid,
                shm_mode: rec.shm_mode,
                shm_uid: rec.shm_uid,
                shm_gid: rec.shm_gid,
                restored_during_rollback: rec_ok,
            });
        }

        journal_entries.reverse();

        let file_rollback_incomplete = !rollback_errors.is_empty();
        let mut services_left_stopped = false;

        if file_rollback_incomplete {
            services_left_stopped = !effective_services.is_empty();
        } else if let Err(journal_err) = persist_recovery_journal_snapshot(
            &in_progress_journal_path,
            &provenance_dir,
            &mut journal_generation,
            &manifest.backup_id,
            filename,
            &normalized_root,
            &rollback_dir,
            &effective_services,
            &rollback_records,
            JOURNAL_STATE_ROLLED_BACK,
            options.trusted_sqlite_db_path.as_deref(),
        ) {
            services_left_stopped = true;
            rollback_errors.push(format!(
                "persisting terminal rolled_back journal before restarting services: {}",
                journal_err
            ));
        } else if let Err(svc_err) = quiescence.start_and_verify_services(&effective_services) {
            services_left_stopped = true;
            rollback_errors.push(format!("service restart after rollback: {}", svc_err));
        }

        let rollback_record_count = rollback_records.len();
        drop(rollback_records);

        if rollback_errors.is_empty() {
            if let Err(cleanup_err) = remove_recovery_dir_and_provenance_with_fault(
                &rollback_dir,
                &provenance_dir,
                options.fail_cleanup_remove_rb_dir,
            ) {
                rollback_errors.push(format!(
                    "cleaning up recovery directory after rollback: {}",
                    cleanup_err
                ));
            } else {
                let rollback_summary = format!(
                    "all {} touched target file(s) and SQLite WAL/SHM sidecars restored cleanly to pre-restore state",
                    rollback_record_count
                );
                return Err(HostBackupError::RestoreRolledBack {
                    reason: apply_err.to_string(),
                    rollback_summary,
                });
            }
        }

        let journal_path = rollback_dir.join("rollback-failure-journal.json");
        let failure_state = if file_rollback_incomplete {
            JOURNAL_STATE_ROLLBACK_FAILED
        } else {
            JOURNAL_STATE_ROLLED_BACK
        };
        let mut journal = RollbackFailureJournal {
            backup_id: manifest.backup_id,
            primary_artifact: filename.to_string(),
            target_root: normalized_root,
            recovery_dir: rollback_dir.clone(),
            apply_failure_reason: apply_err.to_string(),
            rollback_errors: rollback_errors.clone(),
            file_rollback_incomplete,
            services_left_stopped,
            quiesced_services: effective_services,
            entries: journal_entries,
            journal_state: failure_state.to_string(),
            trusted_sqlite_db_path: options.trusted_sqlite_db_path.clone(),
            generation: 0,
            journal_digest_sha256: None,
        };
        let _ = write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rollback_dir,
            &mut journal,
            &mut journal_generation,
            "failure-journal",
            "rollback failure journal",
        );

        return Err(HostBackupError::RestoreRollbackFailed {
            reason: apply_err.to_string(),
            rollback_errors: rollback_errors.join("; "),
            recovery_dir: rollback_dir,
            failure_journal_path: journal_path,
            services_left_stopped,
        });
    }

    drop(rollback_records);
    remove_recovery_dir_and_provenance_with_fault(
        &rollback_dir,
        &provenance_dir,
        options.fail_cleanup_remove_rb_dir,
    )?;

    Ok(RestoreExecutionReport {
        backup_id: manifest.backup_id,
        primary_artifact: filename.to_string(),
        target_root: normalized_root,
        sqlite_restored,
        sqlite_user_version: sqlite_uv,
        sqlite_integrity_verified: sqlite_verified,
        restored_files,
        quiesced_services: effective_services,
        rolled_back: false,
    })
}
