use super::journal::{
    compute_journal_canonical_digest, is_terminal_journal_state,
    provenance_journal_path_for_recovery_dir, provenance_prev_journal_path,
    remove_recovery_dir_and_provenance, sanitize_sqlite_sidecar_mode, sqlite_sidecar_paths,
    write_journal_with_sidecar_and_provenance, RollbackFailureJournal,
    IN_PROGRESS_RECOVERY_JOURNAL_FILENAME, JOURNAL_STATE_ABORTED_CLEAN, JOURNAL_STATE_COMMITTED,
    JOURNAL_STATE_IN_PROGRESS, JOURNAL_STATE_QUIESCING, JOURNAL_STATE_RECOVERED,
    JOURNAL_STATE_ROLLBACK_FAILED, JOURNAL_STATE_ROLLED_BACK,
};
use super::policy::{
    is_service_data_dir_secret_destination, resolve_effective_quiesce_services,
    resolve_recovery_provenance_dir,
    resolve_trusted_canonical_host_destination_with_sqlite_override,
    validate_destination_not_provenance, validate_quiesce_service_entries,
    validate_trusted_sqlite_db_path, RecoveryContext,
};
use super::preflight::validate_execution_target_root;
use super::quiescence::{
    stop_services_for_recovery, stop_services_with_compensation, ServiceQuiescenceController,
};
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::BackupTargetKind;
use crate::verify::{
    atomic_install_file_at_destination_with_verification, checksum_sidecar_path,
    open_or_create_dir_nofollow, open_or_create_provenance_dir_nofollow, parse_sha256_sidecar_str,
    read_verified_text_file_nofollow, reject_if_symlink, reject_symlink_chain,
    unlink_file_at_destination_with_trusted_ancestor_uid, validate_backup_filename,
    validate_no_parent_traversal, verify_file_sha256,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn verify_private_journal_or_backup_file(path: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(path, context)?;
    let meta = fs::symlink_metadata(path).map_err(|err| {
        HostBackupError::io(format!("stat {} ({})", path.display(), context), err)
    })?;
    if !meta.file_type().is_file() {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} is not a regular file", context),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let euid = unsafe { libc::geteuid() };
        let mut open_opts = fs::OpenOptions::new();
        open_opts
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let opened = open_opts.open(path).map_err(|err| {
            HostBackupError::io(format!("opening {} ({})", path.display(), context), err)
        })?;
        let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(opened.as_raw_fd(), &mut fd_stat) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} is not a regular file", context),
            });
        }
        if fd_stat.st_nlink > 1 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} must not have multiple hard links", context),
            });
        }
        if fd_stat.st_uid != euid {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "{} is owned by untrusted uid {} (expected effective uid {})",
                    context, fd_stat.st_uid, euid
                ),
            });
        }
        let mode = (fd_stat.st_mode as u32) & 0o777;
        if mode != 0o600 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} must have mode 0600, found {:04o}", context, mode),
            });
        }
    }
    Ok(())
}

fn verify_recovery_dir_owned_by_euid(rb_dir: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(rb_dir, context)?;
    let meta = fs::symlink_metadata(rb_dir).map_err(|err| {
        HostBackupError::io(format!("stat {} ({})", rb_dir.display(), context), err)
    })?;
    if !meta.file_type().is_dir() {
        return Err(HostBackupError::PathValidation {
            path: rb_dir.to_path_buf(),
            reason: format!("{} is not a directory", context),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(HostBackupError::PathValidation {
                path: rb_dir.to_path_buf(),
                reason: format!(
                    "{} is owned by untrusted uid {} (expected effective uid {})",
                    context,
                    meta.uid(),
                    euid
                ),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(HostBackupError::PathValidation {
                path: rb_dir.to_path_buf(),
                reason: format!("{} must have mode 0700, found {:04o}", context, mode),
            });
        }
    }
    Ok(())
}

fn validate_recovery_copy_path(
    copy_path: &Path,
    rb_dir: &Path,
    expected_prefix: &str,
    expected_suffix: &str,
    expected_sha256: Option<&str>,
) -> HostBackupResult<(Option<(u64, u64)>, u64)> {
    validate_no_parent_traversal(copy_path, "recovery copy path")?;
    if copy_path.parent() != Some(rb_dir) {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery copy '{}' is not a direct child of recovery dir '{}'",
            copy_path.display(),
            rb_dir.display()
        )));
    }
    let name = copy_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "recovery copy '{}' has invalid filename",
                copy_path.display()
            ))
        })?;
    if !name.starts_with(expected_prefix) || !name.ends_with(expected_suffix) {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery copy '{}' does not match expected pattern '{}*{}'",
            copy_path.display(),
            expected_prefix,
            expected_suffix
        )));
    }
    verify_private_journal_or_backup_file(copy_path, "recovery backup copy")?;
    let expected_digest = expected_sha256.ok_or_else(|| {
        HostBackupError::InvalidManifest(format!(
            "recovery journal is missing SHA-256 digest for backup copy '{}'",
            copy_path.display()
        ))
    })?;
    let verification = verify_file_sha256(copy_path, expected_digest)?;
    #[cfg(unix)]
    let copy_dev_ino = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(copy_path)
            .map_err(|err| HostBackupError::io(format!("lstat {}", copy_path.display()), err))?;
        Some((meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let copy_dev_ino: Option<(u64, u64)> = None;
    Ok((copy_dev_ino, verification.size_bytes))
}

fn validate_recovery_journal(
    journal: &RollbackFailureJournal,
    rb_dir: &Path,
    context: &RecoveryContext,
) -> HostBackupResult<()> {
    if journal.backup_id.trim().is_empty() {
        return Err(HostBackupError::InvalidManifest(
            "recovery journal backup_id must not be empty".to_string(),
        ));
    }
    validate_backup_filename(&journal.primary_artifact)?;
    if journal.recovery_dir != rb_dir {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal recovery_dir '{}' does not match actual directory '{}'",
            journal.recovery_dir.display(),
            rb_dir.display()
        )));
    }
    if journal.generation == 0 {
        return Err(HostBackupError::InvalidManifest(
            "recovery journal generation must be >= 1".to_string(),
        ));
    }
    let expected_digest = journal.journal_digest_sha256.as_deref().ok_or_else(|| {
        HostBackupError::InvalidManifest(
            "recovery journal is missing journal_digest_sha256".to_string(),
        )
    })?;
    let computed_digest = compute_journal_canonical_digest(journal)?;
    if !computed_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: rb_dir.display().to_string(),
            expected: expected_digest.to_string(),
            actual: computed_digest,
        });
    }

    let _ = validate_quiesce_service_entries(&journal.quiesced_services)?;
    let (norm_root, is_canonical) = validate_execution_target_root(&journal.target_root)?;

    let caller_expected_root = context.expected_target_root.as_deref().ok_or_else(|| {
        HostBackupError::InvalidConfig(
            "RecoveryContext::expected_target_root is required for recovery".to_string(),
        )
    })?;
    let (validated_caller_root, _) = validate_execution_target_root(caller_expected_root)?;
    if norm_root != validated_caller_root {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal target_root '{}' does not match trusted RecoveryContext target_root '{}'",
            norm_root.display(),
            validated_caller_root.display()
        )));
    }

    let validated_context_sqlite = match context.trusted_sqlite_db_path.as_deref() {
        Some(custom_db) => Some(validate_trusted_sqlite_db_path(custom_db)?),
        None => None,
    };
    let validated_journal_sqlite = match journal.trusted_sqlite_db_path.as_deref() {
        Some(custom_db) => Some(validate_trusted_sqlite_db_path(custom_db)?),
        None => None,
    };
    if let Some(ref journal_sqlite) = validated_journal_sqlite {
        if validated_context_sqlite.as_ref() != Some(journal_sqlite) {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal trusted_sqlite_db_path '{}' is not authorized by trusted RecoveryContext",
                journal_sqlite.display()
            )));
        }
    }

    match journal.journal_state.as_str() {
        JOURNAL_STATE_QUIESCING
        | JOURNAL_STATE_IN_PROGRESS
        | JOURNAL_STATE_COMMITTED
        | JOURNAL_STATE_ROLLED_BACK
        | JOURNAL_STATE_RECOVERED
        | JOURNAL_STATE_ABORTED_CLEAN
        | JOURNAL_STATE_ROLLBACK_FAILED => {}
        other => {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal contains invalid or empty journal_state '{}'",
                other
            )));
        }
    }

    if journal.journal_state == JOURNAL_STATE_COMMITTED {
        let has_rollback_error = journal
            .rollback_errors
            .iter()
            .any(|err_msg| !err_msg.starts_with("post-commit service start failed"));
        let has_unrestored_entry = journal
            .entries
            .iter()
            .any(|entry_item| !entry_item.restored_during_rollback);
        if journal.file_rollback_incomplete || has_rollback_error || has_unrestored_entry {
            return Err(HostBackupError::InvalidManifest(format!(
                "recovery journal for '{}' cannot claim terminal committed state while rollback is in progress or incomplete",
                rb_dir.display()
            )));
        }
    }

    let is_terminal = is_terminal_journal_state(&journal.journal_state);
    let mut seen_destinations = HashSet::new();

    for (idx, rec) in journal.entries.iter().enumerate() {
        let entry_kind = rec.kind.ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "journal entry {} for '{}' is missing required kind",
                idx,
                rec.destination_path.display()
            ))
        })?;
        validate_no_parent_traversal(&rec.destination_path, "journal destination_path")?;
        if !rec.destination_path.is_absolute() {
            return Err(HostBackupError::InvalidManifest(format!(
                "journal entry {} destination_path '{}' must be absolute",
                idx,
                rec.destination_path.display()
            )));
        }
        if !seen_destinations.insert(rec.destination_path.clone()) {
            return Err(HostBackupError::InvalidManifest(format!(
                "journal contains duplicate destination_path '{}'",
                rec.destination_path.display()
            )));
        }
        validate_destination_not_provenance(
            &rec.destination_path,
            &norm_root,
            context.provenance_dir.as_deref(),
        )?;
        if rec.destination_path == rb_dir
            || rec.destination_path.starts_with(rb_dir)
            || rb_dir.starts_with(&rec.destination_path)
        {
            return Err(HostBackupError::PathValidation {
                path: rec.destination_path.clone(),
                reason: format!(
                    "journal entry {} destination '{}' overlaps recovery directory '{}'",
                    idx,
                    rec.destination_path.display(),
                    rb_dir.display()
                ),
            });
        }

        let matches_trusted_sqlite = entry_kind == BackupTargetKind::SqliteSnapshot
            && validated_journal_sqlite
                .as_ref()
                .map(|trusted_path| trusted_path == &rec.destination_path)
                .unwrap_or(false);

        if is_canonical {
            if !matches_trusted_sqlite {
                let rel_trimmed = rec
                    .destination_path
                    .to_string_lossy()
                    .trim_start_matches('/')
                    .to_string();
                let (_, canonical_dest) =
                    resolve_trusted_canonical_host_destination_with_sqlite_override(
                        &norm_root,
                        &rel_trimmed,
                        validated_journal_sqlite.as_deref(),
                    )?;
                if canonical_dest != rec.destination_path {
                    return Err(HostBackupError::InvalidManifest(format!(
                        "journal entry {} canonical destination '{}' does not match allowlisted path '{}'",
                        idx,
                        rec.destination_path.display(),
                        canonical_dest.display()
                    )));
                }
            }
        } else if !matches_trusted_sqlite {
            if !rec.destination_path.starts_with(&norm_root) || rec.destination_path == norm_root {
                return Err(HostBackupError::InvalidManifest(format!(
                    "journal entry {} destination '{}' is outside target_root '{}'",
                    idx,
                    rec.destination_path.display(),
                    norm_root.display()
                )));
            }
            reject_symlink_chain(&norm_root, &rec.destination_path)?;
        }

        if entry_kind != BackupTargetKind::SqliteSnapshot
            && (rec.had_wal_copy.is_some() || rec.had_shm_copy.is_some())
        {
            return Err(HostBackupError::InvalidManifest(format!(
                "non-SQLite journal entry {} ('{}') must not declare WAL or SHM sidecar copies",
                idx,
                rec.destination_path.display()
            )));
        }

        if rec.existed_before {
            let rb_copy = rec.rollback_copy_path.as_ref().ok_or_else(|| {
                HostBackupError::InvalidManifest(format!(
                    "journal entry {} for existing destination '{}' is missing rollback_copy_path",
                    idx,
                    rec.destination_path.display()
                ))
            })?;
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    rb_copy,
                    rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
            }
        } else if let Some(ref rb_copy) = rec.rollback_copy_path {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    rb_copy,
                    rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
            }
        }

        if let Some(ref wal_copy) = rec.had_wal_copy {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    wal_copy,
                    rb_dir,
                    "entry_",
                    ".wal.bak",
                    rec.wal_copy_sha256.as_deref(),
                )?;
            }
        }
        if let Some(ref shm_copy) = rec.had_shm_copy {
            if !is_terminal {
                let _ = validate_recovery_copy_path(
                    shm_copy,
                    rb_dir,
                    "entry_",
                    ".shm.bak",
                    rec.shm_copy_sha256.as_deref(),
                )?;
            }
        }
    }

    Ok(())
}

fn load_validated_journal_checkpoint(
    journal_path: &Path,
    rb_dir: &Path,
    context: &RecoveryContext,
    allowed_stale_sidecar_digests: &[String],
    allow_missing_sidecar_if_digest_in: &[String],
) -> HostBackupResult<(RollbackFailureJournal, String)> {
    verify_private_journal_or_backup_file(journal_path, "recovery journal")?;
    let raw_text =
        read_verified_text_file_nofollow(journal_path, None, 16 * 1024 * 1024, "recovery journal")?
            .ok_or_else(|| {
                HostBackupError::InvalidManifest(format!(
                    "recovery journal '{}' does not exist",
                    journal_path.display()
                ))
            })?;
    let actual_file_sha256 = hex::encode(Sha256::digest(raw_text.as_bytes()));
    let parsed_journal: RollbackFailureJournal =
        serde_json::from_str(&raw_text).map_err(|err| {
            HostBackupError::InvalidManifest(format!(
                "corrupt recovery journal {}: {}",
                journal_path.display(),
                err
            ))
        })?;
    validate_recovery_journal(&parsed_journal, rb_dir, context)?;
    let internal_digest = parsed_journal
        .journal_digest_sha256
        .clone()
        .unwrap_or_default();

    let sidecar_path = checksum_sidecar_path(journal_path);
    if fs::symlink_metadata(&sidecar_path).is_ok() {
        verify_private_journal_or_backup_file(&sidecar_path, "recovery journal sidecar")?;
        let raw_sidecar = read_verified_text_file_nofollow(
            &sidecar_path,
            None,
            16 * 1024,
            "recovery journal sidecar",
        )?
        .ok_or_else(|| HostBackupError::MissingChecksumSidecar {
            artifact: journal_path.to_path_buf(),
            sidecar_path: sidecar_path.clone(),
        })?;
        let sidecar_hex = parse_sha256_sidecar_str(&raw_sidecar)?;
        if !sidecar_hex.eq_ignore_ascii_case(&actual_file_sha256) {
            let matches_allowed_stale = allowed_stale_sidecar_digests
                .iter()
                .any(|allowed_hex| allowed_hex.eq_ignore_ascii_case(&sidecar_hex))
                || allow_missing_sidecar_if_digest_in
                    .iter()
                    .any(|allowed_hex| {
                        allowed_hex.eq_ignore_ascii_case(&actual_file_sha256)
                            || (!internal_digest.is_empty()
                                && allowed_hex.eq_ignore_ascii_case(&internal_digest))
                    });
            if !matches_allowed_stale {
                return Err(HostBackupError::ChecksumMismatch {
                    artifact: journal_path.display().to_string(),
                    expected: sidecar_hex,
                    actual: actual_file_sha256,
                });
            }
        }
    } else {
        let allowed_missing = allow_missing_sidecar_if_digest_in
            .iter()
            .any(|allowed_hex| {
                allowed_hex.eq_ignore_ascii_case(&actual_file_sha256)
                    || allowed_hex.eq_ignore_ascii_case(&internal_digest)
            });
        if !allowed_missing {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: journal_path.to_path_buf(),
                sidecar_path,
            });
        }
    }

    Ok((parsed_journal, actual_file_sha256))
}

fn check_journal_metadata_matches_provenance(
    rb_journal: &RollbackFailureJournal,
    prov_journal: &RollbackFailureJournal,
    journal_path: &Path,
    prov_journal_path: &Path,
) -> HostBackupResult<()> {
    if rb_journal.backup_id != prov_journal.backup_id
        || rb_journal.primary_artifact != prov_journal.primary_artifact
        || rb_journal.target_root != prov_journal.target_root
        || rb_journal.recovery_dir != prov_journal.recovery_dir
        || rb_journal.trusted_sqlite_db_path != prov_journal.trusted_sqlite_db_path
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal '{}' metadata diverges from protected provenance journal '{}'",
            journal_path.display(),
            prov_journal_path.display()
        )));
    }
    if rb_journal.generation > prov_journal.generation
        || prov_journal
            .generation
            .saturating_sub(rb_journal.generation)
            > 1
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal generation {} is inconsistent with protected provenance generation {}",
            rb_journal.generation, prov_journal.generation
        )));
    }
    if rb_journal.generation == prov_journal.generation
        && rb_journal.journal_digest_sha256 != prov_journal.journal_digest_sha256
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal digest does not match protected provenance digest at generation {}",
            prov_journal.generation
        )));
    }
    if prov_journal.journal_state == JOURNAL_STATE_COMMITTED
        && rb_journal.journal_state == JOURNAL_STATE_ROLLBACK_FAILED
    {
        return Err(HostBackupError::InvalidManifest(format!(
            "recovery journal '{}' records rollback_failed while provenance '{}' claims committed",
            journal_path.display(),
            prov_journal_path.display()
        )));
    }
    Ok(())
}

/// Legacy context-free recovery entrypoint.
///
/// Always fails closed with [`HostBackupError::InvalidConfig`] so privileged callers can never
/// recover an interrupted restore without supplying a trusted [`RecoveryContext`].
pub fn recover_interrupted_restore<Q: ServiceQuiescenceController>(
    _backup_dir: &Path,
    _quiescence: &Q,
) -> HostBackupResult<Vec<PathBuf>> {
    Err(HostBackupError::InvalidConfig(
        "recover_interrupted_restore without explicit RecoveryContext is disabled; use recover_interrupted_restore_with_context".to_string(),
    ))
}

/// Scans `backup_dir` for any `.rollback-restore.*` directories containing an interrupted
/// write-ahead `.restore-recovery-journal.json` (or an unrecovered `rollback-failure-journal.json`),
/// authenticates each recovery directory against its protected provenance record outside `backup_dir`
/// and the caller's trusted [`RecoveryContext`], quiesces the recorded writer services, restores
/// pre-restore `.bak` / `.wal.bak` / `.shm.bak` files when uncommitted, restarts services, and
/// cleans up the recovery directory and provenance record once recovery succeeds.
pub fn recover_interrupted_restore_with_context<Q: ServiceQuiescenceController>(
    backup_dir: &Path,
    context: &RecoveryContext,
    quiescence: &Q,
) -> HostBackupResult<Vec<PathBuf>> {
    let caller_expected_root = context.expected_target_root.as_deref().ok_or_else(|| {
        HostBackupError::InvalidConfig(
            "RecoveryContext::expected_target_root is required for recover_interrupted_restore_with_context".to_string(),
        )
    })?;
    let (validated_caller_root, _) = validate_execution_target_root(caller_expected_root)?;
    if let Some(ref custom_db) = context.trusted_sqlite_db_path {
        let _ = validate_trusted_sqlite_db_path(custom_db)?;
    }

    validate_no_parent_traversal(backup_dir, "backup_dir")?;
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }
    reject_if_symlink(backup_dir, "backup_dir")?;
    open_or_create_dir_nofollow(backup_dir, 0o700, "backup_dir")?;

    let provenance_dir =
        resolve_recovery_provenance_dir(&validated_caller_root, context.provenance_dir.as_deref());

    let mut recovered_dirs = Vec::new();
    for entry in fs::read_dir(backup_dir)
        .map_err(|err| HostBackupError::io(format!("reading {}", backup_dir.display()), err))?
    {
        let entry = entry.map_err(|err| HostBackupError::io("reading dir entry", err))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(".rollback-restore.") {
            continue;
        }
        let rb_dir = entry.path();
        reject_symlink_chain(backup_dir, &rb_dir)?;
        verify_recovery_dir_owned_by_euid(&rb_dir, "restore recovery directory")?;
        open_or_create_dir_nofollow(&rb_dir, 0o700, "restore recovery directory")?;

        let in_prog = rb_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
        let failed_j = rb_dir.join("rollback-failure-journal.json");

        open_or_create_provenance_dir_nofollow(&provenance_dir, "recovery provenance directory")?;
        let prov_journal_path = provenance_journal_path_for_recovery_dir(&provenance_dir, &rb_dir)?;
        let prev_prov_path = provenance_prev_journal_path(&prov_journal_path);

        if fs::symlink_metadata(&prov_journal_path).is_err()
            && fs::symlink_metadata(&prev_prov_path).is_err()
        {
            for candidate_local in [&failed_j, &in_prog] {
                if fs::symlink_metadata(candidate_local).is_ok() {
                    verify_private_journal_or_backup_file(candidate_local, "recovery journal")?;
                    let sidecar_local = checksum_sidecar_path(candidate_local);
                    if fs::symlink_metadata(&sidecar_local).is_err() {
                        return Err(HostBackupError::MissingChecksumSidecar {
                            artifact: candidate_local.clone(),
                            sidecar_path: sidecar_local,
                        });
                    }
                }
            }
            if fs::symlink_metadata(&failed_j).is_err() && fs::symlink_metadata(&in_prog).is_err() {
                return Err(HostBackupError::InvalidManifest(format!(
                    "recovery directory '{}' contains no recovery journal",
                    rb_dir.display()
                )));
            }
            return Err(HostBackupError::InvalidManifest(format!(
                "unauthenticated recovery directory '{}': missing protected provenance journal '{}'",
                rb_dir.display(),
                prov_journal_path.display()
            )));
        }

        let prev_prov_opt: Option<(RollbackFailureJournal, String)> =
            if fs::symlink_metadata(&prev_prov_path).is_ok() {
                load_validated_journal_checkpoint(&prev_prov_path, &rb_dir, context, &[], &[]).ok()
            } else {
                None
            };

        let mut allowed_prov_stale_digests: Vec<String> = Vec::new();
        if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
            allowed_prov_stale_digests.push(prev_sha.clone());
            if let Some(ref prev_internal_dig) = prev_j.journal_digest_sha256 {
                allowed_prov_stale_digests.push(prev_internal_dig.clone());
            }
        }
        for local_cand in [&failed_j, &in_prog] {
            if fs::symlink_metadata(local_cand).is_ok() {
                if let Ok((local_j, local_sha)) =
                    load_validated_journal_checkpoint(local_cand, &rb_dir, context, &[], &[])
                {
                    allowed_prov_stale_digests.push(local_sha);
                    if let Some(ref local_internal_dig) = local_j.journal_digest_sha256 {
                        allowed_prov_stale_digests.push(local_internal_dig.clone());
                    }
                }
            }
        }

        let (prov_journal, prov_file_sha256) = match load_validated_journal_checkpoint(
            &prov_journal_path,
            &rb_dir,
            context,
            &allowed_prov_stale_digests,
            &allowed_prov_stale_digests,
        ) {
            Ok((loaded_prov, loaded_sha)) => {
                if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
                    let prov_sidecar = checksum_sidecar_path(&prov_journal_path);
                    let sidecar_matches_current = read_verified_text_file_nofollow(
                        &prov_sidecar,
                        None,
                        16 * 1024,
                        "provenance sidecar",
                    )
                    .ok()
                    .flatten()
                    .and_then(|raw_sc| parse_sha256_sidecar_str(&raw_sc).ok())
                    .map(|sc_hex| sc_hex.eq_ignore_ascii_case(&loaded_sha))
                    .unwrap_or(false);
                    if !sidecar_matches_current {
                        if loaded_prov.backup_id != prev_j.backup_id
                            || loaded_prov.primary_artifact != prev_j.primary_artifact
                            || loaded_prov.target_root != prev_j.target_root
                            || loaded_prov.recovery_dir != prev_j.recovery_dir
                            || loaded_prov.generation != prev_j.generation.saturating_add(1)
                        {
                            (prev_j.clone(), prev_sha.clone())
                        } else {
                            (loaded_prov, loaded_sha)
                        }
                    } else {
                        (loaded_prov, loaded_sha)
                    }
                } else {
                    (loaded_prov, loaded_sha)
                }
            }
            Err(prov_err) => {
                if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
                    (prev_j.clone(), prev_sha.clone())
                } else {
                    return Err(prov_err);
                }
            }
        };

        let mut allowed_local_digests = vec![prov_file_sha256.clone()];
        if let Some(ref internal_dig) = prov_journal.journal_digest_sha256 {
            allowed_local_digests.push(internal_dig.clone());
        }
        if let Some((ref prev_j, ref prev_sha)) = prev_prov_opt {
            allowed_local_digests.push(prev_sha.clone());
            if let Some(ref prev_internal_dig) = prev_j.journal_digest_sha256 {
                allowed_local_digests.push(prev_internal_dig.clone());
            }
        }

        let mut valid_local_candidates: Vec<(PathBuf, RollbackFailureJournal)> = Vec::new();
        let mut first_local_err: Option<HostBackupError> = None;
        let mut any_local_exists = false;

        for candidate_path in [&failed_j, &in_prog] {
            if fs::symlink_metadata(candidate_path).is_err() {
                continue;
            }
            any_local_exists = true;
            match load_validated_journal_checkpoint(
                candidate_path,
                &rb_dir,
                context,
                &allowed_local_digests,
                &allowed_local_digests,
            ) {
                Ok((cand_journal, _)) => {
                    match check_journal_metadata_matches_provenance(
                        &cand_journal,
                        &prov_journal,
                        candidate_path,
                        &prov_journal_path,
                    ) {
                        Ok(()) => {
                            valid_local_candidates.push((candidate_path.clone(), cand_journal));
                        }
                        Err(meta_err) => {
                            if (cand_journal.journal_state == JOURNAL_STATE_ROLLBACK_FAILED
                                && prov_journal.journal_state == JOURNAL_STATE_COMMITTED)
                                || cand_journal.generation == prov_journal.generation
                            {
                                return Err(meta_err);
                            }
                            if first_local_err.is_none() {
                                first_local_err = Some(meta_err);
                            }
                        }
                    }
                }
                Err(load_err) => {
                    let is_generation_zero = matches!(
                        &load_err,
                        HostBackupError::InvalidManifest(msg_str)
                            if msg_str.contains("generation must be >= 1")
                    );
                    if !is_generation_zero {
                        return Err(load_err);
                    }
                    if first_local_err.is_none() {
                        first_local_err = Some(load_err);
                    }
                }
            }
        }

        if !any_local_exists {
            let allow_provenance_only_quiescing = prov_journal.entries.is_empty()
                && matches!(
                    prov_journal.journal_state.as_str(),
                    JOURNAL_STATE_QUIESCING | JOURNAL_STATE_ABORTED_CLEAN
                );
            if !allow_provenance_only_quiescing {
                return Err(HostBackupError::InvalidManifest(format!(
                    "recovery directory '{}' contains no recovery journal",
                    rb_dir.display()
                )));
            }
        }

        let (journal_path, _selected_local_journal) = if !valid_local_candidates.is_empty() {
            valid_local_candidates.sort_by(|left_item, right_item| {
                right_item.1.generation.cmp(&left_item.1.generation)
            });
            valid_local_candidates.remove(0)
        } else if let Some(local_err) = first_local_err {
            return Err(local_err);
        } else {
            (in_prog.clone(), prov_journal.clone())
        };

        let mut journal = prov_journal;
        let mut generation = journal.generation;
        let services = resolve_effective_quiesce_services(&journal.quiesced_services);
        let is_terminal = is_terminal_journal_state(&journal.journal_state);

        if is_terminal {
            if journal.services_left_stopped {
                quiescence.start_and_verify_services(&services)?;
                journal.services_left_stopped = false;
                write_journal_with_sidecar_and_provenance(
                    &journal_path,
                    &provenance_dir,
                    &rb_dir,
                    &mut journal,
                    &mut generation,
                    "recovery-journal",
                    "terminal restore recovery journal",
                )?;
            }
            remove_recovery_dir_and_provenance(&rb_dir, &provenance_dir)?;
            recovered_dirs.push(rb_dir);
            continue;
        }

        if journal.entries.is_empty() {
            if let Err((stop_err, _)) = stop_services_with_compensation(quiescence, &services) {
                return Err(stop_err);
            }
        } else {
            stop_services_for_recovery(quiescence, &services)?;
        }

        for rec in journal.entries.iter().rev() {
            let entry_kind = rec.kind.unwrap_or(BackupTargetKind::ConfigFile);
            let trusted_ancestor_uid = if entry_kind == BackupTargetKind::SqliteSnapshot
                || is_service_data_dir_secret_destination(&rec.destination_path)
            {
                context.trusted_sqlite_uid
            } else {
                None
            };

            if entry_kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &wal_path,
                    trusted_ancestor_uid,
                    "interrupted recovery WAL cleanup",
                )?;
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &shm_path,
                    trusted_ancestor_uid,
                    "interrupted recovery SHM cleanup",
                )?;
            }

            if rec.existed_before {
                let rb_copy = rec.rollback_copy_path.as_ref().ok_or_else(|| {
                    HostBackupError::InvalidManifest(format!(
                        "missing rollback copy for existing file {}",
                        rec.destination_path.display()
                    ))
                })?;
                let (copy_dev_ino, copy_size) = validate_recovery_copy_path(
                    rb_copy,
                    &rb_dir,
                    "entry_",
                    ".bak",
                    rec.rollback_copy_sha256.as_deref(),
                )?;
                atomic_install_file_at_destination_with_verification(
                    rb_copy,
                    copy_dev_ino,
                    rec.rollback_copy_sha256.as_deref(),
                    Some(copy_size),
                    &rec.destination_path,
                    rec.original_mode.unwrap_or(0o600),
                    rec.original_uid,
                    rec.original_gid,
                    trusted_ancestor_uid,
                    "recovering interrupted destination file",
                )?;
            } else if rec.destination_path.exists() {
                unlink_file_at_destination_with_trusted_ancestor_uid(
                    &rec.destination_path,
                    trusted_ancestor_uid,
                    "removing newly created file from interrupted restore",
                )?;
            }

            if entry_kind == BackupTargetKind::SqliteSnapshot {
                let (wal_path, shm_path) = sqlite_sidecar_paths(&rec.destination_path);
                if let Some(ref rb_wal) = rec.had_wal_copy {
                    let (wal_dev_ino, wal_size) = validate_recovery_copy_path(
                        rb_wal,
                        &rb_dir,
                        "entry_",
                        ".wal.bak",
                        rec.wal_copy_sha256.as_deref(),
                    )?;
                    atomic_install_file_at_destination_with_verification(
                        rb_wal,
                        wal_dev_ino,
                        rec.wal_copy_sha256.as_deref(),
                        Some(wal_size),
                        &wal_path,
                        sanitize_sqlite_sidecar_mode(rec.wal_mode),
                        rec.wal_uid.or(rec.original_uid),
                        rec.wal_gid.or(rec.original_gid),
                        trusted_ancestor_uid,
                        "recovering interrupted WAL sidecar",
                    )?;
                }
                if let Some(ref rb_shm) = rec.had_shm_copy {
                    let (shm_dev_ino, shm_size) = validate_recovery_copy_path(
                        rb_shm,
                        &rb_dir,
                        "entry_",
                        ".shm.bak",
                        rec.shm_copy_sha256.as_deref(),
                    )?;
                    atomic_install_file_at_destination_with_verification(
                        rb_shm,
                        shm_dev_ino,
                        rec.shm_copy_sha256.as_deref(),
                        Some(shm_size),
                        &shm_path,
                        sanitize_sqlite_sidecar_mode(rec.shm_mode),
                        rec.shm_uid.or(rec.original_uid),
                        rec.shm_gid.or(rec.original_gid),
                        trusted_ancestor_uid,
                        "recovering interrupted SHM sidecar",
                    )?;
                }
            }
        }

        for entry_rec in &mut journal.entries {
            entry_rec.restored_during_rollback = true;
        }
        journal.file_rollback_incomplete = false;
        journal.journal_state = JOURNAL_STATE_RECOVERED.to_string();
        write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rb_dir,
            &mut journal,
            &mut generation,
            "recovery-journal",
            "durable terminal recovered journal",
        )?;

        quiescence.start_and_verify_services(&services)?;
        journal.services_left_stopped = false;
        write_journal_with_sidecar_and_provenance(
            &journal_path,
            &provenance_dir,
            &rb_dir,
            &mut journal,
            &mut generation,
            "recovery-journal",
            "durable terminal recovered journal after service restart",
        )?;

        remove_recovery_dir_and_provenance(&rb_dir, &provenance_dir)?;
        recovered_dirs.push(rb_dir);
    }

    Ok(recovered_dirs)
}
