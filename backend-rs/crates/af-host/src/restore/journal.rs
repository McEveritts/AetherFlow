use super::policy::DEFAULT_MANDATORY_QUIESCE_SERVICES;
use crate::error::{HostBackupError, HostBackupResult};
use crate::manifest::BackupTargetKind;
use crate::verify::{
    checksum_sidecar_path, open_or_create_dir_nofollow, open_or_create_provenance_dir_nofollow,
    parse_sha256_sidecar_str, read_verified_text_file_nofollow, sync_parent_directory,
    unlink_file_at_destination, write_private_file_atomic,
    write_private_file_atomic_tracking_rename, write_sha256_sidecar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Options governing a verified, staged, rollback-protected restore execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreExecutionOptions {
    /// Current host AetherFlow version (e.g., `"v4.0.0"`).
    pub host_app_version: String,
    /// Optional maximum SQLite `PRAGMA user_version` supported by the host binary.
    pub max_supported_sqlite_user_version: Option<i64>,
    /// Explicit confirmation required before any target file replacement is allowed.
    /// When `false`, [`execute_staged_restore`] fails closed with [`HostBackupError::DestructiveRestoreUnsupported`].
    pub confirm_destructive_restore: bool,
    /// Whether existing regular files under `target_root` may be replaced (after staging rollback copies).
    pub allow_overwrite: bool,
    /// Ordered list of systemd service units to stop before replacement and restart/verify afterwards.
    /// When empty, [`DEFAULT_MANDATORY_QUIESCE_SERVICES`] is enforced automatically.
    pub quiesce_services: Vec<String>,
    /// File mode (`0o600` default) applied to restored SQLite databases, `.env` secrets, and credentials.
    pub secret_file_mode: u32,
    /// Fallback file mode (`0o640` default) applied to restored config files without an explicit manifest mode.
    pub regular_file_mode: u32,
    /// Optional relative destination path override for standalone `.sqlite` snapshot restores
    /// (e.g. `"aetherflow.sqlite"` when `target_root` is the SQLite database's parent directory).
    #[serde(default)]
    pub sqlite_target_rel_path: Option<String>,
    /// Optional server-configured trusted SQLite database destination path (e.g. `/opt/AetherFlow/backend/data/aetherflow.sqlite`).
    /// Never derived from untrusted archive or manifest fields.
    #[serde(default)]
    pub trusted_sqlite_db_path: Option<PathBuf>,
    /// Optional server-configured trusted SQLite owner UID override.
    #[serde(default)]
    pub trusted_sqlite_uid: Option<u32>,
    /// Optional server-configured trusted SQLite owner GID override.
    #[serde(default)]
    pub trusted_sqlite_gid: Option<u32>,
    /// Optional explicit protected provenance directory override outside `backup_dir`.
    #[serde(default)]
    pub provenance_dir: Option<PathBuf>,
    /// Deterministic fault-injection hook: if set to `Some(limit)`, fails after `limit` file replacements
    /// so tests can verify automatic mid-restore rollback and service recovery.
    pub fail_after_replacements: Option<usize>,
    /// Deterministic rollback fault-injection hook: if set to `Some(limit)`, fails during rollback after `limit`
    /// file rollback steps so tests can verify that pre-restore recovery copies, WAL/SHM sidecars,
    /// and the durable `rollback-failure-journal.json` survive a failed rollback and services remain stopped.
    #[serde(default)]
    pub fail_rollback_after_restores: Option<usize>,
    /// Deterministic fault-injection hook: fail the local recovery journal write when publishing `committed`
    /// after the authoritative provenance journal has already been durably committed.
    #[serde(default)]
    pub fail_local_journal_on_commit: bool,
    /// Deterministic fault-injection hook: fail the authoritative provenance journal write when publishing `committed`.
    #[serde(default)]
    pub fail_provenance_on_commit: bool,
    /// Deterministic fault-injection hook: fail the parent directory sync immediately after renaming
    /// the authoritative provenance journal into place when publishing `committed`.
    #[serde(default)]
    pub fail_provenance_parent_sync_on_commit: bool,
    /// Deterministic fault-injection hook: fail the initial local journal write during `QUIESCING`
    /// after the initial provenance journal has been written.
    #[serde(default)]
    pub fail_initial_local_journal_write: bool,
    /// Deterministic fault-injection hook: fail removing the recovery directory during early pre-replacement cleanup.
    #[serde(default)]
    pub fail_early_cleanup_remove_rb_dir: bool,
    /// Deterministic fault-injection hook: fail removing the recovery directory during terminal cleanup.
    #[serde(default)]
    pub fail_cleanup_remove_rb_dir: bool,
}

impl Default for RestoreExecutionOptions {
    fn default() -> Self {
        Self {
            host_app_version: "4.0.0".to_string(),
            max_supported_sqlite_user_version: None,
            confirm_destructive_restore: false,
            allow_overwrite: false,
            quiesce_services: DEFAULT_MANDATORY_QUIESCE_SERVICES
                .iter()
                .map(|svc| (*svc).to_string())
                .collect(),
            secret_file_mode: 0o600,
            regular_file_mode: 0o640,
            sqlite_target_rel_path: None,
            trusted_sqlite_db_path: None,
            trusted_sqlite_uid: None,
            trusted_sqlite_gid: None,
            provenance_dir: None,
            fail_after_replacements: None,
            fail_rollback_after_restores: None,
            fail_local_journal_on_commit: false,
            fail_provenance_on_commit: false,
            fail_provenance_parent_sync_on_commit: false,
            fail_initial_local_journal_write: false,
            fail_early_cleanup_remove_rb_dir: false,
            fail_cleanup_remove_rb_dir: false,
        }
    }
}

/// Receipt returned by [`execute_staged_restore`] after a verified, atomic restore completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreExecutionReport {
    pub backup_id: String,
    pub primary_artifact: String,
    pub target_root: PathBuf,
    pub sqlite_restored: bool,
    pub sqlite_user_version: Option<i64>,
    pub sqlite_integrity_verified: bool,
    pub restored_files: Vec<PathBuf>,
    pub quiesced_services: Vec<String>,
    pub rolled_back: bool,
}

/// Durable journal entry written to `rollback-failure-journal.json` and `.restore-recovery-journal.json`
/// inside `.rollback-restore.<run_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackFailureJournalEntry {
    pub destination_path: PathBuf,
    #[serde(default)]
    pub kind: Option<BackupTargetKind>,
    pub existed_before: bool,
    pub rollback_copy_path: Option<PathBuf>,
    #[serde(default)]
    pub rollback_copy_sha256: Option<String>,
    pub had_wal_copy: Option<PathBuf>,
    #[serde(default)]
    pub wal_copy_sha256: Option<String>,
    pub had_shm_copy: Option<PathBuf>,
    #[serde(default)]
    pub shm_copy_sha256: Option<String>,
    #[serde(default)]
    pub original_mode: Option<u32>,
    #[serde(default)]
    pub original_uid: Option<u32>,
    #[serde(default)]
    pub original_gid: Option<u32>,
    #[serde(default)]
    pub wal_mode: Option<u32>,
    #[serde(default)]
    pub wal_uid: Option<u32>,
    #[serde(default)]
    pub wal_gid: Option<u32>,
    #[serde(default)]
    pub shm_mode: Option<u32>,
    #[serde(default)]
    pub shm_uid: Option<u32>,
    #[serde(default)]
    pub shm_gid: Option<u32>,
    pub restored_during_rollback: bool,
}

/// Durable failure journal persisted to `<recovery_dir>/rollback-failure-journal.json` when
/// automatic rollback cannot cleanly restore all files or restart services, AND written ahead
/// of replacement as `<recovery_dir>/.restore-recovery-journal.json` for crash-interruption recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackFailureJournal {
    pub backup_id: String,
    pub primary_artifact: String,
    pub target_root: PathBuf,
    pub recovery_dir: PathBuf,
    pub apply_failure_reason: String,
    pub rollback_errors: Vec<String>,
    pub file_rollback_incomplete: bool,
    pub services_left_stopped: bool,
    pub quiesced_services: Vec<String>,
    pub entries: Vec<RollbackFailureJournalEntry>,
    #[serde(default)]
    pub journal_state: String,
    #[serde(default)]
    pub trusted_sqlite_db_path: Option<PathBuf>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub journal_digest_sha256: Option<String>,
}

/// Canonical filename for the write-ahead interruption recovery journal inside `.rollback-restore.<run_id>`.
pub const IN_PROGRESS_RECOVERY_JOURNAL_FILENAME: &str = ".restore-recovery-journal.json";

pub(super) const JOURNAL_STATE_QUIESCING: &str = "quiescing";
pub(super) const JOURNAL_STATE_IN_PROGRESS: &str = "in_progress";
pub(super) const JOURNAL_STATE_COMMITTED: &str = "committed";
pub(super) const JOURNAL_STATE_ROLLED_BACK: &str = "rolled_back";
pub(super) const JOURNAL_STATE_RECOVERED: &str = "recovered";
pub(super) const JOURNAL_STATE_ABORTED_CLEAN: &str = "aborted_clean";
pub(super) const JOURNAL_STATE_ROLLBACK_FAILED: &str = "rollback_failed";

pub(super) fn is_terminal_journal_state(state: &str) -> bool {
    matches!(
        state,
        JOURNAL_STATE_COMMITTED
            | JOURNAL_STATE_ROLLED_BACK
            | JOURNAL_STATE_RECOVERED
            | JOURNAL_STATE_ABORTED_CLEAN
    )
}

#[derive(Debug)]
pub(super) struct StagedRestoreEntry {
    pub(super) relative_key: String,
    pub(super) staged_path: PathBuf,
    pub(super) _pinned_file: fs::File,
    pub(super) staged_dev_ino: Option<(u64, u64)>,
    pub(super) expected_sha256: String,
    pub(super) expected_size: u64,
    pub(super) destination_path: PathBuf,
    pub(super) kind: BackupTargetKind,
    pub(super) unix_mode: u32,
    pub(super) unix_uid: Option<u32>,
    pub(super) unix_gid: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct RollbackRecord {
    pub(super) destination_path: PathBuf,
    pub(super) kind: BackupTargetKind,
    pub(super) existed_before: bool,
    pub(super) rollback_copy_path: Option<PathBuf>,
    pub(super) _rollback_copy_file: Option<std::sync::Arc<fs::File>>,
    pub(super) rollback_copy_dev_ino: Option<(u64, u64)>,
    pub(super) rollback_copy_sha256: Option<String>,
    pub(super) rollback_copy_size: Option<u64>,
    pub(super) had_wal_copy: Option<PathBuf>,
    pub(super) _wal_copy_file: Option<std::sync::Arc<fs::File>>,
    pub(super) wal_copy_dev_ino: Option<(u64, u64)>,
    pub(super) wal_copy_sha256: Option<String>,
    pub(super) wal_copy_size: Option<u64>,
    pub(super) had_shm_copy: Option<PathBuf>,
    pub(super) _shm_copy_file: Option<std::sync::Arc<fs::File>>,
    pub(super) shm_copy_dev_ino: Option<(u64, u64)>,
    pub(super) shm_copy_sha256: Option<String>,
    pub(super) shm_copy_size: Option<u64>,
    pub(super) original_mode: Option<u32>,
    pub(super) original_uid: Option<u32>,
    pub(super) original_gid: Option<u32>,
    pub(super) wal_mode: Option<u32>,
    pub(super) wal_uid: Option<u32>,
    pub(super) wal_gid: Option<u32>,
    pub(super) shm_mode: Option<u32>,
    pub(super) shm_uid: Option<u32>,
    pub(super) shm_gid: Option<u32>,
}

fn is_secret_credential_entry(relative_path: &str, kind: BackupTargetKind) -> bool {
    if kind == BackupTargetKind::SqliteSnapshot {
        return false;
    }
    let lower = relative_path.to_ascii_lowercase();
    lower.ends_with(".env")
        || lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.contains("secret")
        || lower.contains("token")
}

pub(super) fn resolve_restored_entry_mode(
    raw_mode: Option<u32>,
    relative_path: &str,
    kind: BackupTargetKind,
    options: &RestoreExecutionOptions,
) -> u32 {
    let secret_cap = (options.secret_file_mode & 0o777).max(0o600) & 0o600;
    let regular_default = {
        let masked = options.regular_file_mode & 0o777;
        if masked == 0 {
            0o640
        } else {
            masked & 0o755
        }
    };

    if is_secret_credential_entry(relative_path, kind) {
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(secret_cap);
        let capped = candidate & secret_cap;
        if capped == 0 {
            secret_cap
        } else {
            capped
        }
    } else if kind == BackupTargetKind::SqliteSnapshot {
        let sqlite_default = regular_default & 0o660;
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(sqlite_default);
        let sanitized = candidate & 0o660;
        if sanitized == 0 {
            0o600
        } else {
            sanitized
        }
    } else {
        let candidate = raw_mode
            .map(|mode_val| mode_val & 0o777)
            .filter(|&mode_val| mode_val != 0)
            .unwrap_or(regular_default);
        let sanitized = candidate & 0o755;
        if sanitized == 0 {
            regular_default
        } else {
            sanitized
        }
    }
}

pub(super) fn sanitize_sqlite_sidecar_mode(raw_mode: Option<u32>) -> u32 {
    let candidate = raw_mode
        .map(|mode_val| mode_val & 0o660)
        .filter(|&mode_val| mode_val != 0)
        .unwrap_or(0o600);
    if candidate == 0 {
        0o600
    } else {
        candidate
    }
}

pub(super) fn sqlite_sidecar_paths(db_path: &Path) -> (PathBuf, PathBuf) {
    let mut wal_os = db_path.as_os_str().to_os_string();
    wal_os.push("-wal");
    let mut shm_os = db_path.as_os_str().to_os_string();
    shm_os.push("-shm");
    (PathBuf::from(wal_os), PathBuf::from(shm_os))
}

#[allow(clippy::type_complexity)]
pub(super) fn write_exclusive_staged_file(
    path: &Path,
    reader: &mut dyn Read,
    mode: u32,
) -> HostBackupResult<(fs::File, Option<(u64, u64)>, String, u64)> {
    if let Some(parent) = path.parent() {
        open_or_create_dir_nofollow(parent, 0o700, "staging parent directory")?;
    }
    let mut open_opts = fs::OpenOptions::new();
    open_opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(mode & 0o777);
        open_opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut out = open_opts.open(path).map_err(|err| {
        HostBackupError::io(format!("creating staged file {}", path.display()), err)
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buf).map_err(|err| {
            HostBackupError::io(format!("reading stream for {}", path.display()), err)
        })?;
        if count == 0 {
            break;
        }
        std::io::Write::write_all(&mut out, &buf[..count]).map_err(|err| {
            HostBackupError::io(format!("writing staged file {}", path.display()), err)
        })?;
        hasher.update(&buf[..count]);
        total += count as u64;
    }
    out.sync_all().map_err(|err| {
        HostBackupError::io(format!("fsyncing staged file {}", path.display()), err)
    })?;
    std::io::Seek::seek(&mut out, std::io::SeekFrom::Start(0)).map_err(|err| {
        HostBackupError::io(format!("rewinding staged file {}", path.display()), err)
    })?;

    #[cfg(unix)]
    let staged_dev_ino = {
        use std::os::unix::io::AsRawFd;
        let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(out.as_raw_fd(), &mut fd_stat) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat staged file {}", path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        if (fd_stat.st_mode & libc::S_IFMT) != libc::S_IFREG || fd_stat.st_nlink != 1 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "staged file descriptor is not a single-link regular file".to_string(),
            });
        }
        Some((fd_stat.st_dev as u64, fd_stat.st_ino as u64))
    };
    #[cfg(not(unix))]
    let staged_dev_ino: Option<(u64, u64)> = None;

    if let Some(parent) = path.parent() {
        sync_parent_directory(parent, "fsyncing staged file parent directory")?;
    }
    Ok((out, staged_dev_ino, hex::encode(hasher.finalize()), total))
}

pub(super) fn compute_journal_canonical_digest(
    journal: &RollbackFailureJournal,
) -> HostBackupResult<String> {
    let mut normalized_journal = journal.clone();
    normalized_journal.journal_digest_sha256 = None;
    let canonical_bytes = serde_json::to_vec(&normalized_journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!(
            "serializing recovery journal digest payload: {}",
            err
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn provenance_journal_path_for_recovery_dir(
    provenance_dir: &Path,
    rb_dir: &Path,
) -> HostBackupResult<PathBuf> {
    let dir_name = rb_dir
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .filter(|name_str| name_str.starts_with(".rollback-restore."))
        .ok_or_else(|| {
            HostBackupError::InvalidManifest(format!(
                "recovery directory '{}' does not have a valid .rollback-restore.* name",
                rb_dir.display()
            ))
        })?;
    Ok(provenance_dir.join(format!("{}.journal.json", dir_name)))
}

pub(super) fn provenance_prev_journal_path(prov_journal_path: &Path) -> PathBuf {
    let mut os_str = prov_journal_path.as_os_str().to_os_string();
    os_str.push(".prev");
    PathBuf::from(os_str)
}

fn preserve_previous_provenance_checkpoint(prov_journal_path: &Path) -> HostBackupResult<()> {
    let sidecar_path = checksum_sidecar_path(prov_journal_path);
    let Some(existing_json) = read_verified_text_file_nofollow(
        prov_journal_path,
        None,
        16 * 1024 * 1024,
        "existing provenance journal",
    )?
    else {
        return Ok(());
    };
    let Some(existing_sidecar) = read_verified_text_file_nofollow(
        &sidecar_path,
        None,
        16 * 1024,
        "existing provenance sidecar",
    )?
    else {
        return Ok(());
    };
    let Ok(expected_hex) = parse_sha256_sidecar_str(&existing_sidecar) else {
        return Ok(());
    };
    let actual_hex = hex::encode(Sha256::digest(existing_json.as_bytes()));
    if !actual_hex.eq_ignore_ascii_case(&expected_hex) {
        return Ok(());
    }
    let prev_path = provenance_prev_journal_path(prov_journal_path);
    write_private_file_atomic(
        &prev_path,
        existing_json.as_bytes(),
        "provenance-prev",
        "previous provenance checkpoint",
    )?;
    let _ = write_sha256_sidecar(&prev_path)?;
    Ok(())
}

pub(super) fn write_journal_with_sidecar_and_provenance(
    journal_path: &Path,
    provenance_dir: &Path,
    rb_dir: &Path,
    journal: &mut RollbackFailureJournal,
    generation: &mut u64,
    label: &str,
    context: &str,
) -> HostBackupResult<()> {
    write_journal_with_sidecar_and_provenance_with_fault(
        journal_path,
        provenance_dir,
        rb_dir,
        journal,
        generation,
        label,
        context,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_journal_with_sidecar_and_provenance_with_fault(
    journal_path: &Path,
    provenance_dir: &Path,
    rb_dir: &Path,
    journal: &mut RollbackFailureJournal,
    generation: &mut u64,
    label: &str,
    context: &str,
    fail_local_write: bool,
) -> HostBackupResult<()> {
    *generation = generation.saturating_add(1);
    journal.generation = *generation;
    let digest = compute_journal_canonical_digest(journal)?;
    journal.journal_digest_sha256 = Some(digest);

    let bytes = serde_json::to_vec_pretty(journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!("serializing {}: {}", context, err))
    })?;

    open_or_create_provenance_dir_nofollow(provenance_dir, "recovery provenance directory")?;
    let prov_journal_path = provenance_journal_path_for_recovery_dir(provenance_dir, rb_dir)?;
    let _ = preserve_previous_provenance_checkpoint(&prov_journal_path);
    write_private_file_atomic(&prov_journal_path, &bytes, "provenance-journal", context)?;
    let _ = write_sha256_sidecar(&prov_journal_path)?;

    if fail_local_write {
        return Err(HostBackupError::InvalidManifest(
            "simulated initial local recovery journal write failure after provenance write"
                .to_string(),
        ));
    }

    write_private_file_atomic(journal_path, &bytes, label, context)?;
    let _ = write_sha256_sidecar(journal_path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn persist_recovery_journal_snapshot(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    state: &str,
    trusted_sqlite_db_path: Option<&Path>,
) -> HostBackupResult<()> {
    persist_recovery_journal_snapshot_with_fault(
        journal_path,
        provenance_dir,
        generation,
        backup_id,
        primary_artifact,
        target_root,
        rollback_dir,
        quiesced_services,
        records,
        state,
        trusted_sqlite_db_path,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn persist_recovery_journal_snapshot_with_fault(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    state: &str,
    trusted_sqlite_db_path: Option<&Path>,
    fail_local_write: bool,
) -> HostBackupResult<()> {
    let is_terminal = is_terminal_journal_state(state);
    let entries: Vec<RollbackFailureJournalEntry> = records
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
            restored_during_rollback: is_terminal,
        })
        .collect();

    let services_left_stopped = match state {
        JOURNAL_STATE_ABORTED_CLEAN => false,
        _ => !quiesced_services.is_empty(),
    };

    let mut journal = RollbackFailureJournal {
        backup_id: backup_id.to_string(),
        primary_artifact: primary_artifact.to_string(),
        target_root: target_root.to_path_buf(),
        recovery_dir: rollback_dir.to_path_buf(),
        apply_failure_reason: state.to_string(),
        rollback_errors: Vec::new(),
        file_rollback_incomplete: !is_terminal,
        services_left_stopped,
        quiesced_services: quiesced_services.to_vec(),
        entries,
        journal_state: state.to_string(),
        trusted_sqlite_db_path: trusted_sqlite_db_path.map(Path::to_path_buf),
        generation: 0,
        journal_digest_sha256: None,
    };

    write_journal_with_sidecar_and_provenance_with_fault(
        journal_path,
        provenance_dir,
        rollback_dir,
        &mut journal,
        generation,
        "recovery-journal",
        "durable restore recovery journal",
        fail_local_write,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn persist_committed_journal_snapshot(
    journal_path: &Path,
    provenance_dir: &Path,
    generation: &mut u64,
    backup_id: &str,
    primary_artifact: &str,
    target_root: &Path,
    rollback_dir: &Path,
    quiesced_services: &[String],
    records: &[RollbackRecord],
    trusted_sqlite_db_path: Option<&Path>,
    fail_provenance_on_commit: bool,
    fail_provenance_parent_sync_on_commit: bool,
    fail_local_journal_on_commit: bool,
    committed_durably: &mut bool,
) -> HostBackupResult<()> {
    let entries: Vec<RollbackFailureJournalEntry> = records
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

    *generation = generation.saturating_add(1);
    let mut journal = RollbackFailureJournal {
        backup_id: backup_id.to_string(),
        primary_artifact: primary_artifact.to_string(),
        target_root: target_root.to_path_buf(),
        recovery_dir: rollback_dir.to_path_buf(),
        apply_failure_reason: JOURNAL_STATE_COMMITTED.to_string(),
        rollback_errors: Vec::new(),
        file_rollback_incomplete: false,
        services_left_stopped: !quiesced_services.is_empty(),
        quiesced_services: quiesced_services.to_vec(),
        entries,
        journal_state: JOURNAL_STATE_COMMITTED.to_string(),
        trusted_sqlite_db_path: trusted_sqlite_db_path.map(Path::to_path_buf),
        generation: *generation,
        journal_digest_sha256: None,
    };
    let digest = compute_journal_canonical_digest(&journal)?;
    journal.journal_digest_sha256 = Some(digest);

    let bytes = serde_json::to_vec_pretty(&journal).map_err(|err| {
        HostBackupError::InvalidManifest(format!("serializing committed recovery journal: {}", err))
    })?;

    open_or_create_provenance_dir_nofollow(provenance_dir, "recovery provenance directory")?;
    let prov_journal_path = provenance_journal_path_for_recovery_dir(provenance_dir, rollback_dir)?;
    let _ = preserve_previous_provenance_checkpoint(&prov_journal_path);

    if fail_provenance_on_commit {
        return Err(HostBackupError::InvalidManifest(
            "simulated provenance commit failure before authority publication".to_string(),
        ));
    }

    write_private_file_atomic_tracking_rename(
        &prov_journal_path,
        &bytes,
        "provenance-journal",
        "durable restore recovery journal",
        fail_provenance_parent_sync_on_commit,
        committed_durably,
    )?;
    let _ = write_sha256_sidecar(&prov_journal_path)?;

    if fail_local_journal_on_commit {
        return Err(HostBackupError::InvalidManifest(
            "simulated local journal commit failure after provenance commit".to_string(),
        ));
    }

    write_private_file_atomic(
        journal_path,
        &bytes,
        "recovery-journal",
        "durable restore recovery journal",
    )?;
    let _ = write_sha256_sidecar(journal_path)?;
    Ok(())
}

pub(super) fn remove_recovery_dir_and_provenance(
    rb_dir: &Path,
    provenance_dir: &Path,
) -> HostBackupResult<()> {
    remove_recovery_dir_and_provenance_with_fault(rb_dir, provenance_dir, false)
}

pub(super) fn remove_recovery_dir_and_provenance_with_fault(
    rb_dir: &Path,
    provenance_dir: &Path,
    fail_remove_rb_dir: bool,
) -> HostBackupResult<()> {
    let prov_journal = provenance_journal_path_for_recovery_dir(provenance_dir, rb_dir)?;
    if fail_remove_rb_dir {
        return Err(HostBackupError::io(
            format!("removing completed recovery directory {}", rb_dir.display()),
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated recovery directory removal failure",
            ),
        ));
    }
    if rb_dir.exists() {
        fs::remove_dir_all(rb_dir).map_err(|err| {
            HostBackupError::io(
                format!("removing completed recovery directory {}", rb_dir.display()),
                err,
            )
        })?;
        if let Some(parent) = rb_dir.parent() {
            sync_parent_directory(
                parent,
                "fsyncing backup_dir after removing recovery directory",
            )?;
        }
    }

    let prov_sidecar = checksum_sidecar_path(&prov_journal);
    let prev_journal = provenance_prev_journal_path(&prov_journal);
    let prev_sidecar = checksum_sidecar_path(&prev_journal);

    unlink_file_at_destination(&prov_sidecar, "removing provenance journal sidecar")?;
    unlink_file_at_destination(
        &prev_sidecar,
        "removing previous provenance journal sidecar",
    )?;
    unlink_file_at_destination(&prev_journal, "removing previous provenance journal")?;
    unlink_file_at_destination(&prov_journal, "removing provenance journal")?;

    if let Ok(mut iter) = fs::read_dir(provenance_dir) {
        if iter.next().is_none() {
            let _ = fs::remove_dir(provenance_dir);
        }
    }
    Ok(())
}
