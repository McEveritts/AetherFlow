use super::*;

// -----------------------------------------------------------------------------
// Rollback Journal & Compensating Recovery
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub(super) enum RollbackEntry {
    /// A file that existed before the execution and was backed up to `<path>.bak-af`.
    RestorableFile {
        target: PathBuf,
        backup: PathBuf,
        ownership: Option<(u32, u32)>,
    },
    /// A file that did not exist before the execution and should be removed on failure/cancellation.
    CreatedFile { target: PathBuf },
    /// A systemd unit that was newly written and should be stopped/disabled/removed on rollback.
    CreatedSystemdUnit {
        unit_name: String,
        unit_path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub(super) struct DirectorySnapshot {
    target_dir: PathBuf,
    backup_dir: PathBuf,
}

pub(super) fn is_version_receipt_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name == ".af-version")
        .unwrap_or(false)
}

pub(super) fn is_transient_af_artifact_name(name: &str) -> bool {
    name == ".af-version"
        || name.starts_with(".af-version.bak-af.")
        || name.contains(".bak-af.")
        || name.contains(".bak-af-state.")
        || name.contains(".af-tmp-")
        || name.contains(".af-restore-")
        || name.contains(".af-old-")
}

pub(super) fn backup_dir_path_for(target_dir: &Path) -> PathBuf {
    let mut os = target_dir.as_os_str().to_os_string();
    os.push(format!(".bak-af-state.{}", uuid::Uuid::new_v4()));
    PathBuf::from(os)
}

pub(super) fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(super) fn scan_dir_snapshot_bytes(
    src_dir: &Path,
    root_bound: Option<&Path>,
    cumulative_bytes: &mut u64,
    limit: u64,
    cancel: Option<(&CancellationToken, &str)>,
) -> Result<u64, PackageExecutorError> {
    if let Some((token, pkg_id)) = cancel {
        token.check(pkg_id)?;
    }
    validate_filesystem_path(src_dir, root_bound)?;
    let src_meta = fs::symlink_metadata(src_dir)?;
    if src_meta.file_type().is_symlink() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to snapshot symlink directory: {}",
            src_dir.display()
        )));
    }
    if !src_meta.is_dir() {
        return Ok(0);
    }

    let mut dir_bytes = 0_u64;
    for entry_res in fs::read_dir(src_dir)? {
        if let Some((token, pkg_id)) = cancel {
            token.check(pkg_id)?;
        }
        let entry = entry_res?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if is_transient_af_artifact_name(&name_str) {
            continue;
        }
        let child_src = entry.path();
        let meta = fs::symlink_metadata(&child_src)?;
        if meta.file_type().is_symlink() {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to snapshot symlink entry: {}",
                child_src.display()
            )));
        }
        if meta.is_dir() {
            let sub_bytes =
                scan_dir_snapshot_bytes(&child_src, root_bound, cumulative_bytes, limit, cancel)?;
            dir_bytes = dir_bytes.saturating_add(sub_bytes);
        } else if meta.is_file() {
            let len = meta.len();
            *cumulative_bytes = cumulative_bytes.saturating_add(len);
            dir_bytes = dir_bytes.saturating_add(len);
            if *cumulative_bytes > limit {
                return Err(PackageExecutorError::ExecutionError(format!(
                    "Declarative rollback snapshot exceeds the {limit}-byte copy ceiling (at least {cumulative_bytes} bytes)"
                )));
            }
        }
    }
    Ok(dir_bytes)
}

pub(super) fn copy_dir_snapshot_recursive(
    src_dir: &Path,
    dst_dir: &Path,
    root_bound: Option<&Path>,
    mut budget: Option<&mut SnapshotBudget>,
    cancel: Option<(&CancellationToken, &str)>,
) -> Result<(), PackageExecutorError> {
    if let Some((token, pkg_id)) = cancel {
        token.check(pkg_id)?;
    }
    validate_filesystem_path(src_dir, root_bound)?;
    validate_filesystem_path(dst_dir, root_bound)?;
    let src_meta = fs::symlink_metadata(src_dir)?;
    if src_meta.file_type().is_symlink() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to snapshot symlink directory: {}",
            src_dir.display()
        )));
    }
    create_dir_all_0755(dst_dir)?;

    for entry_res in fs::read_dir(src_dir)? {
        if let Some((token, pkg_id)) = cancel {
            token.check(pkg_id)?;
        }
        let entry = entry_res?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if is_transient_af_artifact_name(&name_str) {
            continue;
        }
        let child_src = entry.path();
        let child_dst = dst_dir.join(&file_name);
        let meta = fs::symlink_metadata(&child_src)?;
        if meta.file_type().is_symlink() {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to snapshot symlink entry: {}",
                child_src.display()
            )));
        }
        if meta.is_dir() {
            copy_dir_snapshot_recursive(
                &child_src,
                &child_dst,
                root_bound,
                budget.as_deref_mut(),
                cancel,
            )?;
        } else if meta.is_file() {
            if let Some(budget) = budget.as_deref_mut() {
                budget
                    .charge(&child_src, meta.len())
                    .map_err(PackageExecutorError::ExecutionError)?;
            }
            let mut src_file = open_read_nofollow(&child_src)?;
            let mut dst_file = open_new_private_file(&child_dst, 0o600)?;
            let copied = std::io::copy(&mut src_file, &mut dst_file)?;
            if copied > meta.len() {
                if let Some(budget) = budget.as_deref_mut() {
                    budget
                        .charge(&child_src, copied - meta.len())
                        .map_err(PackageExecutorError::ExecutionError)?;
                }
            }
            dst_file.set_permissions(meta.permissions())?;
            dst_file.sync_all()?;
        }
    }
    let _ = fs::set_permissions(dst_dir, src_meta.permissions());
    Ok(())
}

pub(super) fn restore_directory_snapshot_atomic(
    target_dir: &Path,
    backup_dir: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(target_dir, root_bound)?;
    validate_filesystem_path(backup_dir, root_bound)?;
    if !backup_dir.is_dir() {
        return Err(PackageExecutorError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("state snapshot directory missing: {}", backup_dir.display()),
        )));
    }
    let dir_name = target_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let staging_dir =
        target_dir.with_file_name(format!(".{}.af-restore-{}", dir_name, uuid::Uuid::new_v4()));
    let old_dir =
        target_dir.with_file_name(format!(".{}.af-old-{}", dir_name, uuid::Uuid::new_v4()));
    validate_filesystem_path(&staging_dir, root_bound)?;
    validate_filesystem_path(&old_dir, root_bound)?;

    if let Err(err) = copy_dir_snapshot_recursive(backup_dir, &staging_dir, root_bound, None, None)
    {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err);
    }

    // Preserve any live `.af-version` and `.af-version.bak-af.*` files inside `target_dir`
    // so receipt restoration remains strictly gated on Step 4 (receipt honesty rule).
    if target_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(target_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name();
                let fname_str = fname.to_string_lossy();
                if fname_str == ".af-version" || fname_str.starts_with(".af-version.bak-af.") {
                    let src_path = entry.path();
                    let dst_path = staging_dir.join(&fname);
                    if let Ok(meta) = fs::symlink_metadata(&src_path) {
                        if meta.is_file() {
                            if let (Ok(mut s), Ok(mut d)) = (
                                File::open(&src_path),
                                open_new_private_file(&dst_path, 0o600),
                            ) {
                                let _ = std::io::copy(&mut s, &mut d);
                                let _ = d.set_permissions(meta.permissions());
                                let _ = d.sync_all();
                            }
                        }
                    }
                }
            }
        }
    }

    if target_dir.exists() {
        if let Err(err) = fs::rename(target_dir, &old_dir) {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(PackageExecutorError::Io(err));
        }
        match fs::rename(&staging_dir, target_dir) {
            Ok(()) => {
                let _ = fs::remove_dir_all(&old_dir);
                Ok(())
            }
            Err(err) => {
                let _ = fs::rename(&old_dir, target_dir);
                let _ = fs::remove_dir_all(&staging_dir);
                Err(PackageExecutorError::Io(err))
            }
        }
    } else {
        match fs::rename(&staging_dir, target_dir) {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_dir_all(&staging_dir);
                Err(PackageExecutorError::Io(err))
            }
        }
    }
}

/// Tracks mutations performed during an install/update/remove transaction so that failures
/// or cancellations cleanly restore modified files and remove partial artifacts.
#[derive(Debug, Default)]
pub(crate) struct RollbackJournal {
    pub(super) entries: Vec<RollbackEntry>,
    restorable_services: Vec<String>,
    touched_services: Vec<String>,
    pub(super) dir_snapshots: Vec<DirectorySnapshot>,
    apt_downgrades: Vec<(String, String)>,
    apt_removals: Vec<String>,
    pub(super) pre_existing_version: Option<String>,
    pub(super) has_existing_installation: bool,
    pub(super) incomplete_rollback_error: Option<String>,
    temp_files: Vec<PathBuf>,
    pub(super) fs_root: Option<PathBuf>,
    staged_snapshot_bytes: u64,
}

impl RollbackJournal {
    pub(super) fn new(fs_root: Option<PathBuf>) -> Self {
        Self {
            fs_root,
            ..Self::default()
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.restorable_services.is_empty()
            && self.touched_services.is_empty()
            && self.dir_snapshots.is_empty()
            && self.apt_downgrades.is_empty()
            && self.apt_removals.is_empty()
            && self.temp_files.is_empty()
    }

    pub(super) fn stage_directory_snapshots_with_cancel(
        &mut self,
        target_dirs: &[PathBuf],
        cancel: Option<(&CancellationToken, &str)>,
    ) -> Result<(), PackageExecutorError> {
        let mut candidate_dirs: Vec<PathBuf> = Vec::new();
        for target_dir in target_dirs {
            if let Some((token, pkg_id)) = cancel {
                token.check(pkg_id)?;
            }
            validate_filesystem_path(target_dir, self.fs_root.as_deref())?;
            if self
                .dir_snapshots
                .iter()
                .any(|s| s.target_dir == *target_dir)
                || candidate_dirs.iter().any(|d| d == target_dir)
            {
                continue;
            }
            match fs::symlink_metadata(target_dir) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(PackageExecutorError::SecurityViolation(format!(
                            "refusing to snapshot symlink state directory: {}",
                            target_dir.display()
                        )));
                    }
                    if meta.is_dir() {
                        candidate_dirs.push(target_dir.to_path_buf());
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(PackageExecutorError::Io(err)),
            }
        }

        // Sort shallowest-first so nested subtrees (e.g. /var/lib/novnc/.vnc under /var/lib/novnc)
        // are not double-counted or double-snapshotted once their ancestor is covered.
        candidate_dirs.sort_by_key(|p| p.components().count());
        let mut pending_dirs: Vec<PathBuf> = Vec::new();
        for dir in candidate_dirs {
            let covered_by_existing = self
                .dir_snapshots
                .iter()
                .any(|s| dir.starts_with(&s.target_dir));
            let covered_by_pending = pending_dirs.iter().any(|p| dir.starts_with(p));
            if !covered_by_existing && !covered_by_pending {
                pending_dirs.push(dir);
            }
        }

        if pending_dirs.is_empty() {
            return Ok(());
        }

        let limit =
            configured_max_snapshot_bytes().map_err(PackageExecutorError::ExecutionError)?;
        let mut cumulative_bytes = self.staged_snapshot_bytes;
        if cumulative_bytes > limit {
            return Err(PackageExecutorError::ExecutionError(format!(
                "Declarative rollback snapshot exceeds the {limit}-byte copy ceiling (at least {cumulative_bytes} bytes)"
            )));
        }

        struct SnapshotPlan {
            target_dir: PathBuf,
            backup_dir: PathBuf,
        }

        let mut plans = Vec::with_capacity(pending_dirs.len());
        let mut per_dev_usage: HashMap<u64, (u64, u64)> = HashMap::new();

        for target_dir in pending_dirs {
            let backup_dir = backup_dir_path_for(&target_dir);
            validate_filesystem_path(&backup_dir, self.fs_root.as_deref())?;
            let dir_bytes = scan_dir_snapshot_bytes(
                &target_dir,
                self.fs_root.as_deref(),
                &mut cumulative_bytes,
                limit,
                cancel,
            )?;
            let (dev, available) = snapshot_filesystem_capacity(&backup_dir)
                .map_err(PackageExecutorError::ExecutionError)?;
            let entry = per_dev_usage.entry(dev).or_insert((0, available));
            entry.0 = entry.0.saturating_add(dir_bytes);
            entry.1 = available;
            plans.push(SnapshotPlan {
                target_dir,
                backup_dir,
            });
        }

        for (needed_bytes, available) in per_dev_usage.values() {
            ensure_snapshot_free_space(*needed_bytes, *available)
                .map_err(PackageExecutorError::ExecutionError)?;
        }

        let batch_start_idx = self.dir_snapshots.len();
        let initial_staged_bytes = self.staged_snapshot_bytes;

        for plan in plans {
            let copy_res = (|| -> Result<u64, PackageExecutorError> {
                if let Some((token, pkg_id)) = cancel {
                    token.check(pkg_id)?;
                }
                let (_dev, available_now) = snapshot_filesystem_capacity(&plan.backup_dir)
                    .map_err(PackageExecutorError::ExecutionError)?;
                if available_now < SNAPSHOT_RESERVE_BYTES {
                    ensure_snapshot_free_space(0, available_now)
                        .map_err(PackageExecutorError::ExecutionError)?;
                }
                let remaining_global = limit.saturating_sub(self.staged_snapshot_bytes);
                let budget_cap =
                    remaining_global.min(available_now.saturating_sub(SNAPSHOT_RESERVE_BYTES));
                let mut budget = SnapshotBudget::new(budget_cap);
                copy_dir_snapshot_recursive(
                    &plan.target_dir,
                    &plan.backup_dir,
                    self.fs_root.as_deref(),
                    Some(&mut budget),
                    cancel,
                )?;
                Ok(budget_cap.saturating_sub(budget.remaining()))
            })();

            match copy_res {
                Ok(copied_bytes) => {
                    self.staged_snapshot_bytes =
                        self.staged_snapshot_bytes.saturating_add(copied_bytes);
                    self.dir_snapshots.push(DirectorySnapshot {
                        target_dir: plan.target_dir,
                        backup_dir: plan.backup_dir,
                    });
                }
                Err(err) => {
                    if validate_filesystem_path(&plan.backup_dir, self.fs_root.as_deref()).is_ok() {
                        let _ = fs::remove_dir_all(&plan.backup_dir);
                    }
                    for staged in self.dir_snapshots.drain(batch_start_idx..) {
                        if validate_filesystem_path(&staged.backup_dir, self.fs_root.as_deref())
                            .is_ok()
                        {
                            let _ = fs::remove_dir_all(&staged.backup_dir);
                        }
                    }
                    self.staged_snapshot_bytes = initial_staged_bytes;
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub(super) fn stage_directory_snapshot(
        &mut self,
        target_dir: &Path,
    ) -> Result<(), PackageExecutorError> {
        self.stage_directory_snapshots_with_cancel(&[target_dir.to_path_buf()], None)
    }

    pub(super) fn record_touched_service(&mut self, unit_name: &str) {
        let norm = normalize_unit_filename(unit_name);
        if !norm.is_empty() && !self.touched_services.iter().any(|u| u == &norm) {
            self.touched_services.push(norm);
        }
    }

    pub(super) fn record_apt_upgrade(&mut self, package: &str, prior_version: &str) {
        let pkg = package.trim();
        let ver = prior_version.trim();
        if !pkg.is_empty() && !ver.is_empty() && !self.apt_downgrades.iter().any(|(p, _)| p == pkg)
        {
            self.apt_downgrades.push((pkg.to_string(), ver.to_string()));
        }
    }

    pub(super) fn record_apt_install(&mut self, package: &str) {
        let pkg = package.trim();
        if !pkg.is_empty()
            && !self.apt_downgrades.iter().any(|(p, _)| p == pkg)
            && !self.apt_removals.iter().any(|p| p == pkg)
        {
            self.apt_removals.push(pkg.to_string());
        }
    }

    /// Prepares a file for mutation: validates all ancestors against symlinks, and if `target`
    /// already exists as a regular file, copies it once to `<target>.bak-af`; otherwise records
    /// it as a newly created file.
    pub(super) fn stage_file_mutation(
        &mut self,
        target: &Path,
    ) -> Result<(), PackageExecutorError> {
        validate_filesystem_path(target, self.fs_root.as_deref())?;
        let backup = backup_path_for(target);
        validate_filesystem_path(&backup, self.fs_root.as_deref())?;

        let already_staged = self.entries.iter().any(|e| match e {
            RollbackEntry::RestorableFile { target: t, .. } => t == target,
            RollbackEntry::CreatedFile { target: t } => t == target,
            _ => false,
        });
        if already_staged {
            return Ok(());
        }

        match fs::symlink_metadata(target) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing to stage or overwrite symlink target: {}",
                        target.display()
                    )));
                }
                if meta.is_file() {
                    let mut source = File::open(target)?;
                    let mut destination = open_new_private_file(&backup, 0o600)?;
                    std::io::copy(&mut source, &mut destination)?;
                    destination.set_permissions(meta.permissions())?;
                    destination.sync_all()?;
                    self.entries.push(RollbackEntry::RestorableFile {
                        target: target.to_path_buf(),
                        backup,
                        ownership: {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                Some((meta.uid(), meta.gid()))
                            }
                            #[cfg(not(unix))]
                            {
                                None
                            }
                        },
                    });
                } else {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing to stage non-regular file target: {}",
                        target.display()
                    )));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.entries.push(RollbackEntry::CreatedFile {
                    target: target.to_path_buf(),
                });
            }
            Err(err) => return Err(PackageExecutorError::Io(err)),
        }
        Ok(())
    }

    pub(super) fn record_created_systemd_unit(&mut self, unit_name: &str, unit_path: &Path) {
        self.entries.push(RollbackEntry::CreatedSystemdUnit {
            unit_name: unit_name.to_string(),
            unit_path: unit_path.to_path_buf(),
        });
    }

    pub(super) fn record_restorable_systemd_service(&mut self, unit_name: &str) {
        let norm = normalize_unit_filename(unit_name);
        if !self.restorable_services.iter().any(|u| u == &norm) {
            self.restorable_services.push(norm);
        }
    }

    pub(super) fn track_temp_file(&mut self, path: PathBuf) {
        self.temp_files.push(path);
    }

    pub(super) fn cleanup_temp_files(&mut self) {
        for tmp in self.temp_files.drain(..) {
            if validate_filesystem_path(&tmp, self.fs_root.as_deref()).is_ok() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }

    /// Commits the transaction: removes `.bak-af` backup files, state snapshots, and temporary downloads.
    pub(super) fn commit(&mut self) {
        self.cleanup_temp_files();
        self.restorable_services.clear();
        self.touched_services.clear();
        self.apt_downgrades.clear();
        self.apt_removals.clear();
        self.incomplete_rollback_error = None;
        for entry in self.entries.drain(..) {
            if let RollbackEntry::RestorableFile { backup, .. } = entry {
                if validate_filesystem_path(&backup, self.fs_root.as_deref()).is_ok() {
                    let _ = fs::remove_file(backup);
                }
            }
        }
        for snapshot in self.dir_snapshots.drain(..) {
            if validate_filesystem_path(&snapshot.backup_dir, self.fs_root.as_deref()).is_ok() {
                let _ = fs::remove_dir_all(snapshot.backup_dir);
            }
        }
        self.staged_snapshot_bytes = 0;
    }

    /// Rolls back all staged mutations in reverse order, validating all ancestor paths before
    /// restoring backups or unlinking created files.
    pub(super) async fn rollback<R: CommandRunner>(&mut self, runner: &R) -> Vec<String> {
        let mut notes = Vec::new();
        let mut incomplete_errors = Vec::new();
        self.incomplete_rollback_error = None;
        self.cleanup_temp_files();
        let noop_cancel = CancellationToken::new();

        // 1. Stop any service units touched/started by the recipe and verify quiescence BEFORE
        //    restoring any files or mutable state directories.
        let mut service_quiescence_failed = false;
        let mut touched_units: Vec<String> = self.touched_services.drain(..).rev().collect();
        af_release::lifecycle::sort_units_for_stop(&mut touched_units);
        for unit_name in touched_units {
            let stop_res = runner
                .run_command(
                    "systemctl",
                    &["stop".to_string(), "--".to_string(), unit_name.clone()],
                    &[],
                    &noop_cancel,
                )
                .await;
            let stop_ok = matches!(&stop_res, Ok(out) if out.success());
            let active_res = runner
                .run_command(
                    "systemctl",
                    &["is-active".to_string(), "--".to_string(), unit_name.clone()],
                    &[],
                    &noop_cancel,
                )
                .await;
            let still_active = match &active_res {
                Ok(out) => matches!(out.stdout.trim(), "active" | "activating" | "reloading"),
                Err(_) => true,
            };
            if !stop_ok || still_active {
                service_quiescence_failed = true;
                let msg = format!(
                    "incomplete rollback: service {} failed to stop or reach quiescence before state restoration",
                    unit_name
                );
                notes.push(msg.clone());
                incomplete_errors.push(msg);
            } else {
                notes.push(format!(
                    "stopped and verified quiescence of service {}",
                    unit_name
                ));
            }
        }

        if service_quiescence_failed {
            self.incomplete_rollback_error = Some(incomplete_errors.join("; "));
            return notes;
        }

        let mut deferred_receipt_entries = Vec::new();
        let mut non_receipt_entries = Vec::new();
        while let Some(entry) = self.entries.pop() {
            let is_receipt = match &entry {
                RollbackEntry::RestorableFile { target, .. } => is_version_receipt_path(target),
                RollbackEntry::CreatedFile { target } => is_version_receipt_path(target),
                RollbackEntry::CreatedSystemdUnit { .. } => false,
            };
            if is_receipt {
                deferred_receipt_entries.push(entry);
            } else {
                non_receipt_entries.push(entry);
            }
        }

        let mut state_restore_failed = false;

        // 2a. Restore non-receipt entries (systemd units, config files, newly created files).
        for entry in non_receipt_entries {
            match entry {
                RollbackEntry::CreatedSystemdUnit {
                    unit_name,
                    unit_path,
                } => {
                    let _ = runner
                        .run_command(
                            "systemctl",
                            &["stop".to_string(), "--".to_string(), unit_name.clone()],
                            &[],
                            &noop_cancel,
                        )
                        .await;
                    let _ = runner
                        .run_command(
                            "systemctl",
                            &["disable".to_string(), "--".to_string(), unit_name.clone()],
                            &[],
                            &noop_cancel,
                        )
                        .await;
                    if let Err(err) = validate_filesystem_path(&unit_path, self.fs_root.as_deref())
                    {
                        notes.push(format!(
                            "skipped unsafe rollback path {}: {}",
                            unit_path.display(),
                            err
                        ));
                    } else if unit_path.is_file() {
                        let _ = fs::remove_file(&unit_path);
                        notes.push(format!("rolled back systemd unit {}", unit_name));
                    }
                }
                RollbackEntry::RestorableFile {
                    target,
                    backup,
                    ownership,
                } => {
                    if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref())
                        .and_then(|_| validate_filesystem_path(&backup, self.fs_root.as_deref()))
                    {
                        let msg = format!(
                            "skipped unsafe backup restore for {}: {}",
                            target.display(),
                            err
                        );
                        notes.push(msg.clone());
                        incomplete_errors.push(msg);
                        state_restore_failed = true;
                        continue;
                    }
                    if backup.is_file() {
                        if let Some((owner_uid, owner_gid)) = ownership {
                            let result = runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-h".to_string(),
                                        format!("{}:{}", owner_uid, owner_gid),
                                        backup.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    &noop_cancel,
                                )
                                .await;
                            if !matches!(result, Ok(output) if output.success()) {
                                let msg =
                                    format!("failed to restore ownership for {}", target.display());
                                notes.push(msg.clone());
                                incomplete_errors.push(msg);
                                state_restore_failed = true;
                                continue;
                            }
                        }
                        match fs::rename(&backup, &target) {
                            Ok(()) => {
                                notes.push(format!("restored backup for {}", target.display()));
                            }
                            Err(_rename_err) => match fs::copy(&backup, &target) {
                                Ok(_) => {
                                    let _ = fs::remove_file(&backup);
                                    notes.push(format!("restored backup for {}", target.display()));
                                }
                                Err(copy_err) => {
                                    let msg = format!(
                                        "failed to restore backup for {} ({}); recovery backup preserved at {}",
                                        target.display(),
                                        copy_err,
                                        backup.display()
                                    );
                                    notes.push(msg.clone());
                                    incomplete_errors.push(msg);
                                    state_restore_failed = true;
                                }
                            },
                        }
                    }
                }
                RollbackEntry::CreatedFile { target } => {
                    if let Err(err) =
                        validate_filesystem_symlink_path(&target, self.fs_root.as_deref())
                    {
                        notes.push(format!(
                            "skipped unsafe rollback removal for {}: {}",
                            target.display(),
                            err
                        ));
                        continue;
                    }
                    if target.is_file() || fs::symlink_metadata(&target).is_ok() {
                        let _ = fs::remove_file(&target);
                        notes.push(format!("removed newly created file {}", target.display()));
                    }
                }
            }
        }

        // 2b. Atomically restore snapshotted mutable state/config directories once the service is stopped.
        for snapshot in self.dir_snapshots.iter().rev() {
            match restore_directory_snapshot_atomic(
                &snapshot.target_dir,
                &snapshot.backup_dir,
                self.fs_root.as_deref(),
            ) {
                Ok(()) => {
                    notes.push(format!(
                        "restored state directory snapshot for {}",
                        snapshot.target_dir.display()
                    ));
                }
                Err(err) => {
                    state_restore_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to restore state directory snapshot for {} ({}); recovery backup preserved at {}",
                        snapshot.target_dir.display(),
                        err,
                        snapshot.backup_dir.display()
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
            }
        }

        // 3. For APT package upgrades where a prior version was recorded before the upgrade,
        //    attempt `apt-get install -y --allow-downgrades <pkg>=<old_version>`.
        let mut package_downgrade_failed = false;
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];
        let downgrades: Vec<(String, String)> = self.apt_downgrades.drain(..).rev().collect();
        for (pkg, old_version) in downgrades {
            let pkg_spec = format!("{pkg}={old_version}");
            let downgrade_args = vec![
                "-o".to_string(),
                "DPkg::Lock::Timeout=120".to_string(),
                "-o".to_string(),
                "DPkg::Options::=--force-confdef".to_string(),
                "-o".to_string(),
                "DPkg::Options::=--force-confold".to_string(),
                "install".to_string(),
                "-y".to_string(),
                "-qq".to_string(),
                "--allow-downgrades".to_string(),
                pkg_spec.clone(),
            ];
            let downgrade_res = runner
                .run_command("apt-get", &downgrade_args, &apt_env, &noop_cancel)
                .await;
            match downgrade_res {
                Ok(out) if out.success() => {
                    notes.push(format!("downgraded APT package {}", pkg_spec));
                }
                Ok(out) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to downgrade APT package {} (exit {}): {}",
                        pkg_spec,
                        out.exit_code,
                        out.combined_output()
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
                Err(err) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to downgrade APT package {}: {}",
                        pkg_spec, err
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
            }
        }
        let removals: Vec<String> = self.apt_removals.drain(..).rev().collect();
        for pkg in removals {
            let remove_args = vec![
                "-o".to_string(),
                "DPkg::Lock::Timeout=120".to_string(),
                "remove".to_string(),
                "-y".to_string(),
                "-qq".to_string(),
                "--no-auto-remove".to_string(),
                pkg.clone(),
            ];
            let remove_res = runner
                .run_command("apt-get", &remove_args, &apt_env, &noop_cancel)
                .await;
            match remove_res {
                Ok(out) if out.success() => {
                    notes.push(format!("removed newly installed APT package {}", pkg));
                }
                Ok(out) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to remove newly installed APT package {} (exit {}): {}",
                        pkg,
                        out.exit_code,
                        out.combined_output()
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
                Err(err) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to remove newly installed APT package {}: {}",
                        pkg, err
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
            }
        }

        // 4. Critical receipt honesty rule: only restore the prior `.af-version` receipt if
        //    service stop, state restoration, AND package version restoration all succeeded.
        if !service_quiescence_failed && !state_restore_failed && !package_downgrade_failed {
            for entry in deferred_receipt_entries {
                match entry {
                    RollbackEntry::RestorableFile {
                        target,
                        backup,
                        ownership,
                    } => {
                        if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref())
                            .and_then(|_| {
                                validate_filesystem_path(&backup, self.fs_root.as_deref())
                            })
                        {
                            let msg = format!(
                                "skipped unsafe receipt restore for {}: {}",
                                target.display(),
                                err
                            );
                            notes.push(msg.clone());
                            incomplete_errors.push(msg);
                            continue;
                        }
                        if backup.is_file() {
                            if let Some((owner_uid, owner_gid)) = ownership {
                                let result = runner
                                    .run_command(
                                        "chown",
                                        &[
                                            "-h".to_string(),
                                            format!("{}:{}", owner_uid, owner_gid),
                                            backup.to_string_lossy().to_string(),
                                        ],
                                        &[],
                                        &noop_cancel,
                                    )
                                    .await;
                                if !matches!(result, Ok(output) if output.success()) {
                                    let msg = format!(
                                        "failed to restore ownership for {}",
                                        target.display()
                                    );
                                    notes.push(msg.clone());
                                    incomplete_errors.push(msg);
                                    continue;
                                }
                            }
                            match fs::rename(&backup, &target) {
                                Ok(()) => {
                                    notes.push(format!("restored backup for {}", target.display()));
                                }
                                Err(_rename_err) => match fs::copy(&backup, &target) {
                                    Ok(_) => {
                                        let _ = fs::remove_file(&backup);
                                        notes.push(format!(
                                            "restored backup for {}",
                                            target.display()
                                        ));
                                    }
                                    Err(copy_err) => {
                                        let msg = format!(
                                            "failed to restore backup for {} ({}); recovery backup preserved at {}",
                                            target.display(),
                                            copy_err,
                                            backup.display()
                                        );
                                        notes.push(msg.clone());
                                        incomplete_errors.push(msg);
                                    }
                                },
                            }
                        }
                    }
                    RollbackEntry::CreatedFile { target } => {
                        if validate_filesystem_symlink_path(&target, self.fs_root.as_deref())
                            .is_ok()
                            && (target.is_file() || fs::symlink_metadata(&target).is_ok())
                        {
                            let _ = fs::remove_file(&target);
                            notes.push(format!("removed newly created file {}", target.display()));
                        }
                    }
                    RollbackEntry::CreatedSystemdUnit { .. } => {}
                }
            }

            if incomplete_errors.is_empty() {
                for snapshot in self.dir_snapshots.drain(..) {
                    if validate_filesystem_path(&snapshot.backup_dir, self.fs_root.as_deref())
                        .is_ok()
                    {
                        let _ = fs::remove_dir_all(&snapshot.backup_dir);
                    }
                }
                self.staged_snapshot_bytes = 0;
                if !self.restorable_services.is_empty() {
                    let _ = runner
                        .run_command(
                            "systemctl",
                            &["daemon-reload".to_string()],
                            &[],
                            &noop_cancel,
                        )
                        .await;
                    for unit_name in self.restorable_services.drain(..) {
                        let _ = runner
                            .run_command(
                                "systemctl",
                                &["start".to_string(), unit_name.clone()],
                                &[],
                                &noop_cancel,
                            )
                            .await;
                        notes.push(format!("restarted restored systemd service {}", unit_name));
                    }
                }
            } else {
                self.incomplete_rollback_error = Some(incomplete_errors.join("; "));
            }
        } else {
            notes.push(
                "refused to restore stale .af-version receipt after incomplete recovery; recovery backup preserved"
                    .to_string(),
            );
            self.incomplete_rollback_error = Some(incomplete_errors.join("; "));
        }

        notes
    }
}

pub(super) fn backup_path_for(target: &Path) -> PathBuf {
    let mut os = target.as_os_str().to_os_string();
    os.push(format!(".bak-af.{}", uuid::Uuid::new_v4()));
    PathBuf::from(os)
}

/// Writes `content` atomically to `target` via a sibling `.tmp.<uuid>` file and applies permissions,
/// verifying all ancestor components against symlinks before and after directory creation.
#[cfg(test)]
pub(super) fn write_file_atomic_with_mode(
    target: &Path,
    content: &[u8],
    mode: u32,
) -> Result<(), PackageExecutorError> {
    write_file_atomic_with_mode_bounded(target, content, mode, None)
}

pub(super) fn write_file_atomic_with_mode_bounded(
    target: &Path,
    content: &[u8],
    mode: u32,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    write_file_atomic_with_file_owner(target, content, mode, root_bound, None)
}

pub(super) fn write_file_atomic_with_file_owner(
    target: &Path,
    content: &[u8],
    mode: u32,
    root_bound: Option<&Path>,
    owner: Option<(u32, u32)>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(target, root_bound)?;
    if let Some(parent) = target.parent() {
        validate_filesystem_path(parent, root_bound)?;
        create_dir_all_0755(parent)?;
        validate_filesystem_path(parent, root_bound)?;
    }
    validate_filesystem_path(target, root_bound)?;

    let filename = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let temporary = target.with_file_name(format!(".{}.af-tmp-{}", filename, uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), PackageExecutorError> {
        let mut file = open_new_private_file(&temporary, mode)?;
        file.write_all(content)?;
        if let Some((uid, gid)) = owner {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        file.sync_all()?;
        validate_filesystem_path(target, root_bound)?;
        fs::rename(&temporary, target)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn create_dir_all_0755(path: &Path) -> std::io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all_0755(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)?;
            directory.set_permissions(fs::Permissions::from_mode(0o755))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn open_new_private_file(path: &Path, mode: u32) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(file)
}

pub(super) fn set_path_mode(path: &Path, _mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if _mode > 0 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(_mode));
        }
    }
}

// -----------------------------------------------------------------------------
// Cancellation-Aware In-Process & Cross-Process Advisory File Lock Guards
// -----------------------------------------------------------------------------

pub(crate) async fn wait_for_cancellation(cancel: &CancellationToken) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) async fn acquire_package_mutex_with_cancel(
    pkg_id: &str,
    cancel: &CancellationToken,
) -> Result<tokio::sync::MutexGuard<'static, ()>, PackageExecutorError> {
    cancel.check(pkg_id)?;
    tokio::select! {
        guard = crate::PACKAGE_MUTEX.lock() => {
            cancel.check(pkg_id)?;
            Ok(guard)
        }
        _ = wait_for_cancellation(cancel) => {
            Err(PackageExecutorError::Cancelled(pkg_id.to_string()))
        }
    }
}

/// Persistent cross-process advisory file lock guard (`flock`).
///
/// Security invariants:
/// 1. Opens `.af-package-executor.flock` WITHOUT `.truncate(true)` so a contending process
///    never clobbers the active lock holder's metadata before acquiring `flock`.
/// 2. Truncates, seeks to offset 0, and writes holder metadata ONLY after `LOCK_EX` is held.
/// 3. Never unlinks `.af-package-executor.flock` on [`Drop`] so all processes contend on the
///    exact same persistent inode.
pub(crate) struct CrossProcessLockGuard {
    _file: Option<File>,
}

impl CrossProcessLockGuard {
    pub(crate) fn resolve_flock_path(
        env_cfg: &PackageExecutionEnv,
    ) -> Result<PathBuf, PackageExecutorError> {
        let lock_dir_logical = env_cfg.lock_dir.to_string_lossy();
        let flock_logical = format!(
            "{}/.af-package-executor.flock",
            lock_dir_logical.trim_end_matches('/')
        );
        let flock_path = env_cfg.resolve_path(&flock_logical)?;
        if let Some(parent) = flock_path.parent() {
            validate_filesystem_path(parent, env_cfg.fs_root.as_deref())?;
            crate::create_package_lock_directory(parent)?;
            validate_filesystem_path(parent, env_cfg.fs_root.as_deref())?;
        }
        validate_filesystem_path(&flock_path, env_cfg.fs_root.as_deref())?;
        Ok(flock_path)
    }

    /// Attempts a non-blocking acquisition (`LOCK_EX | LOCK_NB`) of the cross-process lock file.
    pub(crate) fn try_acquire(
        env_cfg: &PackageExecutionEnv,
        pkg_id: &str,
    ) -> Result<Self, PackageExecutorError> {
        let flock_path = Self::resolve_flock_path(env_cfg)?;

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&flock_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                return Err(PackageExecutorError::LockConflict(format!(
                    "another privileged package operation holds {}",
                    flock_path.display()
                )));
            }
        }

        // Only mutate lock file contents AFTER acquiring the exclusive flock
        file.set_len(0)?;
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0))?;
        writeln!(
            file,
            "pid={} pkg={} ts={}",
            std::process::id(),
            pkg_id,
            Utc::now().to_rfc3339()
        )?;
        file.flush()?;

        Ok(Self { _file: Some(file) })
    }

    /// Acquires the cross-process advisory lock while honoring cooperative cancellation.
    pub(crate) async fn acquire_with_cancel(
        env_cfg: &PackageExecutionEnv,
        pkg_id: &str,
        cancel: &CancellationToken,
    ) -> Result<Self, PackageExecutorError> {
        loop {
            cancel.check(pkg_id)?;
            match Self::try_acquire(env_cfg, pkg_id) {
                Ok(guard) => return Ok(guard),
                Err(PackageExecutorError::LockConflict(_)) => {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                        _ = wait_for_cancellation(cancel) => {
                            return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                        }
                    }
                }
                Err(other) => return Err(other),
            }
        }
    }
}

impl Drop for CrossProcessLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(ref f) = self._file {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
        let _ = self._file.take();
        // NEVER unlink `self.lock_file_path`: the advisory lock file must keep a stable
        // persistent inode across processes so concurrent waiters cannot lock an unlinked inode.
    }
}
