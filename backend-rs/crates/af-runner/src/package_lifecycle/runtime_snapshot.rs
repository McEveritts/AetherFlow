use super::receipt_snapshots::{
    read_file_entry_bounded_nofollow, restore_candidate_receipts, FileSnapshot,
};
use super::recovery_storage::prepare_runtime_snapshot_backup_root;
use super::runtime_targets::{
    candidate_runtime_targets, is_protected_root, is_receipt_file_name,
    is_trusted_merged_usr_symlink, verify_no_symlink_ancestors_with_root, RuntimeTargetKind,
};
use super::snapshot_policy::{preflight_runtime_snapshot, RuntimeFilter, SnapshotBudget};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum RuntimeSnapshotEntry {
    Absent {
        target_path: PathBuf,
        kind: RuntimeTargetKind,
    },
    File {
        target_path: PathBuf,
        backup_path: PathBuf,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target_path: PathBuf,
        link_target: PathBuf,
    },
    Directory {
        target_path: PathBuf,
        backup_path: PathBuf,
        mode: u32,
        uid: u32,
        gid: u32,
    },
}

#[derive(Debug)]
pub struct PackageRuntimeSnapshot {
    pub package_id: String,
    pub backup_root: PathBuf,
    pub entries: Vec<RuntimeSnapshotEntry>,
    pub embedded_receipts: Vec<FileSnapshot>,
    pub preserve_on_drop: bool,
    pub fs_root: Option<PathBuf>,
}

pub(super) fn force_remove_backup_tree(path: &Path) {
    if std::fs::remove_dir_all(path).is_ok() {
        return;
    }
    #[cfg(unix)]
    {
        fn grant_owner_rwx(dir: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::symlink_metadata(dir) else {
                return;
            };
            if meta.file_type().is_dir() {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        grant_owner_rwx(&entry.path());
                    }
                }
            }
        }
        grant_owner_rwx(path);
        let _ = std::fs::remove_dir_all(path);
    }
}

impl Drop for PackageRuntimeSnapshot {
    fn drop(&mut self) {
        if self.preserve_on_drop {
            tracing::warn!(
                package = %self.package_id,
                backup_root = %self.backup_root.display(),
                "Preserved package runtime recovery snapshot on disk for manual recovery"
            );
        } else {
            force_remove_backup_tree(&self.backup_root);
        }
    }
}

fn copy_range_sparse(
    src_file: &mut std::fs::File,
    dst_file: &mut std::fs::File,
    start: u64,
    end: u64,
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    src_file.seek(SeekFrom::Start(start))?;
    dst_file.seek(SeekFrom::Start(start))?;
    let mut remaining = end.saturating_sub(start);
    let mut buf = [0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = src_file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().all(|&b| b == 0) {
            dst_file.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst_file.write_all(&buf[..n])?;
        }
        remaining = remaining.saturating_sub(n as u64);
    }
    dst_file.flush()?;
    Ok(())
}

fn copy_file_preserving_sparse_and_meta(
    src: &Path,
    dst: &Path,
    meta: &std::fs::Metadata,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(parent) = dst.parent() {
            if let Ok(c_parent) = std::ffi::CString::new(parent.as_os_str().as_bytes()) {
                let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::statvfs(c_parent.as_ptr(), &mut vfs) } == 0 {
                    let needed_bytes = meta.blocks().saturating_mul(512);
                    let avail_bytes = (vfs.f_bavail as u64).saturating_mul(vfs.f_frsize as u64);
                    if needed_bytes > avail_bytes {
                        return Err(format!(
                            "Insufficient disk space to snapshot {}: need {} bytes, available {} bytes",
                            src.display(),
                            needed_bytes,
                            avail_bytes
                        ));
                    }
                }
            }
        }
    }

    #[cfg(test)]
    {
        if std::env::var("AETHERFLOW_TEST_FORCE_DISK_FULL").is_ok() {
            return Err(format!(
                "Insufficient disk space to snapshot {}: need 1000000000 bytes, available 0 bytes",
                src.display()
            ));
        }
    }

    let mut dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| format!("Failed to create {}: {}", dst.display(), e))?;

    let mut source = std::fs::OpenOptions::new();
    source.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut src_file = match source.open(src) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            return Err(format!("Failed to open {}: {}", src.display(), e));
        }
    };

    if !src_file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        let _ = std::fs::remove_file(dst);
        return Err(format!(
            "Snapshot source {} is no longer a regular file",
            src.display()
        ));
    }

    #[cfg(target_os = "linux")]
    let reflink_ok = {
        use std::os::unix::io::AsRawFd;
        let src_fd = src_file.as_raw_fd();
        let dst_fd = dst_file.as_raw_fd();
        unsafe { libc::ioctl(dst_fd, 0x40049409 as libc::c_ulong, src_fd) == 0 }
    };
    #[cfg(not(target_os = "linux"))]
    let reflink_ok = false;

    if !reflink_ok {
        let len = meta.len();
        if let Err(e) = dst_file.set_len(len) {
            let _ = std::fs::remove_file(dst);
            return Err(format!("Failed to set len on {}: {}", dst.display(), e));
        }

        #[cfg(target_os = "linux")]
        if len > 0 {
            use std::os::unix::io::AsRawFd;
            let src_fd = src_file.as_raw_fd();
            let mut offset: u64 = 0;
            let mut seek_data_supported = true;

            while offset < len {
                let data_start =
                    unsafe { libc::lseek(src_fd, offset as libc::off_t, libc::SEEK_DATA) };
                if data_start < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENXIO) {
                        break;
                    } else {
                        seek_data_supported = false;
                        break;
                    }
                }
                let data_start = data_start as u64;
                if data_start >= len {
                    break;
                }
                let next_hole =
                    unsafe { libc::lseek(src_fd, data_start as libc::off_t, libc::SEEK_HOLE) };
                let extent_end = if next_hole < 0 {
                    len
                } else {
                    (next_hole as u64).min(len)
                };
                if extent_end <= data_start {
                    break;
                }

                if let Err(e) =
                    copy_range_sparse(&mut src_file, &mut dst_file, data_start, extent_end)
                {
                    let _ = std::fs::remove_file(dst);
                    return Err(format!("Failed to copy range in {}: {}", src.display(), e));
                }

                offset = extent_end;
            }

            if !seek_data_supported {
                if let Err(e) = copy_range_sparse(&mut src_file, &mut dst_file, 0, len) {
                    let _ = std::fs::remove_file(dst);
                    return Err(format!("Failed to copy file {}: {}", src.display(), e));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        if len > 0 {
            if let Err(e) = copy_range_sparse(&mut src_file, &mut dst_file, 0, len) {
                let _ = std::fs::remove_file(dst);
                return Err(format!("Failed to copy file {}: {}", src.display(), e));
            }
        }
    }

    drop(src_file);
    drop(dst_file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(meta.mode()));
        unsafe {
            if libc::geteuid() == 0 {
                if let Ok(c_path) = std::ffi::CString::new(dst.as_os_str().as_bytes()) {
                    libc::chown(c_path.as_ptr(), meta.uid(), meta.gid());
                }
            }
        }
    }

    Ok(())
}

fn copy_live_receipts_to_stage(
    live_dir: &Path,
    stage_dir: &Path,
    filter: RuntimeFilter,
) -> Result<(), String> {
    if !std::fs::symlink_metadata(live_dir).is_ok_and(|meta| meta.is_dir()) {
        return Ok(());
    }
    fn walk(
        curr_live: &Path,
        rel_path: &Path,
        stage_root: &Path,
        filter: RuntimeFilter,
    ) -> Result<(), String> {
        let entries = match std::fs::read_dir(curr_live) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            let child_live = curr_live.join(&fname);
            let child_rel = rel_path.join(&fname);
            if let Ok(meta) = std::fs::symlink_metadata(&child_live) {
                if filter.excludes(&child_rel, &meta) {
                    continue;
                }
                if meta.is_dir() {
                    walk(&child_live, &child_rel, stage_root, filter)?;
                } else if meta.is_file() && is_receipt_file_name(&name_str) {
                    let stage_file = stage_root.join(&child_rel);
                    if let Some(p) = stage_file.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = std::fs::copy(&child_live, &stage_file);
                }
            }
        }
        Ok(())
    }
    walk(live_dir, Path::new(""), stage_dir, filter)
}

fn remove_untracked_receipt_files(dir: &Path, embedded: &[FileSnapshot], filter: RuntimeFilter) {
    fn walk(curr: &Path, root: &Path, embedded: &[FileSnapshot], filter: RuntimeFilter) {
        let entries = match std::fs::read_dir(curr) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if filter.excludes(p.strip_prefix(root).expect("child is beneath root"), &meta) {
                    continue;
                }
                if meta.is_dir() {
                    walk(&p, root, embedded, filter);
                } else if meta.is_file()
                    && is_receipt_file_name(&name_str)
                    && !embedded.iter().any(|snap| snap.path == p)
                {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    walk(dir, dir, embedded, filter);
}

fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    root: &Path,
    mut embedded_receipts: Option<&mut Vec<FileSnapshot>>,
    filter: RuntimeFilter,
    fs_root: Option<&Path>,
    mut budget: Option<&mut SnapshotBudget>,
) -> Result<(), String> {
    // PermissionDenied is never skipped. A partial directory backup would
    // delete unread files such as mode 000 databases on restore.
    let src_meta = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(e) => return Err(format!("Failed to stat {}: {}", src.display(), e)),
    };
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("Failed to create dir {}: {}", dst.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o700));
    }
    let read_res = std::fs::read_dir(src);
    let entries = match read_res {
        Ok(e) => e,
        Err(e) => return Err(format!("Failed to read dir {}: {}", src.display(), e)),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(format!("Failed to read entry in {}: {}", src.display(), e)),
        };
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with(".af-backup.") || name_str.contains(".af-backup.") {
            continue;
        }
        let child_src = entry.path();
        let child_dst = dst.join(&file_name);
        let meta = match std::fs::symlink_metadata(&child_src) {
            Ok(m) => m,
            Err(e) => return Err(format!("Failed to stat {}: {}", child_src.display(), e)),
        };
        if filter.excludes(
            child_src.strip_prefix(root).expect("child is beneath root"),
            &meta,
        ) {
            continue;
        }
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = match std::fs::read_link(&child_src) {
                Ok(t) => t,
                Err(e) => {
                    return Err(format!(
                        "Failed to read symlink {}: {}",
                        child_src.display(),
                        e
                    ))
                }
            };
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &child_dst).map_err(|e| {
                    format!("Failed to create symlink {}: {}", child_dst.display(), e)
                })?;
            }
        } else if ft.is_dir() {
            let receipts_sub = embedded_receipts.as_deref_mut();
            copy_dir_recursive(
                &child_src,
                &child_dst,
                root,
                receipts_sub,
                filter,
                fs_root,
                budget.as_deref_mut(),
            )?;
        } else if ft.is_file() {
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge(&child_src, meta.len())?;
            }
            if let Some(ref mut receipts) = embedded_receipts {
                if is_receipt_file_name(&name_str) {
                    verify_no_symlink_ancestors_with_root(&child_src, fs_root)?;
                    let state = read_file_entry_bounded_nofollow(&child_src, 1024 * 1024)?;
                    receipts.push(FileSnapshot {
                        path: child_src,
                        state,
                    });
                    continue;
                }
            }
            if let Err(e) = copy_file_preserving_sparse_and_meta(&child_src, &child_dst, &meta) {
                return Err(format!(
                    "Failed to copy file {}: {}",
                    child_src.display(),
                    e
                ));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(src_meta.mode()));
        unsafe {
            if libc::geteuid() == 0 {
                if let Ok(c_path) = std::ffi::CString::new(dst.as_os_str().as_bytes()) {
                    libc::chown(c_path.as_ptr(), src_meta.uid(), src_meta.gid());
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum StagedRuntimeItem {
    File {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
    Symlink {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
    Directory {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
}

#[derive(Debug)]
pub(super) struct CommittedSwap {
    pub(super) target_path: PathBuf,
    pub(super) old_path: Option<PathBuf>,
    pub(super) retained: Vec<PathBuf>,
}

fn cleanup_staged_items(items: &[StagedRuntimeItem]) {
    for item in items {
        match item {
            StagedRuntimeItem::File { stage_path, .. }
            | StagedRuntimeItem::Symlink { stage_path, .. } => {
                let _ = std::fs::remove_file(stage_path);
            }
            StagedRuntimeItem::Directory { stage_path, .. } => {
                let _ = std::fs::remove_dir_all(stage_path);
            }
        }
    }
}

#[cfg(test)]
pub(super) static SNAPSHOT_CAPTURE_THREAD: std::sync::Mutex<Option<std::thread::ThreadId>> =
    std::sync::Mutex::new(None);

impl PackageRuntimeSnapshot {
    pub(super) async fn capture_blocking(
        package_id: String,
        units: Vec<String>,
        env_cfg: crate::PackageExecutionEnv,
    ) -> Result<Self, String> {
        tokio::task::spawn_blocking(move || Self::capture(&package_id, &units, &env_cfg, false))
            .await
            .map_err(|err| format!("Snapshot capture worker failed: {err}"))?
    }

    pub fn capture(
        package_id: &str,
        units: &[String],
        env_cfg: &crate::PackageExecutionEnv,
        _ignore_permission_denied: bool,
    ) -> Result<Self, String> {
        #[cfg(test)]
        {
            *SNAPSHOT_CAPTURE_THREAD.lock().unwrap() = Some(std::thread::current().id());
        }
        let safe_pkg: String = package_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let folder_name = format!(".af-rt-snap-{}-{}", safe_pkg, uuid::Uuid::new_v4());
        let backup_root = prepare_runtime_snapshot_backup_root(&folder_name, env_cfg)?;
        // `backup_root` exists before any target is copied. If a later target
        // fails, `PackageRuntimeSnapshot` is never built, so its Drop cannot
        // remove the directory. Disarm the guard only after `Self` owns it.
        struct CaptureBackupGuard {
            path: PathBuf,
            armed: bool,
        }
        impl Drop for CaptureBackupGuard {
            fn drop(&mut self) {
                if self.armed {
                    force_remove_backup_tree(&self.path);
                }
            }
        }
        let mut backup_guard = CaptureBackupGuard {
            path: backup_root.clone(),
            armed: true,
        };

        let targets = candidate_runtime_targets(package_id, units, env_cfg);
        let mut budget = preflight_runtime_snapshot(
            package_id,
            env_cfg.fs_root.as_deref(),
            &backup_root,
            &targets,
        )?;
        let mut entries = Vec::new();
        let mut embedded_receipts = Vec::new();

        for (idx, (target_path, kind)) in targets.into_iter().enumerate() {
            let filter =
                RuntimeFilter::for_target(package_id, &target_path, env_cfg.fs_root.as_deref());
            verify_no_symlink_ancestors_with_root(&target_path, env_cfg.fs_root.as_deref())?;
            match std::fs::symlink_metadata(&target_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    entries.push(RuntimeSnapshotEntry::Absent { target_path, kind });
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to read metadata for {}: {}",
                        target_path.display(),
                        e
                    ));
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    let link_target = std::fs::read_link(&target_path).map_err(|e| {
                        format!("Failed to read link {}: {}", target_path.display(), e)
                    })?;
                    entries.push(RuntimeSnapshotEntry::Symlink {
                        target_path,
                        link_target,
                    });
                }
                Ok(meta) if meta.is_file() => {
                    budget.charge(&target_path, meta.len())?;
                    let file_name = target_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if is_receipt_file_name(&file_name) {
                        verify_no_symlink_ancestors_with_root(
                            &target_path,
                            env_cfg.fs_root.as_deref(),
                        )?;
                        let state = read_file_entry_bounded_nofollow(&target_path, 1024 * 1024)?;
                        embedded_receipts.push(FileSnapshot {
                            path: target_path.clone(),
                            state,
                        });
                        continue;
                    }
                    let backup_path = backup_root.join(format!("entry_{idx}"));
                    copy_file_preserving_sparse_and_meta(&target_path, &backup_path, &meta)?;
                    #[cfg(unix)]
                    let (mode, uid, gid) = {
                        use std::os::unix::fs::MetadataExt;
                        (meta.mode(), meta.uid(), meta.gid())
                    };
                    #[cfg(not(unix))]
                    let (mode, uid, gid) = (0o644, 0, 0);
                    entries.push(RuntimeSnapshotEntry::File {
                        target_path,
                        backup_path,
                        mode,
                        uid,
                        gid,
                    });
                }
                Ok(meta) if meta.is_dir() => {
                    let backup_path = backup_root.join(format!("entry_{idx}"));
                    copy_dir_recursive(
                        &target_path,
                        &backup_path,
                        &target_path,
                        Some(&mut embedded_receipts),
                        filter,
                        env_cfg.fs_root.as_deref(),
                        Some(&mut budget),
                    )?;
                    #[cfg(unix)]
                    let (mode, uid, gid) = {
                        use std::os::unix::fs::MetadataExt;
                        (meta.mode(), meta.uid(), meta.gid())
                    };
                    #[cfg(not(unix))]
                    let (mode, uid, gid) = (0o755, 0, 0);
                    entries.push(RuntimeSnapshotEntry::Directory {
                        target_path,
                        backup_path,
                        mode,
                        uid,
                        gid,
                    });
                }
                _ => {}
            }
        }

        backup_guard.armed = false;
        Ok(Self {
            package_id: package_id.to_string(),
            backup_root,
            entries,
            embedded_receipts,
            preserve_on_drop: false,
            fs_root: env_cfg.fs_root.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<(), String> {
        fn dir_contains_any_non_dir(path: &Path) -> std::io::Result<bool> {
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.is_dir() {
                return Ok(true);
            }
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if dir_contains_any_non_dir(&entry.path())? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn absent_filtered_dir_has_user_payloads(
            root: &Path,
            current: &Path,
            filter: RuntimeFilter,
        ) -> std::io::Result<bool> {
            for entry in std::fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)?;
                let rel = path.strip_prefix(root).unwrap_or(&path);
                if filter.excludes(rel, &meta) {
                    if dir_contains_any_non_dir(&path)? {
                        return Ok(true);
                    }
                } else if meta.is_dir()
                    && absent_filtered_dir_has_user_payloads(root, &path, filter)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        // Phase 1 (Preflight & Stage — zero live mutations!)
        let mut staged_items: Vec<StagedRuntimeItem> = Vec::new();
        let mut absent_staged_targets: std::collections::HashSet<PathBuf> =
            std::collections::HashSet::new();

        for entry in &self.entries {
            let entry_target = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. } => target_path,
                RuntimeSnapshotEntry::File { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Symlink { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            if let Err(e) =
                verify_no_symlink_ancestors_with_root(entry_target, self.fs_root.as_deref())
            {
                cleanup_staged_items(&staged_items);
                self.preserve_on_drop = true;
                return Err(e);
            }
            for ancestor in entry_target.ancestors().skip(1) {
                if ancestor.as_os_str().is_empty() {
                    continue;
                }
                match std::fs::symlink_metadata(ancestor) {
                    Ok(meta) => {
                        let trusted_merged_usr = meta.file_type().is_symlink()
                            && is_trusted_merged_usr_symlink(ancestor, self.fs_root.as_deref());
                        if !trusted_merged_usr && !meta.is_dir() {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!(
                                "Runtime target path {} ancestor {} is not a directory",
                                entry_target.display(),
                                ancestor.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to stat ancestor {}: {}",
                            ancestor.display(),
                            e
                        ));
                    }
                }
            }
            match entry {
                RuntimeSnapshotEntry::Absent { target_path, kind } => {
                    match std::fs::symlink_metadata(target_path) {
                        Ok(meta) => {
                            if *kind == RuntimeTargetKind::Directory && !meta.is_dir() {
                                cleanup_staged_items(&staged_items);
                                self.preserve_on_drop = true;
                                return Err(format!(
                                    "Runtime directory path {} blocked by non-directory entry (ENOTDIR)",
                                    target_path.display()
                                ));
                            }
                            if is_protected_root(target_path) {
                                cleanup_staged_items(&staged_items);
                                self.preserve_on_drop = true;
                                return Err(format!(
                                    "Refusing to delete protected root directory: {}",
                                    target_path.display()
                                ));
                            }
                            let filter = RuntimeFilter::for_target(
                                &self.package_id,
                                target_path,
                                self.fs_root.as_deref(),
                            );
                            if *kind == RuntimeTargetKind::Directory
                                && meta.is_dir()
                                && filter != RuntimeFilter::None
                            {
                                let has_payloads = match absent_filtered_dir_has_user_payloads(
                                    target_path,
                                    target_path,
                                    filter,
                                ) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        return Err(format!(
                                            "Failed to inspect absent filtered target {}: {}",
                                            target_path.display(),
                                            e
                                        ));
                                    }
                                };
                                if has_payloads {
                                    let parent = target_path.parent().ok_or_else(|| {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        format!(
                                            "Target path {} has no parent",
                                            target_path.display()
                                        )
                                    })?;
                                    let name = target_path
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy();
                                    let stage = parent.join(format!(
                                        ".{}.af-rt-stage-{}",
                                        name,
                                        uuid::Uuid::new_v4()
                                    ));
                                    if let Err(e) = std::fs::create_dir_all(&stage) {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        return Err(format!(
                                            "Failed to stage absent filtered directory {}: {}",
                                            stage.display(),
                                            e
                                        ));
                                    }
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::{MetadataExt, PermissionsExt};
                                        let _ = std::fs::set_permissions(
                                            &stage,
                                            std::fs::Permissions::from_mode(meta.mode()),
                                        );
                                        unsafe {
                                            if libc::geteuid() == 0 {
                                                if let Ok(c_path) = std::ffi::CString::new(
                                                    stage.as_os_str().as_bytes(),
                                                ) {
                                                    libc::chown(
                                                        c_path.as_ptr(),
                                                        meta.uid(),
                                                        meta.gid(),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    absent_staged_targets.insert(target_path.clone());
                                    staged_items.push(StagedRuntimeItem::Directory {
                                        target_path: target_path.clone(),
                                        stage_path: stage,
                                    });
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!("Failed to stat {}: {}", target_path.display(), e));
                        }
                    }
                }
                RuntimeSnapshotEntry::File {
                    target_path,
                    backup_path,
                    mode,
                    uid,
                    gid,
                } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let stage = parent.join(format!(".af-rt-file-{}", uuid::Uuid::new_v4()));
                    let meta = std::fs::metadata(backup_path).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!(
                            "Failed to stat backup file {}: {}",
                            backup_path.display(),
                            e
                        )
                    })?;
                    if let Err(e) = copy_file_preserving_sparse_and_meta(backup_path, &stage, &meta)
                    {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to stage restored file {}: {}",
                            stage.display(),
                            e
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &stage,
                            std::fs::Permissions::from_mode(*mode),
                        );
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) =
                                    std::ffi::CString::new(stage.as_os_str().as_bytes())
                                {
                                    libc::chown(c_path.as_ptr(), *uid, *gid);
                                }
                            }
                        }
                    }
                    staged_items.push(StagedRuntimeItem::File {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
                RuntimeSnapshotEntry::Symlink {
                    target_path,
                    link_target,
                } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let stage = parent.join(format!(".af-rt-sym-{}", uuid::Uuid::new_v4()));
                    #[cfg(unix)]
                    {
                        if let Err(e) = std::os::unix::fs::symlink(link_target, &stage) {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!(
                                "Failed to create symlink {}: {}",
                                stage.display(),
                                e
                            ));
                        }
                    }
                    staged_items.push(StagedRuntimeItem::Symlink {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
                RuntimeSnapshotEntry::Directory {
                    target_path,
                    backup_path,
                    mode,
                    uid,
                    gid,
                } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let name = target_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let stage =
                        parent.join(format!(".{}.af-rt-stage-{}", name, uuid::Uuid::new_v4()));
                    if let Err(e) = copy_dir_recursive(
                        backup_path,
                        &stage,
                        backup_path,
                        None,
                        RuntimeFilter::None,
                        self.fs_root.as_deref(),
                        None,
                    ) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to stage restored directory {}: {}",
                            stage.display(),
                            e
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &stage,
                            std::fs::Permissions::from_mode(*mode),
                        );
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) =
                                    std::ffi::CString::new(stage.as_os_str().as_bytes())
                                {
                                    libc::chown(c_path.as_ptr(), *uid, *gid);
                                }
                            }
                        }
                    }
                    if let Err(e) = copy_live_receipts_to_stage(
                        target_path,
                        &stage,
                        RuntimeFilter::for_target(
                            &self.package_id,
                            target_path,
                            self.fs_root.as_deref(),
                        ),
                    ) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to preserve live receipts into stage {}: {}",
                            stage.display(),
                            e
                        ));
                    }
                    staged_items.push(StagedRuntimeItem::Directory {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
            }
        }

        // Phase 2 (Commit Runtime Swaps & Absent Removals)
        let mut committed_swaps: Vec<CommittedSwap> = Vec::new();
        let mut swap_err: Option<String> = None;

        let mut staged = staged_items.into_iter();
        for item in staged.by_ref() {
            let (target_path, stage_path, is_dir) = match item {
                StagedRuntimeItem::File {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, false),
                StagedRuntimeItem::Symlink {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, false),
                StagedRuntimeItem::Directory {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, true),
            };
            let parent = match target_path.parent() {
                Some(p) => p,
                None => {
                    let _ = if is_dir {
                        std::fs::remove_dir_all(&stage_path)
                    } else {
                        std::fs::remove_file(&stage_path)
                    };
                    swap_err = Some(format!("Target {} has no parent", target_path.display()));
                    break;
                }
            };
            let name = target_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let old_path = parent.join(format!(".{}.af-rt-old-{}", name, uuid::Uuid::new_v4()));
            let had_target = std::fs::symlink_metadata(&target_path).is_ok();
            if had_target {
                if let Err(e) = std::fs::rename(&target_path, &old_path) {
                    let _ = if is_dir {
                        std::fs::remove_dir_all(&stage_path)
                    } else {
                        std::fs::remove_file(&stage_path)
                    };
                    swap_err = Some(format!(
                        "Failed to move old {} to {}: {}",
                        target_path.display(),
                        old_path.display(),
                        e
                    ));
                    break;
                }
            }
            if let Err(e) = std::fs::rename(&stage_path, &target_path) {
                if had_target {
                    let _ = std::fs::rename(&old_path, &target_path);
                }
                let _ = if is_dir {
                    std::fs::remove_dir_all(&stage_path)
                } else {
                    std::fs::remove_file(&stage_path)
                };
                swap_err = Some(format!(
                    "Failed to move stage {} to {}: {}",
                    stage_path.display(),
                    target_path.display(),
                    e
                ));
                break;
            }
            let mut swap = CommittedSwap {
                target_path,
                old_path: had_target.then_some(old_path),
                retained: Vec::new(),
            };
            if is_dir {
                let filter = RuntimeFilter::for_target(
                    &self.package_id,
                    &swap.target_path,
                    self.fs_root.as_deref(),
                );
                if let Err(error) = swap.retain_exclusions(filter) {
                    swap_err = Some(format!("Failed to retain runtime payloads: {error}"));
                }
            }
            committed_swaps.push(swap);
            if swap_err.is_some() {
                break;
            }
        }

        if let Some(err) = swap_err {
            cleanup_staged_items(staged.as_slice());
            for swap in committed_swaps.into_iter().rev() {
                if let Err(error) = swap.revert() {
                    tracing::error!(%error, "Runtime swap rollback failed");
                }
            }
            self.preserve_on_drop = true;
            return Err(err);
        }

        let mut absent_parked: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut absent_err: Option<String> = None;
        for entry in &self.entries {
            if let RuntimeSnapshotEntry::Absent { target_path, .. } = entry {
                if absent_staged_targets.contains(target_path) {
                    continue;
                }
                match std::fs::symlink_metadata(target_path) {
                    Ok(meta) => {
                        if let Some(parent) = target_path.parent() {
                            let name = target_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy();
                            let parked = parent.join(format!(
                                ".{}.af-rt-abs-{}",
                                name,
                                uuid::Uuid::new_v4()
                            ));
                            if std::fs::rename(target_path, &parked).is_ok() {
                                absent_parked.push((target_path.clone(), parked));
                                continue;
                            }
                        }
                        let rem_res = if meta.is_dir() {
                            std::fs::remove_dir_all(target_path)
                        } else {
                            std::fs::remove_file(target_path)
                        };
                        if let Err(e) = rem_res {
                            absent_err = Some(format!(
                                "Failed to remove absent runtime target {}: {}",
                                target_path.display(),
                                e
                            ));
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        absent_err = Some(format!(
                            "Failed to stat absent runtime target {}: {}",
                            target_path.display(),
                            e
                        ));
                        break;
                    }
                }
            }
        }

        if let Some(err) = absent_err {
            for (orig, parked) in absent_parked.into_iter().rev() {
                let _ = std::fs::rename(&parked, &orig);
            }
            for swap in committed_swaps.into_iter().rev() {
                if let Err(error) = swap.revert() {
                    tracing::error!(%error, "Runtime swap rollback failed");
                }
            }
            self.preserve_on_drop = true;
            return Err(err);
        }

        for (_, parked) in absent_parked {
            if let Ok(meta) = std::fs::symlink_metadata(&parked) {
                if meta.is_dir() {
                    let _ = std::fs::remove_dir_all(&parked);
                } else {
                    let _ = std::fs::remove_file(&parked);
                }
            }
        }

        for swap in committed_swaps {
            if let Some(old) = swap.old_path {
                if let Ok(meta) = std::fs::symlink_metadata(&old) {
                    let _ = if meta.is_dir() {
                        std::fs::remove_dir_all(&old)
                    } else {
                        std::fs::remove_file(&old)
                    };
                }
            }
        }

        // Clean up <target_path>.af-backup.* sibling directories
        for entry in &self.entries {
            let target_path = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. } => target_path,
                RuntimeSnapshotEntry::File { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Symlink { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            if let (Some(parent), Some(fname)) = (target_path.parent(), target_path.file_name()) {
                let prefix = format!("{}.af-backup.", fname.to_string_lossy());
                if let Ok(dir_entries) = std::fs::read_dir(parent) {
                    for de in dir_entries.flatten() {
                        let name = de.file_name().to_string_lossy().to_string();
                        if name.starts_with(&prefix) && de.file_type().is_ok_and(|ft| ft.is_dir()) {
                            let owner_file = de.path().join(".af-archive-owner");
                            if let Ok(owner) = std::fs::read_to_string(&owner_file) {
                                if owner.trim() == self.package_id {
                                    let _ = std::fs::remove_dir_all(de.path());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 3 (Commit Embedded Receipts — ONLY reached after 100% of runtime targets succeeded!)
        for entry in &self.entries {
            if let RuntimeSnapshotEntry::Directory { target_path, .. } = entry {
                remove_untracked_receipt_files(
                    target_path,
                    &self.embedded_receipts,
                    RuntimeFilter::for_target(
                        &self.package_id,
                        target_path,
                        self.fs_root.as_deref(),
                    ),
                );
            }
        }
        restore_candidate_receipts(&self.embedded_receipts)?;

        Ok(())
    }
}
