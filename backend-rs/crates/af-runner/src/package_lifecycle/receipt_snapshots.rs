use super::runtime_snapshot::PackageRuntimeSnapshot;
use super::runtime_targets::{verify_no_symlink_ancestors, verify_no_symlink_ancestors_with_root};
use std::path::{Path, PathBuf};

pub fn candidate_version_marker_paths(package_id: &str) -> Result<Vec<PathBuf>, String> {
    candidate_version_marker_paths_with_env(package_id, &crate::PackageExecutionEnv::default())
}

pub fn candidate_version_marker_paths_with_env(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    if let Some(recipe) = crate::package_executor::get_declarative_recipe(package_id) {
        if let Some(vf) = crate::package_executor::recipe_version_file_logical_path(&recipe) {
            let p = env_cfg.resolve_path(&vf).map_err(|e| {
                format!("Failed to resolve version file logical path {}: {}", vf, e)
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && package_id.eq_ignore_ascii_case("filebot") {
            let candidate = "/opt/filebot-node/.af-version";
            let p = env_cfg.resolve_path(candidate).map_err(|e| {
                format!(
                    "Failed to resolve candidate receipt path {}: {}",
                    candidate, e
                )
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        if prefix == "/opt" && package_id.eq_ignore_ascii_case("listenarr") {
            let candidate = "/opt/Listenarr/.af-version";
            let p = env_cfg.resolve_path(candidate).map_err(|e| {
                format!(
                    "Failed to resolve candidate receipt path {}: {}",
                    candidate, e
                )
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [package_id, &package_id.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = env_cfg.resolve_path(&candidate).map_err(|e| {
                format!(
                    "Failed to resolve candidate receipt path {}: {}",
                    candidate, e
                )
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if package_id.eq_ignore_ascii_case("piped") {
        for extra in [
            "/opt/piped/.af-components.json",
            "/var/lib/piped/.af-components.json",
        ] {
            let p = env_cfg
                .resolve_path(extra)
                .map_err(|e| format!("Failed to resolve extra receipt path {}: {}", extra, e))?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFileState {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub type SnapshotFileEntry = SnapshotFileState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub state: Option<SnapshotFileState>,
}

impl FileSnapshot {
    pub fn absent(path: PathBuf) -> Self {
        Self { path, state: None }
    }

    pub fn present(path: PathBuf, bytes: Vec<u8>, mode: u32, uid: u32, gid: u32) -> Self {
        Self {
            path,
            state: Some(SnapshotFileState {
                bytes,
                mode,
                uid,
                gid,
            }),
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        self.state.as_ref().map(|s| s.bytes.as_slice())
    }
}

impl From<(PathBuf, Option<SnapshotFileState>)> for FileSnapshot {
    fn from((path, state): (PathBuf, Option<SnapshotFileState>)) -> Self {
        Self { path, state }
    }
}

impl From<(PathBuf, Option<Vec<u8>>)> for FileSnapshot {
    fn from((path, opt_bytes): (PathBuf, Option<Vec<u8>>)) -> Self {
        Self {
            path,
            state: opt_bytes.map(|bytes| SnapshotFileState {
                bytes,
                mode: 0o644,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            }),
        }
    }
}

pub fn snapshot_blueprint_targets(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<FileSnapshot>, String> {
    let mut snaps = Vec::new();
    let paths = crate::package_executor::collect_blueprint_target_paths(
        package_id,
        env_cfg.fs_root.as_deref(),
    );
    for path in paths {
        if matches!(package_id, "transmission" | "transmission-daemon")
            && crate::blueprint::is_transmission_config_alias(&path, |logical| {
                env_cfg.fs_root.as_ref().map_or_else(
                    || PathBuf::from(logical),
                    |root| root.join(logical.trim_start_matches('/')),
                )
            })
        {
            continue;
        }
        verify_no_symlink_ancestors_with_root(&path, env_cfg.fs_root.as_deref())?;
        let state = read_file_entry_bounded_nofollow(&path, 1024 * 1024)?;
        snaps.push(FileSnapshot { path, state });
    }
    Ok(snaps)
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub static TEST_ROLLBACK_HOOK: once_cell::sync::Lazy<
    std::sync::Mutex<Option<Box<dyn Fn(&[FileSnapshot]) + Send + Sync>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub static TEST_CERTIFY_FAIL_HOOK: once_cell::sync::Lazy<
    std::sync::Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

pub fn rollback_operation_state(
    receipt_snapshots: &[FileSnapshot],
    blueprint_snapshots: &[FileSnapshot],
) -> Result<(), String> {
    rollback_operation_state_with_runtime(receipt_snapshots, blueprint_snapshots, None)
}

pub fn rollback_operation_state_with_runtime(
    receipt_snapshots: &[FileSnapshot],
    blueprint_snapshots: &[FileSnapshot],
    mut runtime_snapshot: Option<&mut PackageRuntimeSnapshot>,
) -> Result<(), String> {
    #[cfg(test)]
    {
        if let Some(hook) = TEST_ROLLBACK_HOOK.lock().unwrap().as_ref() {
            hook(receipt_snapshots);
        }
    }
    if let Some(ref mut rt) = runtime_snapshot {
        rt.restore()?;
    }
    restore_candidate_receipts(blueprint_snapshots)?;
    restore_candidate_receipts(receipt_snapshots)?;
    Ok(())
}

pub fn snapshot_candidate_receipts(package_id: &str) -> Result<Vec<FileSnapshot>, String> {
    snapshot_candidate_receipts_with_env(package_id, &crate::PackageExecutionEnv::default())
}

#[derive(Debug)]
pub struct StepwiseDirError {
    pub message: String,
    pub raw_os_error: Option<i32>,
}

impl std::fmt::Display for StepwiseDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StepwiseDirError {}

impl StepwiseDirError {
    pub fn is_not_found(&self) -> bool {
        self.raw_os_error == Some(libc::ENOENT)
    }
}

pub fn open_dir_nofollow_stepwise_inner_ext(
    dir_path: &Path,
    create_missing: bool,
) -> Result<Option<std::os::fd::OwnedFd>, StepwiseDirError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Component;

    if !dir_path.is_absolute() {
        return Err(StepwiseDirError {
            message: format!("Directory path must be absolute: {}", dir_path.display()),
            raw_os_error: Some(libc::EINVAL),
        });
    }

    let root_raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        let err = std::io::Error::last_os_error();
        return Err(StepwiseDirError {
            message: format!("Failed to open root directory /: {}", err),
            raw_os_error: err.raw_os_error(),
        });
    }
    let mut curr_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };

    for comp in dir_path.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(part) => {
                let part_bytes = part.to_string_lossy().into_owned();
                let part_cstr = match CString::new(part_bytes) {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(StepwiseDirError {
                            message: format!("CString error: {}", e),
                            raw_os_error: Some(libc::EINVAL),
                        })
                    }
                };
                let mut next_raw = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_raw < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOENT) {
                        if create_missing {
                            let mk_rc = unsafe {
                                libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755)
                            };
                            if mk_rc != 0 {
                                let mk_err = std::io::Error::last_os_error();
                                if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                    return Err(StepwiseDirError {
                                        message: format!(
                                            "Failed to create directory component {:?} in {}: {}",
                                            part,
                                            dir_path.display(),
                                            mk_err
                                        ),
                                        raw_os_error: mk_err.raw_os_error(),
                                    });
                                }
                            }
                            next_raw = unsafe {
                                libc::openat(
                                    curr_fd.as_raw_fd(),
                                    part_cstr.as_ptr(),
                                    libc::O_RDONLY
                                        | libc::O_DIRECTORY
                                        | libc::O_NOFOLLOW
                                        | libc::O_CLOEXEC,
                                )
                            };
                            if next_raw < 0 {
                                let retry_err = std::io::Error::last_os_error();
                                return Err(StepwiseDirError {
                                    message: format!(
                                        "Failed to open directory component {:?} after creation in {}: {}",
                                        part,
                                        dir_path.display(),
                                        retry_err
                                    ),
                                    raw_os_error: retry_err.raw_os_error(),
                                });
                            }
                        } else {
                            return Ok(None);
                        }
                    } else {
                        let msg = format!(
                            "Failed to open directory component {:?} in {}: {}",
                            part,
                            dir_path.display(),
                            err
                        );
                        return Err(StepwiseDirError {
                            message: msg,
                            raw_os_error: err.raw_os_error(),
                        });
                    }
                }
                curr_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(StepwiseDirError {
                    message: format!(
                        "Parent directory traversal '..' forbidden: {}",
                        dir_path.display()
                    ),
                    raw_os_error: Some(libc::EPERM),
                });
            }
            Component::Prefix(_) => {
                return Err(StepwiseDirError {
                    message: format!("Prefix path component forbidden: {}", dir_path.display()),
                    raw_os_error: Some(libc::EINVAL),
                });
            }
        }
    }

    Ok(Some(curr_fd))
}

pub fn open_dir_nofollow_stepwise_inner(
    dir_path: &Path,
) -> Result<std::os::fd::OwnedFd, StepwiseDirError> {
    match open_dir_nofollow_stepwise_inner_ext(dir_path, false)? {
        Some(fd) => Ok(fd),
        None => Err(StepwiseDirError {
            message: format!("Directory not found: {}", dir_path.display()),
            raw_os_error: Some(libc::ENOENT),
        }),
    }
}

pub fn open_dir_nofollow_stepwise_ext(
    dir_path: &Path,
    create_missing: bool,
) -> Result<Option<std::os::fd::OwnedFd>, String> {
    open_dir_nofollow_stepwise_inner_ext(dir_path, create_missing).map_err(|e| e.to_string())
}

pub fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    open_dir_nofollow_stepwise_inner(dir_path).map_err(|e| e.to_string())
}

pub fn read_file_entry_bounded_nofollow(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<SnapshotFileState>, String> {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let parent = match path.parent() {
        Some(p) => p,
        None => return Err(format!("Receipt path has no parent: {}", path.display())),
    };
    let file_name = match path.file_name() {
        Some(f) => f.to_string_lossy().into_owned(),
        None => return Err(format!("Receipt path has no filename: {}", path.display())),
    };

    let dir_fd = match open_dir_nofollow_stepwise_inner(parent) {
        Ok(fd) => fd,
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };

    let file_cstr =
        CString::new(file_name.as_bytes()).map_err(|e| format!("CString error: {}", e))?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            file_cstr.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!(
            "fstatat failed on receipt {}: {}",
            path.display(),
            err
        ));
    }

    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "Receipt path {} is a symlink or non-regular file",
            path.display()
        ));
    }
    if st.st_size > max_bytes as libc::off_t {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let file_raw = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            file_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_raw < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!(
            "openat failed on receipt {}: {}",
            path.display(),
            err
        ));
    }
    let file_fd = unsafe { OwnedFd::from_raw_fd(file_raw) };

    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_rc = unsafe { libc::fstat(file_fd.as_raw_fd(), &mut fst) };
    if fstat_rc != 0 {
        return Err(format!(
            "fstat failed on receipt {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    if (fst.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "Receipt path {} is not a regular file after opening",
            path.display()
        ));
    }
    if fst.st_dev != st.st_dev || fst.st_ino != st.st_ino {
        return Err(format!(
            "Inode or device changed for receipt {}",
            path.display()
        ));
    }
    if fst.st_size > max_bytes as libc::off_t {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let mut std_file = std::fs::File::from(file_fd);
    let mut buf = Vec::new();
    std_file
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read receipt {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit during read",
            path.display(),
            max_bytes
        ));
    }

    let mode = (fst.st_mode & 0o7777) as u32;
    let uid = fst.st_uid;
    let gid = fst.st_gid;

    Ok(Some(SnapshotFileState {
        bytes: buf,
        mode,
        uid,
        gid,
    }))
}

pub fn read_receipt_bounded_nofollow(path: &Path) -> Result<Option<Vec<u8>>, String> {
    read_file_entry_bounded_nofollow(path, 512 * 1024).map(|opt| opt.map(|s| s.bytes))
}

pub fn snapshot_candidate_receipts_with_env(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<FileSnapshot>, String> {
    let paths = candidate_version_marker_paths_with_env(package_id, env_cfg)?;
    let mut snapshots = Vec::new();
    for path in paths {
        verify_no_symlink_ancestors_with_root(&path, env_cfg.fs_root.as_deref())?;
        let state = read_file_entry_bounded_nofollow(&path, 512 * 1024)?;
        snapshots.push(FileSnapshot { path, state });
    }
    Ok(snapshots)
}

pub fn restore_candidate_receipts(snapshots: &[FileSnapshot]) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let mut errors = Vec::new();

    for snap in snapshots {
        let path = &snap.path;
        let prior_state = &snap.state;

        if let Err(e) = verify_no_symlink_ancestors(path) {
            errors.push(e);
            continue;
        }

        let parent = match path.parent() {
            Some(p) => p,
            None => {
                errors.push(format!(
                    "Invalid receipt path with no parent: {}",
                    path.display()
                ));
                continue;
            }
        };

        let dir = match open_dir_nofollow_stepwise_ext(parent, prior_state.is_some()) {
            Ok(Some(fd)) => fd,
            Ok(None) => {
                // ENOENT when prior_state.is_none() and create_missing is false
                continue;
            }
            Err(e) => {
                errors.push(format!(
                    "Failed to open directory stepwise {}: {}",
                    parent.display(),
                    e
                ));
                continue;
            }
        };
        let dir_fd = dir.as_raw_fd();

        let file_name = match path.file_name() {
            Some(f) => f.to_string_lossy().to_string(),
            None => {
                errors.push(format!("Receipt path has no file name: {}", path.display()));
                continue;
            }
        };
        let file_cstr = match CString::new(file_name.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("CString error: {}", e));
                continue;
            }
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_rc = unsafe {
            libc::fstatat(
                dir_fd,
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && prior_state.is_some() {
            errors.push(format!(
                "Refusing to overwrite directory at receipt path {}",
                path.display()
            ));
            continue;
        }

        if let Some(entry) = prior_state {
            let tmp_name = format!(
                ".af-receipt-tmp-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            );
            let tmp_cstr = match CString::new(tmp_name.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("CString error: {}", e));
                    continue;
                }
            };

            // Create temporary file with mode 0o600 so it is never world-readable even briefly before fchmod/fchown
            let fd = unsafe {
                libc::openat(
                    dir_fd,
                    tmp_cstr.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                errors.push(format!(
                    "Failed to create temporary file for receipt restoration {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let mut written = 0;
            let mut write_err: Option<std::io::Error> = None;
            while written < entry.bytes.len() {
                let n = unsafe {
                    libc::write(
                        fd,
                        entry.bytes[written..].as_ptr() as *const libc::c_void,
                        entry.bytes.len() - written,
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    write_err = Some(err);
                    break;
                }
                written += n as usize;
            }

            if let Some(err) = write_err {
                unsafe {
                    libc::close(fd);
                    libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                };
                errors.push(format!(
                    "Failed to write receipt bytes to {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            // Restore original ownership via fchown
            let current_uid = unsafe { libc::geteuid() };
            let current_gid = unsafe { libc::getegid() };
            if current_uid == 0 || entry.uid != current_uid || entry.gid != current_gid {
                let chown_rc =
                    unsafe { libc::fchown(fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
                if chown_rc != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe {
                        libc::close(fd);
                        libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                    };
                    errors.push(format!(
                        "Failed to restore ownership (uid={}, gid={}) on {}: {}",
                        entry.uid,
                        entry.gid,
                        path.display(),
                        err
                    ));
                    continue;
                }
            }

            // Restore original permissions via fchmod AFTER fchown (since fchown can clear special bits)
            let target_mode = (entry.mode & 0o7777) as libc::mode_t;
            let chmod_rc = unsafe { libc::fchmod(fd, target_mode) };
            if chmod_rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                    libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                };
                errors.push(format!(
                    "Failed to restore permissions ({:#o}) on {}: {}",
                    target_mode,
                    path.display(),
                    err
                ));
                continue;
            }

            let sync_rc = unsafe { libc::fsync(fd) };
            let close_rc = unsafe { libc::close(fd) };

            if sync_rc != 0 || close_rc != 0 {
                unsafe { libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to fsync or close receipt fd for {}",
                    path.display()
                ));
                continue;
            }

            let rename_rc =
                unsafe { libc::renameat(dir_fd, tmp_cstr.as_ptr(), dir_fd, file_cstr.as_ptr()) };
            if rename_rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to atomically rename receipt {} into place: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        } else {
            let unlink_rc = unsafe { libc::unlinkat(dir_fd, file_cstr.as_ptr(), 0) };
            if unlink_rc != 0 {
                let err = std::io::Error::last_os_error();
                let raw_err = err.raw_os_error();
                if raw_err == Some(libc::EISDIR) || raw_err == Some(libc::EPERM) {
                    let rmdir_rc =
                        unsafe { libc::unlinkat(dir_fd, file_cstr.as_ptr(), libc::AT_REMOVEDIR) };
                    if rmdir_rc != 0 {
                        let rmdir_err = std::io::Error::last_os_error();
                        if rmdir_err.raw_os_error() != Some(libc::ENOENT) {
                            errors.push(format!(
                                "Failed to remove directory at receipt path {}: {}",
                                path.display(),
                                rmdir_err
                            ));
                        }
                    }
                } else if raw_err != Some(libc::ENOENT) {
                    errors.push(format!(
                        "Failed to unlink receipt {}: {}",
                        path.display(),
                        err
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}
