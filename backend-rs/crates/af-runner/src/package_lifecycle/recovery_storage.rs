use super::runtime_targets::is_protected_root;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub(super) struct RecoveryStoragePolicy {
    pub(super) privileged: bool,
    pub(super) expected_uid: u32,
}

impl RecoveryStoragePolicy {
    fn current() -> Self {
        #[cfg(unix)]
        {
            let euid = unsafe { libc::geteuid() };
            Self {
                privileged: euid == 0,
                expected_uid: euid,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                privileged: false,
                expected_uid: 0,
            }
        }
    }
}

fn normalize_recovery_path(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return Err("Recovery root path must not be empty".to_string());
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err("Recovery root path must not contain NUL bytes".to_string());
    }
    if !path.is_absolute() {
        return Err(format!(
            "Recovery root must be an absolute path: {}",
            path.display()
        ));
    }
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "Recovery root must not contain '..' traversal: {}",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "Unsupported path prefix in recovery root: {}",
                    path.display()
                ));
            }
        }
    }
    if normalized == Path::new("/") {
        return Err("Refusing filesystem root '/' as recovery root".to_string());
    }
    Ok(normalized)
}

fn is_ephemeral_tmp_logical_path(logical: &Path) -> bool {
    let norm = logical.to_string_lossy();
    let trimmed = norm.trim_end_matches('/');
    matches!(
        trimmed,
        "/tmp" | "/var/tmp" | "/dev/shm" | "/run" | "/var/run"
    ) || trimmed.starts_with("/tmp/")
        || trimmed.starts_with("/var/tmp/")
        || trimmed.starts_with("/dev/shm/")
        || trimmed.starts_with("/run/")
        || trimmed.starts_with("/var/run/")
}

fn is_protected_recovery_logical_root(logical: &Path) -> bool {
    if is_protected_root(logical) {
        return true;
    }
    let norm = logical.to_string_lossy();
    matches!(
        norm.trim_end_matches('/'),
        "/var/backups"
            | "/var/log"
            | "/srv"
            | "/home"
            | "/root"
            | "/tmp"
            | "/var/tmp"
            | "/dev"
            | "/dev/shm"
            | "/run"
            | "/var/run"
    )
}

#[cfg(unix)]
fn is_symlink_open_error(err: &std::io::Error, path: &Path) -> bool {
    if err.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    if err.raw_os_error() == Some(libc::ENOTDIR) {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            return meta.file_type().is_symlink();
        }
    }
    false
}

#[cfg(unix)]
fn is_symlink_openat_error(
    err: &std::io::Error,
    dir_fd: libc::c_int,
    name: &std::ffi::CStr,
) -> bool {
    if err.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    if err.raw_os_error() == Some(libc::ENOTDIR) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0
        {
            return (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        }
    }
    false
}

#[cfg(unix)]
fn open_dir_nofollow(path: &Path, label: &str) -> Result<std::os::fd::OwnedFd, String> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| format!("Invalid {} path {}: {}", label, path.display(), e))?;
    let raw = unsafe {
        libc::open(
            path_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let err = std::io::Error::last_os_error();
        if is_symlink_open_error(&err, path) {
            return Err(format!(
                "{} {} is a symlink (symlink traversal prohibited)",
                label,
                path.display()
            ));
        }
        return Err(format!(
            "Failed to open {} {}: {}",
            label,
            path.display(),
            err
        ));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

#[cfg(unix)]
fn deepest_existing_ancestor(path: &Path) -> PathBuf {
    let mut probe = path.to_path_buf();
    while std::fs::symlink_metadata(&probe).is_err() {
        let Some(parent) = probe.parent() else {
            return PathBuf::from("/");
        };
        if parent == probe {
            break;
        }
        probe = parent.to_path_buf();
    }
    probe
}

#[cfg(unix)]
fn create_private_snapshot_under_recovery_root(
    recovery_root: &Path,
    folder_name: &str,
    strict_ancestor_anchor: Option<(&Path, bool)>,
    policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let (start_path, check_start, rel_target) = match strict_ancestor_anchor {
        Some((anchor, include_anchor)) if anchor == Path::new("/") => (
            PathBuf::from("/"),
            include_anchor,
            recovery_root.to_path_buf(),
        ),
        Some((anchor, include_anchor)) => {
            if !include_anchor && std::fs::symlink_metadata(anchor).is_err() {
                std::fs::create_dir_all(anchor).map_err(|e| {
                    format!(
                        "Failed to create recovery fixture root {}: {}",
                        anchor.display(),
                        e
                    )
                })?;
            }
            let rel = recovery_root.strip_prefix(anchor).map_err(|_| {
                format!(
                    "Recovery root {} is outside expected anchor {}",
                    recovery_root.display(),
                    anchor.display()
                )
            })?;
            (anchor.to_path_buf(), include_anchor, rel.to_path_buf())
        }
        None => {
            let parent = recovery_root.parent().ok_or_else(|| {
                format!("Invalid recovery root path: {}", recovery_root.display())
            })?;
            let existing = deepest_existing_ancestor(parent);
            let rel = recovery_root
                .strip_prefix(&existing)
                .map_err(|_| format!("Invalid recovery root path: {}", recovery_root.display()))?;
            (existing, false, rel.to_path_buf())
        }
    };

    let components: Vec<&std::ffi::OsStr> = rel_target
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err(format!(
            "Invalid recovery root path: {}",
            recovery_root.display()
        ));
    }

    let mut curr_fd = if start_path == Path::new("/") {
        let root_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(format!(
                "Failed to open root directory /: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { OwnedFd::from_raw_fd(root_raw) }
    } else {
        open_dir_nofollow(&start_path, "Recovery root ancestor")?
    };
    let mut current = start_path.clone();

    if check_start {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(curr_fd.as_raw_fd(), &mut st) } != 0 {
            return Err(format!(
                "Failed to stat recovery ancestor {}: {}",
                current.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mode = (st.st_mode as u32) & 0o777;
        if st.st_uid != policy.expected_uid || (mode & 0o022) != 0 {
            return Err(format!(
                "Recovery root ancestor {} has untrusted ownership/mode (uid={}, mode=0o{:o})",
                current.display(),
                st.st_uid,
                mode
            ));
        }
    }

    let (ancestors, leaf) = components.split_at(components.len() - 1);
    let leaf = leaf[0];

    for comp in ancestors {
        current.push(comp);
        let part_cstr = CString::new(comp.as_bytes()).map_err(|e| {
            format!(
                "Invalid path component in {}: {}",
                recovery_root.display(),
                e
            )
        })?;
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
                let mk_rc =
                    unsafe { libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755) };
                if mk_rc != 0 {
                    let mk_err = std::io::Error::last_os_error();
                    if mk_err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(format!(
                            "Failed to create recovery ancestor directory {}: {}",
                            current.display(),
                            mk_err
                        ));
                    }
                }
                next_raw = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            if next_raw < 0 {
                let open_err = std::io::Error::last_os_error();
                if is_symlink_openat_error(&open_err, curr_fd.as_raw_fd(), &part_cstr) {
                    return Err(format!(
                        "Recovery root ancestor {} is a symlink (symlink traversal prohibited)",
                        current.display()
                    ));
                }
                return Err(format!(
                    "Failed to open recovery ancestor directory {}: {}",
                    current.display(),
                    open_err
                ));
            }
        }
        let next_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        if let Some((_, include_anchor)) = strict_ancestor_anchor {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(next_fd.as_raw_fd(), &mut st) } != 0 {
                return Err(format!(
                    "Failed to stat recovery ancestor {}: {}",
                    current.display(),
                    std::io::Error::last_os_error()
                ));
            }
            let mode = (st.st_mode as u32) & 0o777;
            if st.st_uid != policy.expected_uid {
                return Err(format!(
                    "Recovery root ancestor {} is owned by uid {}, expected {}",
                    current.display(),
                    st.st_uid,
                    policy.expected_uid
                ));
            }
            let forbidden_write_bits = if policy.privileged || include_anchor {
                0o022
            } else {
                0o002
            };
            if (mode & forbidden_write_bits) != 0 {
                return Err(format!(
                    "Recovery root ancestor {} has unsafe writable permissions 0o{:o}",
                    current.display(),
                    mode
                ));
            }
        }
        curr_fd = next_fd;
    }

    current.push(leaf);
    let leaf_cstr = CString::new(leaf.as_bytes()).map_err(|e| {
        format!(
            "Invalid recovery root name in {}: {}",
            recovery_root.display(),
            e
        )
    })?;
    let mut created_leaf = false;
    let mut leaf_raw = unsafe {
        libc::openat(
            curr_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if leaf_raw < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            let mk_rc = unsafe { libc::mkdirat(curr_fd.as_raw_fd(), leaf_cstr.as_ptr(), 0o700) };
            if mk_rc == 0 {
                created_leaf = true;
            } else {
                let mk_err = std::io::Error::last_os_error();
                if mk_err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(format!(
                        "Failed to create recovery root {}: {}",
                        current.display(),
                        mk_err
                    ));
                }
            }
            leaf_raw = unsafe {
                libc::openat(
                    curr_fd.as_raw_fd(),
                    leaf_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if leaf_raw < 0 {
            let open_err = std::io::Error::last_os_error();
            if is_symlink_openat_error(&open_err, curr_fd.as_raw_fd(), &leaf_cstr) {
                return Err(format!(
                    "Recovery root {} is a symlink (symlink traversal prohibited)",
                    current.display()
                ));
            }
            return Err(format!(
                "Failed to open recovery root {}: {}",
                current.display(),
                open_err
            ));
        }
    }
    let leaf_fd = unsafe { OwnedFd::from_raw_fd(leaf_raw) };
    if created_leaf {
        let _ = unsafe { libc::fchmod(leaf_fd.as_raw_fd(), 0o700) };
    }
    let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(leaf_fd.as_raw_fd(), &mut leaf_st) } != 0 {
        return Err(format!(
            "Failed to stat recovery root {}: {}",
            current.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mode_mask = if policy.privileged { 0o7777 } else { 0o777 };
    let leaf_mode = (leaf_st.st_mode as u32) & mode_mask;
    if leaf_st.st_uid != policy.expected_uid {
        return Err(format!(
            "Recovery root {} is owned by uid {}, expected {}",
            current.display(),
            leaf_st.st_uid,
            policy.expected_uid
        ));
    }
    if leaf_mode != 0o700 {
        return Err(format!(
            "Recovery root {} has permissions 0o{:o}, expected private 0o700",
            current.display(),
            leaf_mode
        ));
    }

    let child_cstr = CString::new(folder_name.as_bytes())
        .map_err(|e| format!("Invalid snapshot folder name: {}", e))?;
    let mk_child = unsafe { libc::mkdirat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), 0o700) };
    if mk_child != 0 {
        return Err(format!(
            "Failed to create backup root {}/{}: {}",
            current.display(),
            folder_name,
            std::io::Error::last_os_error()
        ));
    }
    let child_raw = unsafe {
        libc::openat(
            leaf_fd.as_raw_fd(),
            child_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_raw < 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to verify created backup root {}/{}: {}",
            current.display(),
            folder_name,
            err
        ));
    }
    let child_fd = unsafe { OwnedFd::from_raw_fd(child_raw) };
    let _ = unsafe { libc::fchmod(child_fd.as_raw_fd(), 0o700) };
    let mut child_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(child_fd.as_raw_fd(), &mut child_st) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to stat backup root {}/{}: {}",
            current.display(),
            folder_name,
            err
        ));
    }
    let child_mode = (child_st.st_mode as u32) & mode_mask;
    if child_st.st_uid != policy.expected_uid || child_mode != 0o700 {
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Created backup root {}/{} has unexpected ownership/mode (uid={}, mode=0o{:o})",
            current.display(),
            folder_name,
            child_st.st_uid,
            child_mode
        ));
    }
    Ok(current.join(folder_name))
}

#[cfg(unix)]
fn create_private_snapshot_under_fallback_parent(
    parent: &Path,
    folder_name: &str,
    allow_create_parent: bool,
    policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let norm_parent = normalize_recovery_path(parent)?;
    let existing = deepest_existing_ancestor(&norm_parent);
    let rel = norm_parent.strip_prefix(&existing).map_err(|_| {
        format!(
            "Invalid fallback snapshot parent: {}",
            norm_parent.display()
        )
    })?;
    let mut curr_fd = if existing == Path::new("/") {
        let root_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(format!(
                "Failed to open root directory /: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { OwnedFd::from_raw_fd(root_raw) }
    } else {
        open_dir_nofollow(&existing, "Fallback snapshot parent")?
    };
    let mut current = existing;
    for comp in rel.components() {
        if let Component::Normal(part) = comp {
            current.push(part);
            let part_cstr = CString::new(part.as_bytes())
                .map_err(|e| format!("Invalid path component in {}: {}", parent.display(), e))?;
            let mut next_raw = unsafe {
                libc::openat(
                    curr_fd.as_raw_fd(),
                    part_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next_raw < 0 && allow_create_parent {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    let mk_rc =
                        unsafe { libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o700) };
                    if mk_rc == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
                    {
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
                    }
                }
            }
            if next_raw < 0 {
                return Err(format!(
                    "Failed to open fallback snapshot parent {}: {}",
                    current.display(),
                    std::io::Error::last_os_error()
                ));
            }
            curr_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        }
    }

    let child_cstr = CString::new(folder_name.as_bytes())
        .map_err(|e| format!("Invalid snapshot folder name: {}", e))?;
    let mk_child = unsafe { libc::mkdirat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), 0o700) };
    if mk_child != 0 {
        return Err(format!(
            "Failed to create backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            std::io::Error::last_os_error()
        ));
    }
    let child_raw = unsafe {
        libc::openat(
            curr_fd.as_raw_fd(),
            child_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_raw < 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to verify fallback backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            err
        ));
    }
    let child_fd = unsafe { OwnedFd::from_raw_fd(child_raw) };
    let _ = unsafe { libc::fchmod(child_fd.as_raw_fd(), 0o700) };
    let mut child_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(child_fd.as_raw_fd(), &mut child_st) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to stat fallback backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            err
        ));
    }
    let child_mode = (child_st.st_mode as u32) & 0o777;
    if child_st.st_uid != policy.expected_uid || child_mode != 0o700 {
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Fallback backup root {}/{} has unexpected ownership/mode (uid={}, mode=0o{:o})",
            norm_parent.display(),
            folder_name,
            child_st.st_uid,
            child_mode
        ));
    }
    Ok(norm_parent.join(folder_name))
}

#[cfg(not(unix))]
fn create_private_snapshot_under_recovery_root(
    recovery_root: &Path,
    folder_name: &str,
    _strict_ancestor_anchor: Option<(&Path, bool)>,
    _policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(recovery_root).map_err(|e| {
        format!(
            "Failed to create recovery root {}: {}",
            recovery_root.display(),
            e
        )
    })?;
    let candidate = recovery_root.join(folder_name);
    std::fs::create_dir(&candidate).map_err(|e| {
        format!(
            "Failed to create backup root {}: {}",
            candidate.display(),
            e
        )
    })?;
    Ok(candidate)
}

#[cfg(not(unix))]
fn create_private_snapshot_under_fallback_parent(
    parent: &Path,
    folder_name: &str,
    allow_create_parent: bool,
    _policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    if allow_create_parent {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create fallback snapshot parent {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    let candidate = parent.join(folder_name);
    std::fs::create_dir(&candidate).map_err(|e| {
        format!(
            "Failed to create backup root {}: {}",
            candidate.display(),
            e
        )
    })?;
    Ok(candidate)
}

pub(super) fn prepare_runtime_snapshot_backup_root_with_policy(
    folder_name: &str,
    env_cfg: &crate::PackageExecutionEnv,
    policy: RecoveryStoragePolicy,
    data_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let norm_fs_root = match env_cfg.fs_root.as_deref() {
        Some(root) => Some(normalize_recovery_path(root)?),
        None => None,
    };

    // Mode 1: Explicit recovery root configured on PackageExecutionEnv (or AETHERFLOW_RECOVERY_ROOT).
    if let Some(ref custom) = env_cfg.recovery_root {
        let norm_custom = normalize_recovery_path(custom)?;
        if let Some(ref fs_root) = norm_fs_root {
            if let Ok(rel) = norm_custom.strip_prefix(fs_root) {
                let logical = Path::new("/").join(rel);
                if is_protected_recovery_logical_root(&logical) {
                    return Err(format!(
                        "Refusing protected directory as recovery root: {}",
                        norm_custom.display()
                    ));
                }
                if is_ephemeral_tmp_logical_path(&logical) {
                    return Err(format!(
                        "Recovery root {} must reside on persistent storage outside /tmp, /var/tmp, /dev/shm, and /run",
                        norm_custom.display()
                    ));
                }
                return create_private_snapshot_under_recovery_root(
                    &norm_custom,
                    folder_name,
                    Some((fs_root.as_path(), false)),
                    policy,
                );
            }
            if is_protected_recovery_logical_root(&norm_custom) {
                return Err(format!(
                    "Refusing protected directory as recovery root: {}",
                    norm_custom.display()
                ));
            }
            return create_private_snapshot_under_recovery_root(
                &norm_custom,
                folder_name,
                None,
                policy,
            );
        }

        if is_protected_recovery_logical_root(&norm_custom) {
            return Err(format!(
                "Refusing protected directory as recovery root: {}",
                norm_custom.display()
            ));
        }
        if policy.privileged && is_ephemeral_tmp_logical_path(&norm_custom) {
            return Err(format!(
                "Privileged recovery root {} must reside on persistent storage outside /tmp, /var/tmp, /dev/shm, and /run",
                norm_custom.display()
            ));
        }
        let anchor = if policy.privileged {
            Some((Path::new("/"), true))
        } else {
            None
        };
        return create_private_snapshot_under_recovery_root(
            &norm_custom,
            folder_name,
            anchor,
            policy,
        );
    }

    // Mode 2: Isolated fixture (fs_root set, no explicit recovery_root).
    if let Some(ref fs_root) = norm_fs_root {
        let isolated_recovery = fs_root.join("var/backups/aetherflow-recovery");
        return create_private_snapshot_under_recovery_root(
            &isolated_recovery,
            folder_name,
            Some((fs_root.as_path(), false)),
            policy,
        );
    }

    // Mode 3: Privileged real host (root runner or direct root CLI). Never fall back to /tmp or /var/tmp.
    if policy.privileged {
        let default_root = PathBuf::from(crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT);
        return create_private_snapshot_under_recovery_root(
            &default_root,
            folder_name,
            Some((Path::new("/"), true)),
            policy,
        );
    }

    // Mode 4: Unprivileged API fallback on a real host.
    // Prefer persistent <DATA_DIR>/recovery (e.g. /var/lib/aetherflow/recovery inside aetherflow-api.service)
    // when available and owned by this user; otherwise fall back to private 0700 temp_dir / /var/tmp / TMPDIR.
    if let Some(dd) = data_dir {
        if let Ok(norm_dd) = normalize_recovery_path(dd) {
            if !is_ephemeral_tmp_logical_path(&norm_dd)
                && !is_protected_recovery_logical_root(&norm_dd)
                && norm_dd.is_dir()
            {
                let dd_recovery = norm_dd.join("recovery");
                if let Ok(created) = create_private_snapshot_under_recovery_root(
                    &dd_recovery,
                    folder_name,
                    Some((norm_dd.as_path(), true)),
                    policy,
                ) {
                    return Ok(created);
                }
            }
        }
    }

    let mut parent_candidates: Vec<(PathBuf, bool)> = Vec::new();
    if !env_cfg.temp_dir.as_os_str().is_empty() {
        parent_candidates.push((env_cfg.temp_dir.clone(), true));
    }
    let var_tmp = Path::new("/var/tmp");
    if var_tmp.is_dir() && !parent_candidates.iter().any(|(p, _)| p == var_tmp) {
        parent_candidates.push((var_tmp.to_path_buf(), false));
    }
    let sys_tmp = std::env::temp_dir();
    if !parent_candidates.iter().any(|(p, _)| p == &sys_tmp) {
        parent_candidates.push((sys_tmp, false));
    }
    let mut last_create_err = String::from("No usable fallback directory for runtime snapshot");
    for (parent, allow_create) in parent_candidates {
        match create_private_snapshot_under_fallback_parent(
            &parent,
            folder_name,
            allow_create,
            policy,
        ) {
            Ok(created) => return Ok(created),
            Err(err) => {
                last_create_err = err;
            }
        }
    }
    Err(last_create_err)
}

pub(super) fn prepare_runtime_snapshot_backup_root(
    folder_name: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<PathBuf, String> {
    let data_dir = std::env::var_os("DATA_DIR")
        .or_else(|| std::env::var_os("AETHERFLOW_DATA_DIR"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    prepare_runtime_snapshot_backup_root_with_policy(
        folder_name,
        env_cfg,
        RecoveryStoragePolicy::current(),
        data_dir.as_deref(),
    )
}
