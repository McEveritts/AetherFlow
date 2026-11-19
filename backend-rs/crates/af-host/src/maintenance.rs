//! Pure-Rust host maintenance utilities replacing legacy `packages/system/*` scripts.
//!
//! Provides:
//! 1. [`sentinel_scan_auth_log`]: Scans authentication logs (`auth.log`) for failed password and
//!    invalid user attempts, aggregating counts per IPv4/IPv6 address and identifying brute-force
//!    offenders exceeding a threshold (matching `packages/system/af-sentinel.py`).
//! 2. [`compute_sysctl_network_tuning`] & [`apply_network_tuning`]: Computes and writes optimized
//!    kernel network buffer and congestion control sysctl parameters atomically without following
//!    symlinks (matching `packages/system/af-tune`).
//! 3. [`clean_system_logs`]: Safely truncates oversized log files under `/var/log` or
//!    `/srv/aetherflow/lock` without following symlinks (matching `packages/system/clean_log`).
//! 4. [`inspect_home_disk_space`]: Calculates directory usage per `/home/<user>` entry and returns
//!    human-readable space metrics (matching `packages/system/showspace`).

use crate::error::{HostBackupError, HostBackupResult};
use crate::verify::{reject_if_symlink, reject_symlink_chain, validate_no_parent_traversal};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Default threshold for failed attempts before an IP is flagged as an offender (matching `af-sentinel.py`).
pub const DEFAULT_SENTINEL_THRESHOLD: usize = 5;

/// Regex pattern matching authentication failure indicators and extracting candidate IP strings.
static AUTH_LOG_IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:Failed password|Invalid user|authentication failure).*?\bfrom\s+([0-9a-fA-F:.]+)",
    )
    .unwrap()
});

/// Report produced by [`sentinel_scan_auth_log`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelScanReport {
    /// Absolute path of the scanned authentication log.
    pub log_path: PathBuf,
    /// Total lines scanned from the file.
    pub scanned_lines: usize,
    /// Total failed authentication events detected.
    pub failed_event_count: usize,
    /// Failure count threshold used to classify offending IPs.
    pub threshold: usize,
    /// Aggregated failed attempt count per IP address.
    pub ip_counts: BTreeMap<String, usize>,
    /// Unique IP addresses whose failure count meets or exceeds `threshold`.
    pub offending_ips: Vec<String>,
}

/// Scans an authentication log (`auth.log`) for `Failed password` / `Invalid user` entries,
/// aggregates attempt counts by IPv4/IPv6 address, and identifies offending IPs exceeding `threshold`.
///
/// Refuses to follow symlinks to protect against log redirection attacks.
pub fn sentinel_scan_auth_log(
    log_path: &Path,
    threshold: usize,
) -> HostBackupResult<SentinelScanReport> {
    validate_no_parent_traversal(log_path, "auth_log_path")?;
    reject_if_symlink(log_path, "auth.log")?;

    let effective_threshold = if threshold == 0 {
        DEFAULT_SENTINEL_THRESHOLD
    } else {
        threshold
    };

    let file = open_regular_file_read_nofollow(log_path, "auth.log")?;

    let reader = BufReader::new(file);
    let mut scanned_lines = 0usize;
    let mut failed_event_count = 0usize;
    let mut ip_counts: BTreeMap<String, usize> = BTreeMap::new();

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| {
            HostBackupError::io(format!("reading auth log {}", log_path.display()), e)
        })?;
        scanned_lines += 1;

        if let Some(caps) = AUTH_LOG_IP_REGEX.captures(&line) {
            if let Some(m) = caps.get(1) {
                let candidate = m.as_str().trim_end_matches('.');
                if let Ok(ip) = IpAddr::from_str(candidate) {
                    let normalized_ip = ip.to_string();
                    *ip_counts.entry(normalized_ip).or_insert(0) += 1;
                    failed_event_count += 1;
                }
            }
        }
    }

    let offending_ips: Vec<String> = ip_counts
        .iter()
        .filter(|&(_, &count)| count >= effective_threshold)
        .map(|(ip, _)| ip.clone())
        .collect();

    Ok(SentinelScanReport {
        log_path: log_path.to_path_buf(),
        scanned_lines,
        failed_event_count,
        threshold: effective_threshold,
        ip_counts,
        offending_ips,
    })
}

/// Report produced by [`apply_network_tuning`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuningReport {
    /// Destination sysctl drop-in path (typically `/etc/sysctl.d/99-aetherflow-tune.conf`).
    pub config_path: PathBuf,
    /// Kernel sysctl key-value pairs configured.
    pub settings: BTreeMap<String, String>,
    /// Whether configuration was written to disk.
    pub applied: bool,
    /// Whether execution was dry-run only.
    pub dry_run: bool,
    /// Whether `sysctl` was reloaded live on the host after writing the drop-in.
    #[serde(default)]
    pub sysctl_reloaded: bool,
    /// Diagnostic note if live `sysctl` reload was skipped or unsupported (e.g. container environment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sysctl_reload_note: Option<String>,
}

/// Computes the standard network sysctl tuning parameters matching `packages/system/af-tune`.
pub fn compute_sysctl_network_tuning() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("net.core.default_qdisc".to_string(), "fq".to_string());
    map.insert("net.core.rmem_max".to_string(), "67108864".to_string());
    map.insert("net.core.wmem_max".to_string(), "67108864".to_string());
    map.insert(
        "net.ipv4.tcp_congestion_control".to_string(),
        "bbr".to_string(),
    );
    map.insert(
        "net.ipv4.tcp_rmem".to_string(),
        "4096 87380 33554432".to_string(),
    );
    map.insert(
        "net.ipv4.tcp_wmem".to_string(),
        "4096 65536 33554432".to_string(),
    );
    map
}

/// Returns `true` when `root` targets the live host filesystem (`/`) rather than an isolated test root.
pub fn is_live_host_root(root: &Path) -> bool {
    af_models::normalize_lexical_path(root, "root")
        .map(|normalized| normalized == Path::new("/"))
        .unwrap_or_else(|_| root == Path::new("/"))
}

fn apply_sysctl_with_runner<F>(conf_path: &Path, runner: F) -> (bool, Option<String>)
where
    F: FnOnce(&Path) -> std::io::Result<std::process::Output>,
{
    match runner(conf_path) {
        Ok(out) if out.status.success() => (true, None),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            let note = format!(
                "sysctl reload returned {} (tuning file {} saved for next boot; container or read-only /proc/sys may restrict live sysctl): {}",
                out.status,
                conf_path.display(),
                detail
            );
            eprintln!("[af-host] WARNING: {}", note);
            (false, Some(note))
        }
        Err(err) => {
            let note = format!(
                "sysctl binary could not be executed ({}); tuning file {} saved for next boot",
                err,
                conf_path.display()
            );
            eprintln!("[af-host] WARNING: {}", note);
            (false, Some(note))
        }
    }
}

/// Writes `/etc/sysctl.d/99-aetherflow-tune.conf` (relative to `root`) with optimized network
/// tuning parameters using symlink-safe atomic file replacement, and applies `sysctl -p`
/// immediately when running against the live host root (`/`).
pub fn apply_network_tuning(root: &Path, dry_run: bool) -> HostBackupResult<TuningReport> {
    let conf_rel = Path::new("etc/sysctl.d/99-aetherflow-tune.conf");
    let conf_path = root.join(conf_rel);

    validate_no_parent_traversal(root, "root")?;
    validate_no_parent_traversal(&conf_path, "conf_path")?;

    let settings = compute_sysctl_network_tuning();

    if dry_run {
        return Ok(TuningReport {
            config_path: conf_path,
            settings,
            applied: false,
            dry_run: true,
            sysctl_reloaded: false,
            sysctl_reload_note: None,
        });
    }

    let parent_dir = conf_path.parent().ok_or_else(|| {
        HostBackupError::InvalidConfig(format!(
            "invalid parent for sysctl config {}",
            conf_path.display()
        ))
    })?;

    fs::create_dir_all(parent_dir).map_err(|e| {
        HostBackupError::io(format!("creating directory {}", parent_dir.display()), e)
    })?;

    reject_symlink_chain(root, &conf_path)?;

    let mut body = String::new();
    body.push_str("# AetherFlow AI Resource Tuner sysctl configuration\n");
    body.push_str("# Automatically generated by af-host maintenance\n");
    for (k, v) in &settings {
        body.push_str(&format!("{} = {}\n", k, v));
    }

    let temp_name = format!(
        ".99-aetherflow-tune.conf.tmp-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let temp_path = parent_dir.join(temp_name);

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| {
                HostBackupError::io(
                    format!("creating temp sysctl file {}", temp_path.display()),
                    e,
                )
            })?;

        #[cfg(unix)]
        {
            let mut perms = file
                .metadata()
                .map_err(|e| HostBackupError::io("reading temp sysctl file metadata", e))?
                .permissions();
            perms.set_mode(0o644);
            let _ = file.set_permissions(perms);
        }

        file.write_all(body.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            HostBackupError::io(
                format!("writing sysctl configuration to {}", temp_path.display()),
                e,
            )
        })?;
        file.sync_all().map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            HostBackupError::io("syncing sysctl file", e)
        })?;
    }

    fs::rename(&temp_path, &conf_path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        HostBackupError::io(
            format!(
                "atomic rename {} -> {}",
                temp_path.display(),
                conf_path.display()
            ),
            e,
        )
    })?;

    let (sysctl_reloaded, sysctl_reload_note) = if is_live_host_root(root) {
        apply_sysctl_with_runner(&conf_path, |path| {
            std::process::Command::new("sysctl")
                .arg("-p")
                .arg(path)
                .output()
        })
    } else {
        (false, None)
    };

    Ok(TuningReport {
        config_path: conf_path,
        settings,
        applied: true,
        dry_run: false,
        sysctl_reloaded,
        sysctl_reload_note,
    })
}

/// Record of an individual log file truncated by [`clean_system_logs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanedLogFile {
    pub path: PathBuf,
    pub original_size_bytes: u64,
}

/// Report produced by [`clean_system_logs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanLogReport {
    pub scanned_directories: Vec<PathBuf>,
    pub cleaned_files: Vec<CleanedLogFile>,
    pub total_bytes_freed: u64,
    pub dry_run: bool,
}

#[cfg(unix)]
fn open_dir_step_nofollow(
    parent_fd: std::os::unix::io::RawFd,
    segment: &std::ffi::CStr,
    display_path: &Path,
    context: &str,
) -> HostBackupResult<Option<File>> {
    use std::os::unix::io::FromRawFd;

    let fd = unsafe {
        libc::openat(
            parent_fd,
            segment.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(HostBackupError::SymlinkRejected {
                path: display_path.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            }),
            Some(libc::ENOTDIR) => Err(HostBackupError::PathValidation {
                path: display_path.to_path_buf(),
                reason: format!("{} is not a directory", context),
            }),
            _ => Err(HostBackupError::io(
                format!("opening directory {} ({})", display_path.display(), context),
                err,
            )),
        };
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

#[cfg(unix)]
fn open_existing_dir_chain_nofollow(dir: &Path, context: &str) -> HostBackupResult<Option<File>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Component;

    let abs_dir = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| HostBackupError::io(format!("resolving cwd for {}", context), e))?
            .join(dir)
    };

    let root_c = CString::new("/").unwrap();
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(HostBackupError::io(
            format!("opening '/' directory ({})", context),
            std::io::Error::last_os_error(),
        ));
    }
    let mut cur = unsafe { File::from_raw_fd(root_fd) };
    let mut acc = PathBuf::from("/");

    for comp in abs_dir.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..'", context),
                });
            }
            Component::Normal(seg) => {
                acc.push(seg);
                let seg_c =
                    CString::new(seg.as_bytes()).map_err(|_| HostBackupError::PathValidation {
                        path: acc.clone(),
                        reason: format!("{} path component contains NUL byte", context),
                    })?;
                match open_dir_step_nofollow(cur.as_raw_fd(), &seg_c, &acc, context)? {
                    Some(next) => cur = next,
                    None => return Ok(None),
                }
            }
        }
    }
    Ok(Some(cur))
}

#[cfg(unix)]
fn open_regular_file_read_nofollow(path: &Path, context: &str) -> HostBackupResult<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| HostBackupError::io(format!("resolving cwd for {}", context), e))?
            .join(path)
    };
    let parent = abs_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has no parent directory", context),
        })?;
    let leaf = abs_path
        .file_name()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has no file name", context),
        })?;
    let leaf_c = CString::new(leaf.as_bytes()).map_err(|_| HostBackupError::PathValidation {
        path: path.to_path_buf(),
        reason: format!("{} filename contains NUL byte", context),
    })?;

    let parent_dir = open_existing_dir_chain_nofollow(parent, context)?.ok_or_else(|| {
        HostBackupError::io(
            format!("opening auth log {}", path.display()),
            std::io::Error::from_raw_os_error(libc::ENOENT),
        )
    })?;

    let fd = unsafe {
        libc::openat(
            parent_dir.as_raw_fd(),
            leaf_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ELOOP) {
            return Err(HostBackupError::SymlinkRejected {
                path: path.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            });
        }
        return Err(HostBackupError::io(
            format!("opening auth log {}", path.display()),
            err,
        ));
    }

    let file = unsafe { File::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(HostBackupError::io(
            format!("inspecting auth log {}", path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} is not a regular file", context),
        });
    }

    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_file_read_nofollow(path: &Path, _context: &str) -> HostBackupResult<File> {
    File::open(path)
        .map_err(|e| HostBackupError::io(format!("opening auth log {}", path.display()), e))
}

/// Safely scans log directories (`/var/log` and `/srv/aetherflow/lock` relative to `root`)
/// and truncates regular `.log` files exceeding `max_size_bytes`.
///
/// Never follows symlinks to ensure that log truncation cannot escape permitted directories.
pub fn clean_system_logs(
    root: &Path,
    max_size_bytes: u64,
    dry_run: bool,
) -> HostBackupResult<CleanLogReport> {
    validate_no_parent_traversal(root, "root")?;
    reject_if_symlink(root, "root")?;

    let mut scanned_directories = Vec::new();
    let mut cleaned_files = Vec::new();
    let mut total_bytes_freed = 0u64;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let Some(root_dir) = open_existing_dir_chain_nofollow(root, "root")? else {
            return Ok(CleanLogReport {
                scanned_directories,
                cleaned_files,
                total_bytes_freed,
                dry_run,
            });
        };

        let candidate_chains: [&[&str]; 2] = [&["var", "log"], &["srv", "aetherflow", "lock"]];
        for chain in candidate_chains {
            let mut cur_opt: Option<File> = None;
            let mut cur_path = root.to_path_buf();
            let mut skip = false;

            for seg in chain {
                cur_path.push(seg);
                let seg_c = CString::new(*seg).unwrap();
                let parent_fd = cur_opt
                    .as_ref()
                    .map(|f| f.as_raw_fd())
                    .unwrap_or_else(|| root_dir.as_raw_fd());
                match open_dir_step_nofollow(parent_fd, &seg_c, &cur_path, "log directory") {
                    Ok(Some(next_dir)) => cur_opt = Some(next_dir),
                    Ok(None)
                    | Err(HostBackupError::SymlinkRejected { .. })
                    | Err(HostBackupError::PathValidation { .. }) => {
                        skip = true;
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }

            if skip {
                continue;
            }
            if let Some(dir_file) = cur_opt {
                scanned_directories.push(cur_path.clone());
                let in_aetherflow_dir = chain.last() == Some(&"aetherflow");
                scan_and_clean_dir_logs_fd(
                    &dir_file,
                    &cur_path,
                    in_aetherflow_dir,
                    max_size_bytes,
                    dry_run,
                    0,
                    &mut cleaned_files,
                    &mut total_bytes_freed,
                )?;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let candidate_dirs = [root.join("var/log"), root.join("srv/aetherflow/lock")];
        for dir in &candidate_dirs {
            if !dir.exists() {
                continue;
            }
            let meta = fs::symlink_metadata(dir).map_err(|e| {
                HostBackupError::io(format!("inspecting directory {}", dir.display()), e)
            })?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            scanned_directories.push(dir.clone());
            scan_and_clean_dir_logs(
                dir,
                max_size_bytes,
                dry_run,
                0,
                &mut cleaned_files,
                &mut total_bytes_freed,
            )?;
        }
    }

    Ok(CleanLogReport {
        scanned_directories,
        cleaned_files,
        total_bytes_freed,
        dry_run,
    })
}

const MAX_TRAVERSAL_DEPTH: usize = 32;

#[cfg(unix)]
fn read_dir_entries_from_fd(
    dir_fd: std::os::unix::io::RawFd,
    dir_path: &Path,
) -> HostBackupResult<Vec<std::ffi::CString>> {
    use std::ffi::CStr;

    let dup_fd = unsafe { libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(HostBackupError::io(
            format!("duplicating dirfd for {}", dir_path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    let dirp = unsafe { libc::fdopendir(dup_fd) };
    if dirp.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(dup_fd) };
        return Err(HostBackupError::io(
            format!("reading dir {}", dir_path.display()),
            err,
        ));
    }

    struct DirGuard(*mut libc::DIR);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let _guard = DirGuard(dirp);

    let mut names = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name_c = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = name_c.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(name_c.to_owned());
    }
    Ok(names)
}

#[cfg(unix)]
fn try_acquire_retention_lock_at(dir_fd: std::os::unix::io::RawFd) -> Option<File> {
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let lock_name = CString::new(".af-retention.lock").unwrap();
    let fd = unsafe {
        libc::openat(
            dir_fd,
            lock_name.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return None;
    }
    let lock_file = unsafe { File::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(lock_file.as_raw_fd(), &mut st) } != 0
        || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        return None;
    }
    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    Some(lock_file)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn scan_and_clean_dir_logs_fd(
    dir_file: &File,
    dir_path: &Path,
    in_aetherflow_dir: bool,
    max_size_bytes: u64,
    dry_run: bool,
    depth: usize,
    cleaned_files: &mut Vec<CleanedLogFile>,
    total_bytes_freed: &mut u64,
) -> HostBackupResult<()> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    if depth > MAX_TRAVERSAL_DEPTH {
        return Ok(());
    }

    let dir_fd = dir_file.as_raw_fd();
    let entries = read_dir_entries_from_fd(dir_fd, dir_path)?;

    for name_c in entries {
        let name_os = OsStr::from_bytes(name_c.as_bytes());
        let child_path = dir_path.join(name_os);

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir_fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) }
            != 0
        {
            continue;
        }

        let file_type = st.st_mode & libc::S_IFMT;
        if file_type == libc::S_IFLNK {
            continue;
        }

        if file_type == libc::S_IFDIR {
            let next_fd = unsafe {
                libc::openat(
                    dir_fd,
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next_fd < 0 {
                continue;
            }
            let next_dir = unsafe { File::from_raw_fd(next_fd) };
            let child_is_aetherflow = name_c.as_bytes() == b"aetherflow";
            scan_and_clean_dir_logs_fd(
                &next_dir,
                &child_path,
                child_is_aetherflow,
                max_size_bytes,
                dry_run,
                depth + 1,
                cleaned_files,
                total_bytes_freed,
            )?;
        } else if file_type == libc::S_IFREG {
            let filename = name_os.to_str().unwrap_or("");
            if !filename.ends_with(".log") || st.st_nlink != 1 {
                continue;
            }
            let size = st.st_size.max(0) as u64;
            if size <= max_size_bytes {
                continue;
            }

            if dry_run {
                *total_bytes_freed = total_bytes_freed.saturating_add(size);
                cleaned_files.push(CleanedLogFile {
                    path: child_path,
                    original_size_bytes: size,
                });
                continue;
            }

            let fd = unsafe {
                libc::openat(
                    dir_fd,
                    name_c.as_ptr(),
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                if matches!(
                    err.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ELOOP) | Some(libc::ENXIO)
                ) {
                    continue;
                }
                return Err(HostBackupError::io(
                    format!("opening log file {}", child_path.display()),
                    err,
                ));
            }
            let log_file = unsafe { File::from_raw_fd(fd) };

            let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(log_file.as_raw_fd(), &mut opened_st) } != 0 {
                return Err(HostBackupError::io(
                    format!("inspecting log file {}", child_path.display()),
                    std::io::Error::last_os_error(),
                ));
            }
            if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG || opened_st.st_nlink != 1 {
                continue;
            }
            let actual_size = opened_st.st_size.max(0) as u64;
            if actual_size <= max_size_bytes {
                continue;
            }

            let _retention_lock = if in_aetherflow_dir && filename == "deploy.log" {
                match try_acquire_retention_lock_at(dir_fd) {
                    Some(lock) => Some(lock),
                    None => continue,
                }
            } else {
                None
            };

            if unsafe { libc::flock(log_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let err = std::io::Error::last_os_error();
                if matches!(
                    err.raw_os_error(),
                    Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
                ) {
                    continue;
                }
                return Err(HostBackupError::io(
                    format!("locking log file {}", child_path.display()),
                    err,
                ));
            }

            if unsafe { libc::ftruncate(log_file.as_raw_fd(), 0) } != 0 {
                return Err(HostBackupError::io(
                    format!("truncating log file {}", child_path.display()),
                    std::io::Error::last_os_error(),
                ));
            }

            *total_bytes_freed = total_bytes_freed.saturating_add(actual_size);
            cleaned_files.push(CleanedLogFile {
                path: child_path,
                original_size_bytes: actual_size,
            });
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn scan_and_clean_dir_logs(
    dir: &Path,
    max_size_bytes: u64,
    dry_run: bool,
    depth: usize,
    cleaned_files: &mut Vec<CleanedLogFile>,
    total_bytes_freed: &mut u64,
) -> HostBackupResult<()> {
    if depth > MAX_TRAVERSAL_DEPTH {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(HostBackupError::io(
                format!("reading dir {}", dir.display()),
                err,
            ))
        }
    };

    for entry_res in entries {
        let entry = entry_res.map_err(|e| {
            HostBackupError::io(format!("reading dir entry in {}", dir.display()), e)
        })?;
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() {
            continue;
        }

        if meta.is_dir() {
            scan_and_clean_dir_logs(
                &path,
                max_size_bytes,
                dry_run,
                depth + 1,
                cleaned_files,
                total_bytes_freed,
            )?;
        } else if meta.is_file() {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.ends_with(".log") {
                let size = meta.len();
                if size > max_size_bytes {
                    *total_bytes_freed = total_bytes_freed.saturating_add(size);
                    cleaned_files.push(CleanedLogFile {
                        path: path.clone(),
                        original_size_bytes: size,
                    });

                    if !dry_run {
                        let _ = OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&path)
                            .map_err(|e| {
                                HostBackupError::io(
                                    format!("truncating log file {}", path.display()),
                                    e,
                                )
                            })?;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Disk usage entry per user home directory matching `packages/system/showspace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeSpaceEntry {
    pub user: String,
    pub home_path: PathBuf,
    pub bytes: u64,
    pub human: String,
}

/// Formats byte counts into human-readable strings (e.g. `512B`, `12.5MB`, `1.2GB`).
pub fn format_human_space_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut b = bytes as f64;
    let mut idx = 0;
    while b >= 1024.0 && idx < UNITS.len() - 1 {
        b /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else {
        format!("{:.1}{}", b, UNITS[idx])
    }
}

/// Calculates directory usage per `/home/<user>` entry under `root.join("home")`.
///
/// Follows no symlinks and returns records sorted by username.
pub fn inspect_home_disk_space(root: &Path) -> HostBackupResult<Vec<HomeSpaceEntry>> {
    validate_no_parent_traversal(root, "root")?;
    reject_if_symlink(root, "root")?;

    let home_dir = root.join("home");
    if !home_dir.exists() {
        return Ok(Vec::new());
    }

    let meta = fs::symlink_metadata(&home_dir).map_err(|e| {
        HostBackupError::io(
            format!("inspecting home directory {}", home_dir.display()),
            e,
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&home_dir).map_err(|e| {
        HostBackupError::io(format!("reading home directory {}", home_dir.display()), e)
    })?;

    let mut results = Vec::new();

    for entry_res in entries {
        let entry = entry_res.map_err(|e| {
            HostBackupError::io(
                format!("reading entry in home dir {}", home_dir.display()),
                e,
            )
        })?;
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }

        let user = match path.file_name().and_then(|n| n.to_str()) {
            Some(u) if !u.is_empty() && !u.starts_with('.') => u.to_string(),
            _ => continue,
        };

        let total_bytes = compute_dir_tree_bytes(&path, 0)?;
        let human = format_human_space_bytes(total_bytes);

        results.push(HomeSpaceEntry {
            user,
            home_path: path,
            bytes: total_bytes,
            human,
        });
    }

    results.sort_by(|a, b| a.user.cmp(&b.user));
    Ok(results)
}

fn compute_dir_tree_bytes(dir: &Path, depth: usize) -> HostBackupResult<u64> {
    if depth > MAX_TRAVERSAL_DEPTH {
        return Ok(0);
    }
    let mut total = 0u64;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(0),
    };

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() {
            continue;
        }

        if meta.is_dir() {
            total = total.saturating_add(compute_dir_tree_bytes(&path, depth + 1)?);
        } else if meta.is_file() {
            total = total.saturating_add(meta.len());
        }
    }

    Ok(total)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn live_host_root_and_sysctl_runner_handle_containers_and_temp_roots() {
        assert!(is_live_host_root(Path::new("/")));
        assert!(is_live_host_root(Path::new("/.")));
        assert!(!is_live_host_root(Path::new("/tmp/test-root")));

        let conf = Path::new("/etc/sysctl.d/99-aetherflow-tune.conf");
        #[cfg(unix)]
        {
            let (ok_reloaded, ok_note) = apply_sysctl_with_runner(conf, |_| {
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            });
            assert!(ok_reloaded);
            assert!(ok_note.is_none());

            let (ro_reloaded, ro_note) = apply_sysctl_with_runner(conf, |_| {
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(256),
                    stdout: Vec::new(),
                    stderr: b"sysctl: setting key \"net.core.rmem_max\": Read-only file system"
                        .to_vec(),
                })
            });
            assert!(!ro_reloaded);
            assert!(ro_note
                .as_deref()
                .unwrap_or_default()
                .contains("Read-only file system"));
        }

        let (missing_reloaded, missing_note) = apply_sysctl_with_runner(conf, |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "sysctl not found",
            ))
        });
        assert!(!missing_reloaded);
        assert!(missing_note
            .as_deref()
            .unwrap_or_default()
            .contains("sysctl binary could not be executed"));
    }

    #[cfg(unix)]
    #[test]
    fn clean_system_logs_rejects_symlinks_hardlinks_and_respects_flock() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        use std::os::unix::io::AsRawFd;

        let base = std::env::temp_dir().join(format!(
            "af-host-h01-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let var_log = base.join("var/log");
        let af_log_dir = var_log.join("aetherflow");
        let outside_dir = base.join("outside");
        fs::create_dir_all(&af_log_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let target_secret = outside_dir.join("secret.log");
        fs::write(&target_secret, vec![b'x'; 2000]).unwrap();
        symlink(&target_secret, var_log.join("sym.log")).unwrap();
        symlink(&outside_dir, var_log.join("symdir")).unwrap();

        let hardlink_a = outside_dir.join("shared.log");
        fs::write(&hardlink_a, vec![b'h'; 2000]).unwrap();
        fs::hard_link(&hardlink_a, var_log.join("hardlink.log")).unwrap();

        let flocked_log = var_log.join("busy.log");
        fs::write(&flocked_log, vec![b'b'; 2000]).unwrap();
        let flocked_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&flocked_log)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(flocked_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let deploy_log = af_log_dir.join("deploy.log");
        fs::write(&deploy_log, vec![b'd'; 2000]).unwrap();
        let ret_lock_path = af_log_dir.join(".af-retention.lock");
        let ret_lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&ret_lock_path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(ret_lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let fifo_path = var_log.join("pipe.log");
        let fifo_c = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let rep1 = clean_system_logs(&base, 1000, false).unwrap();
        assert!(
            rep1.cleaned_files.is_empty(),
            "all files should be skipped or rejected"
        );
        assert_eq!(fs::metadata(&target_secret).unwrap().len(), 2000);
        assert_eq!(fs::metadata(&hardlink_a).unwrap().len(), 2000);
        assert_eq!(fs::metadata(&flocked_log).unwrap().len(), 2000);
        assert_eq!(fs::metadata(&deploy_log).unwrap().len(), 2000);

        // Release retention lock -> deploy.log is truncated while busy/hardlink/symlink remain untouched
        drop(ret_lock_file);
        let rep2 = clean_system_logs(&base, 1000, false).unwrap();
        assert_eq!(rep2.cleaned_files.len(), 1);
        assert_eq!(rep2.cleaned_files[0].path, deploy_log);
        assert_eq!(fs::metadata(&deploy_log).unwrap().len(), 0);
        assert_eq!(fs::metadata(&flocked_log).unwrap().len(), 2000);
        assert_eq!(fs::metadata(&hardlink_a).unwrap().len(), 2000);
        assert_eq!(fs::metadata(&target_secret).unwrap().len(), 2000);

        drop(flocked_file);

        // Also verify sentinel_scan_auth_log rejects symlinks and FIFOs
        let auth_fifo = outside_dir.join("auth_pipe");
        let auth_fifo_c = CString::new(auth_fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(auth_fifo_c.as_ptr(), 0o600) }, 0);
        assert!(sentinel_scan_auth_log(&auth_fifo, 5)
            .unwrap_err()
            .is_security_rejection());
        assert!(sentinel_scan_auth_log(&var_log.join("sym.log"), 5)
            .unwrap_err()
            .is_security_rejection());

        let _ = fs::remove_dir_all(&base);
    }
}
