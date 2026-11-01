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
    Regex::new(r"(?i)(?:Failed password|Invalid user|authentication failure).*?\bfrom\s+([0-9a-fA-F:.]+)").unwrap()
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

    let file = File::open(log_path).map_err(|e| {
        HostBackupError::io(format!("opening auth log {}", log_path.display()), e)
    })?;

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

/// Writes `/etc/sysctl.d/99-aetherflow-tune.conf` (relative to `root`) with optimized network
/// tuning parameters using symlink-safe atomic file replacement.
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

    Ok(TuningReport {
        config_path: conf_path,
        settings,
        applied: true,
        dry_run: false,
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

    let candidate_dirs = [root.join("var/log"), root.join("srv/aetherflow/lock")];

    let mut scanned_directories = Vec::new();
    let mut cleaned_files = Vec::new();
    let mut total_bytes_freed = 0u64;

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

    Ok(CleanLogReport {
        scanned_directories,
        cleaned_files,
        total_bytes_freed,
        dry_run,
    })
}

const MAX_TRAVERSAL_DEPTH: usize = 32;

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

        // Strict symlink rejection - never follow symlinks
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
        HostBackupError::io(format!("inspecting home directory {}", home_dir.display()), e)
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
