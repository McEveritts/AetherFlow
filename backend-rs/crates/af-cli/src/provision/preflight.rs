use super::fs_helpers::ensure_no_symlink_ancestors;
use super::lock::is_pid_alive;
use super::ProvisionPaths;
use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed operating system metadata from `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsReleaseInfo {
    pub distro_id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub codename: Option<String>,
    pub supported: bool,
    pub support_reason: String,
}

/// Parses an `/etc/os-release` content string and evaluates compatibility against
/// `setup/modules/00-core.sh` (`check_kernel`: Ubuntu >= 20.04, Debian >= 11, Kali).
pub fn parse_and_validate_os_release(content: &str) -> OsReleaseInfo {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let clean_val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            fields.insert(k.trim().to_ascii_uppercase(), clean_val);
        }
    }

    let distro_id = fields
        .get("ID")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
        .to_ascii_lowercase();
    let version_id = fields.get("VERSION_ID").cloned().unwrap_or_default();
    let pretty_name = fields
        .get("PRETTY_NAME")
        .cloned()
        .unwrap_or_else(|| format!("{} {}", distro_id, version_id));
    let codename = fields
        .get("VERSION_CODENAME")
        .or_else(|| fields.get("UBUNTU_CODENAME"))
        .cloned();

    let major_version = version_id
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let (supported, support_reason) = match distro_id.as_str() {
        "ubuntu" => {
            if major_version >= 20 {
                (
                    true,
                    format!("Ubuntu {} (>= 20.04 LTS supported)", version_id),
                )
            } else {
                (
                    false,
                    format!(
                        "Ubuntu {} is older than minimum required 20.04 LTS",
                        version_id
                    ),
                )
            }
        }
        "debian" => {
            if major_version >= 11 {
                (
                    true,
                    format!("Debian {} (>= 11 Bullseye supported)", version_id),
                )
            } else {
                (
                    false,
                    format!(
                        "Debian {} is older than minimum required Debian 11",
                        version_id
                    ),
                )
            }
        }
        "kali" => (true, format!("Kali Rolling ({}) supported", version_id)),
        other => (
            false,
            format!(
                "unsupported distribution {:?} (supported: Ubuntu 20.04+, Debian 11+, Kali)",
                other
            ),
        ),
    };

    OsReleaseInfo {
        distro_id,
        version_id,
        pretty_name,
        codename,
        supported,
        support_reason,
    }
}

/// Comprehensive preflight check report returned by `af provision preflight`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionPreflightReport {
    pub passed: bool,
    pub fs_root: PathBuf,
    pub is_effective_root: bool,
    pub root_check_passed: bool,
    pub os_release: Option<OsReleaseInfo>,
    pub os_check_passed: bool,
    pub lock_contended: bool,
    pub systemd_dir_present: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Returns `true` if the current process has effective UID 0 on Unix.
pub fn is_effective_root_user() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Runs non-destructive provisioning preflight checks against `paths`.
pub fn run_provision_preflight(
    paths: &ProvisionPaths,
    os_release_override: Option<&Path>,
    require_root: bool,
) -> CliResult<ProvisionPreflightReport> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    ensure_no_symlink_ancestors(&paths.fs_root, "provision fs_root")?;

    let is_root = is_effective_root_user();
    let root_check_passed = !require_root || is_root;
    if !root_check_passed {
        errors.push(
            "effective UID is not 0 (root); bare-metal provisioning requires root privileges or --no-root-check / --root <isolated_dir>".to_string(),
        );
    }

    let os_rel_path = os_release_override.unwrap_or(&paths.os_release_file);
    ensure_no_symlink_ancestors(os_rel_path, "os-release file")?;
    let (os_release, os_check_passed) = if os_rel_path.is_file() {
        let raw = fs::read_to_string(os_rel_path).map_err(|e| {
            CliError::io(format!("reading os-release {}", os_rel_path.display()), e)
        })?;
        let parsed = parse_and_validate_os_release(&raw);
        let ok = parsed.supported;
        if !ok {
            errors.push(parsed.support_reason.clone());
        }
        (Some(parsed), ok)
    } else {
        warnings.push(format!(
            "os-release file not found at {} (skipping distro gate in isolated root)",
            os_rel_path.display()
        ));
        (None, true)
    };

    ensure_no_symlink_ancestors(&paths.lock_file, "provision lockfile")?;
    let mut lock_contended = false;
    if paths.lock_file.exists() {
        let raw_pid = fs::read_to_string(&paths.lock_file).unwrap_or_default();
        if let Ok(pid) = raw_pid.trim().parse::<u32>() {
            if is_pid_alive(pid) {
                lock_contended = true;
                errors.push(format!(
                    "setup lockfile {} is held by active PID {}",
                    paths.lock_file.display(),
                    pid
                ));
            }
        }
    }

    let systemd_dir_present = paths.etc_systemd_system.is_dir();
    if !systemd_dir_present {
        warnings.push(format!(
            "systemd unit directory {} does not exist yet (will be created by 'makedirs'/'boot')",
            paths.etc_systemd_system.display()
        ));
    }

    let passed = errors.is_empty();
    Ok(ProvisionPreflightReport {
        passed,
        fs_root: paths.fs_root.clone(),
        is_effective_root: is_root,
        root_check_passed,
        os_release,
        os_check_passed,
        lock_contended,
        systemd_dir_present,
        warnings,
        errors,
    })
}
