//! Resumable bare-metal provisioning foundation (`STATE_VERSION=2`) for AetherFlow (`af-cli`).
//!
//! # Scope & Architectural Boundaries
//! - Implements persisted resumable step states (`/install/.aetherflow.state` with `# STATE_VERSION=2`),
//!   atomic key-value configuration persistence (`/install/.aetherflow.conf`), PID lockfile acquisition
//!   (`/var/run/aetherflow-setup.lock`), preflight verification (`os-release`, privilege check, FHS layout),
//!   SHA-256 sidecar config overlays (`<target>.aetherflow-sha256` + `<target>.user-backup.<ts>`), and
//!   explicit `--repair` / `--resume` / `--fresh` / `--dry-run` step orchestration.
//! - Reuses verified Rust primitives (`af-release` FHS layout paths, `af-runner` systemd sandbox drop-in
//!   rendering, and `af-host` path/symlink/SHA-256 helpers).
//! - **Does NOT claim full replacement of `setup/AetherFlow-Setup`**: interactive prompts (`whiptail`),
//!   distro-specific `apt-get` repository bootstrap, kernel BBR/tuned sysctl scripts, and TLS certificate
//!   generation remain owned by the shell bootstrap (`setup/AetherFlow-Setup` & `setup/modules/*.sh`).
//! - **Never accepts or executes arbitrary privileged commands or raw shell step strings.**

mod apache_htpasswd;
mod fs_helpers;
mod lock;
mod overlay;
mod preflight;
mod state;
mod steps;

#[cfg(test)]
mod tests;

pub use apache_htpasswd::provision_apache_htpasswd_if_configured;
pub use fs_helpers::ensure_no_symlink_ancestors;
#[cfg(test)]
pub(crate) use fs_helpers::parse_config_map;
pub use lock::ProvisionLockGuard;
pub use overlay::{safe_overlay_config_file, ConfigOverlayOutcome, ConfigOverlayReceipt};
pub use preflight::{
    is_effective_root_user, parse_and_validate_os_release, run_provision_preflight, OsReleaseInfo,
    ProvisionPreflightReport,
};
pub use state::{ProvisionStateStore, ProvisionStatusReport};
pub use steps::{
    execute_provision_steps, ProvisionRunReport, StepExecutionRecord, StepExecutionStatus,
};

use crate::error::{CliError, CliResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// State file format version matching `setup/modules/06-state.sh` (`# STATE_VERSION=2`).
pub const PROVISION_STATE_VERSION: u32 = 2;

/// Header comment written at line 1 of `/install/.aetherflow.state`.
pub const STATE_VERSION_HEADER: &str = "# STATE_VERSION=2";

/// Canonical ordered setup step IDs from `setup/modules/06-state.sh` (`ALL_STEPS`).
pub const CANONICAL_ALL_STEPS: &[&str] = &[
    "bashrc",
    "intro",
    "checkroot",
    "logcheck",
    "checkkernel",
    "hostname",
    "locale",
    "ssdpblock",
    "askcontinue",
    "askpartition",
    "ask10g",
    "adduser",
    "askffmpeg",
    "askvsftpd",
    "denyhosts",
    "askbbr",
    "repos",
    "updates",
    "depends",
    "syscommands",
    "skel",
    "ffmpeg",
    "apachesudo",
    "build_modern",
    "apacheconf",
    "fix_cert",
    "makedirs",
    "installftpd",
    "ftpdconfig",
    "boot",
    "firewall",
    "harden_perms",
    "perms",
    "bbr",
];

static SAFE_STEP_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-z0-9_]{1,31}$").unwrap());
static SAFE_CONF_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$").unwrap());

/// Execution ownership tier for each canonical provisioning step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionStepTier {
    /// Bounded, idempotent Rust-native step executable directly by `af provision run/repair`.
    RustNativeFoundation,
    /// Retained in `setup/AetherFlow-Setup` (`setup/modules/*.sh`); tracked in `.aetherflow.state`
    /// and inspectable/resettable for `--repair`, but never executed as raw shell by `af-cli`.
    RetainedShellBootstrap,
}

/// Metadata describing one of the canonical provisioning steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionStepDescriptor {
    pub index: usize,
    pub step_id: &'static str,
    pub tier: ProvisionStepTier,
    pub summary: &'static str,
}

/// Returns the descriptor table for all canonical `ALL_STEPS`.
pub fn canonical_step_catalog() -> Vec<ProvisionStepDescriptor> {
    CANONICAL_ALL_STEPS
        .iter()
        .enumerate()
        .map(|(idx, &step_id)| {
            let (tier, summary) = match step_id {
                "bashrc" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Ensure root/.bashrc exists with mode 0640 and /usr/local/bin PATH configuration",
                ),
                "checkroot" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify root/operator execution context and lockfile readiness",
                ),
                "logcheck" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Initialize /install directory and structured install log file",
                ),
                "checkkernel" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify Linux OS release compatibility (Ubuntu 20.04+, Debian 11+, Kali)",
                ),
                "hostname" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Configure system hostname and record HOSTNAME_CONFIGURED in .aetherflow.conf",
                ),
                "locale" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Write etc/default/locale with UTF-8 locale configuration",
                ),
                "skel" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Create canonical skeleton user directories under etc/skel",
                ),
                "apachesudo" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Purge legacy sudoers drop-ins to enforce least-privilege runner boundary",
                ),
                "build_modern" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Ensure /etc/aetherflow/aetherflow.env exists with cryptographic secrets and 0600 permissions",
                ),
                "makedirs" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Create canonical bare-metal FHS directories (/opt/aetherflow, /etc/aetherflow, /var/lib/aetherflow, /var/log/aetherflow)",
                ),
                "boot" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Verify systemd unit directory layout (/etc/systemd/system) and remove any stale aetherflow-api sandbox drop-in",
                ),
                "harden_perms" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Enforce 0750/0600 permissions on /install, /etc/aetherflow, /var/lib/aetherflow, and state/secret files",
                ),
                "perms" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Normalize permissions on /etc/aetherflow/aetherflow.env (0600) and /var/lib/aetherflow (0700)",
                ),
                "bbr" => (
                    ProvisionStepTier::RustNativeFoundation,
                    "Apply BBR congestion control and high-BDP sysctl network tuning",
                ),
                _ => (
                    ProvisionStepTier::RetainedShellBootstrap,
                    "Retained interactive/distro shell bootstrap step in setup/AetherFlow-Setup",
                ),
            };
            ProvisionStepDescriptor {
                index: idx + 1,
                step_id,
                tier,
                summary,
            }
        })
        .collect()
}

/// Returns `true` if `step_id` is in the canonical `ALL_STEPS`.
pub fn is_canonical_step(step_id: &str) -> bool {
    CANONICAL_ALL_STEPS.contains(&step_id)
}

/// Validates a step identifier against injection and verifies membership in `CANONICAL_ALL_STEPS`.
pub fn validate_step_id(step_id: &str) -> CliResult<String> {
    let trimmed = step_id.trim();
    if !SAFE_STEP_ID_RE.is_match(trimmed) {
        return Err(CliError::Validation(format!(
            "invalid provisioning step identifier {:?} (arbitrary commands or shell expressions are forbidden)",
            step_id
        )));
    }
    if !is_canonical_step(trimmed) {
        return Err(CliError::Validation(format!(
            "unknown provisioning step {:?} (run 'af provision list-steps' for the canonical step IDs)",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

/// Filesystem layout for provisioning state, config, lockfile, and FHS directories,
/// parameterized by `fs_root` so all unit tests run in isolated temp directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionPaths {
    pub fs_root: PathBuf,
    pub install_dir: PathBuf,
    pub state_file: PathBuf,
    pub config_file: PathBuf,
    pub install_log: PathBuf,
    pub lock_file: PathBuf,
    pub os_release_file: PathBuf,
    pub opt_aetherflow: PathBuf,
    pub opt_releases: PathBuf,
    pub etc_aetherflow: PathBuf,
    pub etc_legacy_aetherflow: PathBuf,
    pub var_lib_aetherflow: PathBuf,
    pub var_lib_backups: PathBuf,
    pub var_log_aetherflow: PathBuf,
    pub etc_systemd_system: PathBuf,
}

impl ProvisionPaths {
    /// Resolves canonical provisioning paths rooted at `fs_root` (`/` on production hosts).
    pub fn for_root(fs_root: impl Into<PathBuf>) -> CliResult<Self> {
        let root = fs_root.into();
        ensure_no_symlink_ancestors(&root, "provision fs_root")?;

        Ok(Self {
            install_dir: root.join("install"),
            state_file: root.join("install/.aetherflow.state"),
            config_file: root.join("install/.aetherflow.conf"),
            install_log: root.join("install/.aetherflow.install.log"),
            lock_file: root.join("run/aetherflow-setup.lock"),
            os_release_file: root.join("etc/os-release"),
            opt_aetherflow: root.join("opt/AetherFlow"),
            opt_releases: root.join("opt/AetherFlow/releases"),
            etc_aetherflow: root.join("etc/aetherflow"),
            etc_legacy_aetherflow: root.join("etc/AetherFlow"),
            var_lib_aetherflow: root.join("var/lib/aetherflow"),
            var_lib_backups: root.join("var/lib/aetherflow/backups"),
            var_log_aetherflow: root.join("var/log/aetherflow"),
            etc_systemd_system: root.join("etc/systemd/system"),
            fs_root: root,
        })
    }
}
