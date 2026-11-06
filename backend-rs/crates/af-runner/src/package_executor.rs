//! Typed Declarative Package Installation, Update & Removal Engine (`af-runner::package_executor`).
//!
//! Provides a Rust-native, security-bounded marketplace lifecycle engine integrated into
//! `af-runner`'s `/v1/package` stream dispatcher, with automatic fallback to legacy Bash
//! scripts (`packages/package/{install,remove,update}/*`) for recipes not yet migrated.
//!
//! ## Core Design Principles
//! 1. **Conservative Security Boundaries**:
//!    - Zero arbitrary shell evaluation (`bash -c` / `sh -c`) in declarative recipes.
//!    - Strict allowlists for identifiers (`SAFE_PKG_ID`), usernames (`SAFE_USERNAME`),
//!      systemd unit names (`SAFE_SERVICE_NAME`), APT package names (`SAFE_APT_PKG_NAME`),
//!      and managed filesystem prefixes (`/etc/`, `/var/lib/`, `/var/log/`, `/var/run/`, `/opt/`,
//!      `/usr/local/bin/`, `/install/`).
//!    - Path traversal (`..`) and root-level destructive mutations are rejected at validation time.
//! 2. **Dependency & State Locking**:
//!    - Process-wide serialization via `PACKAGE_MUTEX` + cross-process advisory lock file
//!      (`${LOCK_DIR}/.af-package-executor.flock`) + per-package in-flight guard (`ACTIVE_CANCELLATIONS`)
//!      so concurrent Marketplace or CLI requests never collide on `/var/lib/dpkg/lock-frontend`.
//!    - Completion lockfile (`/install/.<pkg>.lock`) is written **only** as the final step of
//!      `install`/`update` after all steps and sandboxing succeed, and removed on `remove`.
//! 3. **Artifact Verification**:
//!    - Remote and local artifacts are verified against minimum size bounds (`min_size_bytes`)
//!      to detect truncated/HTML 404 responses, optional SHA-256 digests (`expected_sha256` or
//!      release `.sha256` sidecars), and archive format magic bytes before extraction/installation.
//! 4. **Structured Progress & Wire Compatibility**:
//!    - Emits structured [`PackageProgressEvent`] values and formats lines as
//!      `[PROGRESS:<pct>] <message>` plus timestamped `[INFO]`/`[WARN]`/`[ERROR]` lines compatible
//!      with both the legacy Go scanner (`backend/services/privileged_runner.go`) and the Rust
//!      `consume_package_output` consumer.
//! 5. **Explicit Failure, Cancellation & Rollback Recovery**:
//!    - Every file mutation (`WriteTemplateFile`, `WriteSystemdUnit`, `InstallBinary`, `ExtractTarGz`)
//!      records a `.bak-af` backup or newly-created path in a [`RollbackJournal`].
//!    - If any step fails or is cancelled via [`cancel_package_execution`], the executor runs
//!      compensating rollback actions in reverse order, restores `.bak-af` backups, removes
//!      newly created files, cleans up temporary artifacts, and preserves the pre-operation lock state.

#[cfg(test)]
#[path = "teardown_regressions.rs"]
mod teardown_regressions;

use crate::{resolve_package_script_path, SAFE_PKG_ID, SAFE_SERVICE_NAME, SAFE_USERNAME};
use af_models::PackageRunnerRequest;
use chrono::Utc;
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tar::Archive;
use crate::legacy_stream_output::BoundedLines;
use tokio::process::Command;

// -----------------------------------------------------------------------------
// Security Allowlists & Validation Constants
// -----------------------------------------------------------------------------

/// Strict Debian/Ubuntu APT package name validator (Debian Policy 5.6.1: lowercase alphanumeric + `+-.`).
pub static SAFE_APT_PKG_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9+.-]{0,127}$").unwrap());

/// Strict GitHub `owner/repo` identifier validator.
pub static SAFE_GITHUB_REPO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$").unwrap());

///// Strict release tag/version validator (`v1.2.3`, `1.46.0`, etc.).
pub static SAFE_VERSION_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$").unwrap());

/// Strict X.509 Distinguished Name subject validator (`/CN=AetherFlow-Quassel`, etc.).
pub static SAFE_TLS_SUBJECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/CN=[A-Za-z0-9_.-]{1,64}(/[A-Za-z]{1,4}=[A-Za-z0-9_.-]{1,64})*$").unwrap()
});

/// Pinned upstream Threadfin release version (`https://github.com/Threadfin/Threadfin/releases/expanded_assets/1.2.37`).
pub const THREADFIN_PINNED_VERSION: &str = "1.2.37";

/// Pinned SHA-256 digest for `Threadfin_linux_amd64_glibc_2.31_compat` (`Threadfin_linux_amd64_compat`) 1.2.37.
pub const THREADFIN_AMD64_COMPAT_SHA256: &str =
    "0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42";

/// Pinned SHA-256 digest for `Threadfin_linux_arm64` 1.2.37.
pub const THREADFIN_ARM64_SHA256: &str =
    "1e5e6f065cf2470d1460fae80c68c9631ca79e67ff76f83d47ab4bcb9ceb6213";

/// Pinned SHA-256 digest for `Threadfin_linux_arm` (armhf) 1.2.37.
pub const THREADFIN_ARMHF_SHA256: &str =
    "d64e6b7f8a1ab8aebdd37d06bfb0bddb991c68c9fed52e25530b92ead10c8328";

/// Secondary upstream SHA-256 digest for plain `Threadfin_linux_amd64` 1.2.37.
pub const THREADFIN_AMD64_PLAIN_SHA256: &str =
    "19183058cf28b0080df059113e546a8e8cac16cae210d13be51bda42af94dfc2";

/// Default Quassel IRC core listen port when no custom `app_port` is requested.
pub const QUASSEL_DEFAULT_LISTEN_PORT: i32 = 4242;

/// Allowed managed prefixes for declarative file writes, creations, and removals.
const ALLOWED_MANAGED_PREFIXES: &[&str] = &[
    "/etc/",
    "/var/lib/",
    "/var/log/",
    "/var/run/",
    "/run/",
    "/opt/",
    "/usr/local/bin/",
    "/install/",
    "/mnt/",
];

/// Forbidden exact paths that must never be removed or overwritten even under managed prefixes.
const FORBIDDEN_EXACT_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/sbin",
    "/etc",
    "/etc/apt",
    "/etc/default",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/fstab",
    "/etc/ssh",
    "/etc/ssh/sshd_config",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/run",
    "/run",
    "/opt",
    "/opt/AetherFlow",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/usr/local/bin",
    "/install",
    "/mnt",
];

/// Shared system directories that must never have recursive ownership (`chown -R`) applied.
const SHARED_SYSTEM_CHOWN_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/sbin",
    "/etc",
    "/etc/apt",
    "/etc/default",
    "/etc/systemd",
    "/etc/systemd/system",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/run",
    "/run",
    "/opt",
    "/opt/AetherFlow",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/usr/local/bin",
    "/install",
    "/mnt",
];

/// Maximum stdout/stderr bytes retained per command execution to prevent unbounded memory growth.
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;

static PROGRESS_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[PROGRESS:(\d{1,3})\]\s*(.*)$").unwrap());
static SSH_PORT_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*Port\s+([0-9]{1,5})\b").unwrap());

// -----------------------------------------------------------------------------
// Public Types & Stable Interfaces (for Runner, CLI & Provisioner)
// -----------------------------------------------------------------------------

/// Supported package lifecycle actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageAction {
    Install,
    Remove,
    Update,
}

impl PackageAction {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_lowercase().as_str() {
            "install" => Some(Self::Install),
            "remove" | "uninstall" => Some(Self::Remove),
            "update" => Some(Self::Update),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Remove => "remove",
            Self::Update => "update",
        }
    }
}

/// Execution mode selected by the runner for a package lifecycle request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEngineMode {
    /// Executed by the typed Rust declarative recipe engine.
    DeclarativeRust,
    /// Executed via legacy Bash script fallback (`packages/package/{install,remove,update}/*`).
    LegacyBashFallback,
}

/// Lifecycle phase reported in structured progress events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Preflight,
    LockAcquire,
    ExecuteStep,
    VerifyArtifact,
    SandboxApply,
    FinalizeLock,
    Rollback,
    Complete,
    Failed,
    Cancelled,
}

/// Structured progress event emitted during package installation, update, or removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageProgressEvent {
    pub package_id: String,
    pub action: PackageAction,
    pub engine: PackageEngineMode,
    pub phase: ExecutionPhase,
    pub step_index: usize,
    pub total_steps: usize,
    pub progress_pct: u8,
    pub message: String,
    pub timestamp: String,
}

impl PackageProgressEvent {
    /// Formats the event as a `[PROGRESS:<pct>] <message>` line compatible with the
    /// existing runner stream and WebSocket progress parsers.
    pub fn to_wire_line(&self) -> String {
        format!("[PROGRESS:{}] {}", self.progress_pct.min(100), self.message)
    }
}

/// Parses a `[PROGRESS:<pct>] <message>` line emitted by either the declarative executor or legacy Bash scripts.
pub fn parse_progress_line(line: &str) -> Option<(u8, String)> {
    let caps = PROGRESS_LINE_RE.captures(line.trim())?;
    let pct: u16 = caps.get(1)?.as_str().parse().ok()?;
    let msg = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
    Some((pct.min(100) as u8, msg.to_string()))
}

/// Structured summary returned upon completion of a package execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageExecutionOutcome {
    pub package_id: String,
    pub action: PackageAction,
    pub engine: PackageEngineMode,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub lock_file_path: PathBuf,
    pub lock_present: bool,
    pub resolved_version: Option<String>,
    pub sandbox_status: Option<String>,
    pub rollback_performed: bool,
    pub logs: Vec<String>,
}

/// Architecture mapping table for multi-arch binary/archive downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchAssetMap {
    pub amd64: String,
    pub arm64: String,
    #[serde(default)]
    pub armhf: Option<String>,
}

impl ArchAssetMap {
    pub fn resolve(&self, deb_arch: &str) -> Option<&str> {
        match deb_arch.trim() {
            "amd64" | "x86_64" => Some(self.amd64.as_str()),
            "arm64" | "aarch64" => Some(self.arm64.as_str()),
            "armhf" | "armv7l" | "arm" => self.armhf.as_deref(),
            _ => None,
        }
    }
}

/// Artifact verification policy enforced before extracting or installing downloaded/staged files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerificationPolicy {
    /// Minimum allowed size in bytes (rejects empty files and small HTML 404/rate-limit pages).
    pub min_size_bytes: u64,
    /// Maximum allowed size in bytes (guards against unbounded disk exhaustion).
    pub max_size_bytes: u64,
    /// Optional pinned hex-encoded SHA-256 digest (architecture-independent or single-arch override).
    #[serde(default)]
    pub expected_sha256: Option<String>,
    /// Optional per-architecture pinned hex-encoded SHA-256 digests (`amd64`, `arm64`, `armhf`).
    #[serde(default)]
    pub arch_sha256: Option<ArchAssetMap>,
    /// Verify gzip magic header (`1f 8b`) before extraction.
    #[serde(default)]
    pub require_gzip_magic: bool,
    /// Verify ELF binary magic header (`7f 45 4c 46`) on extracted/downloaded executables.
    #[serde(default)]
    pub require_elf_magic: bool,
}

impl Default for ArtifactVerificationPolicy {
    fn default() -> Self {
        Self {
            min_size_bytes: 1024,
            max_size_bytes: 512 * 1024 * 1024, // 512 MiB
            expected_sha256: None,
            arch_sha256: None,
            require_gzip_magic: false,
            require_elf_magic: false,
        }
    }
}

/// Typed declarative step (no arbitrary privileged shell strings permitted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DeclarativeStep {
    /// Runs `apt-get update -y -qq` with `DEBIAN_FRONTEND=noninteractive` and `DPkg::Lock::Timeout=120`.
    AptUpdate { progress_pct: u8, description: String },
    /// Runs `apt-get install -y -qq <packages>` with validated package identifiers.
    AptInstall {
        packages: Vec<String>,
        progress_pct: u8,
        description: String,
    },
    AptRemove {
        packages: Vec<String>,
        autoremove: bool,
        ignore_errors: bool,
        progress_pct: u8,
        description: String,
    },
    /// Runs `apt-get purge -y -qq <packages>` and optional `autoremove` (non-fatal on missing packages).
    AptPurge {
        packages: Vec<String>,
        autoremove: bool,
        ignore_errors: bool,
        progress_pct: u8,
        description: String,
    },
    /// Ensures a dedicated locked system user (`useradd --system --user-group --shell /usr/sbin/nologin`) exists.
    EnsureSystemUser {
        username: String,
        home_dir: String,
        create_home: bool,
        progress_pct: u8,
        description: String,
    },
    /// Purges a dedicated non-root system user and group (`userdel`, `groupdel`).
    PurgeSystemUser {
        username: String,
        progress_pct: u8,
        description: String,
    },
    /// Creates managed directories with explicit octal mode and optional ownership.
    EnsureDirectories {
        paths: Vec<String>,
        mode: u32,
        owner: Option<String>,
        group: Option<String>,
        progress_pct: u8,
        description: String,
    },
    /// Probes `/etc/ssh/sshd_config` for a custom `Port <N>` directive and stores `SSH_PORT` in context
    /// (defaulting to `"ssh"` if absent or unreadable).
    ProbeSshPort { progress_pct: u8, description: String },
    /// Generates a self-signed X.509 TLS certificate (`openssl req -x509 -nodes -newkey rsa:4096`)
    /// at a validated managed path with rollback staging and explicit file permissions/ownership.
    GenerateSelfSignedTlsCert {
        cert_path: String,
        #[serde(default)]
        key_out_path: Option<String>,
        days: u32,
        subject: String,
        mode: u32,
        owner: Option<String>,
        group: Option<String>,
        #[serde(default)]
        overwrite: bool,
        progress_pct: u8,
        description: String,
    },
    /// Queries an installed Debian package version via `dpkg-query -W -f=${Version} <package>`,
    /// normalizes epochs/revisions into `VERSION`, and optionally writes a `.af-version` file.
    CaptureDpkgVersion {
        package: String,
        fallback_version: String,
        #[serde(default)]
        version_file_path: Option<String>,
        #[serde(default)]
        owner: Option<String>,
        #[serde(default)]
        group: Option<String>,
        progress_pct: u8,
        description: String,
    },
    EnsureThreadfinConfig { progress_pct: u8, description: String },
    /// Resolves the latest release tag for a GitHub repository (`owner/repo`) with a deterministic fallback version.
    ResolveGitHubReleaseTag {
        repo: String,
        fallback_version: String,
        strip_v_prefix: bool,
        progress_pct: u8,
        description: String,
    },
    /// Downloads an artifact from a URL template, verifies it against [`ArtifactVerificationPolicy`],
    /// and extracts specific binary members from a `.tar.gz` archive into `dest_dir`.
    DownloadAndExtractTarGz {
        url_template: String,
        arch_map: ArchAssetMap,
        dest_dir: String,
        extract_binaries: Vec<String>,
        binary_mode: u32,
        verification: ArtifactVerificationPolicy,
        progress_pct: u8,
        description: String,
    },
    /// Downloads a single binary from a URL template, verifies it against [`ArtifactVerificationPolicy`],
    /// and installs it atomically to `dest_path`.
    DownloadBinary {
        url_template: String,
        arch_map: ArchAssetMap,
        dest_path: String,
        mode: u32,
        verification: ArtifactVerificationPolicy,
        progress_pct: u8,
        description: String,
    },
    /// Writes a configuration or version file from a template string (supporting safe `{{VAR}}` interpolation),
    /// backing up any existing file into `.bak-af` for rollback recovery.
    WriteTemplateFile {
        path: String,
        content_template: String,
        mode: u32,
        overwrite: bool,
        owner: Option<String>,
        group: Option<String>,
        progress_pct: u8,
        description: String,
    },
    /// Writes a systemd unit file under `/etc/systemd/system/<unit>` with rollback backup.
    WriteSystemdUnit {
        unit_name: String,
        content_template: String,
        progress_pct: u8,
        description: String,
    },
    /// Executes a validated `systemctl` lifecycle operation (`daemon-reload`, `enable --now`, `restart`, `stop`, etc.).
    Systemctl {
        unit: Option<String>,
        operation: SystemctlOp,
        ignore_errors: bool,
        progress_pct: u8,
        description: String,
    },
    /// Stops, disables, resets failed state, and removes `/etc/systemd/system/<unit>` and `<unit>.d`.
    PurgeSystemdUnit {
        unit_name: String,
        progress_pct: u8,
        description: String,
    },
    /// Removes managed files and directories (validated against `ALLOWED_MANAGED_PREFIXES` and `FORBIDDEN_EXACT_PATHS`).
    RemovePaths {
        paths: Vec<String>,
        only_if_delete_data: bool,
        progress_pct: u8,
        description: String,
    },
}

/// Allowed `systemctl` operations in declarative recipes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemctlOp {
    DaemonReload,
    EnableNow,
    Enable,
    Start,
    Restart,
    Stop,
    Disable,
    ResetFailed,
}

/// Complete declarative recipe for a marketplace package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarativePackageRecipe {
    pub package_id: String,
    pub label: String,
    pub default_port: i32,
    pub service_name: String,
    pub lock_file: String,
    /// Apply `apply_package_sandbox_local` automatically during install/update before lock finalization.
    pub apply_systemd_sandbox: bool,
    pub install_steps: Vec<DeclarativeStep>,
    /// Optional dedicated update steps; if empty, `update` reuses `install_steps`.
    #[serde(default)]
    pub update_steps: Vec<DeclarativeStep>,
    pub remove_steps: Vec<DeclarativeStep>,
}

impl DeclarativePackageRecipe {
    /// Validates all steps, identifiers, and path boundaries in the recipe before any execution begins.
    pub fn validate(&self) -> Result<(), PackageExecutorError> {
        if !SAFE_PKG_ID.is_match(&self.package_id) || self.package_id.contains("..") {
            return Err(PackageExecutorError::Validation(format!(
                "invalid package_id: {:?}",
                self.package_id
            )));
        }
        if !self.service_name.is_empty()
            && (!SAFE_SERVICE_NAME.is_match(&self.service_name) || self.service_name.contains(".."))
        {
            return Err(PackageExecutorError::Validation(format!(
                "invalid service_name: {:?}",
                self.service_name
            )));
        }
        validate_managed_path(&self.lock_file)?;
        for step in &self.install_steps {
            validate_step(step)?;
        }
        for step in &self.update_steps {
            validate_step(step)?;
        }
        for step in &self.remove_steps {
            validate_step(step)?;
        }
        Ok(())
    }

    pub fn steps_for_action(&self, action: PackageAction) -> &[DeclarativeStep] {
        match action {
            PackageAction::Install => &self.install_steps,
            PackageAction::Update => {
                if self.update_steps.is_empty() {
                    &self.install_steps
                } else {
                    &self.update_steps
                }
            }
            PackageAction::Remove => &self.remove_steps,
        }
    }
}

/// Errors produced by the package executor.
#[derive(Debug, thiserror::Error)]
pub enum PackageExecutorError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("security policy violation: {0}")]
    SecurityViolation(String),
    #[error("dependency lock error: {0}")]
    LockConflict(String),
    #[error("operation cancelled for package '{0}'")]
    Cancelled(String),
    #[error("artifact verification failed: {0}")]
    ArtifactVerification(String),
    #[error("step '{step}' failed: {reason}")]
    StepFailed { step: String, reason: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// -----------------------------------------------------------------------------
// Cancellation Token & Active Job Cancellation Registry
// -----------------------------------------------------------------------------

/// Thread-safe cooperative cancellation token for in-flight package operations.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn check(&self, pkg_id: &str) -> Result<(), PackageExecutorError> {
        if self.is_cancelled() {
            Err(PackageExecutorError::Cancelled(pkg_id.to_string()))
        } else {
            Ok(())
        }
    }
}

static ACTIVE_CANCELLATIONS: Lazy<StdMutex<HashMap<String, CancellationToken>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

/// Registers an active cancellation token for `pkg_id`. Returns `Err(LockConflict)` if
/// the same package already has an in-flight execution registered.
pub fn register_package_cancellation(
    pkg_id: &str,
    token: CancellationToken,
) -> Result<ActiveCancellationGuard, PackageExecutorError> {
    let mut map = ACTIVE_CANCELLATIONS
        .lock()
        .map_err(|_| PackageExecutorError::LockConflict("cancellation registry poisoned".into()))?;
    if map.contains_key(pkg_id) {
        return Err(PackageExecutorError::LockConflict(format!(
            "package '{}' already has an operation in flight",
            pkg_id
        )));
    }
    map.insert(pkg_id.to_string(), token);
    Ok(ActiveCancellationGuard {
        pkg_id: pkg_id.to_string(),
    })
}

/// Requests cooperative cancellation of an in-flight package execution (`install`, `update`, or `remove`).
/// Returns `true` if an active execution was found and signalled.
pub fn cancel_package_execution(pkg_id: &str) -> bool {
    if let Ok(map) = ACTIVE_CANCELLATIONS.lock() {
        if let Some(token) = map.get(pkg_id) {
            token.cancel();
            return true;
        }
    }
    false
}

/// Checks whether a package currently has an active execution registered.
pub fn is_package_execution_active(pkg_id: &str) -> bool {
    ACTIVE_CANCELLATIONS
        .lock()
        .ok()
        .map(|m| m.contains_key(pkg_id))
        .unwrap_or(false)
}

pub struct ActiveCancellationGuard {
    pkg_id: String,
}

impl Drop for ActiveCancellationGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = ACTIVE_CANCELLATIONS.lock() {
            map.remove(&self.pkg_id);
        }
    }
}

// -----------------------------------------------------------------------------
// Pluggable Command Runner (Production OS Commands vs Isolated Test Mock)
// -----------------------------------------------------------------------------

/// Output of an external system command (`apt-get`, `systemctl`, `useradd`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn combined_output(&self) -> String {
        match (self.stdout.trim().is_empty(), self.stderr.trim().is_empty()) {
            (true, true) => String::new(),
            (false, true) => self.stdout.trim().to_string(),
            (true, false) => self.stderr.trim().to_string(),
            (false, false) => format!("{}\n{}", self.stdout.trim(), self.stderr.trim()),
        }
    }
}

/// Recorded command invocation for audit and test verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Abstraction over privileged command execution so tests can run deterministically
/// without mutating the host operating system.
pub trait CommandRunner: Send + Sync {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>> + Send + 'a>,
    >;
}

/// Reads from an async pipe up to `max_bytes`, draining any remaining bytes to EOF
/// so the child process never blocks on a full pipe buffer.
async fn read_pipe_bounded<R: tokio::io::AsyncRead + Unpin>(
    mut reader: Option<R>,
    max_bytes: usize,
) -> String {
    use tokio::io::AsyncReadExt;
    let Some(ref mut r) = reader else {
        return String::new();
    };
    let mut retained = Vec::new();
    let mut truncated = false;
    let mut scratch = [0u8; 4096];
    loop {
        match r.read(&mut scratch).await {
            Ok(0) => break,
            Ok(n) => {
                let remaining = max_bytes.saturating_sub(retained.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    retained.extend_from_slice(&scratch[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    let mut out = String::from_utf8_lossy(&retained).into_owned();
    if truncated {
        out.push_str("\n...[output truncated]");
    }
    out
}

/// Terminates a spawned child and its entire Unix process group (`-pgid`), then reaps the child.
pub(crate) async fn terminate_child_process_group(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        if pid > 0 {
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

/// Production command runner using `tokio::process::Command` with dedicated process group
/// isolation (`process_group(0)`), bounded output retention, and group-wide cancellation termination.
#[derive(Debug, Clone, Default)]
pub struct TokioCommandRunner;

impl CommandRunner for TokioCommandRunner {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(PackageExecutorError::Cancelled(program.to_string()));
            }

            let force_real = env::var("AETHERFLOW_TEST_REAL_COMMAND_RUNNER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let dry_run = env::var("AETHERFLOW_PACKAGE_DRY_RUN")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if (dry_run || !cfg!(target_os = "linux")) && !force_real {
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("[dry-run] {} {}", program, args.join(" ")),
                    stderr: String::new(),
                });
            }

            let mut cmd = Command::new(program);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(unix)]
            cmd.process_group(0);
            for (k, v) in env_vars {
                cmd.env(k, v);
            }

            #[cfg(unix)]
            if let Ok(result) = crate::PACKAGE_MAINTENANCE_LEASE
                .try_with(|guard| guard.preserve_in_child(cmd.as_std_mut()))
            {
                result.map_err(PackageExecutorError::Io)?;
            }

            let mut child = cmd.spawn().map_err(|e| PackageExecutorError::StepFailed {
                step: program.to_string(),
                reason: format!("failed to spawn {}: {}", program, e),
            })?;
            #[cfg(unix)]
            let child_pgid = child.id();

            let stdout_pipe = child.stdout.take();
            let stderr_pipe = child.stderr.take();

            let mut out_task = tokio::spawn(async move {
                read_pipe_bounded(stdout_pipe, MAX_COMMAND_OUTPUT_BYTES).await
            });
            let mut err_task = tokio::spawn(async move {
                read_pipe_bounded(stderr_pipe, MAX_COMMAND_OUTPUT_BYTES).await
            });

            loop {
                tokio::select! {
                    status_res = child.wait() => {
                        let status = status_res.map_err(|e| PackageExecutorError::StepFailed {
                            step: program.to_string(),
                            reason: e.to_string(),
                        })?;
                        // Ensure any background descendants in the process group holding pipes open are reaped
                        let stdout = match tokio::time::timeout(Duration::from_millis(250), &mut out_task).await {
                            Ok(res) => res.unwrap_or_default(),
                            Err(_) => {
                                #[cfg(unix)]
                                if let Some(pid) = child_pgid {
                                    if pid > 0 {
                                        unsafe {
                                            let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                                        }
                                    }
                                }
                                out_task.abort();
                                String::new()
                            }
                        };
                        let stderr = match tokio::time::timeout(Duration::from_millis(250), &mut err_task).await {
                            Ok(res) => res.unwrap_or_default(),
                            Err(_) => {
                                err_task.abort();
                                String::new()
                            }
                        };
                        return Ok(CommandOutput {
                            exit_code: status.code().unwrap_or(if status.success() { 0 } else { 1 }),
                            stdout,
                            stderr,
                        });
                    }
                    _ = tokio::time::sleep(Duration::from_millis(30)) => {
                        if cancel.is_cancelled() {
                            terminate_child_process_group(&mut child).await;
                            out_task.abort();
                            err_task.abort();
                            let _ = out_task.await;
                            let _ = err_task.await;
                            return Err(PackageExecutorError::Cancelled(program.to_string()));
                        }
                    }
                }
            }
        })
    }
}

// -----------------------------------------------------------------------------
// Execution Environment & Path Sandboxing
// -----------------------------------------------------------------------------

/// Execution context and filesystem root configuration for [`DeclarativePackageExecutor`].
#[derive(Debug, Clone)]
pub struct PackageExecutionEnv {
    pub lifecycle_job_id: String,
    /// Optional root prefix for isolated testing (`AETHERFLOW_FS_ROOT`). Empty/`/` in production.
    pub fs_root: Option<PathBuf>,
    /// Directory for package lock files (`/install` by default).
    pub lock_dir: PathBuf,
    /// Directory for package installer logs (`/var/log/aetherflow` by default).
    pub log_dir: PathBuf,
    /// Temporary download/staging directory (`/tmp` by default).
    pub temp_dir: PathBuf,
    /// Override architecture (`amd64`, `arm64`, `armhf`) or auto-detected at runtime.
    pub arch_override: Option<String>,
    /// Allocated application port (`1024..=65535` or `0`).
    pub app_port: i32,
    /// Whether `DELETE_DATA=true` is enabled during `remove`.
    pub delete_data: bool,
    /// Optional local artifact override directory (`AETHERFLOW_ARTIFACT_CACHE_DIR`) for offline/airgapped or test runs.
    pub artifact_cache_dir: Option<PathBuf>,
}

impl Default for PackageExecutionEnv {
    fn default() -> Self {
        let fs_root = env::var("AETHERFLOW_FS_ROOT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let lock_dir = env::var("LOCK_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/install"));
        let log_dir = PathBuf::from("/var/log/aetherflow");
        let temp_dir = env::temp_dir();
        let delete_data = env::var("DELETE_DATA")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let artifact_cache_dir = env::var("AETHERFLOW_ARTIFACT_CACHE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);

        Self {
            lifecycle_job_id: crate::current_package_job_id(),
            fs_root,
            lock_dir,
            log_dir,
            temp_dir,
            arch_override: None,
            app_port: 0,
            delete_data,
            artifact_cache_dir,
        }
    }
}

impl PackageExecutionEnv {
    /// Creates an isolated execution environment rooted inside `root` (for unit/integration tests).
    pub fn isolated(root: &Path) -> Self {
        Self {
            lifecycle_job_id: String::new(),
            fs_root: Some(root.to_path_buf()),
            lock_dir: PathBuf::from("/install"),
            log_dir: PathBuf::from("/var/log/aetherflow"),
            temp_dir: root.join("tmp"),
            arch_override: Some("amd64".to_string()),
            app_port: 0,
            delete_data: false,
            artifact_cache_dir: Some(root.join("artifacts")),
        }
    }

    /// Resolves a managed logical path (`/etc/fail2ban/jail.local`) into a concrete host/test path,
    /// verifying all existing ancestor components with `lstat` to reject symlink traversal.
    pub fn resolve_path(&self, logical_path: &str) -> Result<PathBuf, PackageExecutorError> {
        validate_managed_path(logical_path)?;
        let resolved = if let Some(ref root) = self.fs_root {
            let rel = logical_path.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical_path)
        };
        validate_filesystem_path(&resolved, self.fs_root.as_deref())?;
        Ok(resolved)
    }

    /// Resolves a read-only system path (such as `/etc/ssh/sshd_config`) respecting `fs_root`.
    pub fn resolve_readonly_path(&self, logical_path: &str) -> PathBuf {
        if let Some(ref root) = self.fs_root {
            let rel = logical_path.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical_path)
        }
    }

    /// Resolves the package completion lockfile (`/install/.<pkg>.lock`).
    pub fn resolve_lock_file(&self, recipe: &DeclarativePackageRecipe) -> Result<PathBuf, PackageExecutorError> {
        if !recipe.lock_file.trim().is_empty() {
            self.resolve_path(&recipe.lock_file)
        } else {
            let lock_logical = format!(
                "{}/.{}.lock",
                self.lock_dir.to_string_lossy().trim_end_matches('/'),
                recipe.package_id
            );
            self.resolve_path(&lock_logical)
        }
    }

    /// Resolves the per-operation log file (`/var/log/aetherflow/<action>-<pkg>.log`).
    pub fn resolve_log_file(&self, action: PackageAction, pkg_id: &str) -> Result<PathBuf, PackageExecutorError> {
        let prefix = match action {
            PackageAction::Install | PackageAction::Update => "install",
            PackageAction::Remove => "remove",
        };
        let logical = format!(
            "{}/{}-{}.log",
            self.log_dir.to_string_lossy().trim_end_matches('/'),
            prefix,
            pkg_id
        );
        self.resolve_path(&logical)
    }

    pub fn effective_arch(&self) -> String {
        if let Some(ref a) = self.arch_override {
            return a.clone();
        }
        match env::consts::ARCH {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            "arm" => "armhf".to_string(),
            other => other.to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Security Validation Helpers
// -----------------------------------------------------------------------------

/// Validates that `logical_path` is an absolute Unix path without parent traversal (`..`),
/// NUL bytes, or shell metacharacters, and resides inside `ALLOWED_MANAGED_PREFIXES`
/// while not matching `FORBIDDEN_EXACT_PATHS`.
pub fn validate_managed_path(logical_path: &str) -> Result<(), PackageExecutorError> {
    let trimmed = logical_path.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path must be absolute: {:?}",
            logical_path
        )));
    }
    if trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('$')
        || trimmed.contains('`')
        || trimmed.contains(';')
    {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path contains forbidden control or shell characters: {:?}",
            logical_path
        )));
    }
    let normalized = trimmed.trim_end_matches('/');
    let check_exact = if normalized.is_empty() { "/" } else { normalized };
    if FORBIDDEN_EXACT_PATHS.contains(&check_exact) {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to mutate protected system path: {:?}",
            logical_path
        )));
    }

    let path = Path::new(trimmed);
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "path traversal '..' is forbidden: {:?}",
                logical_path
            )));
        }
    }

    if !ALLOWED_MANAGED_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "path {:?} is outside allowed managed prefixes {:?}",
            logical_path, ALLOWED_MANAGED_PREFIXES
        )));
    }

    Ok(())
}

/// Validates that a concrete filesystem path and all of its ancestors (from `root_bound` when set,
/// or from the filesystem/temp root) are free of symlinks and unexpected `lstat` errors.
pub fn validate_filesystem_path(
    target: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_path_ancestors_with_lstat(target, root_bound, |p| {
        fs::symlink_metadata(p).map(|m| m.file_type().is_symlink())
    })
}

pub(crate) fn validate_path_ancestors_with_lstat<F>(
    target: &Path,
    root_bound: Option<&Path>,
    mut is_symlink_lstat: F,
) -> Result<(), PackageExecutorError>
where
    F: FnMut(&Path) -> std::io::Result<bool>,
{
    if target.as_os_str().is_empty() {
        return Err(PackageExecutorError::SecurityViolation(
            "empty filesystem path is forbidden".into(),
        ));
    }
    for comp in target.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "path traversal '..' is forbidden in concrete path: {}",
                target.display()
            )));
        }
    }

    let mut check_one = |p: &Path| -> Result<(), PackageExecutorError> {
        match is_symlink_lstat(p) {
            Ok(true) => Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to traverse or mutate symlink path component: {}",
                p.display()
            ))),
            Ok(false) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(PackageExecutorError::Io(err)),
        }
    };

    if let Some(root) = root_bound {
        for comp in root.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "isolated root contains parent traversal: {}",
                    root.display()
                )));
            }
        }
        let rel = target.strip_prefix(root).map_err(|_| {
            PackageExecutorError::SecurityViolation(format!(
                "concrete path {} escaped isolated root {}",
                target.display(),
                root.display()
            ))
        })?;
        let mut ancestor = PathBuf::new();
        for component in root.components() {
            ancestor.push(component.as_os_str());
            check_one(&ancestor)?;
        }
        let mut cursor = root.to_path_buf();
        for comp in rel.components() {
            if let Component::Normal(part) = comp {
                cursor.push(part);
                check_one(&cursor)?;
            }
        }
        return Ok(());
    }

    let mut cursor = PathBuf::new();
    for comp in target.components() {
        match comp {
            Component::Prefix(p) => cursor.push(p.as_os_str()),
            Component::RootDir => cursor.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => {
                cursor.push(part);
                check_one(&cursor)?;
            }
            Component::ParentDir => {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "path traversal '..' is forbidden: {}",
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

/// Validates that a directory path is safe for ownership change (`chown`) and is not a shared system root.
pub fn validate_chown_target_path(logical_path: &str) -> Result<(), PackageExecutorError> {
    validate_managed_path(logical_path)?;
    let normalized = logical_path.trim().trim_end_matches('/');
    let check_exact = if normalized.is_empty() { "/" } else { normalized };
    if SHARED_SYSTEM_CHOWN_PATHS.contains(&check_exact) {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to chown shared system directory: {:?}",
            logical_path
        )));
    }
    Ok(())
}

fn validate_step(step: &DeclarativeStep) -> Result<(), PackageExecutorError> {
    match step {
        DeclarativeStep::AptUpdate { .. } => Ok(()),
        DeclarativeStep::AptInstall { packages, .. }
        | DeclarativeStep::AptRemove { packages, .. }
        | DeclarativeStep::AptPurge { packages, .. } => {
            if packages.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "APT step requires at least one package".into(),
                ));
            }
            for pkg in packages {
                if !SAFE_APT_PKG_NAME.is_match(pkg) {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid APT package name: {:?}",
                        pkg
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::EnsureSystemUser {
            username, home_dir, ..
        } => {
            if !SAFE_USERNAME.is_match(username) || username == "root" || username == "www-data" {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "disallowed system username: {:?}",
                    username
                )));
            }
            validate_chown_target_path(home_dir)
        }
        DeclarativeStep::PurgeSystemUser { username, .. } => {
            if !SAFE_USERNAME.is_match(username) || username == "root" || username == "www-data" {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "disallowed system username for purge: {:?}",
                    username
                )));
            }
            Ok(())
        }
        DeclarativeStep::EnsureDirectories {
            paths,
            owner,
            group,
            ..
        } => {
            if paths.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "EnsureDirectories requires at least one path".into(),
                ));
            }
            let has_ownership = owner.is_some() || group.is_some();
            for p in paths {
                validate_managed_path(p)?;
                if has_ownership {
                    validate_chown_target_path(p)?;
                }
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::ProbeSshPort { .. }
        | DeclarativeStep::EnsureThreadfinConfig { .. } => Ok(()),
        DeclarativeStep::GenerateSelfSignedTlsCert {
            cert_path,
            key_out_path,
            days,
            subject,
            owner,
            group,
            ..
        } => {
            validate_managed_path(cert_path)?;
            if let Some(ref kp) = key_out_path {
                validate_managed_path(kp)?;
            }
            if *days == 0 || *days > 36500 {
                return Err(PackageExecutorError::Validation(format!(
                    "TLS certificate validity days must be in 1..=36500, got {}",
                    days
                )));
            }
            if !SAFE_TLS_SUBJECT.is_match(subject) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid TLS X.509 subject: {:?}",
                    subject
                )));
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::CaptureDpkgVersion {
            package,
            fallback_version,
            version_file_path,
            owner,
            group,
            ..
        } => {
            if !SAFE_APT_PKG_NAME.is_match(package) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid dpkg package name: {:?}",
                    package
                )));
            }
            if !SAFE_VERSION_TAG.is_match(fallback_version) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid fallback version tag: {:?}",
                    fallback_version
                )));
            }
            if let Some(ref vp) = version_file_path {
                validate_managed_path(vp)?;
            }
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::ResolveGitHubReleaseTag {
            repo,
            fallback_version,
            ..
        } => {
            if !SAFE_GITHUB_REPO.is_match(repo) {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid GitHub repository identifier: {:?}",
                    repo
                )));
            }
            if !SAFE_VERSION_TAG.is_match(fallback_version) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid fallback version tag: {:?}",
                    fallback_version
                )));
            }
            Ok(())
        }
        DeclarativeStep::DownloadAndExtractTarGz {
            url_template,
            dest_dir,
            extract_binaries,
            ..
        } => {
            if !url_template.starts_with("https://") && !url_template.starts_with("file://") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "artifact download URL must use https:// (or file:// in tests): {:?}",
                    url_template
                )));
            }
            validate_managed_path(dest_dir)?;
            if extract_binaries.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "DownloadAndExtractTarGz requires at least one binary member name".into(),
                ));
            }
            for bin in extract_binaries {
                if !SAFE_PKG_ID.is_match(bin) || bin.contains('/') || bin.contains("..") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid binary member name: {:?}",
                        bin
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::DownloadBinary {
            url_template,
            dest_path,
            ..
        } => {
            if !url_template.starts_with("https://") && !url_template.starts_with("file://") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "binary download URL must use https:// (or file:// in tests): {:?}",
                    url_template
                )));
            }
            validate_managed_path(dest_path)
        }
        DeclarativeStep::WriteTemplateFile {
            path, owner, group, ..
        } => {
            validate_managed_path(path)?;
            if let Some(o) = owner {
                if !SAFE_USERNAME.is_match(o) && o != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid owner username: {:?}",
                        o
                    )));
                }
            }
            if let Some(g) = group {
                if !SAFE_USERNAME.is_match(g) && g != "root" {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid group name: {:?}",
                        g
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::WriteSystemdUnit { unit_name, .. }
        | DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
            let norm = normalize_unit_filename(unit_name);
            if !SAFE_SERVICE_NAME.is_match(&norm) || norm.contains("..") {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "invalid systemd unit name: {:?}",
                    unit_name
                )));
            }
            Ok(())
        }
        DeclarativeStep::Systemctl {
            unit, operation, ..
        } => {
            if *operation != SystemctlOp::DaemonReload {
                let Some(u) = unit else {
                    return Err(PackageExecutorError::Validation(format!(
                        "systemctl {:?} requires a unit name",
                        operation
                    )));
                };
                if !SAFE_SERVICE_NAME.is_match(u) || u.contains("..") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "invalid systemctl unit name: {:?}",
                        u
                    )));
                }
            }
            Ok(())
        }
        DeclarativeStep::RemovePaths { paths, .. } => {
            if paths.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RemovePaths requires at least one path".into(),
                ));
            }
            for p in paths {
                validate_managed_path(p)?;
            }
            Ok(())
        }
    }
}

fn normalize_unit_filename(unit: &str) -> String {
    let trimmed = unit.trim();
    if trimmed.ends_with(".service") || trimmed.ends_with(".timer") || trimmed.ends_with(".socket")
    {
        trimmed.to_string()
    } else {
        format!("{}.service", trimmed)
    }
}

// -----------------------------------------------------------------------------
// Artifact Verification Engine
// -----------------------------------------------------------------------------

/// Verifies that an ELF header's `e_machine` field (if populated with a known architecture constant)
/// matches `expected_arch` (`amd64`, `arm64`, or `armhf`).
pub fn verify_elf_header_architecture(
    header: &[u8],
    expected_arch: &str,
    artifact_label: &str,
) -> Result<(), PackageExecutorError> {
    if header.len() < 20 || header[..4] != [0x7f, b'E', b'L', b'F'] {
        return Ok(());
    }
    let is_big_endian = header[5] == 2;
    let e_machine = if is_big_endian {
        u16::from_be_bytes([header[18], header[19]])
    } else {
        u16::from_le_bytes([header[18], header[19]])
    };
    let actual_arch = match e_machine {
        62 => Some("amd64"),  // EM_X86_64
        183 => Some("arm64"), // EM_AARCH64
        40 => Some("armhf"),  // EM_ARM
        3 => Some("i386"),    // EM_386
        243 => Some("riscv64"), // EM_RISCV
        _ => None,
    };
    if let Some(actual) = actual_arch {
        let norm_expected = match expected_arch.trim() {
            "x86_64" | "amd64" => "amd64",
            "aarch64" | "arm64" => "arm64",
            "armv7l" | "arm" | "armhf" => "armhf",
            other => other,
        };
        if actual != norm_expected {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "ELF architecture mismatch for {}: binary header is '{}' (e_machine=0x{:04x}) but target architecture is '{}'",
                artifact_label, actual, e_machine, norm_expected
            )));
        }
    }
    Ok(())
}

/// Verifies a downloaded or staged artifact file against size bounds, optional SHA-256 digest,
/// and magic header signatures. Returns the computed lowercase hex SHA-256 digest.
pub fn verify_artifact_file(
    path: &Path,
    policy: &ArtifactVerificationPolicy,
) -> Result<String, PackageExecutorError> {
    verify_artifact_file_for_arch(path, policy, None)
}

/// Verifies a downloaded or staged artifact file against size bounds, architecture-specific or
/// global SHA-256 digest, and magic/ELF architecture header signatures.
pub fn verify_artifact_file_for_arch(
    path: &Path,
    policy: &ArtifactVerificationPolicy,
    target_arch: Option<&str>,
) -> Result<String, PackageExecutorError> {
    let meta = fs::metadata(path).map_err(|e| {
        PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is missing or unreadable: {}",
            path.display(),
            e
        ))
    })?;
    if !meta.is_file() {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is not a regular file",
            path.display()
        )));
    }
    let len = meta.len();
    if len < policy.min_size_bytes {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} is too small ({} bytes < minimum {} bytes; possible 404 or truncated download)",
            path.display(),
            len,
            policy.min_size_bytes
        )));
    }
    if policy.max_size_bytes > 0 && len > policy.max_size_bytes {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} exceeds maximum size ({} bytes > {} bytes)",
            path.display(),
            len,
            policy.max_size_bytes
        )));
    }

    let mut file = File::open(path)?;
    let mut header = [0u8; 20];
    let head_read = file.read(&mut header)?;

    if policy.require_gzip_magic && (head_read < 2 || header[0] != 0x1f || header[1] != 0x8b) {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} does not have a valid gzip header (0x1f8b)",
            path.display()
        )));
    }
    if policy.require_elf_magic && (head_read < 4 || header[..4] != [0x7f, b'E', b'L', b'F']) {
        return Err(PackageExecutorError::ArtifactVerification(format!(
            "artifact {} does not have a valid ELF executable header (0x7f454c46)",
            path.display()
        )));
    }
    if policy.require_elf_magic {
        if let Some(arch) = target_arch {
            verify_elf_header_architecture(&header[..head_read], arch, &path.display().to_string())?;
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(&header[..head_read]);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hex::encode(hasher.finalize());

    let expected_opt: Option<&str> = if let Some(ref expected) = policy.expected_sha256 {
        Some(expected.as_str())
    } else if let (Some(ref arch_map), Some(arch)) = (&policy.arch_sha256, target_arch) {
        Some(arch_map.resolve(arch).ok_or_else(|| {
            PackageExecutorError::ArtifactVerification(format!(
                "no pinned SHA-256 digest configured for architecture '{}' on {}",
                arch,
                path.display()
            ))
        })?)
    } else {
        None
    };

    if let Some(expected_raw) = expected_opt {
        let allowed_digests: Vec<String> = expected_raw
            .split('|')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty() && s != "skip")
            .collect();
        if !allowed_digests.is_empty() && !allowed_digests.iter().any(|d| d == &digest) {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "SHA-256 mismatch for {}: expected {}, got {}",
                path.display(),
                allowed_digests.join(" or "),
                digest
            )));
        }
    }

    Ok(digest)
}

// -----------------------------------------------------------------------------
// Rollback Journal & Compensating Recovery
// -----------------------------------------------------------------------------

#[derive(Debug)]
enum RollbackEntry {
    /// A file that existed before the execution and was backed up to `<path>.bak-af`.
    RestorableFile {
        target: PathBuf,
        backup: PathBuf,
        ownership: Option<(u32, u32)>,
    },
    /// A file that did not exist before the execution and should be removed on failure/cancellation.
    CreatedFile {
        target: PathBuf,
    },
    /// A systemd unit that was newly written and should be stopped/disabled/removed on rollback.
    CreatedSystemdUnit {
        unit_name: String,
        unit_path: PathBuf,
    },
}

/// Tracks mutations performed during an install/update/remove transaction so that failures
/// or cancellations cleanly restore modified files and remove partial artifacts.
#[derive(Debug, Default)]
struct RollbackJournal {
    entries: Vec<RollbackEntry>,
    temp_files: Vec<PathBuf>,
    fs_root: Option<PathBuf>,
}

impl RollbackJournal {
    fn new(fs_root: Option<PathBuf>) -> Self {
        Self { fs_root, ..Self::default() }
    }

    /// Prepares a file for mutation: validates all ancestors against symlinks, and if `target`
    /// already exists as a regular file, copies it once to `<target>.bak-af`; otherwise records
    /// it as a newly created file.
    fn stage_file_mutation(&mut self, target: &Path) -> Result<(), PackageExecutorError> {
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
                            { None }
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

    fn record_created_systemd_unit(&mut self, unit_name: &str, unit_path: &Path) {
        self.entries.push(RollbackEntry::CreatedSystemdUnit {
            unit_name: unit_name.to_string(),
            unit_path: unit_path.to_path_buf(),
        });
    }

    fn track_temp_file(&mut self, path: PathBuf) {
        self.temp_files.push(path);
    }

    fn cleanup_temp_files(&mut self) {
        for tmp in self.temp_files.drain(..) {
            if validate_filesystem_path(&tmp, self.fs_root.as_deref()).is_ok() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }

    /// Commits the transaction: removes `.bak-af` backup files and temporary downloads.
    fn commit(&mut self) {
        self.cleanup_temp_files();
        for entry in self.entries.drain(..) {
            if let RollbackEntry::RestorableFile { backup, .. } = entry {
                if validate_filesystem_path(&backup, self.fs_root.as_deref()).is_ok() {
                    let _ = fs::remove_file(backup);
                }
            }
        }
    }

    /// Rolls back all staged mutations in reverse order, validating all ancestor paths before
    /// restoring backups or unlinking created files.
    async fn rollback<R: CommandRunner>(&mut self, runner: &R) -> Vec<String> {
        let mut notes = Vec::new();
        self.cleanup_temp_files();
        let noop_cancel = CancellationToken::new();

        while let Some(entry) = self.entries.pop() {
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
                    if let Err(err) = validate_filesystem_path(&unit_path, self.fs_root.as_deref()) {
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
                RollbackEntry::RestorableFile { target, backup, ownership } => {
                    if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref())
                        .and_then(|_| validate_filesystem_path(&backup, self.fs_root.as_deref()))
                    {
                        notes.push(format!(
                            "skipped unsafe backup restore for {}: {}",
                            target.display(),
                            err
                        ));
                        continue;
                    }
                    if backup.is_file() {
                        if let Some((owner_uid, owner_gid)) = ownership {
                            let result = runner.run_command(
                                "chown",
                                &[format!("{}:{}", owner_uid, owner_gid), backup.to_string_lossy().to_string()],
                                &[],
                                &noop_cancel,
                            ).await;
                            if !matches!(result, Ok(output) if output.success()) {
                                notes.push(format!("failed to restore ownership for {}", target.display()));
                                continue;
                            }
                        }
                        if fs::rename(&backup, &target).is_err() {
                            let _ = fs::copy(&backup, &target);
                            let _ = fs::remove_file(&backup);
                        }
                        notes.push(format!("restored backup for {}", target.display()));
                    }
                }
                RollbackEntry::CreatedFile { target } => {
                    if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref()) {
                        notes.push(format!(
                            "skipped unsafe rollback removal for {}: {}",
                            target.display(),
                            err
                        ));
                        continue;
                    }
                    if target.is_file() {
                        let _ = fs::remove_file(&target);
                        notes.push(format!("removed newly created file {}", target.display()));
                    }
                }
            }
        }
        notes
    }
}

fn backup_path_for(target: &Path) -> PathBuf {
    let mut os = target.as_os_str().to_os_string();
    os.push(format!(".bak-af.{}", uuid::Uuid::new_v4()));
    PathBuf::from(os)
}

/// Writes `content` atomically to `target` via a sibling `.tmp.<uuid>` file and applies permissions,
/// verifying all ancestor components against symlinks before and after directory creation.
#[cfg(test)]
fn write_file_atomic_with_mode(
    target: &Path,
    content: &[u8],
    mode: u32,
) -> Result<(), PackageExecutorError> {
    write_file_atomic_with_mode_bounded(target, content, mode, None)
}

fn write_file_atomic_with_mode_bounded(
    target: &Path,
    content: &[u8],
    mode: u32,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(target, root_bound)?;
    if let Some(parent) = target.parent() {
        validate_filesystem_path(parent, root_bound)?;
        fs::create_dir_all(parent)?;
        validate_filesystem_path(parent, root_bound)?;
    }
    validate_filesystem_path(target, root_bound)?;

    let filename = target.file_name().and_then(|value| value.to_str()).unwrap_or("artifact");
    let temporary = target.with_file_name(format!(".{}.af-tmp-{}", filename, uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), PackageExecutorError> {
        let mut file = open_new_private_file(&temporary, mode)?;
        file.write_all(content)?;
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

fn open_new_private_file(path: &Path, mode: u32) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

fn set_path_mode(path: &Path, _mode: u32) {
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
    lock_file_path: PathBuf,
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
            fs::create_dir_all(parent)?;
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

        Ok(Self {
            lock_file_path: flock_path,
            _file: Some(file),
        })
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

    #[allow(dead_code)]
    pub(crate) fn lock_file_path(&self) -> &Path {
        &self.lock_file_path
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

// -----------------------------------------------------------------------------
// Built-In Verified Declarative Recipe Registry
// -----------------------------------------------------------------------------

/// Registry of native Rust declarative recipes that have passed full parity and security verification.
static BUILTIN_DECLARATIVE_RECIPES: Lazy<HashMap<String, DeclarativePackageRecipe>> =
    Lazy::new(|| {
        let mut map = HashMap::new();
        for recipe in [
            build_fail2ban_recipe(),
            build_quassel_recipe(),
            build_threadfin_recipe(),
            build_znc_recipe(),
            build_xrdp_recipe(),
            build_novnc_recipe(),
            build_x2go_recipe(),
            build_prometheus_recipe(),
            build_netdata_recipe(),
            build_mergerfs_recipe(),
            build_rclone_recipe(),
            build_syncthing_recipe(),
        ] {
            recipe
                .validate()
                .expect("built-in declarative package recipe failed validation");
            map.insert(recipe.package_id.clone(), recipe);
        }
        map
    });

/// Returns the built-in declarative recipe for `pkg_id`, if that package has been migrated
/// and verified for full parity. Unported or deferred recipes return `None` and automatically
/// fall back to the legacy Bash scripts in `packages/package/{install,remove,update}/*`.
pub fn get_declarative_recipe(pkg_id: &str) -> Option<DeclarativePackageRecipe> {
    BUILTIN_DECLARATIVE_RECIPES
        .get(pkg_id.trim().to_lowercase().as_str())
        .cloned()
}

/// Lists all package IDs currently supported by the native Rust declarative executor.
pub fn list_declarative_recipe_ids() -> Vec<String> {
    let mut ids: Vec<String> = BUILTIN_DECLARATIVE_RECIPES.keys().cloned().collect();
    ids.sort();
    ids
}

/// Pure helper evaluating engine selection given explicit gate flags (`rust_enabled`, `force_bash`).
pub fn select_package_engine_with_flags(
    pkg_id: &str,
    rust_enabled: bool,
    force_bash: bool,
) -> PackageEngineMode {
    if rust_enabled && !force_bash && get_declarative_recipe(pkg_id).is_some() {
        PackageEngineMode::DeclarativeRust
    } else {
        PackageEngineMode::LegacyBashFallback
    }
}

/// Determines whether `pkg_id` will execute via [`PackageEngineMode::DeclarativeRust`] or
/// [`PackageEngineMode::LegacyBashFallback`].
///
/// Default gate: `AETHERFLOW_ENABLE_RUST_PACKAGES` defaults to OFF (`false`).
/// Override gate: `AETHERFLOW_FORCE_BASH_PACKAGES=1` forces all packages through legacy Bash scripts.
pub fn select_package_engine(pkg_id: &str) -> PackageEngineMode {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    select_package_engine_with_flags(pkg_id, rust_enabled, force_bash)
}

fn build_fail2ban_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 20,
            description: "Updating APT package indexes for Fail2ban...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "fail2ban".to_string(),
                "python3-systemd".to_string(),
                "iptables".to_string(),
            ],
            progress_pct: 40,
            description: "Installing fail2ban and python3-systemd backend...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "fail2ban".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::ProbeSshPort {
            progress_pct: 55,
            description: "Inspecting /etc/ssh/sshd_config for active SSH port...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/fail2ban".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 60,
            description: "Configuring /etc/fail2ban/jail.local...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/fail2ban/jail.local".to_string(),
            content_template: "[DEFAULT]\nbantime  = 1h\nfindtime = 10m\nmaxretry = 5\nbackend  = systemd\n\n[sshd]\nenabled = true\nport    = {{SSH_PORT}},ssh\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: None,
            group: None,
            progress_pct: 70,
            description: "Writing systemd-backed sshd jail configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 80,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("fail2ban.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 85,
            description: "Starting and enabling fail2ban.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("fail2ban.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 95,
            description: "Verifying fail2ban.service restart...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "fail2ban".to_string(),
        label: "Fail2ban".to_string(),
        default_port: 0,
        service_name: "fail2ban".to_string(),
        lock_file: "/install/.fail2ban.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::AptRemove {
                packages: vec!["fail2ban".to_string()],
                autoremove: false,
                ignore_errors: false,
                progress_pct: 20,
                description: "Removing fail2ban APT package (purging only with DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "fail2ban.service".to_string(),
                progress_pct: 55,
                description: "Stopping and disabling fail2ban.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/fail2ban".to_string(),
                    "/var/lib/fail2ban".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 80,
                description: "Purging Fail2ban configuration and state only with DELETE_DATA=true...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/run/fail2ban".to_string()],
                only_if_delete_data: false,
                progress_pct: 85,
                description: "Removing Fail2ban runtime directory...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Fail2ban removal...".to_string(),
            },
        ],
    }
}

fn build_quassel_recipe() -> DeclarativePackageRecipe {
    DeclarativePackageRecipe {
        package_id: "quassel".to_string(),
        label: "Quassel".to_string(),
        default_port: 0,
        service_name: "quasselcore".to_string(),
        lock_file: "/install/.quassel.lock".to_string(),
        apply_systemd_sandbox: true,
        install_steps: vec![
            DeclarativeStep::AptUpdate {
                progress_pct: 15,
                description: "Updating APT package indexes for Quassel Core...".to_string(),
            },
            DeclarativeStep::AptInstall {
                packages: vec!["openssl".to_string()],
                progress_pct: 25,
                description: "Installing OpenSSL before provisioning Quassel credentials...".to_string(),
            },
            DeclarativeStep::EnsureSystemUser {
                username: "quasselcore".to_string(),
                home_dir: "/var/lib/quassel".to_string(),
                create_home: false,
                progress_pct: 35,
                description: "Ensuring dedicated quasselcore system user...".to_string(),
            },
            DeclarativeStep::EnsureDirectories {
                paths: vec![
                    "/var/lib/quassel".to_string(),
                    "/var/log/quassel".to_string(),
                ],
                mode: 0o750,
                owner: Some("quasselcore".to_string()),
                group: Some("quasselcore".to_string()),
                progress_pct: 45,
                description: "Configuring Quassel data and log directories...".to_string(),
            },
            DeclarativeStep::GenerateSelfSignedTlsCert {
                cert_path: "/var/lib/quassel/quasselCert.pem".to_string(),
                key_out_path: None,
                subject: "/CN=quassel.aether.local".to_string(),
                days: 3650,
                mode: 0o600,
                owner: Some("quasselcore".to_string()),
                group: Some("quasselcore".to_string()),
                overwrite: false,
                progress_pct: 55,
                description: "Ensuring Quassel TLS certificate (/var/lib/quassel/quasselCert.pem)...".to_string(),
            },
            DeclarativeStep::WriteTemplateFile {
                path: "/etc/default/quasselcore".to_string(),
                content_template: "LISTEN=\"0.0.0.0\"\nPORT=\"{{LISTEN_PORT}}\"\nCONFIGDIR=\"/var/lib/quassel\"\nLOGFILE=\"/var/log/quassel/quasselcore.log\"\nLOGLEVEL=\"Info\"\n".to_string(),
                mode: 0o644,
                overwrite: true,
                owner: None,
                group: None,
                progress_pct: 65,
                description: "Writing /etc/default/quasselcore daemon defaults...".to_string(),
            },
            DeclarativeStep::AptInstall {
                packages: vec!["quassel-core".to_string()],
                progress_pct: 75,
                description: "Installing quassel-core with preserved TLS credentials and configured defaults...".to_string(),
            },
            DeclarativeStep::CaptureDpkgVersion {
                package: "quassel-core".to_string(),
                fallback_version: "0.14.0".to_string(),
                version_file_path: Some("/var/lib/quassel/.af-version".to_string()),
                owner: Some("quasselcore".to_string()),
                group: Some("quasselcore".to_string()),
                progress_pct: 80,
                description: "Capturing installed quassel-core dpkg version...".to_string(),
            },
            DeclarativeStep::WriteSystemdUnit {
                unit_name: "quasselcore.service".to_string(),
                content_template: "[Unit]\nDescription=Quassel Core IRC Bouncer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=quasselcore\nGroup=quasselcore\nEnvironmentFile=-/etc/default/quasselcore\nExecStart=/usr/bin/quasselcore --configdir=/var/lib/quassel --listen=0.0.0.0 --port={{LISTEN_PORT}}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
                progress_pct: 85,
                description: "Writing quasselcore.service systemd unit...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: false,
                progress_pct: 90,
                description: "Reloading systemd manager configuration...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: Some("quasselcore.service".to_string()),
                operation: SystemctlOp::EnableNow,
                ignore_errors: false,
                progress_pct: 93,
                description: "Enabling and starting quasselcore.service...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: Some("quasselcore.service".to_string()),
                operation: SystemctlOp::Restart,
                ignore_errors: false,
                progress_pct: 96,
                description: "Restarting quasselcore.service with active configuration...".to_string(),
            },
        ],
        update_steps: Vec::new(),
        remove_steps: vec![
            DeclarativeStep::AptRemove {
                packages: vec!["quassel-core".to_string(), "quassel-data".to_string()],
                autoremove: false,
                ignore_errors: false,
                progress_pct: 25,
                description: "Removing quassel-core APT package (purging only with DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "quasselcore.service".to_string(),
                progress_pct: 55,
                description: "Stopping and disabling quasselcore.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/default/quasselcore".to_string(),
                    "/var/lib/quassel/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 75,
                description: "Removing Quassel runtime metadata files...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/quassel".to_string(),
                    "/var/log/quassel".to_string(),
                    "/var/log/quasselcore.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Conditionally purging Quassel SQLite database and TLS certificate (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Quassel removal...".to_string(),
            },
        ],
    }
}

fn build_threadfin_recipe() -> DeclarativePackageRecipe {
    DeclarativePackageRecipe {
        package_id: "threadfin".to_string(),
        label: "Threadfin".to_string(),
        default_port: 34400,
        service_name: "threadfin".to_string(),
        lock_file: "/install/.threadfin.lock".to_string(),
        apply_systemd_sandbox: true,
        install_steps: vec![
            DeclarativeStep::AptUpdate {
                progress_pct: 10,
                description: "Updating APT package indexes for Threadfin...".to_string(),
            },
            DeclarativeStep::AptInstall {
                packages: vec![
                    "curl".to_string(),
                    "wget".to_string(),
                    "ca-certificates".to_string(),
                    "ffmpeg".to_string(),
                    "vlc-bin".to_string(),
                ],
                progress_pct: 22,
                description: "Installing Threadfin prerequisites (curl, wget, ca-certificates, ffmpeg, vlc-bin)...".to_string(),
            },
            DeclarativeStep::EnsureSystemUser {
                username: "threadfin".to_string(),
                home_dir: "/var/lib/threadfin".to_string(),
                create_home: true,
                progress_pct: 32,
                description: "Ensuring dedicated threadfin system user...".to_string(),
            },
            DeclarativeStep::EnsureDirectories {
                paths: vec![
                    "/opt/threadfin".to_string(),
                    "/var/lib/threadfin".to_string(),
                    "/var/lib/threadfin/conf".to_string(),
                    "/var/lib/threadfin/temp".to_string(),
                ],
                mode: 0o750,
                owner: Some("threadfin".to_string()),
                group: Some("threadfin".to_string()),
                progress_pct: 42,
                description: "Creating /var/lib/threadfin state and configuration directories...".to_string(),
            },
            DeclarativeStep::DownloadBinary {
                url_template: format!(
                    "https://github.com/Threadfin/Threadfin/releases/download/{}/{{{{ARCH_ASSET}}}}",
                    THREADFIN_PINNED_VERSION
                ),
                arch_map: ArchAssetMap {
                    amd64: "Threadfin_linux_amd64_glibc_2.31_compat".to_string(),
                    arm64: "Threadfin_linux_arm64".to_string(),
                    armhf: Some("Threadfin_linux_arm".to_string()),
                },
                dest_path: "/usr/local/bin/threadfin".to_string(),
                mode: 0o755,
                verification: ArtifactVerificationPolicy {
                    min_size_bytes: 1024,
                    max_size_bytes: 128 * 1024 * 1024,
                    expected_sha256: None,
                    arch_sha256: Some(ArchAssetMap {
                        amd64: format!(
                            "{}|{}",
                            THREADFIN_AMD64_COMPAT_SHA256, THREADFIN_AMD64_PLAIN_SHA256
                        ),
                        arm64: THREADFIN_ARM64_SHA256.to_string(),
                        armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
                    }),
                    require_gzip_magic: false,
                    require_elf_magic: true,
                },
                progress_pct: 65,
                description: format!(
                    "Downloading and verifying pinned Threadfin {} binary...",
                    THREADFIN_PINNED_VERSION
                ),
            },
            DeclarativeStep::WriteTemplateFile {
                path: "/var/lib/threadfin/.af-version".to_string(),
                content_template: format!("{}\n", THREADFIN_PINNED_VERSION),
                mode: 0o644,
                overwrite: true,
                owner: Some("threadfin".to_string()),
                group: Some("threadfin".to_string()),
                progress_pct: 75,
                description: "Writing /var/lib/threadfin/.af-version metadata...".to_string(),
            },
            DeclarativeStep::WriteSystemdUnit {
                unit_name: "threadfin.service".to_string(),
                content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind=0.0.0.0 -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
                progress_pct: 84,
                description: "Writing /etc/systemd/system/threadfin.service...".to_string(),
            },
            DeclarativeStep::EnsureThreadfinConfig {
                progress_pct: 87,
                description: "Ensuring Threadfin has a loopback bind default without replacing user settings...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: false,
                progress_pct: 90,
                description: "Reloading systemd manager configuration...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: Some("threadfin.service".to_string()),
                operation: SystemctlOp::EnableNow,
                ignore_errors: false,
                progress_pct: 95,
                description: "Enabling and starting threadfin.service...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: Some("threadfin.service".to_string()),
                operation: SystemctlOp::Restart,
                ignore_errors: false,
                progress_pct: 98,
                description: "Restarting threadfin.service to apply the verified binary and configuration...".to_string(),
            },
        ],
        update_steps: Vec::new(),
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "threadfin.service".to_string(),
                progress_pct: 25,
                description: "Stopping, disabling, and removing threadfin.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/usr/local/bin/threadfin".to_string(),
                    "/opt/threadfin".to_string(),
                    "/var/lib/threadfin/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 55,
                description: "Removing /usr/local/bin/threadfin binary and version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/threadfin".to_string()],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Conditionally removing /var/lib/threadfin state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "threadfin".to_string(),
                progress_pct: 85,
                description: "Removing threadfin system user and group...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Threadfin removal...".to_string(),
            },
        ],
    }
}

fn build_znc_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for ZNC...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["znc".to_string()],
            progress_pct: 35,
            description: "Installing znc APT package...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "znc".to_string(),
            home_dir: "/var/lib/znc".to_string(),
            create_home: true,
            progress_pct: 45,
            description: "Ensuring dedicated znc system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/znc".to_string(),
                "/var/lib/znc/configs".to_string(),
            ],
            mode: 0o750,
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 55,
            description: "Preparing /var/lib/znc configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "znc".to_string(),
            fallback_version: "1.9.1".to_string(),
            version_file_path: Some("/var/lib/znc/.af-version".to_string()),
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 65,
            description: "Capturing installed znc dpkg version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/znc/configs/znc.conf".to_string(),
            content_template: "Version = {{VERSION}}\n<Listener l>\n    Port = {{APP_PORT}}\n    IPv4 = true\n    IPv6 = false\n    SSL = false\n    Host = 127.0.0.1\n</Listener>\nLoadModule = webadmin\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 75,
            description: "Writing /var/lib/znc/configs/znc.conf...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "znc.service".to_string(),
            content_template: "[Unit]\nDescription=ZNC, an advanced IRC bouncer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=znc\nGroup=znc\nExecStart=/usr/bin/znc -f --datadir=/var/lib/znc\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing znc.service systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 88,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("znc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting znc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("znc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting znc.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "znc".to_string(),
        label: "ZNC".to_string(),
        default_port: 6501,
        service_name: "znc".to_string(),
        lock_file: "/install/.znc.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "znc.service".to_string(),
                progress_pct: 20,
                description: "Stopping and disabling znc.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["znc".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging znc APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/znc".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /var/lib/znc data directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "znc".to_string(),
                progress_pct: 88,
                description: "Removing znc system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after ZNC removal...".to_string(),
            },
        ],
    }
}

fn build_xrdp_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for XRDP...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "xrdp".to_string(),
                "dbus-x11".to_string(),
                "xfce4".to_string(),
                "xfce4-goodies".to_string(),
                "xorgxrdp".to_string(),
            ],
            progress_pct: 50,
            description: "Installing xrdp, dbus-x11, and XFCE4 session packages...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "xrdp".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/xrdp".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Ensuring /etc/xrdp configuration directory...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/xrdp/startwm.sh".to_string(),
            content_template: "#!/bin/sh\nif [ -r /etc/default/locale ]; then\n  . /etc/default/locale\n  export LANG LANGUAGE\nfi\nunset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR\nexec startxfce4\n".to_string(),
            mode: 0o755,
            overwrite: true,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/xrdp/startwm.sh session startup script...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 84,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 90,
            description: "Enabling and starting xrdp.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting xrdp.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "xrdp".to_string(),
        label: "XRDP".to_string(),
        default_port: 0,
        service_name: "xrdp".to_string(),
        lock_file: "/install/.xrdp.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "xrdp.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling xrdp.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["xrdp".to_string(), "xorgxrdp".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging xrdp APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/xrdp".to_string(),
                    "/var/log/xrdp.log".to_string(),
                    "/var/log/xrdp-sesman.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing XRDP configuration and logs...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after XRDP removal...".to_string(),
            },
        ],
    }
}

fn build_novnc_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for noVNC...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "novnc".to_string(),
                "websockify".to_string(),
                "tigervnc-standalone-server".to_string(),
                "dbus-x11".to_string(),
                "xfce4".to_string(),
            ],
            progress_pct: 50,
            description: "Installing novnc, websockify, tigervnc-standalone-server, and dbus-x11...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "novnc".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/var/lib/novnc".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Ensuring /var/lib/novnc state directory...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow noVNC Websockify Proxy\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/websockify --web=/usr/share/novnc/ 127.0.0.1:{{APP_PORT}} 127.0.0.1:5901\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 78,
            description: "Writing novnc.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting novnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting novnc.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "novnc".to_string(),
        label: "noVNC".to_string(),
        default_port: 6080,
        service_name: "novnc".to_string(),
        lock_file: "/install/.novnc.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc.service".to_string(),
                progress_pct: 25,
                description: "Stopping and removing novnc.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "novnc".to_string(),
                    "websockify".to_string(),
                    "tigervnc-standalone-server".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging novnc and websockify APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/novnc".to_string()],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing /var/lib/novnc state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after noVNC removal...".to_string(),
            },
        ],
    }
}

fn build_x2go_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for X2Go...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "x2goserver".to_string(),
                "x2goserver-xsession".to_string(),
                "xfce4".to_string(),
                "dbus-x11".to_string(),
            ],
            progress_pct: 55,
            description: "Installing x2goserver and x2goserver-xsession...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "x2goserver".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/x2go".to_string(), "/var/lib/x2go".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 70,
            description: "Ensuring /etc/x2go and /var/lib/x2go directories...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 82,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("x2goserver.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 90,
            description: "Enabling and starting x2goserver.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("x2goserver.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting x2goserver.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "x2go".to_string(),
        label: "X2Go".to_string(),
        default_port: 0,
        service_name: "x2goserver".to_string(),
        lock_file: "/install/.x2go.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "x2goserver.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling x2goserver.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "x2goserver".to_string(),
                    "x2goserver-xsession".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging x2goserver APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/x2go".to_string(), "/var/lib/x2go".to_string()],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing X2Go state directories (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after X2Go removal...".to_string(),
            },
        ],
    }
}

fn build_prometheus_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Prometheus...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["prometheus".to_string()],
            progress_pct: 45,
            description: "Installing prometheus APT package...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "prometheus".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/prometheus".to_string(),
                "/var/lib/prometheus".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 60,
            description: "Ensuring /etc/prometheus and /var/lib/prometheus directories...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/default/prometheus".to_string(),
            content_template: "ARGS=\"--web.listen-address=127.0.0.1:{{APP_PORT}} --storage.tsdb.path=/var/lib/prometheus/metrics2 --config.file=/etc/prometheus/prometheus.yml\"\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: None,
            group: None,
            progress_pct: 70,
            description: "Writing /etc/default/prometheus listen configuration...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/prometheus/prometheus.yml".to_string(),
            content_template: "global:\n  scrape_interval: 15s\n  evaluation_interval: 15s\n\nscrape_configs:\n  - job_name: 'prometheus'\n    static_configs:\n      - targets: ['127.0.0.1:{{APP_PORT}}']\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 78,
            description: "Ensuring /etc/prometheus/prometheus.yml scrape config...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting prometheus.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting prometheus.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "prometheus".to_string(),
        label: "Prometheus".to_string(),
        default_port: 9090,
        service_name: "prometheus".to_string(),
        lock_file: "/install/.prometheus.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "prometheus.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling prometheus.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["prometheus".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging prometheus APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/prometheus".to_string(),
                    "/etc/default/prometheus".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Removing Prometheus configuration files...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/prometheus".to_string()],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing Prometheus TSDB data (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Prometheus removal...".to_string(),
            },
        ],
    }
}

fn build_netdata_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Netdata...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["netdata".to_string()],
            progress_pct: 45,
            description: "Installing netdata APT package...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "netdata".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/netdata".to_string(),
                "/var/lib/netdata".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 60,
            description: "Ensuring /etc/netdata and /var/lib/netdata directories...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/netdata/netdata.conf".to_string(),
            content_template: "[global]\n    run as user = netdata\n\n[web]\n    bind to = 127.0.0.1\n    default port = {{APP_PORT}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/netdata/netdata.conf bound to 127.0.0.1:{{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("netdata.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting netdata.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("netdata.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting netdata.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "netdata".to_string(),
        label: "Netdata".to_string(),
        default_port: 19999,
        service_name: "netdata".to_string(),
        lock_file: "/install/.netdata.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "netdata.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling netdata.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["netdata".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging netdata APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/netdata".to_string()],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Removing /etc/netdata configuration...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/netdata".to_string(),
                    "/var/log/netdata".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing Netdata state and logs (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Netdata removal...".to_string(),
            },
        ],
    }
}

fn build_mergerfs_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for MergerFS...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["mergerfs".to_string(), "fuse3".to_string()],
            progress_pct: 45,
            description: "Installing mergerfs and fuse3...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "mergerfs".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/mnt/mergerfs".to_string(),
                "/mnt/local".to_string(),
                "/mnt/remote".to_string(),
                "/mnt/unionfs".to_string(),
                "/etc/mergerfs".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Ensuring /mnt/mergerfs and union mount directories...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/mergerfs/mergerfs.conf".to_string(),
            content_template: "BRANCHES=\"/mnt/local=RW:/mnt/remote=NC\"\nMOUNTPOINT=\"/mnt/mergerfs\"\nOPTIONS=\"defaults,allow_other,use_ino,category.create=ff,moveonenospc=true,dropcacheonclose=true\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/mergerfs/mergerfs.conf...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "mergerfs.service".to_string(),
            content_template: "[Unit]\nDescription=MergerFS Union Filesystem Mount\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironmentFile=-/etc/mergerfs/mergerfs.conf\nExecStart=/usr/bin/mergerfs -o defaults,allow_other,use_ino /mnt/local:/mnt/remote /mnt/mergerfs\nExecStop=/bin/fusermount -uz /mnt/mergerfs\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing mergerfs.service systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 90,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("mergerfs.service".to_string()),
            operation: SystemctlOp::Enable,
            ignore_errors: false,
            progress_pct: 96,
            description: "Enabling mergerfs.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "mergerfs".to_string(),
        label: "MergerFS".to_string(),
        default_port: 0,
        service_name: "mergerfs".to_string(),
        lock_file: "/install/.mergerfs.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "mergerfs.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling mergerfs.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["mergerfs".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging mergerfs APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/mergerfs".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /etc/mergerfs configuration...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/mnt/mergerfs".to_string()],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing /mnt/mergerfs mount directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after MergerFS removal...".to_string(),
            },
        ],
    }
}

fn build_rclone_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Rclone...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["rclone".to_string(), "fuse3".to_string()],
            progress_pct: 40,
            description: "Installing rclone and fuse3...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "rclone".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "rclone".to_string(),
            home_dir: "/var/lib/rclone".to_string(),
            create_home: false,
            progress_pct: 50,
            description: "Ensuring dedicated rclone system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/rclone".to_string(),
                "/etc/rclone".to_string(),
            ],
            mode: 0o750,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 60,
            description: "Ensuring /var/lib/rclone and /etc/rclone directories...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/rclone/rclone.conf".to_string(),
            content_template: "# AetherFlow managed rclone configuration\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 70,
            description: "Ensuring /etc/rclone/rclone.conf exists...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone RC Web GUI Service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=rclone\nGroup=rclone\nWorkingDirectory=/var/lib/rclone\nExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --config=/etc/rclone/rclone.conf\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 80,
            description: "Writing rclone.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 86,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("rclone.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting rclone.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("rclone.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting rclone.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "rclone".to_string(),
        label: "Rclone".to_string(),
        default_port: 5572,
        service_name: "rclone".to_string(),
        lock_file: "/install/.rclone.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "rclone.service".to_string(),
                progress_pct: 25,
                description: "Stopping and removing rclone.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["rclone".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging rclone APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/rclone".to_string(), "/var/lib/rclone".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing Rclone state directories (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "rclone".to_string(),
                progress_pct: 88,
                description: "Removing rclone system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Rclone removal...".to_string(),
            },
        ],
    }
}

fn build_syncthing_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Syncthing...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "syncthing".to_string(),
                "ca-certificates".to_string(),
                "curl".to_string(),
            ],
            progress_pct: 40,
            description: "Installing syncthing APT package...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "syncthing".to_string(),
            fallback_version: "unknown".to_string(),
            version_file_path: None,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "syncthing".to_string(),
            home_dir: "/var/lib/syncthing".to_string(),
            create_home: true,
            progress_pct: 52,
            description: "Ensuring dedicated syncthing system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/syncthing".to_string(),
                "/var/lib/syncthing/.config".to_string(),
                "/var/lib/syncthing/.config/syncthing".to_string(),
            ],
            mode: 0o750,
            owner: Some("syncthing".to_string()),
            group: Some("syncthing".to_string()),
            progress_pct: 65,
            description: "Preparing /var/lib/syncthing configuration directories...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "syncthing.service".to_string(),
            content_template: "[Unit]\nDescription=Syncthing - Open Source Continuous File Synchronization\nAfter=network.target\n\n[Service]\nUser=syncthing\nGroup=syncthing\nWorkingDirectory=/var/lib/syncthing\nExecStart=/usr/bin/syncthing serve --no-browser --no-restart --gui-address=127.0.0.1:{{APP_PORT}} --home=/var/lib/syncthing/.config/syncthing\nRestart=on-failure\nRestartSec=5\nSuccessExitStatus=3 4\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 78,
            description: "Writing syncthing.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("syncthing.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting syncthing.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("syncthing.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting syncthing.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "syncthing".to_string(),
        label: "Syncthing".to_string(),
        default_port: 8384,
        service_name: "syncthing".to_string(),
        lock_file: "/install/.syncthing.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "syncthing.service".to_string(),
                progress_pct: 25,
                description: "Stopping and removing syncthing.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["syncthing".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging syncthing APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/syncthing".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /var/lib/syncthing state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "syncthing".to_string(),
                progress_pct: 88,
                description: "Removing syncthing system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Syncthing removal...".to_string(),
            },
        ],
    }
}

// -----------------------------------------------------------------------------
// Declarative Package Executor Implementation
// -----------------------------------------------------------------------------

/// Typed declarative marketplace package executor.
pub struct DeclarativePackageExecutor<R: CommandRunner = TokioCommandRunner> {
    pub env_cfg: PackageExecutionEnv,
    pub runner: R,
}

impl DeclarativePackageExecutor<TokioCommandRunner> {
    pub fn new(env_cfg: PackageExecutionEnv) -> Self {
        Self {
            env_cfg,
            runner: TokioCommandRunner,
        }
    }
}

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub fn with_runner(env_cfg: PackageExecutionEnv, runner: R) -> Self {
        Self { env_cfg, runner }
    }

    async fn apply_recipe_sandbox(
        &self,
        package_id: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        let systemd_root = self.env_cfg.fs_root.as_ref()
            .map(|root| root.join("etc/systemd/system"))
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
        let status = apply_sandbox_in_root_with_journal(
            package_id, &systemd_root, Some(journal), self.env_cfg.fs_root.as_deref(),
        )?;
        let output = self.runner.run_command("systemctl", &["daemon-reload".to_string()], &[], cancel).await?;
        if !output.success() {
            return Err(PackageExecutorError::StepFailed {
                step: "apply_systemd_sandbox".to_string(), reason: output.combined_output(),
            });
        }
        Ok(status)
    }

    async fn apply_file_metadata(
        &self,
        path: &Path,
        mode: u32,
        owner: Option<&str>,
        group: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        validate_filesystem_path(path, self.env_cfg.fs_root.as_deref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        if let (None, Some(owner_name)) = (self.env_cfg.fs_root.as_ref(), owner) {
                let group_name = group.unwrap_or(owner_name);
                let output = self.runner.run_command("chown", &[
                    format!("{}:{}", owner_name, group_name), path.to_string_lossy().to_string(),
                ], &[], cancel).await?;
                if !output.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apply_file_metadata".to_string(), reason: output.combined_output(),
                    });
                }
        }
        Ok(())
    }

    /// Executes a declarative package recipe for `action` (`Install`, `Update`, or `Remove`),
    /// emitting structured [`PackageProgressEvent`] notifications to `on_progress`.
    pub async fn execute_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        recipe.validate()?;
        cancel.check(&recipe.package_id)?;

        drop(
            crate::acquire_package_maintenance_guard(
                self.env_cfg.fs_root.as_deref(),
                af_release::lifecycle::ReservationTarget::Package(&recipe.package_id),
                &self.env_cfg.lifecycle_job_id,
                Some(action.as_str()),
            )
            .await
            .map_err(|error| PackageExecutorError::LockConflict(error.to_string()))?,
        );

        // Register in-flight cancellation guard BEFORE waiting on process/file locks
        // (rejects duplicate concurrent action on the same package ID immediately).
        let _cancel_guard = register_package_cancellation(&recipe.package_id, cancel.clone())?;

        // Acquire process-wide mutex + cross-process flock with cancellation awareness
        let _proc_lock = acquire_package_mutex_with_cancel(&recipe.package_id, &cancel).await?;
        let _flock_guard =
            CrossProcessLockGuard::acquire_with_cancel(&self.env_cfg, &recipe.package_id, &cancel)
                .await?;

        let _maintenance_guard = crate::acquire_package_maintenance_guard(
            self.env_cfg.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&recipe.package_id),
            &self.env_cfg.lifecycle_job_id,
            Some(action.as_str()),
        )
        .await
        .map_err(|e| PackageExecutorError::LockConflict(e.to_string()))?;

        crate::PACKAGE_MAINTENANCE_LEASE
            .scope(
                Arc::new(_maintenance_guard),
                self.execute_reserved_recipe(recipe, action, cancel, on_progress),
            )
            .await
    }

    async fn execute_reserved_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        mut on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        let steps = recipe.steps_for_action(action);
        let total_steps = steps.len();
        let lock_file_path = self.env_cfg.resolve_lock_file(recipe)?;
        let log_file_path = self
            .env_cfg
            .resolve_log_file(action, &recipe.package_id)?;
        if let Some(parent) = log_file_path.parent() {
            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
            let _ = fs::create_dir_all(parent);
        }

        let mut logs = Vec::new();
        let mut journal = RollbackJournal::new(self.env_cfg.fs_root.clone());

        let effective_port = if (1024..=65535).contains(&self.env_cfg.app_port) {
            self.env_cfg.app_port
        } else {
            recipe.default_port
        };
        let listen_port = if (1024..=65535).contains(&effective_port) {
            effective_port
        } else if recipe.package_id == "quassel" {
            env::var("AF_QUASSEL_PORT")
                .or_else(|_| env::var("AF_APP_PORT"))
                .or_else(|_| env::var("AETHERFLOW_APP_PORT"))
                .ok()
                .and_then(|v| v.trim().parse::<i32>().ok())
                .filter(|p| (1024..=65535).contains(p))
                .unwrap_or(QUASSEL_DEFAULT_LISTEN_PORT)
        } else {
            effective_port
        };
        let initial_version = if recipe.package_id == "threadfin" {
            THREADFIN_PINNED_VERSION.to_string()
        } else {
            "unknown".to_string()
        };

        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("PACKAGE_ID".to_string(), recipe.package_id.clone());
        vars.insert("APP_NAME".to_string(), recipe.package_id.clone());
        vars.insert("APP_LABEL".to_string(), recipe.label.clone());
        vars.insert("APP_PORT".to_string(), effective_port.to_string());
        vars.insert("LISTEN_PORT".to_string(), listen_port.to_string());
        vars.insert("SSH_PORT".to_string(), "ssh".to_string());
        vars.insert("VERSION".to_string(), initial_version.clone());
        vars.insert(
            "TAG".to_string(),
            if initial_version == "unknown" {
                "unknown".to_string()
            } else {
                format!("v{}", initial_version)
            },
        );
        vars.insert("ARCH".to_string(), self.env_cfg.effective_arch());

        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::LockAcquire,
            0,
            total_steps,
            5,
            format!(
                "Starting declarative {} for {} ({})",
                action.as_str(),
                recipe.label,
                recipe.package_id
            ),
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        let mut completed_steps = 0usize;
        let mut exec_err: Option<PackageExecutorError> = None;
        let mut sandbox_status = None;
        let should_apply_sandbox =
            matches!(action, PackageAction::Install | PackageAction::Update)
                && recipe.apply_systemd_sandbox;
        let mut sandbox_applied = false;

        if action == PackageAction::Remove {
            let mut units = vec![normalize_unit_filename(&recipe.service_name)];
            for step in steps {
                match step {
                    DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                        units.push(normalize_unit_filename(unit_name));
                    }
                    DeclarativeStep::Systemctl {
                        unit: Some(unit),
                        operation: SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed,
                        ..
                    } => units.push(normalize_unit_filename(unit)),
                    _ => {}
                }
            }
            units.sort_by_key(|unit| {
                (!unit.ends_with(".timer") && !unit.ends_with(".socket"), unit.clone())
            });
            units.dedup();
            for unit in &units {
                if let Err(error) = self.teardown_systemctl("stop", unit, &cancel).await {
                    exec_err = Some(error);
                    break;
                }
            }
            if exec_err.is_none() {
                for unit in &units {
                    if let Err(error) = self.teardown_systemctl("disable", unit, &cancel).await {
                        exec_err = Some(error);
                        break;
                    }
                }
            }
        }

        for (idx, step) in steps.iter().enumerate() {
            if exec_err.is_some() {
                break;
            }
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
                break;
            }

            // Apply systemd sandbox drop-in BEFORE systemctl reloads/enables/starts/restarts
            // the native service so the service never runs unsandboxed.
            if should_apply_sandbox
                && !sandbox_applied
                && matches!(
                    step,
                    DeclarativeStep::AptInstall { .. }
                    | DeclarativeStep::Systemctl {
                        operation: SystemctlOp::DaemonReload
                            | SystemctlOp::EnableNow
                            | SystemctlOp::Enable
                            | SystemctlOp::Start
                            | SystemctlOp::Restart,
                        ..
                    }
                )
            {
                let (step_pct, _) = step_progress_meta(step);
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    step_pct.saturating_sub(1).max(5),
                    format!(
                        "Applying systemd security sandbox profile for {} before service activation...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => {
                        sandbox_status = Some(st);
                        sandbox_applied = true;
                    }
                    Err(err) => {
                        exec_err = Some(err);
                        break;
                    }
                }
            }

            let (pct, desc) = step_progress_meta(step);
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::ExecuteStep,
                idx + 1,
                total_steps,
                pct,
                desc.to_string(),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );

            match self
                .run_single_step(recipe, step, &mut vars, &mut journal, &cancel)
                .await
            {
                Ok(step_note) => {
                    if !step_note.is_empty() {
                        append_log_line(&log_file_path, &format!("[INFO] {}", step_note));
                        logs.push(format!("[INFO] {}", step_note));
                    }
                    completed_steps += 1;
                }
                Err(err) => {
                    exec_err = Some(err);
                    break;
                }
            }
        }

        // Fallback: if no systemctl activation step was present in the recipe, apply sandbox after steps
        if exec_err.is_none() && should_apply_sandbox && !sandbox_applied {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            } else {
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    97,
                    format!(
                        "Applying systemd security sandbox profile for {}...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => sandbox_status = Some(st),
                    Err(err) => {
                        exec_err = Some(err);
                    }
                }
            }
        }

        if exec_err.is_none() {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            }
        }

        // Handle failure or cancellation -> run compensating rollback
        if let Some(err) = exec_err {
            let phase = match err {
                PackageExecutorError::Cancelled(_) => ExecutionPhase::Cancelled,
                _ => ExecutionPhase::Failed,
            };
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::Rollback,
                completed_steps,
                total_steps,
                98,
                format!(
                    "Rolling back partial {} state for {}: {}",
                    action.as_str(),
                    recipe.package_id,
                    err
                ),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            let rb_notes = journal.rollback(&self.runner).await;
            for note in rb_notes {
                append_log_line(&log_file_path, &format!("[WARN] [rollback] {}", note));
                logs.push(format!("[WARN] [rollback] {}", note));
            }
            if action == PackageAction::Remove {
                append_log_line(&log_file_path, "[WARN] Removal incomplete; installed marker retained. Retry removal to reconcile package state.");
            }
            self.emit_event(
                &recipe.package_id,
                action,
                phase,
                completed_steps,
                total_steps,
                99,
                format!("Package {} {} failed: {}", recipe.package_id, action.as_str(), err),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            return Err(err);
        }

        // Finalize lockfile ONLY after all steps and sandboxing have succeeded
        journal.commit();
        match action {
            PackageAction::Install | PackageAction::Update => {
                validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                if let Some(parent) = lock_file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let lock_payload = format!(
                    "package={}\nversion={}\nupdated_at={}\nengine=declarative_rust\n",
                    recipe.package_id,
                    vars.get("VERSION").cloned().unwrap_or_default(),
                    Utc::now().to_rfc3339()
                );
                write_file_atomic_with_mode_bounded(
                    &lock_file_path,
                    lock_payload.as_bytes(),
                    0o644,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                if self.env_cfg.fs_root.is_none() {
                    trigger_certbot_sync_best_effort(&recipe.package_id);
                }
            }
            PackageAction::Remove => {
                validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                match fs::remove_file(&lock_file_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }

        let done_msg = match action {
            PackageAction::Install => format!("{} installed successfully.", recipe.label),
            PackageAction::Update => format!("{} updated successfully.", recipe.label),
            PackageAction::Remove => format!("{} completely removed.", recipe.label),
        };
        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::Complete,
            completed_steps,
            total_steps,
            100,
            done_msg,
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        Ok(PackageExecutionOutcome {
            package_id: recipe.package_id.clone(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            completed_steps,
            total_steps,
            lock_present: lock_file_path.exists(),
            lock_file_path,
            resolved_version: vars.get("VERSION").cloned(),
            sandbox_status,
            rollback_performed: false,
            logs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_event<F>(
        &self,
        pkg_id: &str,
        action: PackageAction,
        phase: ExecutionPhase,
        step_index: usize,
        total_steps: usize,
        progress_pct: u8,
        message: String,
        log_file_path: &Path,
        logs: &mut Vec<String>,
        on_progress: &mut F,
    ) where
        F: FnMut(PackageProgressEvent),
    {
        let event = PackageProgressEvent {
            package_id: pkg_id.to_string(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            phase,
            step_index,
            total_steps,
            progress_pct: progress_pct.min(100),
            message,
            timestamp: Utc::now().to_rfc3339(),
        };
        let wire_line = event.to_wire_line();
        append_log_line(log_file_path, &wire_line);
        logs.push(wire_line);
        on_progress(event);
    }

    async fn teardown_systemctl(
        &self,
        operation: &str,
        unit: &str,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        let output = self.runner.run_command(
            "systemctl",
            &[operation.to_string(), "--".to_string(), unit.to_string()],
            &[],
            cancel,
        ).await?;
        if output.success() {
            return Ok(());
        }
        let state = self.runner.run_command(
            "systemctl",
            &[
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--property=ActiveState".to_string(),
                "--".to_string(),
                unit.to_string(),
            ],
            &[],
            cancel,
        ).await?;
        let load_state = state.stdout.lines()
            .find_map(|line| line.strip_prefix("LoadState="));
        let active_state = state.stdout.lines()
            .find_map(|line| line.strip_prefix("ActiveState="));
        let known_inactive = state.success()
            && active_state == Some("inactive")
            && matches!(load_state, Some("loaded" | "masked" | "not-found"));
        if known_inactive && (operation == "stop" || load_state == Some("not-found")) {
            return Ok(());
        }
        Err(PackageExecutorError::StepFailed {
            step: format!("systemctl_{operation}"),
            reason: format!(
                "systemctl {operation} {unit} exited with {}: {}; teardown state unproven: {}",
                output.exit_code, output.combined_output(), state.combined_output()
            ),
        })
    }

    async fn run_single_step(
        &self,
        recipe: &DeclarativePackageRecipe,
        step: &DeclarativeStep,
        vars: &mut HashMap<String, String>,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        cancel.check(&recipe.package_id)?;
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];

        match step {
            DeclarativeStep::AptUpdate { .. } => {
                let args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "update".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_update".to_string(),
                        reason: format!(
                            "apt-get update exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok("apt-get update completed".to_string())
            }

            DeclarativeStep::AptInstall { packages, .. } => {
                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confdef".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confold".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                args.extend(packages.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_install".to_string(),
                        reason: format!(
                            "apt-get install {:?} exited with {}: {}",
                            packages,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok(format!("installed APT packages: {}", packages.join(", ")))
            }

            DeclarativeStep::AptRemove {
                packages,
                autoremove,
                ignore_errors: _,
                ..
            }
            | DeclarativeStep::AptPurge {
                packages,
                autoremove,
                ignore_errors: _,
                ..
            } => {
                let removal_action = if self.env_cfg.delete_data { "purge" } else { "remove" };
                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    removal_action.to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                args.extend(packages.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("apt_{}", removal_action),
                        reason: format!(
                            "apt-get {} {:?} exited with {}: {}",
                            removal_action,
                            packages,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if *autoremove {
                    cancel.check(&recipe.package_id)?;
                    let ar_args = vec![
                        "-o".to_string(),
                        "DPkg::Lock::Timeout=120".to_string(),
                        "autoremove".to_string(),
                        "-y".to_string(),
                        "-qq".to_string(),
                    ];
                    let output = self
                        .runner
                        .run_command("apt-get", &ar_args, &apt_env, cancel)
                        .await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "apt_autoremove".to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!("APT {} packages: {}", removal_action, packages.join(", ")))
            }

            DeclarativeStep::EnsureSystemUser {
                username,
                home_dir,
                create_home,
                ..
            } => {
                validate_chown_target_path(home_dir)?;
                let check = self
                    .runner
                    .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                    .await?;
                if check.success() {
                    return Ok(format!("system user {} already exists", username));
                }
                cancel.check(&recipe.package_id)?;
                let mut args = vec![
                    "--system".to_string(),
                    "--user-group".to_string(),
                    if *create_home {
                        "--create-home".to_string()
                    } else {
                        "--no-create-home".to_string()
                    },
                    "--home-dir".to_string(),
                    home_dir.clone(),
                    "--shell".to_string(),
                    "/usr/sbin/nologin".to_string(),
                    username.clone(),
                ];
                let out = self
                    .runner
                    .run_command("useradd", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    // Check again in case user was already created
                    let recheck = self
                        .runner
                        .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                        .await?;
                    if !recheck.success() {
                        args.clear();
                        return Err(PackageExecutorError::StepFailed {
                            step: "ensure_system_user".to_string(),
                            reason: format!(
                                "useradd {} failed ({}): {}",
                                username,
                                out.exit_code,
                                out.combined_output()
                            ),
                        });
                    }
                }
                Ok(format!("ensured system user {}", username))
            }

            DeclarativeStep::PurgeSystemUser { username, .. } => {
                if !self.env_cfg.delete_data {
                    return Ok(format!("retained system user {} with application data", username));
                }
                for (database, program) in [("passwd", "userdel"), ("group", "groupdel")] {
                    let account = self.runner.run_command(
                        "getent", &[database.to_string(), username.clone()], &[], cancel,
                    ).await?;
                    if account.exit_code == 2 {
                        continue;
                    }
                    if !account.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "account_lookup".to_string(),
                            reason: account.combined_output(),
                        });
                    }
                    let output = self.runner.run_command(
                        program, std::slice::from_ref(username), &[], cancel,
                    ).await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: program.to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!("purged system user {}", username))
            }

            DeclarativeStep::EnsureDirectories {
                paths,
                mode,
                owner,
                group,
                ..
            } => {
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    if owner.is_some() || group.is_some() {
                        validate_chown_target_path(logical)?;
                    }
                    let resolved = self.env_cfg.resolve_path(logical)?;
                    fs::create_dir_all(&resolved)?;
                    validate_filesystem_path(&resolved, self.env_cfg.fs_root.as_deref())?;
                    set_path_mode(&resolved, *mode);
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let _ = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-R".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                        }
                    }
                }
                Ok(format!("ensured directories: {}", paths.join(", ")))
            }

            DeclarativeStep::ProbeSshPort { .. } => {
                let sshd_cfg = self.env_cfg.resolve_readonly_path("/etc/ssh/sshd_config");
                validate_filesystem_path(&sshd_cfg, self.env_cfg.fs_root.as_deref())?;
                let mut port = "ssh".to_string();
                if let Ok(raw) = fs::read_to_string(&sshd_cfg) {
                    if let Some(caps) = SSH_PORT_LINE_RE.captures(&raw) {
                        if let Some(m) = caps.get(1) {
                            let candidate = m.as_str().trim();
                            if !candidate.is_empty() {
                                port = candidate.to_string();
                            }
                        }
                    }
                }
                vars.insert("SSH_PORT".to_string(), port.clone());
                Ok(format!("probed SSH port: {}", port))
            }

            DeclarativeStep::GenerateSelfSignedTlsCert {
                cert_path,
                key_out_path,
                days,
                subject,
                mode,
                owner,
                group,
                overwrite,
                ..
            } => {
                let cert_resolved = self.env_cfg.resolve_path(cert_path)?;
                let key_resolved = match key_out_path {
                    Some(ref kp) => self.env_cfg.resolve_path(kp)?,
                    None => cert_resolved.clone(),
                };
                if !*overwrite && (cert_resolved.is_file() || key_resolved.is_file()) {
                    if cert_resolved.is_file() {
                        journal.stage_file_mutation(&cert_resolved)?;
                        self.apply_file_metadata(
                            &cert_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    if key_resolved != cert_resolved && key_resolved.is_file() {
                        journal.stage_file_mutation(&key_resolved)?;
                        self.apply_file_metadata(
                            &key_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    return Ok(format!("preserved existing TLS certificate {}", cert_path));
                }
                if let Some(parent) = cert_resolved.parent() {
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    fs::create_dir_all(parent)?;
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                }
                if key_resolved != cert_resolved {
                    if let Some(parent) = key_resolved.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                        fs::create_dir_all(parent)?;
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                }
                journal.stage_file_mutation(&cert_resolved)?;
                if key_resolved != cert_resolved {
                    journal.stage_file_mutation(&key_resolved)?;
                }

                // Pre-create destination files with strict 0600 permissions before invoking `openssl`
                // so private key material is never briefly exposed under a permissive process umask.
                write_file_atomic_with_mode_bounded(
                    &cert_resolved,
                    b"",
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                if key_resolved != cert_resolved {
                    write_file_atomic_with_mode_bounded(
                        &key_resolved,
                        b"",
                        0o600,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                }

                let args = vec![
                    "req".to_string(),
                    "-x509".to_string(),
                    "-nodes".to_string(),
                    "-days".to_string(),
                    days.to_string(),
                    "-newkey".to_string(),
                    "rsa:4096".to_string(),
                    "-keyout".to_string(),
                    key_resolved.to_string_lossy().to_string(),
                    "-out".to_string(),
                    cert_resolved.to_string_lossy().to_string(),
                    "-subj".to_string(),
                    subject.clone(),
                ];
                let out = self
                    .runner
                    .run_command("openssl", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "generate_self_signed_tls_cert".to_string(),
                        reason: format!(
                            "openssl req -x509 exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }

                // In isolated test roots where `openssl` is mocked via `CommandRunner`, ensure
                // the staged certificate file is materialized on disk with the requested mode.
                if self.env_cfg.fs_root.is_some()
                    && fs::metadata(&cert_resolved)
                        .map(|m| m.len() == 0)
                        .unwrap_or(true)
                {
                    let pem_payload = format!(
                        "# AETHERFLOW-MOCK-TLS-KEY (isolated test sentinel - not a real key)\nsubject={}\ndays={}\n",
                        subject, days
                    );
                    write_file_atomic_with_mode_bounded(
                        &cert_resolved,
                        pem_payload.as_bytes(),
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if key_resolved != cert_resolved
                        && fs::metadata(&key_resolved)
                            .map(|m| m.len() == 0)
                            .unwrap_or(true)
                    {
                        write_file_atomic_with_mode_bounded(
                            &key_resolved,
                            pem_payload.as_bytes(),
                            *mode,
                            self.env_cfg.fs_root.as_deref(),
                        )?;
                    }
                }

                self.apply_file_metadata(
                    &cert_resolved,
                    *mode,
                    owner.as_deref(),
                    group.as_deref(),
                    cancel,
                )
                .await?;
                if key_resolved != cert_resolved {
                    self.apply_file_metadata(
                        &key_resolved,
                        *mode,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                }
                Ok(format!("generated self-signed TLS certificate {}", cert_path))
            }

            DeclarativeStep::CaptureDpkgVersion {
                package,
                fallback_version,
                version_file_path,
                owner,
                group,
                ..
            } => {
                let args = vec![
                    "-W".to_string(),
                    "-f=${Version}".to_string(),
                    package.clone(),
                ];
                let out = self
                    .runner
                    .run_command("dpkg-query", &args, &[], cancel)
                    .await?;
                let resolved_ver = if out.success() {
                    normalize_dpkg_version(&out.stdout, fallback_version)
                } else {
                    fallback_version.clone()
                };
                vars.insert("VERSION".to_string(), resolved_ver.clone());
                vars.insert(
                    "TAG".to_string(),
                    format!("v{}", resolved_ver.trim_start_matches('v')),
                );

                if let Some(ref vp) = version_file_path {
                    let resolved_path = self.env_cfg.resolve_path(vp)?;
                    journal.stage_file_mutation(&resolved_path)?;
                    let content = format!("{}\n", resolved_ver);
                    write_file_atomic_with_mode_bounded(
                        &resolved_path,
                        content.as_bytes(),
                        0o644,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let _ = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        format!("{}:{}", o, grp),
                                        resolved_path.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await;
                        }
                    }
                }
                Ok(format!(
                    "captured dpkg version {} for {}",
                    resolved_ver, package
                ))
            }

            DeclarativeStep::EnsureThreadfinConfig { .. } => {
                let resolved = self.env_cfg.resolve_path("/var/lib/threadfin/conf/settings.json")?;
                let mut settings = serde_json::Map::new();
                if resolved.exists() {
                    let mut contents = Vec::new();
                    File::open(&resolved)?.take(1024 * 1024 + 1).read_to_end(&mut contents)?;
                    if contents.len() > 1024 * 1024 {
                        return Err(PackageExecutorError::Validation("Threadfin settings exceed 1 MiB".to_string()));
                    }
                    settings = serde_json::from_slice::<serde_json::Value>(&contents)
                        .map_err(|error| PackageExecutorError::Validation(format!("invalid Threadfin settings: {}", error)))?
                        .as_object()
                        .cloned()
                        .ok_or_else(|| PackageExecutorError::Validation("Threadfin settings must be a JSON object".to_string()))?;
                }
                if settings.is_empty() {
                    settings.insert("version".to_string(), serde_json::Value::String("0.5.0".to_string()));
                } else if !matches!(settings.get("version"), Some(serde_json::Value::String(version)) if !version.is_empty()) {
                    return Err(PackageExecutorError::Validation("existing Threadfin settings require a version string".to_string()));
                }
                match settings.get("bindIpAddress") {
                    Some(serde_json::Value::String(address)) if !address.is_empty() => {
                        journal.stage_file_mutation(&resolved)?;
                        self.apply_file_metadata(
                            &resolved,
                            0o600,
                            Some("threadfin"),
                            Some("threadfin"),
                            cancel,
                        )
                        .await?;
                        return Ok("preserved explicit Threadfin bindIpAddress".to_string());
                    }
                    Some(serde_json::Value::String(_) | serde_json::Value::Null) | None => {}
                    Some(_) => return Err(PackageExecutorError::Validation("Threadfin bindIpAddress must be a string".to_string())),
                }
                settings.insert("bindIpAddress".to_string(), serde_json::Value::String("127.0.0.1".to_string()));
                journal.stage_file_mutation(&resolved)?;
                let contents = serde_json::to_vec_pretty(&settings)
                    .map_err(|error| PackageExecutorError::Validation(error.to_string()))?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    &contents,
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                self.apply_file_metadata(
                    &resolved,
                    0o600,
                    Some("threadfin"),
                    Some("threadfin"),
                    cancel,
                )
                .await?;
                Ok("defaulted Threadfin bindIpAddress to 127.0.0.1 while preserving other settings".to_string())
            }

            DeclarativeStep::ResolveGitHubReleaseTag {
                repo,
                fallback_version,
                strip_v_prefix,
                ..
            } => {
                let tag = self
                    .resolve_github_tag(repo, fallback_version, *strip_v_prefix)
                    .await;
                let clean_ver = tag.trim_start_matches('v').to_string();
                let raw_tag = if tag.starts_with('v') {
                    tag.clone()
                } else {
                    format!("v{}", tag)
                };
                vars.insert("VERSION".to_string(), clean_ver.clone());
                vars.insert(
                    "TAG".to_string(),
                    if *strip_v_prefix {
                        clean_ver.clone()
                    } else {
                        raw_tag
                    },
                );
                Ok(format!("resolved release version {} for {}", clean_ver, repo))
            }

            DeclarativeStep::DownloadBinary {
                url_template,
                arch_map,
                dest_path,
                mode,
                verification,
                ..
            } => {
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS binary download URL: {}",
                        resolved_url
                    )));
                }
                let tmp_artifact = self
                    .fetch_artifact_to_temp(&recipe.package_id, &resolved_url, arch_asset, journal, cancel)
                    .await?;
                cancel.check(&recipe.package_id)?;
                let sha256 = verify_artifact_file_for_arch(&tmp_artifact, verification, Some(&arch))?;

                let dest_resolved = self.env_cfg.resolve_path(dest_path)?;
                journal.stage_file_mutation(&dest_resolved)?;
                let bytes = fs::read(&tmp_artifact)?;
                write_file_atomic_with_mode_bounded(
                    &dest_resolved,
                    &bytes,
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                let _ = fs::remove_file(&tmp_artifact);

                Ok(format!(
                    "installed verified binary {} (sha256={})",
                    dest_path,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::DownloadAndExtractTarGz {
                url_template,
                arch_map,
                dest_dir,
                extract_binaries,
                binary_mode,
                verification,
                ..
            } => {
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS archive download URL: {}",
                        resolved_url
                    )));
                }
                let tmp_archive = self
                    .fetch_artifact_to_temp(&recipe.package_id, &resolved_url, arch_asset, journal, cancel)
                    .await?;
                cancel.check(&recipe.package_id)?;

                let mut gz_policy = verification.clone();
                gz_policy.require_gzip_magic = true;
                let sha256 = verify_artifact_file_for_arch(&tmp_archive, &gz_policy, Some(&arch))?;

                let dest_dir_resolved = self.env_cfg.resolve_path(dest_dir)?;
                fs::create_dir_all(&dest_dir_resolved)?;
                validate_filesystem_path(&dest_dir_resolved, self.env_cfg.fs_root.as_deref())?;

                extract_binaries_from_targz(
                    &tmp_archive,
                    &dest_dir_resolved,
                    extract_binaries,
                    *binary_mode,
                    verification.require_elf_magic,
                    journal,
                )?;
                let _ = fs::remove_file(&tmp_archive);

                Ok(format!(
                    "extracted verified archive binaries {:?} to {} (sha256={})",
                    extract_binaries,
                    dest_dir,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::WriteTemplateFile {
                path,
                content_template,
                mode,
                overwrite,
                owner,
                group,
                ..
            } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                if !*overwrite && resolved.is_file() {
                    return Ok(format!("preserved existing file {}", path));
                }
                journal.stage_file_mutation(&resolved)?;
                let rendered = interpolate_template(content_template, vars);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;

                if let Some(ref o) = owner {
                    let grp = group.as_deref().unwrap_or(o.as_str());
                    if self.env_cfg.fs_root.is_none() {
                        let _ = self
                            .runner
                            .run_command(
                                "chown",
                                &[
                                    format!("{}:{}", o, grp),
                                    resolved.to_string_lossy().to_string(),
                                ],
                                &[],
                                cancel,
                            )
                            .await?;
                    }
                }
                Ok(format!("wrote configuration file {}", path))
            }

            DeclarativeStep::WriteSystemdUnit {
                unit_name,
                content_template,
                ..
            } => {
                let norm = normalize_unit_filename(unit_name);
                let logical_path = format!("/etc/systemd/system/{}", norm);
                let resolved = self.env_cfg.resolve_path(&logical_path)?;
                let existed = resolved.is_file();
                journal.stage_file_mutation(&resolved)?;
                if !existed {
                    journal.record_created_systemd_unit(&norm, &resolved);
                }
                let rendered = interpolate_template(content_template, vars);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    0o644,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("wrote systemd unit {}", logical_path))
            }

            DeclarativeStep::Systemctl {
                unit,
                operation,
                ignore_errors,
                ..
            } => {
                if matches!(
                    operation,
                    SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed
                ) {
                    let operation_name = match operation {
                        SystemctlOp::Stop => "stop",
                        SystemctlOp::Disable => "disable",
                        _ => "reset-failed",
                    };
                    self.teardown_systemctl(
                        operation_name,
                        &normalize_unit_filename(unit.as_deref().unwrap_or_default()),
                        cancel,
                    ).await?;
                    return Ok(format!("systemctl {operation_name} completed"));
                }
                let args: Vec<String> = match operation {
                    SystemctlOp::DaemonReload => vec!["daemon-reload".to_string()],
                    SystemctlOp::EnableNow => vec![
                        "enable".to_string(),
                        "--now".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Enable => vec![
                        "enable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Start => vec![
                        "start".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Restart => vec![
                        "restart".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Stop => vec![
                        "stop".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Disable => vec![
                        "disable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::ResetFailed => vec![
                        "reset-failed".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                };
                let out = self
                    .runner
                    .run_command("systemctl", &args, &[], cancel)
                    .await?;
                if !out.success()
                    && (!ignore_errors || matches!(operation, SystemctlOp::DaemonReload))
                {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("systemctl {:?}", operation),
                        reason: format!(
                            "systemctl {} exited with {}: {}",
                            args.join(" "),
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok(format!("systemctl {} completed", args.join(" ")))
            }

            DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                let norm = normalize_unit_filename(unit_name);
                for op in ["stop", "disable", "reset-failed"] {
                    cancel.check(&recipe.package_id)?;
                    self.teardown_systemctl(op, &norm, cancel).await?;
                }
                let unit_logical = format!("/etc/systemd/system/{}", norm);
                let dropin_logical = format!("/etc/systemd/system/{}.d", norm);
                let unit_path = self.env_cfg.resolve_path(&unit_logical)?;
                let dropin_path = self.env_cfg.resolve_path(&dropin_logical)?;
                match fs::remove_file(&unit_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                match fs::remove_dir_all(&dropin_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let reload = self.runner.run_command(
                    "systemctl", &["daemon-reload".to_string()], &[], cancel,
                ).await?;
                if !reload.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "systemctl_daemon_reload".to_string(),
                        reason: reload.combined_output(),
                    });
                }
                Ok(format!("purged systemd unit {}", norm))
            }

            DeclarativeStep::RemovePaths {
                paths,
                only_if_delete_data,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped data directory removal (DELETE_DATA=false)".to_string());
                }
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    let resolved = self.env_cfg.resolve_path(logical)?;
                    match fs::symlink_metadata(&resolved) {
                        Ok(meta) => {
                            if meta.file_type().is_symlink() {
                                return Err(PackageExecutorError::SecurityViolation(format!(
                                    "refusing to remove symlink target path: {}",
                                    resolved.display()
                                )));
                            }
                            if meta.is_dir() {
                                fs::remove_dir_all(&resolved)?;
                            } else {
                                fs::remove_file(&resolved)?;
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(PackageExecutorError::Io(err)),
                    }
                }
                Ok(format!("removed paths: {}", paths.join(", ")))
            }
        }
    }

    async fn resolve_github_tag(
        &self,
        repo: &str,
        fallback_version: &str,
        strip_v_prefix: bool,
    ) -> String {
        // 1. Honor explicit version override or offline mode in tests/airgapped environments
        if let Ok(override_ver) = env::var("AETHERFLOW_PACKAGE_VERSION_OVERRIDE") {
            let trimmed = override_ver.trim();
            if SAFE_VERSION_TAG.is_match(trimmed) {
                return if strip_v_prefix {
                    trimmed.trim_start_matches('v').to_string()
                } else {
                    trimmed.to_string()
                };
            }
        }
        if self.env_cfg.artifact_cache_dir.is_some() || self.env_cfg.fs_root.is_some() {
            return if strip_v_prefix {
                fallback_version.trim_start_matches('v').to_string()
            } else if fallback_version.starts_with('v') {
                fallback_version.to_string()
            } else {
                format!("v{}", fallback_version)
            };
        }

        // 2. Query GitHub releases/latest API with short timeout
        let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
        {
            if let Ok(resp) = client.get(&api_url).send().await {
                if resp.status().is_success() {
                    if let Ok(json_val) = resp.json::<serde_json::Value>().await {
                        if let Some(tag_str) = json_val.get("tag_name").and_then(|v| v.as_str()) {
                            let clean = tag_str.trim();
                            if SAFE_VERSION_TAG.is_match(clean) {
                                return if strip_v_prefix {
                                    clean.trim_start_matches('v').to_string()
                                } else {
                                    clean.to_string()
                                };
                            }
                        }
                    }
                }
            }
        }

        if strip_v_prefix {
            fallback_version.trim_start_matches('v').to_string()
        } else if fallback_version.starts_with('v') {
            fallback_version.to_string()
        } else {
            format!("v{}", fallback_version)
        }
    }

    async fn fetch_artifact_to_temp(
        &self,
        pkg_id: &str,
        url: &str,
        asset_name: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<PathBuf, PackageExecutorError> {
        cancel.check(pkg_id)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        fs::create_dir_all(&self.env_cfg.temp_dir)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_dest = self
            .env_cfg
            .temp_dir
            .join(format!("af-{}-{}-{}", pkg_id, nanos, asset_name));
        validate_filesystem_path(&tmp_dest, self.env_cfg.fs_root.as_deref())?;
        journal.track_temp_file(tmp_dest.clone());

        // 1. Check local artifact cache directory first (used by isolated tests and offline staging)
        if let Some(ref cache_dir) = self.env_cfg.artifact_cache_dir {
            validate_filesystem_path(cache_dir, self.env_cfg.fs_root.as_deref())?;
            let mut candidate_names = vec![asset_name];
            if asset_name == "Threadfin_linux_amd64_glibc_2.31_compat" {
                candidate_names.push("Threadfin_linux_amd64_compat");
                candidate_names.push("Threadfin_linux_amd64");
            }
            for cand in candidate_names {
                let cached = cache_dir.join(cand);
                validate_filesystem_path(&cached, self.env_cfg.fs_root.as_deref())?;
                if cached.is_file() {
                    fs::copy(&cached, &tmp_dest)?;
                    return Ok(tmp_dest);
                }
            }
        }

        // 2. Support `file://` URLs for local staging tests
        if let Some(local_path) = url.strip_prefix("file://") {
            let src = Path::new(local_path);
            validate_filesystem_path(src, None)?;
            if !src.is_file() {
                return Err(PackageExecutorError::ArtifactVerification(format!(
                    "staged file artifact not found: {}",
                    src.display()
                )));
            }
            fs::copy(src, &tmp_dest)?;
            return Ok(tmp_dest);
        }

        // 3. Enforce HTTPS fail-closed on remote downloads
        if !url.starts_with("https://") {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing non-HTTPS artifact download URL: {}",
                url
            )));
        }

        // 4. Perform HTTPS download via reqwest with chunked cancellation checks
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
            .map_err(|e| PackageExecutorError::StepFailed {
                step: "http_client".to_string(),
                reason: e.to_string(),
            })?;

        let mut resp = tokio::select! {
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            res = client.get(url).send() => {
                res.map_err(|e| PackageExecutorError::StepFailed {
                    step: "download_artifact".to_string(),
                    reason: format!("failed to download {}: {}", url, e),
                })?
            }
        };

        if !resp.status().is_success() {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "HTTP {} when downloading {}",
                resp.status(),
                url
            )));
        }

        let mut f = File::create(&tmp_dest)?;
        loop {
            let next_chunk = tokio::select! {
                _ = wait_for_cancellation(cancel) => {
                    drop(f);
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                }
                chunk_res = resp.chunk() => {
                    chunk_res.map_err(|e| PackageExecutorError::StepFailed {
                        step: "download_artifact_body".to_string(),
                        reason: e.to_string(),
                    })?
                }
            };
            match next_chunk {
                Some(chunk) => {
                    f.write_all(&chunk)?;
                }
                None => break,
            }
        }
        cancel.check(pkg_id)?;
        f.sync_all()?;

        Ok(tmp_dest)
    }
}

/// Normalizes a raw `dpkg-query -W -f=${Version}` string (e.g. `1:0.14.0-1build2` -> `0.14.0`),
/// falling back to `fallback` if the output is empty or non-conforming (e.g. mock placeholder output).
fn normalize_dpkg_version(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains(' ') {
        return fallback.to_string();
    }
    let without_epoch = match trimmed.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => {
            rest
        }
        _ => trimmed,
    };
    let without_rev = without_epoch
        .split_once('-')
        .map(|(upstream, _)| upstream)
        .unwrap_or(without_epoch)
        .trim();
    if !without_rev.is_empty() && SAFE_VERSION_TAG.is_match(without_rev) {
        without_rev.to_string()
    } else {
        fallback.to_string()
    }
}

fn step_progress_meta(step: &DeclarativeStep) -> (u8, &str) {
    match step {
        DeclarativeStep::AptUpdate {
            progress_pct,
            description,
        }
        | DeclarativeStep::AptInstall {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::AptPurge {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::AptRemove {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureSystemUser {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::PurgeSystemUser {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureDirectories {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::ProbeSshPort {
            progress_pct,
            description,
        }
        | DeclarativeStep::GenerateSelfSignedTlsCert {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::CaptureDpkgVersion {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureThreadfinConfig {
            progress_pct,
            description,
        }
        | DeclarativeStep::ResolveGitHubReleaseTag {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::DownloadAndExtractTarGz {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::DownloadBinary {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WriteTemplateFile {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WriteSystemdUnit {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::Systemctl {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::PurgeSystemdUnit {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::RemovePaths {
            progress_pct,
            description,
            ..
        } => (*progress_pct, description.as_str()),
    }
}

fn interpolate_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        let placeholder = format!("{{{{{}}}}}", k);
        out = out.replace(&placeholder, v);
    }
    out
}

fn append_log_line(log_file_path: &Path, line: &str) {
    if validate_filesystem_path(log_file_path, None).is_err() {
        return;
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)
    {
        let _ = writeln!(f, "[{}] {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), line);
    }
}

/// Best-effort background trigger for `/usr/local/bin/af-certbot-sync <pkg_id>`
/// to preserve parity with `packages/common.sh::write_lock`.
fn trigger_certbot_sync_best_effort(pkg_id: &str) {
    let sync_bin = Path::new("/usr/local/bin/af-certbot-sync");
    if !sync_bin.is_file() {
        return;
    }
    let pkg = pkg_id.to_string();
    std::thread::spawn(move || {
        if let Ok(mut child) = std::process::Command::new(sync_bin)
            .arg(pkg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let _ = child.wait();
        }
    });
}

fn extract_binaries_from_targz(
    archive_path: &Path,
    dest_dir: &Path,
    wanted_binaries: &[String],
    binary_mode: u32,
    require_elf_magic: bool,
    journal: &mut RollbackJournal,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(archive_path, journal.fs_root.as_deref())?;
    validate_filesystem_path(dest_dir, journal.fs_root.as_deref())?;

    let file = File::open(archive_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut found: HashMap<String, bool> = wanted_binaries
        .iter()
        .map(|b| (b.clone(), false))
        .collect();

    for entry_res in archive.entries().map_err(|e| {
        PackageExecutorError::ArtifactVerification(format!("invalid tar.gz archive: {}", e))
    })? {
        let mut entry = entry_res.map_err(|e| {
            PackageExecutorError::ArtifactVerification(format!("corrupt tar entry: {}", e))
        })?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| PackageExecutorError::ArtifactVerification(e.to_string()))?
            .into_owned();

        // Reject any entry containing '..'
        if entry_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive contains path traversal entry: {}",
                entry_path.display()
            )));
        }

        // Reject symlinks, hardlinks, FIFOs, or device nodes inside archives
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive contains disallowed link entry: {}",
                entry_path.display()
            )));
        }

        let Some(fname) = entry_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !found.contains_key(fname) {
            continue;
        }
        if !matches!(entry_type, tar::EntryType::Regular | tar::EntryType::GNUSparse) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive target '{}' is not a regular file",
                entry_path.display()
            )));
        }

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if require_elf_magic && (buf.len() < 4 || buf[..4] != [0x7f, b'E', b'L', b'F']) {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "archive member '{}' is not a valid ELF binary",
                fname
            )));
        }

        let target = dest_dir.join(fname);
        validate_filesystem_path(&target, journal.fs_root.as_deref())?;
        journal.stage_file_mutation(&target)?;
        write_file_atomic_with_mode_bounded(
            &target,
            &buf,
            binary_mode,
            journal.fs_root.as_deref(),
        )?;
        found.insert(fname.to_string(), true);
    }

    for (bin_name, was_found) in found {
        if !was_found {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "expected binary '{}' was not found inside archive {}",
                bin_name,
                archive_path.display()
            )));
        }
    }

    Ok(())
}

fn apply_sandbox_in_root_with_journal(
    pkg_id: &str,
    systemd_root: &Path,
    mut journal: Option<&mut RollbackJournal>,
    fs_root: Option<&Path>,
) -> Result<String, PackageExecutorError> {
    validate_filesystem_path(systemd_root, fs_root)?;

    let pkg = crate::get_runner_package_definition(pkg_id).unwrap_or_else(|| af_models::Package {
        name: pkg_id.to_string(),
        service_type: "systemd".to_string(),
        service_name: pkg_id.to_string(),
        sandbox_profile: "native".to_string(),
        sandbox_read_write: vec![format!("/var/lib/{}", pkg_id)],
        sandbox_service_ids: vec![format!("{}.service", pkg_id)],
        ..Default::default()
    });

    if !pkg.service_type.is_empty() && pkg.service_type != "systemd" {
        return Ok("sandbox skipped (non-systemd service)".to_string());
    }
    if pkg.sandbox_profile.is_empty() {
        return Ok("sandbox skipped (no profile configured)".to_string());
    }

    let mut units = pkg.sandbox_service_ids.clone();
    if units.is_empty() && !pkg.service_name.is_empty() {
        units.push(pkg.service_name.clone());
    }
    if units.is_empty() {
        units.push(pkg_id.to_string());
    }

    for raw_unit in &units {
        let norm = normalize_unit_filename(raw_unit);
        let dropin_dir = systemd_root.join(format!("{}.d", norm));
        validate_filesystem_path(&dropin_dir, fs_root)?;
        let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
        let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
        validate_filesystem_path(&dropin_aether, fs_root)?;
        validate_filesystem_path(&dropin_10, fs_root)?;

        if pkg.sandbox_profile == "privileged"
            || pkg.sandbox_profile == "none"
            || crate::is_exempt_sandbox_unit(&norm)
        {
            let _ = fs::remove_file(&dropin_aether);
            let _ = fs::remove_file(&dropin_10);
            continue;
        }
        fs::create_dir_all(&dropin_dir)?;
        validate_filesystem_path(&dropin_dir, fs_root)?;
        let content = crate::render_systemd_sandbox_dropin(
            &pkg.sandbox_profile,
            &norm,
            &pkg.sandbox_read_write,
        );
        if let Some(ref mut j) = journal {
            j.stage_file_mutation(&dropin_aether)?;
            j.stage_file_mutation(&dropin_10)?;
        }
        write_file_atomic_with_mode_bounded(&dropin_aether, content.as_bytes(), 0o644, fs_root)?;
        write_file_atomic_with_mode_bounded(&dropin_10, content.as_bytes(), 0o644, fs_root)?;
    }

    Ok("sandbox applied".to_string())
}

#[allow(dead_code)]
fn apply_sandbox_in_root(pkg_id: &str, systemd_root: &Path) -> anyhow::Result<String> {
    apply_sandbox_in_root_with_journal(pkg_id, systemd_root, None, None)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

// -----------------------------------------------------------------------------
// Unified Runner Stream Dispatcher (Declarative Rust + Legacy Bash Fallback)
// -----------------------------------------------------------------------------

/// Resolves whether a `PackageRunnerRequest` can be satisfied by either a built-in
/// declarative Rust recipe or a legacy Bash script on disk.
pub fn can_resolve_package_operation(action: &str, pkg_id: &str, script_name: &str) -> bool {
    if PackageAction::parse(action).is_none() {
        return false;
    }
    if select_package_engine(pkg_id) == PackageEngineMode::DeclarativeRust {
        return true;
    }
    resolve_package_script_path(action, script_name).is_some()
}

/// Streams a declarative recipe's [`PackageProgressEvent`] wire lines incrementally as each
/// step emits them, without waiting for the entire recipe to finish before yielding.
pub fn execute_declarative_recipe_stream<R>(
    executor: Arc<DeclarativePackageExecutor<R>>,
    recipe: DeclarativePackageRecipe,
    action: PackageAction,
    cancel: CancellationToken,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> + Send
where
    R: CommandRunner + 'static,
{
    async_stream::stream! {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let exec_handle = tokio::spawn(async move {
            executor
                .execute_recipe(&recipe, action, cancel, move |ev| {
                    let _ = tx.send(format!("{}\n", ev.to_wire_line()));
                })
                .await
        });

        while let Some(line) = rx.recv().await {
            yield Ok(line);
        }

        match exec_handle.await {
            Ok(Ok(_outcome)) => {}
            Ok(Err(err)) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
            }
            Err(join_err) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:declarative task failed: {}\n", join_err));
            }
        }
    }
}

/// Whether a request explicitly asks a removal to purge retained application
/// data. Install and update never purge, and the runner's own `DELETE_DATA`
/// environment is deliberately ignored so a stray daemon setting cannot turn
/// every ordinary uninstall into a destructive one.
pub(crate) fn package_request_deletes_data(req: &PackageRunnerRequest) -> bool {
    req.delete_data && req.action == "remove"
}

/// Sets the lifecycle contract environment for a legacy Bash package script.
/// `DELETE_DATA` is always set explicitly so an inherited runner value can
/// never turn an ordinary removal into a purge.
pub(crate) fn apply_legacy_package_environment(cmd: &mut Command, req: &PackageRunnerRequest) {
    cmd.env("DEBIAN_FRONTEND", "noninteractive")
        .env("AF_PACKAGE_ACTION", req.action.as_str())
        .env(
            "DELETE_DATA",
            if package_request_deletes_data(req) {
                "true"
            } else {
                "false"
            },
        )
        .env("DPKG_LOCK_TIMEOUT", "120");
    if (1024..=65535).contains(&req.app_port) {
        cmd.env("AF_APP_PORT", req.app_port.to_string());
        cmd.env("AETHERFLOW_APP_PORT", req.app_port.to_string());
    } else {
        cmd.env_remove("AF_APP_PORT");
        cmd.env_remove("AETHERFLOW_APP_PORT");
    }
}

/// Streams a package lifecycle operation (`install`, `remove`, or `update`) as newline-delimited
/// progress/log lines, dispatching to [`DeclarativePackageExecutor`] for migrated recipes and
/// automatically falling back to the legacy Bash script for unported recipes.
pub fn execute_package_request_stream(
    req: PackageRunnerRequest,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> + Send {
    async_stream::stream! {
        let Some(action) = PackageAction::parse(&req.action) else {
            yield Ok("__RUNNER_EXIT_ERROR__:disallowed package action\n".to_string());
            return;
        };
        if let Err(error) = crate::acquire_package_maintenance_guard(
            PackageExecutionEnv::default().fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&req.package_id),
            &req.lifecycle_job_id, Some(&req.action),
        ).await {
            yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
            return;
        }

        if select_package_engine(&req.package_id) == PackageEngineMode::DeclarativeRust {
            if let Some(recipe) = get_declarative_recipe(&req.package_id) {
                let env_cfg = PackageExecutionEnv {
                    app_port: req.app_port,
                    lifecycle_job_id: req.lifecycle_job_id.clone(),
                    // Purge is an explicit request property, never ambient
                    // runner environment.
                    delete_data: package_request_deletes_data(&req),
                    ..Default::default()
                };
                let executor = Arc::new(DeclarativePackageExecutor::new(env_cfg));
                let cancel = CancellationToken::new();
                let mut stream = std::pin::pin!(execute_declarative_recipe_stream(
                    executor,
                    recipe,
                    action,
                    cancel,
                ));
                while let Some(item) = futures::StreamExt::next(&mut stream).await {
                    yield item;
                }
                return;
            }
        }

        // Legacy Bash fallback for unported recipes
        let Some(script_path) = resolve_package_script_path(&req.action, &req.script_name) else {
            yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
            return;
        };

        let cancel = CancellationToken::new();
        let _cancel_guard = match register_package_cancellation(&req.package_id, cancel.clone()) {
            Ok(g) => g,
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };

        let _proc_lock = match acquire_package_mutex_with_cancel(&req.package_id, &cancel).await {
            Ok(g) => g,
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };
        let env_cfg = PackageExecutionEnv::default();
        let _flock_guard =
            match CrossProcessLockGuard::acquire_with_cancel(&env_cfg, &req.package_id, &cancel)
                .await
            {
                Ok(g) => g,
                Err(e) => {
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                    return;
                }
            };

        let _maintenance_guard = match crate::acquire_package_maintenance_guard(
            env_cfg.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&req.package_id),
            &req.lifecycle_job_id, Some(&req.action),
        ).await {
            Ok(guard) => guard,
            Err(e) => { yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e)); return; }
        };

        let mut cmd = Command::new("bash");
        cmd.arg(&script_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        apply_legacy_package_environment(&mut cmd, &req);

        #[cfg(unix)]
        if let Err(error) = _maintenance_guard.preserve_in_child(cmd.as_std_mut()) {
            yield Ok(format!("__RUNNER_EXIT_ERROR__:{error}\n"));
            return;
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let mut stdout = BoundedLines::new(child.stdout.take().unwrap());
                let mut stderr = BoundedLines::new(child.stderr.take().unwrap());
                let mut stdout_open = true;
                let mut stderr_open = true;
                while stdout_open || stderr_open {
                    if cancel.is_cancelled() {
                        terminate_child_process_group(&mut child).await;
                        yield Ok(format!(
                            "__RUNNER_EXIT_ERROR__:operation cancelled for package '{}'\n",
                            req.package_id
                        ));
                        return;
                    }
                    let (is_stdout, result) = tokio::select! {
                        _ = wait_for_cancellation(&cancel) => {
                            terminate_child_process_group(&mut child).await;
                            yield Ok(format!(
                                "__RUNNER_EXIT_ERROR__:operation cancelled for package '{}'\n",
                                req.package_id
                            ));
                            return;
                        }
                        result = stdout.next_line(), if stdout_open => (true, result),
                        result = stderr.next_line(), if stderr_open => (false, result),
                    };
                    match result {
                        Ok(Some(line)) => yield Ok(format!("{}\n", line)),
                        Ok(None) if is_stdout => stdout_open = false,
                        Ok(None) => stderr_open = false,
                        Err(error) => {
                            terminate_child_process_group(&mut child).await;
                            yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
                            return;
                        }
                    }
                }
                match child.wait().await {
                    Ok(status) if !status.success() => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:exit status {}\n", status));
                    }
                    Err(error) => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
                    }
                    _ => {}
                }
            }
            Err(error) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Focused Unit & Integration Tests (Isolated Temp Paths & Mocked Commands)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::sync::atomic::AtomicUsize;

    fn legacy_env(req: &PackageRunnerRequest) -> HashMap<String, Option<String>> {
        let mut cmd = Command::new("bash");
        apply_legacy_package_environment(&mut cmd, req);
        cmd.as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    #[test]
    fn test_purge_is_explicit_per_request_and_never_inherited() {
        let request = |action: &str, delete_data: bool| PackageRunnerRequest {
            action: action.to_string(),
            package_id: "sonarr".to_string(),
            script_name: "removepackage-sonarr".to_string(),
            lifecycle_job_id: String::new(),
            app_port: 0,
            delete_data,
        };
        assert!(!package_request_deletes_data(&request("remove", false)));
        assert!(package_request_deletes_data(&request("remove", true)));
        assert!(!package_request_deletes_data(&request("install", true)));
        assert!(!package_request_deletes_data(&request("update", true)));

        // Ordinary removal explicitly overrides any DELETE_DATA the runner
        // daemon itself may carry in its environment.
        let env = legacy_env(&request("remove", false));
        assert_eq!(env.get("DELETE_DATA"), Some(&Some("false".to_string())));
        assert_eq!(
            env.get("AF_PACKAGE_ACTION"),
            Some(&Some("remove".to_string()))
        );
        assert_eq!(env.get("AF_APP_PORT"), Some(&None));
        let env = legacy_env(&request("remove", true));
        assert_eq!(env.get("DELETE_DATA"), Some(&Some("true".to_string())));
        let mut update = request("update", true);
        update.app_port = 18989;
        let env = legacy_env(&update);
        assert_eq!(env.get("DELETE_DATA"), Some(&Some("false".to_string())));
        assert_eq!(env.get("AF_APP_PORT"), Some(&Some("18989".to_string())));
        assert_eq!(
            env.get("AETHERFLOW_APP_PORT"),
            Some(&Some("18989".to_string()))
        );

        // Wire compatibility: older clients omit the field and get retention.
        let legacy: PackageRunnerRequest = serde_json::from_str(
            r#"{"action":"remove","package_id":"sonarr","script_name":"removepackage-sonarr"}"#,
        )
        .unwrap();
        assert!(!legacy.delete_data);
        assert!(!serde_json::to_string(&request("remove", false))
            .unwrap()
            .contains("delete_data"));
    }

    #[test]
    fn test_registry_contains_catalog_packages_and_defers_incomplete_recipes() {
        for id in list_declarative_recipe_ids() {
            assert!(
                crate::get_runner_package_definition(&id).is_some(),
                "{}",
                id
            );
            let recipe = get_declarative_recipe(&id).unwrap();
            assert!(
                recipe.install_steps.iter().any(|step| matches!(
                    step,
                    DeclarativeStep::CaptureDpkgVersion { .. }
                        | DeclarativeStep::ResolveGitHubReleaseTag { .. }
                )) || recipe.install_steps.iter().any(|step| matches!(
                    step,
                    DeclarativeStep::WriteTemplateFile { path, content_template, .. }
                        if path == "/var/lib/threadfin/.af-version"
                            && content_template.trim() == THREADFIN_PINNED_VERSION
                )),
                "{} must capture an installed version",
                id
            );
        }
        for id in ["scrutiny", "clamav", "mosquitto"] {
            assert_eq!(
                select_package_engine_with_flags(id, true, false),
                PackageEngineMode::LegacyBashFallback
            );
        }
    }

    #[test]
    fn test_atomic_writes_and_journal_backups_are_exclusive() {
        let root = create_isolated_test_dir("exclusive-files");
        let target = root.join("settings");
        write_file_atomic_with_mode(&target, b"original", 0o600).unwrap();
        assert!(open_new_private_file(&target, 0o600).is_err());
        let planted_backup = root.join("settings.bak-af");
        let unrelated = root.join("unrelated");
        fs::write(&unrelated, b"unrelated").unwrap();
        fs::hard_link(&unrelated, &planted_backup).unwrap();
        let mut journal = RollbackJournal::new(Some(root.clone()));
        journal.stage_file_mutation(&target).unwrap();
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
        match &journal.entries[0] {
            RollbackEntry::RestorableFile { backup, .. } => {
                assert_ne!(backup, &planted_backup);
                assert_eq!(fs::read(backup).unwrap(), b"original");
            }
            other => panic!("unexpected rollback entry: {:?}", other),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(journal.stage_file_mutation(&root.with_extension("outside")).is_err());
        journal.commit();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_isolated_root_checks_ancestors_above_root() {
        let root = create_isolated_test_dir("root-ancestors");
        let actual = root.join("actual");
        fs::create_dir_all(actual.join("nested")).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        let bound = alias.join("nested");
        assert!(matches!(
            validate_filesystem_path(&bound.join("settings"), Some(&bound)),
            Err(PackageExecutorError::SecurityViolation(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    /// Serializes async execution tests that share process-global `PACKAGE_MUTEX` or
    /// `ACTIVE_CANCELLATIONS` entries for `"fail2ban"`.
    static TEST_EXECUTION_SERIALIZER: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    /// Deterministic mock command runner that records every command invocation and never executes
    /// live privileged OS commands.
    #[derive(Clone, Default)]
    struct MockCommandRunner {
        recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
        fail_on_call: Option<usize>,
        fail_program: Option<String>,
        cancel_on_call: Option<(usize, CancellationToken)>,
        call_counter: Arc<AtomicUsize>,
    }

    impl MockCommandRunner {
        fn recorded_commands(&self) -> Vec<RecordedCommand> {
            self.recorded.lock().unwrap().clone()
        }
    }

    impl CommandRunner for MockCommandRunner {
        fn run_command<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
            env_vars: &'a [(String, String)],
            cancel: &'a CancellationToken,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let idx = self.call_counter.fetch_add(1, Ordering::SeqCst);
                if let Some((trigger_idx, ref token)) = self.cancel_on_call {
                    if idx == trigger_idx {
                        token.cancel();
                    }
                }
                if cancel.is_cancelled() {
                    return Err(PackageExecutorError::Cancelled(program.to_string()));
                }

                self.recorded.lock().unwrap().push(RecordedCommand {
                    program: program.to_string(),
                    args: args.to_vec(),
                    env: env_vars.to_vec(),
                });

                if self.fail_on_call == Some(idx)
                    || self.fail_program.as_deref() == Some(program)
                {
                    return Ok(CommandOutput {
                        exit_code: 100,
                        stdout: String::new(),
                        stderr: format!("simulated failure in {} {:?}", program, args),
                    });
                }

                // Simulate `id -u <user>` returning non-zero on first check so `useradd` is exercised
                if program == "id" {
                    return Ok(CommandOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "no such user".to_string(),
                    });
                }

                // Simulate `dpkg-query -W -f=${Version} <pkg>` returning a Debian epoch+revision version
                if program == "dpkg-query" {
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "1:0.14.2-1ubuntu2\n".to_string(),
                        stderr: String::new(),
                    });
                }

                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("ok: {} {}", program, args.join(" ")),
                    stderr: String::new(),
                })
            })
        }
    }

    fn create_isolated_test_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = env::temp_dir().join(format!(
            "af-runner-pkg-test-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn create_mock_elf_payload(size: usize) -> Vec<u8> {
        create_mock_elf_payload_for_arch(size, 62) // EM_X86_64 = 62
    }

    fn create_mock_elf_payload_for_arch(size: usize, e_machine: u16) -> Vec<u8> {
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.resize(size.max(2048), 0x90);
        // ELF little-endian (EI_DATA = 1 at offset 5) and e_machine at offset 18..20
        data[4] = if e_machine == 40 { 1 } else { 2 }; // ELFCLASS32 for ARM, ELFCLASS64 for x86_64/aarch64
        data[5] = 1; // ELFDATA2LSB
        let machine_bytes = e_machine.to_le_bytes();
        data[18] = machine_bytes[0];
        data[19] = machine_bytes[1];
        data
    }

    #[test]
    fn test_builtin_recipes_validate_cleanly() {
        // Accessing BUILTIN_DECLARATIVE_RECIPES must never panic and every registered recipe
        // must pass strict security validation and have full install, update, and remove steps.
        let ids = list_declarative_recipe_ids();
        let expected_ids = vec![
            "fail2ban".to_string(),
            "mergerfs".to_string(),
            "netdata".to_string(),
            "novnc".to_string(),
            "prometheus".to_string(),
            "quassel".to_string(),
            "rclone".to_string(),
            "syncthing".to_string(),
            "threadfin".to_string(),
            "x2go".to_string(),
            "xrdp".to_string(),
            "znc".to_string(),
        ];
        assert_eq!(ids, expected_ids);

        for id in &ids {
            let recipe = get_declarative_recipe(id).expect("registered recipe must resolve");
            recipe
                .validate()
                .expect("recipe must pass strict security validation");
            assert!(
                !recipe.install_steps.is_empty(),
                "recipe {} must have install_steps",
                id
            );
            assert!(
                !recipe.steps_for_action(PackageAction::Update).is_empty(),
                "recipe {} must have update steps",
                id
            );
            assert!(
                !recipe.remove_steps.is_empty(),
                "recipe {} must have remove_steps",
                id
            );
        }

        // Preserve security validation coverage for unsafe shared system root chown patterns:
        let bad_threadfin_dirs = DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/threadfin".to_string(),
                "/usr/local/bin".to_string(),
            ],
            mode: 0o755,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 30,
            description: "unsafe shared root chown".to_string(),
        };
        assert!(validate_step(&bad_threadfin_dirs).is_err());

        let bad_quassel_dirs = DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/quassel".to_string(),
                "/etc/default".to_string(),
            ],
            mode: 0o750,
            owner: Some("quasselcore".to_string()),
            group: Some("quasselcore".to_string()),
            progress_pct: 30,
            description: "unsafe /etc/default directory mutation".to_string(),
        };
        assert!(validate_step(&bad_quassel_dirs).is_err());

        let bad_tls_subj = DeclarativeStep::GenerateSelfSignedTlsCert {
            cert_path: "/var/lib/quassel/quasselCert.pem".to_string(),
            key_out_path: None,
            days: 3650,
            subject: "/CN=Bad;rm -rf /".to_string(),
            mode: 0o600,
            owner: Some("quasselcore".to_string()),
            group: Some("quasselcore".to_string()),
            overwrite: false,
            progress_pct: 50,
            description: "unsafe subject".to_string(),
        };
        assert!(validate_step(&bad_tls_subj).is_err());
    }

    #[test]
    fn test_engine_selection_and_legacy_bash_fallback() {
        // Default gate is OFF when AETHERFLOW_ENABLE_RUST_PACKAGES is unset
        assert_eq!(
            select_package_engine("fail2ban"),
            PackageEngineMode::LegacyBashFallback
        );
        assert_eq!(
            select_package_engine("quassel"),
            PackageEngineMode::LegacyBashFallback
        );
        assert_eq!(
            select_package_engine("threadfin"),
            PackageEngineMode::LegacyBashFallback
        );
        assert_eq!(
            select_package_engine("plex"),
            PackageEngineMode::LegacyBashFallback
        );

        // Explicit flag evaluation:
        assert_eq!(
            select_package_engine_with_flags("fail2ban", false, false),
            PackageEngineMode::LegacyBashFallback
        );
        assert_eq!(
            select_package_engine_with_flags("fail2ban", true, false),
            PackageEngineMode::DeclarativeRust
        );
        // FORCE_BASH overrides ENABLE_RUST
        assert_eq!(
            select_package_engine_with_flags("fail2ban", true, true),
            PackageEngineMode::LegacyBashFallback
        );
        // Migrated packages execute via DeclarativeRust when enabled
        assert_eq!(
            select_package_engine_with_flags("quassel", true, false),
            PackageEngineMode::DeclarativeRust
        );
        assert_eq!(
            select_package_engine_with_flags("threadfin", true, false),
            PackageEngineMode::DeclarativeRust
        );
        // Unmigrated packages remain on LegacyBashFallback even when Rust packages are enabled
        assert_eq!(
            select_package_engine_with_flags("sonarr", true, false),
            PackageEngineMode::LegacyBashFallback
        );
    }

    #[tokio::test]
    async fn test_quassel_install_update_remove_and_rollback_in_isolated_root() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("quassel-lifecycle");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        let recipe = get_declarative_recipe("quassel").expect("quassel recipe must be registered");

        // 1. Install
        let mock = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
        let install_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel install must succeed");
        assert!(install_outcome.lock_present);
        assert!(root.join("install/.quassel.lock").is_file());
        assert!(root.join("var/lib/quassel/quasselCert.pem").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(root.join("var/lib/quassel/quasselCert.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(
            fs::read_to_string(root.join("var/lib/quassel/.af-version"))
                .unwrap()
                .trim(),
            "0.14.2"
        );
        let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
        assert!(default_cfg.contains("PORT=\"4242\""));
        assert!(root
            .join("etc/systemd/system/quasselcore.service")
            .is_file());

        let cmds = mock.recorded_commands();
        assert!(cmds
            .iter()
            .any(|c| c.program == "openssl" && c.args.contains(&"-x509".to_string())));
        assert!(cmds
            .iter()
            .any(|c| c.program == "dpkg-query" && c.args.contains(&"quassel-core".to_string())));

        // 2. Update
        let update_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel update must succeed");
        assert!(update_outcome.lock_present);

        // 3. Remove (with delete_data = true)
        env_cfg.delete_data = true;
        let executor_rm = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
        let remove_outcome = executor_rm
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel remove must succeed");
        assert!(!remove_outcome.lock_present);
        assert!(!root.join("install/.quassel.lock").exists());
        assert!(!root.join("etc/default/quasselcore").exists());
        assert!(!root.join("var/lib/quassel").exists());

        // 4. Failure rollback on fresh isolated root
        let fail_root = create_isolated_test_dir("quassel-rollback");
        let fail_env = PackageExecutionEnv::isolated(&fail_root);
        // Fail on systemctl enable --now after TLS cert, .af-version, and /etc/default/quasselcore were written
        let fail_mock = MockCommandRunner {
            fail_on_call: Some(8),
            ..Default::default()
        };
        let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
        let err = fail_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("systemctl"));
        assert!(!fail_root.join("install/.quassel.lock").exists());
        assert!(!fail_root.join("var/lib/quassel/quasselCert.pem").exists());
        assert!(!fail_root.join("var/lib/quassel/.af-version").exists());
        assert!(!fail_root.join("etc/default/quasselcore").exists());
        assert!(!fail_root
            .join("etc/systemd/system/quasselcore.service")
            .exists());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&fail_root);
    }

    #[tokio::test]
    async fn test_threadfin_install_update_remove_and_rollback_in_isolated_root() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("threadfin-lifecycle");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        let elf_bytes = create_mock_elf_payload_for_arch(4096, 62);
        let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();

        let mut recipe =
            get_declarative_recipe("threadfin").expect("threadfin recipe must be registered");
        for step in &mut recipe.install_steps {
            if let DeclarativeStep::DownloadBinary { verification, .. } = step {
                verification.expected_sha256 = Some(hex::encode(Sha256::digest(&elf_bytes)));
            }
        }

        // 1. Install
        let mock = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock);
        let install_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin install must succeed");
        assert!(install_outcome.lock_present);
        assert!(root.join("install/.threadfin.lock").is_file());
        assert!(root.join("usr/local/bin/threadfin").is_file());
        assert_eq!(
            fs::read_to_string(root.join("var/lib/threadfin/.af-version"))
                .unwrap()
                .trim(),
            THREADFIN_PINNED_VERSION
        );
        let unit = fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
        assert!(unit.contains("-port=34400"));

        // 2. Update
        let update_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin update must succeed");
        assert!(update_outcome.lock_present);

        // 3. Remove (with delete_data = true)
        env_cfg.delete_data = true;
        let executor_rm =
            DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
        let remove_outcome = executor_rm
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin remove must succeed");
        assert!(!remove_outcome.lock_present);
        assert!(!root.join("install/.threadfin.lock").exists());
        assert!(!root.join("usr/local/bin/threadfin").exists());
        assert!(!root.join("var/lib/threadfin").exists());

        // 4. Failure rollback on fresh isolated root
        let fail_root = create_isolated_test_dir("threadfin-rollback");
        let fail_env = PackageExecutionEnv::isolated(&fail_root);
        let fail_cache = fail_env.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&fail_cache).unwrap();
        fs::write(fail_cache.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();
        // Fail on systemctl enable --now after binary, .af-version, and systemd unit were written
        let fail_mock = MockCommandRunner {
            fail_on_call: Some(5),
            ..Default::default()
        };
        let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
        let err = fail_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("systemctl"));
        assert!(!fail_root.join("install/.threadfin.lock").exists());
        assert!(!fail_root.join("usr/local/bin/threadfin").exists());
        assert!(!fail_root.join("var/lib/threadfin/.af-version").exists());
        assert!(!fail_root
            .join("etc/systemd/system/threadfin.service")
            .exists());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&fail_root);
    }

    #[test]
    fn test_security_boundary_rejects_traversal_and_forbidden_paths() {
        assert!(validate_managed_path("/etc/fail2ban/jail.local").is_ok());
        assert!(validate_managed_path("/var/lib/threadfin/conf").is_ok());
        assert!(validate_managed_path("/install/.fail2ban.lock").is_ok());
        assert!(validate_managed_path("/var/lib/quassel/quasselCert.pem").is_ok());
        assert!(validate_managed_path("/etc/default/quasselcore").is_ok());

        // Reject relative paths, parent traversal, and root/critical/shared files
        assert!(validate_managed_path("etc/fail2ban").is_err());
        assert!(validate_managed_path("/etc/fail2ban/../../etc/shadow").is_err());
        assert!(validate_managed_path("/etc/passwd").is_err());
        assert!(validate_managed_path("/etc/shadow").is_err());
        assert!(validate_managed_path("/etc").is_err());
        assert!(validate_managed_path("/etc/default").is_err());
        assert!(validate_managed_path("/usr/local/bin").is_err());
        assert!(validate_managed_path("/").is_err());
        assert!(validate_managed_path("/home/user/.bashrc").is_err());

        // Reject recursive chown on shared system roots
        assert!(validate_chown_target_path("/usr/local/bin").is_err());
        assert!(validate_chown_target_path("/etc/default").is_err());
        assert!(validate_chown_target_path("/etc").is_err());
        assert!(validate_chown_target_path("/var/lib").is_err());
        assert!(validate_chown_target_path("/var/lib/fail2ban").is_ok());

        // Reject shell injection in APT package names
        let bad_step = DeclarativeStep::AptInstall {
            packages: vec!["fail2ban; rm -rf /".to_string()],
            progress_pct: 20,
            description: "bad".to_string(),
        };
        assert!(validate_step(&bad_step).is_err());

        // Reject root user purge
        let bad_user = DeclarativeStep::PurgeSystemUser {
            username: "root".to_string(),
            progress_pct: 50,
            description: "bad".to_string(),
        };
        assert!(validate_step(&bad_user).is_err());
    }

    #[test]
    fn test_artifact_verification_size_magic_and_sha256() {
        let root = create_isolated_test_dir("artifact-verify");
        let small_file = root.join("small.bin");
        fs::write(&small_file, b"404: Not Found").unwrap();

        let default_policy = ArtifactVerificationPolicy::default();
        let err = verify_artifact_file(&small_file, &default_policy).unwrap_err();
        assert!(err.to_string().contains("too small"));

        // Valid ELF payload with matching SHA-256
        let elf_path = root.join("threadfin.bin");
        let elf_bytes = create_mock_elf_payload(4096);
        let expected_hash = hex::encode(Sha256::digest(&elf_bytes));
        fs::write(&elf_path, &elf_bytes).unwrap();

        let strict_policy = ArtifactVerificationPolicy {
            min_size_bytes: 1024,
            max_size_bytes: 1024 * 1024,
            expected_sha256: Some(expected_hash.clone()),
            arch_sha256: None,
            require_gzip_magic: false,
            require_elf_magic: true,
        };
        let actual_hash = verify_artifact_file(&elf_path, &strict_policy).unwrap();
        assert_eq!(actual_hash, expected_hash);

        // Wrong SHA-256 must fail
        let wrong_sha_policy = ArtifactVerificationPolicy {
            expected_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            ..strict_policy
        };
        assert!(verify_artifact_file(&elf_path, &wrong_sha_policy).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_fail2ban_install_and_remove_parity_in_isolated_root() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("fail2ban-lifecycle");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        // Seed custom SSH port in isolated /etc/ssh/sshd_config
        let sshd_cfg = root.join("etc/ssh/sshd_config");
        fs::create_dir_all(sshd_cfg.parent().unwrap()).unwrap();
        fs::write(
            &sshd_cfg,
            "# OpenSSH config\nPort 2222\nPermitRootLogin no\n",
        )
        .unwrap();

        let mock = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
        let recipe = get_declarative_recipe("fail2ban").unwrap();

        let mut events = Vec::new();
        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |ev| events.push(ev),
            )
            .await
            .expect("fail2ban install should succeed");

        assert!(outcome.lock_present);
        assert!(root.join("install/.fail2ban.lock").is_file());

        // Verify jail.local content matches installpackage-fail2ban parity including custom SSH port
        let jail_local = fs::read_to_string(root.join("etc/fail2ban/jail.local")).unwrap();
        assert!(jail_local.contains("backend  = systemd"));
        assert!(jail_local.contains("port    = 2222,ssh"));

        // Verify structured progress monotonically reaches 100%
        assert!(!events.is_empty());
        assert_eq!(events.last().unwrap().progress_pct, 100);
        assert_eq!(events.last().unwrap().phase, ExecutionPhase::Complete);

        // Verify SandboxApply was emitted BEFORE the systemctl activation steps
        let sandbox_pos = events
            .iter()
            .position(|e| e.phase == ExecutionPhase::SandboxApply)
            .expect("SandboxApply phase must be emitted");
        let last_step_pos = events
            .iter()
            .rposition(|e| e.phase == ExecutionPhase::ExecuteStep)
            .expect("ExecuteStep phase must be emitted");
        assert!(
            sandbox_pos < last_step_pos,
            "systemd sandbox drop-in must be applied before systemctl activation steps complete"
        );

        // Verify recorded commands used non-shell argv execution
        let cmds = mock.recorded_commands();
        assert!(cmds
            .iter()
            .any(|c| c.program == "apt-get" && c.args.contains(&"fail2ban".to_string())));
        assert!(cmds
            .iter()
            .any(|c| c.program == "systemctl" && c.args.contains(&"fail2ban.service".to_string())));

        // Now execute Remove and verify cleanup + lock removal
        fs::create_dir_all(root.join("run/fail2ban")).unwrap();
        #[cfg(unix)]
        {
            fs::create_dir_all(root.join("var")).unwrap();
            std::os::unix::fs::symlink("../run", root.join("var/run")).unwrap();
        }
        let remove_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("fail2ban remove should succeed");

        assert!(!remove_outcome.lock_present);
        assert!(!root.join("install/.fail2ban.lock").exists());
        assert!(root.join("etc/fail2ban/jail.local").is_file());
        assert!(!root.join("run/fail2ban").exists());
        assert_eq!(outcome.resolved_version.as_deref(), Some("0.14.2"));
        assert!(mock
            .recorded_commands()
            .iter()
            .any(|command| command.program == "apt-get"
                && command.args.iter().any(|arg| arg == "remove")));

        let mut purge_env = env_cfg;
        purge_env.delete_data = true;
        let purge_executor = DeclarativePackageExecutor::with_runner(purge_env, mock.clone());
        purge_executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("explicit purge should remove application data");
        assert!(!root.join("etc/fail2ban").exists());
        assert!(mock.recorded_commands().iter().any(
            |command| command.program == "apt-get" && command.args.iter().any(|arg| arg == "purge")
        ));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_verified_elf_binary_recipe_and_pre_service_sandbox() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("elf-binary-install");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 34400;

        // Stage mock ELF binary in isolated artifact cache with pinned SHA-256
        let elf_bytes = create_mock_elf_payload(4096);
        let expected_sha256 = hex::encode(Sha256::digest(&elf_bytes));
        let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();

        let recipe = DeclarativePackageRecipe {
            package_id: "threadfin".to_string(),
            label: "Threadfin".to_string(),
            lock_file: "/install/.threadfin.lock".to_string(),
            service_name: "threadfin".to_string(),
            default_port: 34400,
            apply_systemd_sandbox: true,
            install_steps: vec![
                DeclarativeStep::EnsureSystemUser {
                    username: "threadfin".to_string(),
                    home_dir: "/var/lib/threadfin".to_string(),
                    create_home: true,
                    progress_pct: 15,
                    description: "Ensuring threadfin user...".to_string(),
                },
                DeclarativeStep::EnsureDirectories {
                    paths: vec![
                        "/var/lib/threadfin".to_string(),
                        "/var/lib/threadfin/conf".to_string(),
                    ],
                    mode: 0o755,
                    owner: Some("threadfin".to_string()),
                    group: Some("threadfin".to_string()),
                    progress_pct: 30,
                    description: "Creating threadfin state directories...".to_string(),
                },
                DeclarativeStep::ResolveGitHubReleaseTag {
                    repo: "Threadfin/Threadfin".to_string(),
                    fallback_version: "1.2.37".to_string(),
                    strip_v_prefix: true,
                    progress_pct: 45,
                    description: "Resolving Threadfin release tag...".to_string(),
                },
                DeclarativeStep::DownloadBinary {
                    url_template: "https://example.invalid/{{TAG}}/{{ARCH_ASSET}}".to_string(),
                    arch_map: ArchAssetMap {
                        amd64: "Threadfin_linux_amd64".to_string(),
                        arm64: "Threadfin_linux_arm64".to_string(),
                        armhf: None,
                    },
                    dest_path: "/usr/local/bin/threadfin".to_string(),
                    mode: 0o755,
                    verification: ArtifactVerificationPolicy {
                        min_size_bytes: 1024,
                        max_size_bytes: 10 * 1024 * 1024,
                        expected_sha256: Some(expected_sha256),
                        arch_sha256: None,
                        require_gzip_magic: false,
                        require_elf_magic: true,
                    },
                    progress_pct: 65,
                    description: "Installing verified Threadfin ELF binary...".to_string(),
                },
                DeclarativeStep::WriteTemplateFile {
                    path: "/var/lib/threadfin/.af-version".to_string(),
                    content_template: "{{VERSION}}\n".to_string(),
                    mode: 0o644,
                    overwrite: true,
                    owner: Some("threadfin".to_string()),
                    group: Some("threadfin".to_string()),
                    progress_pct: 75,
                    description: "Recording Threadfin version...".to_string(),
                },
                DeclarativeStep::WriteSystemdUnit {
                    unit_name: "threadfin.service".to_string(),
                    content_template: "[Unit]\nDescription=Threadfin\n[Service]\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}}\n".to_string(),
                    progress_pct: 85,
                    description: "Writing threadfin.service...".to_string(),
                },
                DeclarativeStep::Systemctl {
                    unit: None,
                    operation: SystemctlOp::DaemonReload,
                    ignore_errors: false,
                    progress_pct: 90,
                    description: "Reloading systemd...".to_string(),
                },
                DeclarativeStep::Systemctl {
                    unit: Some("threadfin.service".to_string()),
                    operation: SystemctlOp::EnableNow,
                    ignore_errors: false,
                    progress_pct: 95,
                    description: "Enabling and starting threadfin.service...".to_string(),
                },
            ],
            update_steps: Vec::new(),
            remove_steps: Vec::new(),
        };

        let mock = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);

        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("verified ELF binary recipe should succeed");

        assert!(outcome.lock_present);
        assert!(root.join("usr/local/bin/threadfin").is_file());
        assert_eq!(
            fs::read_to_string(root.join("var/lib/threadfin/.af-version"))
                .unwrap()
                .trim(),
            "1.2.37"
        );
        let unit = fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
        assert!(unit.contains("-port=34400"));

        // Verify systemd sandbox drop-in was generated for threadfin.service
        let dropin = root.join("etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf");
        assert!(dropin.is_file());
        let dropin_text = fs::read_to_string(dropin).unwrap();
        assert!(dropin_text.contains("NoNewPrivileges=yes"));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_failure_triggers_rollback_and_preserves_prior_config_and_lock_absence() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("rollback-recovery");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        // Pre-populate an existing /etc/fail2ban/jail.local to verify .bak-af rollback restoration
        let jail_path = root.join("etc/fail2ban/jail.local");
        fs::create_dir_all(jail_path.parent().unwrap()).unwrap();
        fs::write(&jail_path, "# previous user custom config\nmaxretry = 9\n").unwrap();

        let mock = MockCommandRunner {
            fail_on_call: Some(5),
            ..Default::default()
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
        let recipe = get_declarative_recipe("fail2ban").unwrap();

        let mut phases = Vec::new();
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |ev| phases.push(ev.phase),
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("systemctl"));
        assert!(phases.contains(&ExecutionPhase::Rollback));
        assert!(phases.contains(&ExecutionPhase::Failed));

        // Lockfile must NOT have been written
        assert!(!root.join("install/.fail2ban.lock").exists());

        // Previous jail.local must be restored from .bak-af and .bak-af cleaned up
        let restored = fs::read_to_string(&jail_path).unwrap();
        assert_eq!(restored, "# previous user custom config\nmaxretry = 9\n");
        assert!(!root.join("etc/fail2ban/jail.local.bak-af").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_cancellation_aborts_execution_and_rolls_back() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("cancellation");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let cancel = CancellationToken::new();

        // Trigger cancellation on the 2nd command call (`systemctl daemon-reload`)
        let mock = MockCommandRunner {
            cancel_on_call: Some((2, cancel.clone())),
            ..Default::default()
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
        let recipe = get_declarative_recipe("fail2ban").unwrap();

        let mut phases = Vec::new();
        let err = executor
            .execute_recipe(&recipe, PackageAction::Install, cancel, |ev| {
                phases.push(ev.phase)
            })
            .await
            .unwrap_err();

        assert!(matches!(err, PackageExecutorError::Cancelled(_)));
        assert!(phases.contains(&ExecutionPhase::Rollback));
        assert!(phases.contains(&ExecutionPhase::Cancelled));
        assert!(!root.join("install/.fail2ban.lock").exists());
        assert!(!root.join("etc/fail2ban/jail.local").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_duplicate_concurrent_package_registration_rejected() {
        let tok1 = CancellationToken::new();
        let guard = register_package_cancellation("quassel", tok1).unwrap();
        assert!(is_package_execution_active("quassel"));

        let tok2 = CancellationToken::new();
        let dup_err = register_package_cancellation("quassel", tok2);
        assert!(matches!(
            dup_err,
            Err(PackageExecutorError::LockConflict(_))
        ));

        assert!(cancel_package_execution("quassel"));
        drop(guard);
        assert!(!is_package_execution_active("quassel"));
    }

    #[test]
    fn test_targz_extraction_rejects_missing_or_non_elf_member() {
        let root = create_isolated_test_dir("targz-extract");
        let archive_path = root.join("sample.tar.gz");
        let dest_dir = root.join("usr/local/bin");
        fs::create_dir_all(&dest_dir).unwrap();

        // Build a valid .tar.gz containing an ELF binary `autobrr`
        {
            let file = File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::default());
            let mut tar = tar::Builder::new(enc);
            let payload = create_mock_elf_payload(2048);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, "autobrr", payload.as_slice())
                .unwrap();
            tar.finish().unwrap();
        }

        let mut journal = RollbackJournal::new(Some(root.clone()));
        extract_binaries_from_targz(
            &archive_path,
            &dest_dir,
            &["autobrr".to_string()],
            0o755,
            true,
            &mut journal,
        )
        .expect("valid ELF member should extract cleanly");
        assert!(dest_dir.join("autobrr").is_file());

        // Requesting a non-existent binary member must fail
        let missing_err = extract_binaries_from_targz(
            &archive_path,
            &dest_dir,
            &["missing-bin".to_string()],
            0o755,
            true,
            &mut journal,
        )
        .unwrap_err();
        assert!(missing_err.to_string().contains("missing-bin"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_cross_process_lock_preserves_inode_and_does_not_truncate_on_conflict() {
        let root = create_isolated_test_dir("flock-inode");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        let guard1 = CrossProcessLockGuard::try_acquire(&env_cfg, "fail2ban")
            .expect("initial lock acquisition must succeed");
        let flock_path = guard1.lock_file_path.clone();
        assert!(flock_path.is_file());

        let initial_content = fs::read_to_string(&flock_path).unwrap();
        assert!(initial_content.contains("pkg=fail2ban"));

        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt;
            let ino = fs::metadata(&flock_path).unwrap().ino();

            // Contending lock attempt must fail with LockConflict WITHOUT truncating the file
            let conflict_err = CrossProcessLockGuard::try_acquire(&env_cfg, "other-pkg");
            assert!(matches!(
                conflict_err,
                Err(PackageExecutorError::LockConflict(_))
            ));
            let content_during_conflict = fs::read_to_string(&flock_path).unwrap();
            assert_eq!(
                content_during_conflict, initial_content,
                "contending opener must not truncate persistent lock file before acquiring flock"
            );
            assert_eq!(fs::metadata(&flock_path).unwrap().ino(), ino);
            ino
        };

        drop(guard1);
        // Persistent flock file must NEVER be unlinked on Drop
        assert!(
            flock_path.is_file(),
            "persistent flock file must remain on disk after guard drop"
        );

        let guard2 = CrossProcessLockGuard::try_acquire(&env_cfg, "other-pkg")
            .expect("second lock acquisition after drop must succeed");
        let updated_content = fs::read_to_string(&flock_path).unwrap();
        assert!(updated_content.contains("pkg=other-pkg"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode_after = fs::metadata(&flock_path).unwrap().ino();
            assert_eq!(
                inode_before, inode_after,
                "persistent flock file must retain the exact same inode across lock cycles"
            );
        }
        drop(guard2);

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_queued_lock_wait_honors_cancellation_and_rejects_duplicate_inflight() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("queued-cancel");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        // Hold the process-wide package mutex to force the next operation to queue
        let held_mutex = crate::PACKAGE_MUTEX.lock().await;

        let mock = MockCommandRunner::default();
        let executor = Arc::new(DeclarativePackageExecutor::with_runner(env_cfg, mock));
        let recipe = get_declarative_recipe("fail2ban").unwrap();
        let cancel = CancellationToken::new();

        let exec_clone = Arc::clone(&executor);
        let recipe_clone = recipe.clone();
        let cancel_clone = cancel.clone();
        let queued_task = tokio::spawn(async move {
            exec_clone
                .execute_recipe(&recipe_clone, PackageAction::Install, cancel_clone, |_| {})
                .await
        });

        // Wait briefly until the queued task registers its in-flight cancellation token
        for _ in 0..50 {
            if is_package_execution_active("fail2ban") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            is_package_execution_active("fail2ban"),
            "queued task must register cancellation before waiting on PACKAGE_MUTEX"
        );

        // Duplicate in-flight operation for the same package ID must be rejected immediately
        let dup_res = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await;
        assert!(matches!(
            dup_res,
            Err(PackageExecutorError::LockConflict(_))
        ));

        // Cancel the queued operation while `held_mutex` is still held
        assert!(cancel_package_execution("fail2ban"));

        let queued_res = tokio::time::timeout(Duration::from_secs(2), queued_task)
            .await
            .expect("queued task must abort promptly on cancellation without waiting for mutex")
            .unwrap();
        assert!(matches!(
            queued_res,
            Err(PackageExecutorError::Cancelled(_))
        ));
        assert!(!is_package_execution_active("fail2ban"));

        drop(held_mutex);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ancestor_symlink_escape_and_unexpected_lstat_errors_propagated() {
        let root = create_isolated_test_dir("ancestor-lstat");
        let outside = create_isolated_test_dir("ancestor-outside");

        // 1. Verify non-NotFound lstat errors (e.g. PermissionDenied / EACCES) are propagated
        // rather than swallowed as NotFound.
        let target = root.join("etc/fail2ban/jail.local");
        let perm_err = validate_path_ancestors_with_lstat(&target, Some(&root), |p| {
            if p.ends_with("fail2ban") {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated EACCES on ancestor",
                ))
            } else {
                fs::symlink_metadata(p).map(|metadata| metadata.file_type().is_symlink())
            }
        });
        assert!(matches!(perm_err, Err(PackageExecutorError::Io(_))));

        // 2. On Unix, verify symlinked ancestor directory and ENOTDIR ancestor are rejected
        #[cfg(unix)]
        {
            let etc_dir = root.join("etc");
            fs::create_dir_all(&etc_dir).unwrap();
            let symlink_dir = etc_dir.join("fail2ban");
            std::os::unix::fs::symlink(&outside, &symlink_dir).unwrap();

            let env_cfg = PackageExecutionEnv::isolated(&root);
            let sym_res = env_cfg.resolve_path("/etc/fail2ban/jail.local");
            assert!(
                matches!(sym_res, Err(PackageExecutorError::SecurityViolation(_))),
                "symlink ancestor must be rejected with SecurityViolation"
            );

            // Create regular file `etc/not_a_dir` and query `etc/not_a_dir/child/conf` -> ENOTDIR Io error
            let file_ancestor = etc_dir.join("not_a_dir");
            fs::write(&file_ancestor, b"not a directory").unwrap();
            let enotdir_path = file_ancestor.join("child").join("conf");
            let enotdir_res = validate_filesystem_path(&enotdir_path, Some(&root));
            assert!(
                matches!(enotdir_res, Err(PackageExecutorError::Io(_))),
                "ENOTDIR on ancestor traversal must propagate as PackageExecutorError::Io"
            );
        }

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_tokio_command_runner_process_group_cancellation_and_bounded_output() {
        let runner = TokioCommandRunner;

        // 1. Process-group cancellation: child spawns a background grandchild that inherits
        // stdout/stderr and sleeps for 60s. Cancelling must kill the entire process group
        // and return promptly without hanging on the grandchild's open pipe.
        let cancel = CancellationToken::new();
        let cancel_trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            cancel_trigger.cancel();
        });

        let args = vec![
            "-c".to_string(),
            "sh -c 'sleep 60' & sleep 60".to_string(),
        ];
        let res = tokio::time::timeout(
            Duration::from_secs(3),
            runner.run_command("sh", &args, &[], &cancel),
        )
        .await
        .expect("process-group cancellation must not hang waiting on background descendant pipes");
        assert!(matches!(res, Err(PackageExecutorError::Cancelled(_))));

        // 2. Bounded output retention: command emitting > MAX_COMMAND_OUTPUT_BYTES must be
        // drained cleanly without OOM or pipe deadlock, and truncated with marker.
        let noisy_args = vec![
            "-c".to_string(),
            "head -c 150000 /dev/zero | tr '\\0' 'A'".to_string(),
        ];
        let out = runner
            .run_command("sh", &noisy_args, &[], &CancellationToken::new())
            .await
            .expect("noisy command should succeed with bounded output");
        assert!(out.success());
        assert!(out.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES + 64);
        assert!(out.stdout.contains("[output truncated]"));
    }

    #[tokio::test]
    async fn test_live_progress_stream_emits_events_before_step_completion() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("live-stream");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        #[derive(Clone)]
        struct GatedRunner {
            step_entered: Arc<tokio::sync::Notify>,
            allow_finish: Arc<tokio::sync::Notify>,
            first_call: Arc<AtomicBool>,
        }

        impl CommandRunner for GatedRunner {
            fn run_command<'a>(
                &'a self,
                program: &'a str,
                args: &'a [String],
                _env_vars: &'a [(String, String)],
                cancel: &'a CancellationToken,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    if !self.first_call.swap(true, Ordering::SeqCst) {
                        self.step_entered.notify_one();
                        self.allow_finish.notified().await;
                    }
                    if cancel.is_cancelled() {
                        return Err(PackageExecutorError::Cancelled(program.to_string()));
                    }
                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: format!("ok: {} {}", program, args.join(" ")),
                        stderr: String::new(),
                    })
                })
            }
        }

        let step_entered = Arc::new(tokio::sync::Notify::new());
        let allow_finish = Arc::new(tokio::sync::Notify::new());
        let runner = GatedRunner {
            step_entered: Arc::clone(&step_entered),
            allow_finish: Arc::clone(&allow_finish),
            first_call: Arc::new(AtomicBool::new(false)),
        };

        let executor = Arc::new(DeclarativePackageExecutor::with_runner(env_cfg, runner));
        let recipe = get_declarative_recipe("fail2ban").unwrap();
        let mut stream = std::pin::pin!(execute_declarative_recipe_stream(
            executor,
            recipe,
            PackageAction::Install,
            CancellationToken::new(),
        ));

        // Wait until Step 1 (`apt-get update`) is actively blocked inside `run_command`
        let first_line = futures::StreamExt::next(&mut stream)
            .await
            .expect("stream must yield LockAcquire event before completion")
            .unwrap();
        assert!(first_line.contains("[PROGRESS:5]"));

        let second_line = futures::StreamExt::next(&mut stream)
            .await
            .expect("stream must yield Step 1 progress event while Step 1 is still in-flight")
            .unwrap();
        assert!(second_line.contains("[PROGRESS:20]"));
        step_entered.notified().await;

        // Release Step 1 and drain remaining stream events to 100% completion
        allow_finish.notify_one();
        let mut lines = vec![first_line, second_line];
        while let Some(item) = futures::StreamExt::next(&mut stream).await {
            lines.push(item.unwrap());
        }
        assert!(lines.last().unwrap().contains("[PROGRESS:100]"));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_quassel_install_update_remove_and_cert_data_preservation() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("quassel-lifecycle");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        // Verify custom app_port propagates to /etc/default/quasselcore
        env_cfg.app_port = 4249;

        // Custom runner that simulates openssl writing a cert file when invoked
        #[derive(Clone, Default)]
        struct QuasselMockRunner {
            recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
            fail_systemctl_restart: bool,
        }

        impl CommandRunner for QuasselMockRunner {
            fn run_command<'a>(
                &'a self,
                program: &'a str,
                args: &'a [String],
                env_vars: &'a [(String, String)],
                cancel: &'a CancellationToken,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    if cancel.is_cancelled() {
                        return Err(PackageExecutorError::Cancelled(program.to_string()));
                    }
                    self.recorded.lock().unwrap().push(RecordedCommand {
                        program: program.to_string(),
                        args: args.to_vec(),
                        env: env_vars.to_vec(),
                    });

                    if program == "id" {
                        return Ok(CommandOutput {
                            exit_code: 1,
                            stdout: String::new(),
                            stderr: "no such user".to_string(),
                        });
                    }
                    if program == "dpkg-query" {
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "1:0.14.0-1ubuntu2\n".to_string(),
                            stderr: String::new(),
                        });
                    }
                    if program == "openssl" {
                        // Find `-out` and `-keyout` argument and write synthetic PEM payload
                        if let Some(pos) = args.iter().position(|a| a == "-out") {
                            if let Some(out_path) = args.get(pos + 1) {
                                fs::write(
                                    out_path,
                                    b"-----BEGIN PRIVATE KEY-----\nNEWKEY\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nNEWCERT\n-----END CERTIFICATE-----\n",
                                )
                                .unwrap();
                            }
                        }
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "Certificate generated".to_string(),
                            stderr: String::new(),
                        });
                    }
                    if self.fail_systemctl_restart
                        && program == "systemctl"
                        && args.iter().any(|a| a == "restart")
                    {
                        return Ok(CommandOutput {
                            exit_code: 1,
                            stdout: String::new(),
                            stderr: "simulated systemctl restart failure".to_string(),
                        });
                    }
                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: format!("ok: {} {}", program, args.join(" ")),
                        stderr: String::new(),
                    })
                })
            }
        }

        let runner = QuasselMockRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
        let recipe = get_declarative_recipe("quassel").unwrap();

        let mut install_events = Vec::new();
        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |ev| install_events.push(ev),
            )
            .await
            .expect("quassel install should succeed");

        assert!(outcome.lock_present);
        assert!(root.join("install/.quassel.lock").is_file());
        assert_eq!(outcome.resolved_version.as_deref(), Some("0.14.0"));
        let install_commands = runner.recorded.lock().unwrap().clone();
        let certificate_command = install_commands
            .iter()
            .position(|command| command.program == "openssl")
            .expect("TLS credentials must be provisioned");
        let quassel_install_command = install_commands
            .iter()
            .position(|command| {
                command.program == "apt-get"
                    && command.args.contains(&"install".to_string())
                    && command.args.contains(&"quassel-core".to_string())
            })
            .expect("quassel-core must be installed");
        assert!(certificate_command < quassel_install_command);
        assert!(install_commands[quassel_install_command].args.contains(&"DPkg::Options::=--force-confold".to_string()));
        let defaults_step = recipe.install_steps.iter().position(|step| matches!(
            step, DeclarativeStep::WriteTemplateFile { path, .. } if path == "/etc/default/quasselcore"
        )).unwrap();
        let package_step = recipe.install_steps.iter().position(|step| matches!(
            step, DeclarativeStep::AptInstall { packages, .. } if packages.iter().any(|package| package == "quassel-core")
        )).unwrap();
        assert!(defaults_step < package_step);
        let sandbox_event = install_events.iter().position(|event| event.phase == ExecutionPhase::SandboxApply).unwrap();
        let first_install_event = install_events.iter().position(|event| event.phase == ExecutionPhase::ExecuteStep && event.message.contains("Installing")).unwrap();
        assert!(sandbox_event < first_install_event);

        // Verify dependencies, config, sandbox drop-in, cert, and version metadata
        let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
        assert!(default_cfg.contains("LISTEN=\"0.0.0.0\""));
        assert!(default_cfg.contains("PORT=\"4249\""));
        assert!(default_cfg.contains("CONFIGDIR=\"/var/lib/quassel\""));
        assert!(default_cfg.contains("LOGFILE=\"/var/log/quassel/quasselcore.log\""));

        let sandbox_cfg = fs::read_to_string(
            root.join("etc/systemd/system/quasselcore.service.d/aetherflow-sandbox.conf"),
        )
        .unwrap();
        assert!(sandbox_cfg.contains("ReadWritePaths=-/var/lib/quassel -/var/log/quassel"));

        let cert_path = root.join("var/lib/quassel/quasselCert.pem");
        assert!(cert_path.is_file());

        let version_marker =
            fs::read_to_string(root.join("var/lib/quassel/.af-version")).unwrap();
        assert_eq!(version_marker.trim(), "0.14.0");

        // Verify bounded monotonic progress
        assert!(!install_events.is_empty());
        for pair in install_events.windows(2) {
            assert!(pair[1].progress_pct >= pair[0].progress_pct);
        }
        assert_eq!(install_events.last().unwrap().progress_pct, 100);

        // Verify apt-get installed quassel-core and openssl
        let cmds = runner.recorded.lock().unwrap().clone();
        for dependency in ["quassel-core", "openssl"] {
            assert!(cmds.iter().any(|command| {
                command.program == "apt-get"
                    && command.args.contains(&"install".to_string())
                    && command.args.contains(&dependency.to_string())
            }));
        }
        assert!(cmds.iter().any(|c| c.program == "openssl"));

        // Seed custom certificate and SQLite database to verify preservation across reinstall/update/remove
        let custom_cert = b"-----BEGIN CERTIFICATE-----\nEXISTING_USER_CERT_DO_NOT_OVERWRITE\n-----END CERTIFICATE-----\n";
        fs::write(&cert_path, custom_cert).unwrap();
        let sqlite_db = root.join("var/lib/quassel/quassel-storage.sqlite");
        fs::write(&sqlite_db, b"SQLite format 3 user backlog data").unwrap();

        // Clear recorded commands and run Update
        runner.recorded.lock().unwrap().clear();
        let update_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel update should succeed");
        assert!(update_outcome.lock_present);
        assert_eq!(
            fs::read(&cert_path).unwrap(),
            custom_cert,
            "existing Quassel TLS certificate must be preserved on update"
        );
        assert!(
            !runner
                .recorded
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.program == "openssl"),
            "openssl must not be invoked when quasselCert.pem already exists"
        );

        // Even if a subsequent reinstall fails mid-flight and rolls back, pre-existing cert must survive!
        let failing_runner = QuasselMockRunner {
            recorded: Arc::new(StdMutex::new(Vec::new())),
            fail_systemctl_restart: true,
        };
        let failing_exec =
            DeclarativePackageExecutor::with_runner(env_cfg.clone(), failing_runner);
        let err = failing_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PackageExecutorError::StepFailed { .. }));
        assert_eq!(
            fs::read(&cert_path).unwrap(),
            custom_cert,
            "rollback on failed reinstall must never delete pre-existing quasselCert.pem"
        );
        assert!(
            sqlite_db.is_file(),
            "rollback must preserve existing Quassel SQLite database"
        );

        // Remove with delete_data = false (default): must remove /etc/default/quasselcore, lock, and sandbox drop-in,
        // but PRESERVE /var/lib/quassel & cert
        let remove_command_start = runner.recorded.lock().unwrap().len();
        let remove_preserve = executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel remove (preserve data) should succeed");
        assert!(!remove_preserve.lock_present);
        let remove_commands = runner.recorded.lock().unwrap()[remove_command_start..].to_vec();
        assert!(remove_commands.iter().any(|command| {
            command.program == "apt-get"
                && command.args.contains(&"remove".to_string())
                && command.args.contains(&"quassel-core".to_string())
        }));
        assert!(!remove_commands.iter().any(|command| {
            command.program == "apt-get" && command.args.contains(&"purge".to_string())
        }));
        assert!(!root.join("install/.quassel.lock").exists());
        assert!(!root.join("etc/default/quasselcore").exists());
        assert_eq!(
            fs::read(&cert_path).unwrap(),
            custom_cert,
            "quasselCert.pem must be preserved on remove when delete_data=false"
        );
        assert!(
            sqlite_db.is_file(),
            "quassel SQLite database must be preserved on remove when delete_data=false"
        );

        // Remove with delete_data = true: must purge /var/lib/quassel and /var/log/quassel
        let mut purge_env = env_cfg.clone();
        purge_env.delete_data = true;
        let purge_exec = DeclarativePackageExecutor::with_runner(purge_env, runner.clone());
        let purge_command_start = runner.recorded.lock().unwrap().len();
        purge_exec
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("quassel remove (purge data) should succeed");
        assert!(!root.join("var/lib/quassel").exists());
        assert!(!root.join("var/log/quassel").exists());
        let purge_commands = runner.recorded.lock().unwrap()[purge_command_start..].to_vec();
        assert!(purge_commands.iter().any(|command| {
            command.program == "apt-get"
                && command.args.contains(&"purge".to_string())
                && command.args.contains(&"quassel-core".to_string())
        }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_threadfin_recipe_verifies_pinned_digests_tamper_arch_and_https_fail_closed() {
        let recipe = get_declarative_recipe("threadfin").expect("threadfin recipe must exist");
        recipe
            .validate()
            .expect("threadfin recipe must validate cleanly");

        // Ensure no ResolveGitHubReleaseTag step or unverified latest download exists in threadfin
        let mut found_download_step = false;
        for step in recipe
            .install_steps
            .iter()
            .chain(recipe.update_steps.iter())
        {
            assert!(
                !matches!(step, DeclarativeStep::ResolveGitHubReleaseTag { .. }),
                "threadfin must use pinned release 1.2.37 rather than unverified latest release lookup"
            );
            if let DeclarativeStep::DownloadBinary {
                url_template,
                arch_map,
                verification,
                ..
            } = step
            {
                found_download_step = true;
                assert_eq!(
                    url_template,
                    "https://github.com/Threadfin/Threadfin/releases/download/1.2.37/{{ARCH_ASSET}}"
                );
                assert_eq!(arch_map.amd64, "Threadfin_linux_amd64_glibc_2.31_compat");
                assert_eq!(arch_map.arm64, "Threadfin_linux_arm64");
                let arch_digests = verification
                    .arch_sha256
                    .as_ref()
                    .expect("threadfin must pin per-architecture SHA-256 digests");
                assert!(arch_digests.amd64.contains(THREADFIN_AMD64_COMPAT_SHA256));
                assert!(arch_digests.amd64.contains(THREADFIN_AMD64_PLAIN_SHA256));
                assert_eq!(arch_digests.arm64, THREADFIN_ARM64_SHA256);
                assert_eq!(
                    arch_digests.armhf.as_deref(),
                    Some(THREADFIN_ARMHF_SHA256)
                );
                assert!(verification.require_elf_magic);
            }
        }
        assert!(found_download_step);

        // Also confirm the plain amd64 upstream digest constant matches official 1.2.37 metadata
        assert_eq!(
            THREADFIN_AMD64_PLAIN_SHA256,
            "19183058cf28b0080df059113e546a8e8cac16cae210d13be51bda42af94dfc2"
        );

        let root = create_isolated_test_dir("threadfin-verify");
        let bin_path = root.join("Threadfin_linux_amd64_compat");

        // 1. Construct a valid x86_64 ELF binary (EM_X86_64 = 62) and verify arch_sha256 matching
        let amd64_elf = create_mock_elf_payload_for_arch(4096, 62);
        let amd64_sha = hex::encode(Sha256::digest(&amd64_elf));
        let arm64_elf = create_mock_elf_payload_for_arch(4096, 183);
        let arm64_sha = hex::encode(Sha256::digest(&arm64_elf));

        let policy = ArtifactVerificationPolicy {
            min_size_bytes: 2048,
            max_size_bytes: 1024 * 1024,
            expected_sha256: None,
            arch_sha256: Some(ArchAssetMap {
                amd64: amd64_sha.clone(),
                arm64: arm64_sha.clone(),
                armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
            }),
            require_gzip_magic: false,
            require_elf_magic: true,
        };

        fs::write(&bin_path, &amd64_elf).unwrap();
        let verified_sha =
            verify_artifact_file_for_arch(&bin_path, &policy, Some("amd64")).unwrap();
        assert_eq!(verified_sha, amd64_sha);

        // 2. Digest tamper must fail closed with ArtifactVerification error
        let mut tampered = amd64_elf.clone();
        tampered[100] ^= 0xff;
        fs::write(&bin_path, &tampered).unwrap();
        let tamper_err =
            verify_artifact_file_for_arch(&bin_path, &policy, Some("amd64")).unwrap_err();
        assert!(matches!(
            tamper_err,
            PackageExecutorError::ArtifactVerification(_)
        ));
        assert!(tamper_err.to_string().contains("SHA-256 mismatch"));

        // 3. Wrong architecture ELF header (e.g. arm64 binary supplied on amd64 host even if hash matches) must fail closed
        fs::write(&bin_path, &arm64_elf).unwrap();
        let wrong_arch_policy = ArtifactVerificationPolicy {
            arch_sha256: Some(ArchAssetMap {
                amd64: arm64_sha.clone(), // pretend digest matched so ELF header check is tested directly
                arm64: arm64_sha,
                armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
            }),
            ..policy.clone()
        };
        let arch_err =
            verify_artifact_file_for_arch(&bin_path, &wrong_arch_policy, Some("amd64"))
                .unwrap_err();
        assert!(matches!(
            arch_err,
            PackageExecutorError::ArtifactVerification(_)
        ));
        assert!(arch_err.to_string().contains("ELF architecture mismatch"));

        // 4. Unsupported architecture in ArchAssetMap::resolve must fail closed
        assert!(ArchAssetMap {
            amd64: "a".to_string(),
            arm64: "b".to_string(),
            armhf: Some("c".to_string()),
        }
        .resolve("riscv64")
        .is_none());

        // 5. Non-HTTPS URL in DownloadBinary must fail validation closed
        let insecure_http_step = DeclarativeStep::DownloadBinary {
            url_template: "http://github.com/Threadfin/Threadfin/releases/download/1.2.37/{{ARCH_ASSET}}".to_string(),
            arch_map: ArchAssetMap {
                amd64: "Threadfin_linux_amd64_compat".to_string(),
                arm64: "Threadfin_linux_arm64".to_string(),
                armhf: Some("Threadfin_linux_arm_v7".to_string()),
            },
            dest_path: "/usr/local/bin/threadfin".to_string(),
            mode: 0o755,
            verification: policy,
            progress_pct: 50,
            description: "insecure http".to_string(),
        };
        let http_err = validate_step(&insecure_http_step).unwrap_err();
        assert!(matches!(
            http_err,
            PackageExecutorError::SecurityViolation(_)
        ));
        assert!(http_err.to_string().contains("https://"));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_incomplete_removal_retains_completion_marker_without_purging_data() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        for package_id in ["fail2ban", "quassel"] {
            let root = create_isolated_test_dir(&format!("incomplete-remove-{}", package_id));
            let recipe = get_declarative_recipe(package_id).unwrap();
            let env_cfg = PackageExecutionEnv::isolated(&root);
            let marker = root.join(format!("install/.{}.lock", package_id));
            fs::create_dir_all(marker.parent().unwrap()).unwrap();
            fs::write(&marker, "engine=declarative_rust\n").unwrap();
            let state_dir = root.join(format!("var/lib/{}", package_id));
            fs::create_dir_all(&state_dir).unwrap();
            fs::write(state_dir.join("sentinel"), "preserved user data").unwrap();
            let mock = MockCommandRunner { fail_program: Some("apt-get".to_string()), ..Default::default() };
            let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
            assert!(executor.execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {}).await.is_err());
            assert!(marker.exists());
            assert_eq!(fs::read_to_string(state_dir.join("sentinel")).unwrap(), "preserved user data");
            assert!(mock.recorded_commands().iter().any(|command| command.program == "systemctl" && command.args.first().map(String::as_str) == Some("stop")));
            let retry = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
            assert!(!retry.execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {}).await.unwrap().lock_present);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn test_threadfin_bind_default_preserves_settings_and_rollback() {
        let root = create_isolated_test_dir("threadfin-bind-default");
        let settings_path = root.join("var/lib/threadfin/conf/settings.json");
        fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        let original = br#"{"version":"0.5.0","bindIpAddress":"","custom":{"playlist":"keep"}}"#;
        fs::write(&settings_path, original).unwrap();
        let runner = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(PackageExecutionEnv::isolated(&root), runner.clone());
        let recipe = get_declarative_recipe("threadfin").unwrap();
        let step = DeclarativeStep::EnsureThreadfinConfig { progress_pct: 85, description: "bind default".to_string() };
        let mut journal = RollbackJournal::new(Some(root.clone()));
        executor.run_single_step(&recipe, &step, &mut HashMap::new(), &mut journal, &CancellationToken::new()).await.unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
        assert_eq!(settings["bindIpAddress"], "127.0.0.1");
        assert_eq!(settings["custom"]["playlist"], "keep");
        journal.rollback(&runner).await;
        assert_eq!(fs::read(&settings_path).unwrap(), original);
        let explicit = br#"{"version":"0.5.0","bindIpAddress":"192.0.2.10","custom":"preserve"}"#;
        fs::write(&settings_path, explicit).unwrap();
        executor.run_single_step(&recipe, &step, &mut HashMap::new(), &mut journal, &CancellationToken::new()).await.unwrap();
        assert_eq!(fs::read(&settings_path).unwrap(), explicit);
        fs::write(&settings_path, br#"{"bindIpAddress":42}"#).unwrap();
        assert!(executor.run_single_step(&recipe, &step, &mut HashMap::new(), &mut journal, &CancellationToken::new()).await.is_err());
        fs::remove_file(&settings_path).unwrap();
        executor.run_single_step(&recipe, &step, &mut HashMap::new(), &mut journal, &CancellationToken::new()).await.unwrap();
        let fresh: serde_json::Value = serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
        assert_eq!(fresh["version"], "0.5.0");
        assert_eq!(fresh["bindIpAddress"], "127.0.0.1");
        journal.commit();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_existing_certificate_normalizes_mode_and_rollback_preserves_original_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let root = create_isolated_test_dir("existing-certificate-mode");
        let certificate_path = root.join("var/lib/quassel/quasselCert.pem");
        fs::create_dir_all(certificate_path.parent().unwrap()).unwrap();
        fs::write(&certificate_path, "existing private certificate").unwrap();
        fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o644)).unwrap();
        let runner = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(PackageExecutionEnv::isolated(&root), runner.clone());
        let recipe = get_declarative_recipe("quassel").unwrap();
        let step = recipe.install_steps.iter().find(|step| matches!(step, DeclarativeStep::GenerateSelfSignedTlsCert { .. })).unwrap();
        let mut journal = RollbackJournal::new(Some(root.clone()));
        executor.run_single_step(&recipe, step, &mut HashMap::new(), &mut journal, &CancellationToken::new()).await.unwrap();
        assert_eq!(fs::metadata(&certificate_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&certificate_path).unwrap(), "existing private certificate");
        assert!(!runner.recorded_commands().iter().any(|command| command.program == "openssl"));
        journal.rollback(&runner).await;
        assert_eq!(fs::metadata(&certificate_path).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::read_to_string(&certificate_path).unwrap(), "existing private certificate");
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn test_threadfin_install_remove_cancellation_and_rollback_in_isolated_root() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("threadfin-lifecycle");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 34409;

        let mock = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());

        // 1. Non-HTTPS remote download URL must fail closed in fetch_artifact_to_temp
        let mut journal = RollbackJournal::new(Some(root.clone()));
        let cancel = CancellationToken::new();
        let http_fail = executor
            .fetch_artifact_to_temp(
                "threadfin",
                "http://github.com/Threadfin/Threadfin/releases/download/1.2.37/Threadfin_linux_amd64_compat",
                "Threadfin_linux_amd64_compat",
                &mut journal,
                &cancel,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            http_fail,
            PackageExecutorError::SecurityViolation(_)
        ));

        // 2. Pre-cancelled token must abort fetch_artifact_to_temp before any network request
        let pre_cancelled = CancellationToken::new();
        pre_cancelled.cancel();
        let cancel_fetch_err = executor
            .fetch_artifact_to_temp(
                "threadfin",
                "https://github.com/Threadfin/Threadfin/releases/download/1.2.37/Threadfin_linux_amd64_compat",
                "Threadfin_linux_amd64_compat",
                &mut journal,
                &pre_cancelled,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            cancel_fetch_err,
            PackageExecutorError::Cancelled(_)
        ));

        // 3. Stage a valid mock ELF binary in `artifact_cache_dir` and run the real DownloadBinary step!
        let cache_dir = root.join("artifact-cache");
        fs::create_dir_all(&cache_dir).unwrap();
        env_cfg.artifact_cache_dir = Some(cache_dir.clone());

        let elf_payload = create_mock_elf_payload_for_arch(1_100_000, 62); // > 1 MiB min_size_bytes
        let elf_sha = hex::encode(Sha256::digest(&elf_payload));
        fs::write(cache_dir.join("Threadfin_linux_amd64_compat"), &elf_payload).unwrap();

        let mut recipe = get_declarative_recipe("threadfin").unwrap();
        for step in recipe.install_steps.iter_mut() {
            if let DeclarativeStep::DownloadBinary { verification, .. } = step {
                verification.arch_sha256 = Some(ArchAssetMap {
                    amd64: elf_sha.clone(),
                    arm64: elf_sha.clone(),
                    armhf: Some(elf_sha.clone()),
                });
            }
        }

        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
        let mut events = Vec::new();
        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |ev| events.push(ev),
            )
            .await
            .expect("threadfin install should succeed");

        assert!(outcome.lock_present);
        assert_eq!(outcome.resolved_version.as_deref(), Some("1.2.37"));
        assert!(root.join("install/.threadfin.lock").is_file());
        assert!(root.join("usr/local/bin/threadfin").is_file());
        assert!(root.join("var/lib/threadfin/conf").is_dir());
        assert!(root.join("var/lib/threadfin/temp").is_dir());

        let unit_content =
            fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
        assert!(unit_content.contains("User=threadfin"));
        assert!(unit_content.contains("Group=threadfin"));
        assert!(unit_content.contains("Environment=HOME=/var/lib/threadfin"));
        assert!(unit_content.contains(
            "ExecStart=/usr/local/bin/threadfin -port=34409 -bind=0.0.0.0 -config=/var/lib/threadfin/conf"
        ));

        let sandbox_content = fs::read_to_string(
            root.join("etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf"),
        )
        .unwrap();
        assert!(sandbox_content.contains("ProtectSystem=strict"));
        assert!(sandbox_content.contains("/var/lib/threadfin"));

        let version_marker =
            fs::read_to_string(root.join("var/lib/threadfin/.af-version")).unwrap();
        assert_eq!(version_marker.trim(), "1.2.37");

        let settings_path = root.join("var/lib/threadfin/conf/settings.json");
        let settings_before_update = fs::read(&settings_path).unwrap();
        let commands_before_update = mock.recorded_commands().len();
        env_cfg.app_port = 34410;
        let update_executor =
            DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
        let update_outcome = update_executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin update should restart the daemon after rewriting its unit");
        assert!(update_outcome.lock_present);
        assert_eq!(fs::read(&settings_path).unwrap(), settings_before_update);
        let updated_unit =
            fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
        assert!(updated_unit.contains("-port=34410"));
        let recorded_commands = mock.recorded_commands();
        let update_systemctl_commands: Vec<_> = recorded_commands[commands_before_update..]
            .iter()
            .filter(|command| command.program == "systemctl")
            .map(|command| command.args.join(" "))
            .collect();
        assert!(update_systemctl_commands
            .iter()
            .any(|command| command == "daemon-reload"));
        assert!(update_systemctl_commands
            .iter()
            .any(|command| command == "enable --now -- threadfin.service"));
        assert_eq!(
            update_systemctl_commands.last().map(String::as_str),
            Some("restart -- threadfin.service")
        );

        // Verify injected failure rollback on a fresh install root cleans up unit, binary, and lock
        let fail_root = create_isolated_test_dir("threadfin-rollback");
        let fail_cache_dir = fail_root.join("artifact-cache");
        fs::create_dir_all(&fail_cache_dir).unwrap();
        fs::write(fail_cache_dir.join("Threadfin_linux_amd64_compat"), &elf_payload).unwrap();
        let mut fail_env = PackageExecutionEnv::isolated(&fail_root);
        fail_env.artifact_cache_dir = Some(fail_cache_dir);
        let fail_mock = MockCommandRunner {
            fail_program: Some("systemctl".to_string()),
            ..Default::default()
        };
        let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
        let fail_res = fail_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await;
        assert!(matches!(
            fail_res,
            Err(PackageExecutorError::StepFailed { .. })
        ));
        assert!(!fail_root.join("install/.threadfin.lock").exists());
        assert!(!fail_root
            .join("etc/systemd/system/threadfin.service")
            .exists());
        assert!(!fail_root.join("usr/local/bin/threadfin").exists());
        let _ = fs::remove_dir_all(&fail_root);

        // Verify Threadfin removal preserves /var/lib/threadfin when delete_data=false and purges when delete_data=true
        let user_conf = root.join("var/lib/threadfin/conf/settings.json");
        fs::write(&user_conf, b"{\"port\":34409}").unwrap();

        let rem_outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin remove (preserve data) should succeed");
        assert!(!rem_outcome.lock_present);
        assert!(!root.join("install/.threadfin.lock").exists());
        assert!(!root.join("usr/local/bin/threadfin").exists());
        assert!(
            user_conf.is_file(),
            "threadfin user config must be preserved when delete_data=false"
        );

        let mut purge_env = env_cfg.clone();
        purge_env.delete_data = true;
        let purge_exec = DeclarativePackageExecutor::with_runner(purge_env, mock.clone());
        purge_exec
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("threadfin remove (purge data) should succeed");
        assert!(!root.join("var/lib/threadfin").exists());

        let _ = fs::remove_dir_all(&root);
    }
}
