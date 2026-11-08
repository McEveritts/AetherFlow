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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    Reinstall,
    Remove,
    Update,
}

/// Alias for [`PackageAction`] used by declarative lifecycle callers.
pub type PackageOperation = PackageAction;

impl PackageAction {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_lowercase().as_str() {
            "install" => Some(Self::Install),
            "reinstall" => Some(Self::Reinstall),
            "remove" | "uninstall" => Some(Self::Remove),
            "update" => Some(Self::Update),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Reinstall => "reinstall",
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
        #[serde(default)]
        home_dir: Option<String>,
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
    MergeIniSettings {
        path: String,
        section: String,
        settings: Vec<(String, String)>,
        mode: u32,
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
    /// Executes a validated system command (e.g. FUSE mountpoint preflight/unmount before directory removal).
    RunCommand {
        program: String,
        args: Vec<String>,
        #[serde(default)]
        only_if_delete_data: bool,
        #[serde(default)]
        ignore_errors: bool,
        progress_pct: u8,
        description: String,
    },
    /// Verifies that the application HTTP endpoint on `127.0.0.1:{{APP_PORT}}<path>` is listening and responding.
    WaitForHttpReady {
        path: String,
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
            PackageAction::Install | PackageAction::Reinstall => &self.install_steps,
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
    #[error("verification failed: {0}")]
    VerificationFailed(String),
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
/// Polls `child.try_wait()` up to a bounded grace window (default `2500ms`, configurable via
/// `AETHERFLOW_ROLLBACK_GRACE_MS`) after `SIGTERM` so `trap ... TERM EXIT` rollback handlers
/// can restore state cleanly without being cut short by `SIGKILL`.
pub(crate) async fn terminate_child_process_group(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        if pid > 0 {
            let pgid = -(pid as libc::pid_t);
            let grace_ms = env::var("AETHERFLOW_ROLLBACK_GRACE_MS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(2500);
            unsafe {
                let _ = libc::kill(pgid, libc::SIGTERM);
                let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            let deadline = tokio::time::Instant::now() + Duration::from_millis(grace_ms);
            loop {
                if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
                    unsafe {
                        let _ = libc::kill(pgid, libc::SIGKILL);
                    }
                    return;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            unsafe {
                let _ = libc::kill(pgid, libc::SIGKILL);
            }
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

#[allow(dead_code)]
pub(crate) async fn terminate_child_process(child: &mut tokio::process::Child) {
    terminate_child_process_group(child).await;
}

/// Production command runner using `tokio::process::Command` with dedicated process group
/// isolation (`process_group(0)`), bounded output retention, and group-wide cancellation termination.
#[derive(Debug, Clone)]
pub struct TokioCommandRunner {
    pub respect_dry_run_env: bool,
}

impl Default for TokioCommandRunner {
    fn default() -> Self {
        Self {
            respect_dry_run_env: true,
        }
    }
}

#[allow(non_upper_case_globals)]
pub const TokioCommandRunner: TokioCommandRunner = TokioCommandRunner {
    respect_dry_run_env: true,
};

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
            let dry_run = self.respect_dry_run_env
                && env::var("AETHERFLOW_PACKAGE_DRY_RUN")
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
    /// Optional explicit password override (`AF_PASS`) supplied for install/reinstall.
    pub password: Option<String>,
    /// Whether `DELETE_DATA=true` is enabled during `remove`.
    pub delete_data: bool,
    /// Whether `AF_KEEP_EXISTING_SECRETS=1` was explicitly requested via environment.
    pub keep_existing_secrets: bool,
    /// Optional local artifact override directory (`AETHERFLOW_ARTIFACT_CACHE_DIR`) for offline/airgapped or test runs.
    pub artifact_cache_dir: Option<PathBuf>,
}

impl Default for PackageExecutionEnv {
    fn default() -> Self {
        let fs_root = env::var("AETHERFLOW_FS_ROOT")
            .or_else(|_| env::var("AETHERFLOW_INSTALL_ROOT"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "/")
            .map(PathBuf::from);
        let lock_dir = env::var("LOCK_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/install"));
        let log_dir = PathBuf::from("/var/log/aetherflow");
        let temp_dir = env::temp_dir();
        let password = env::var("AF_PASS")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin");
        let delete_data = env::var("DELETE_DATA")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let keep_existing_secrets = env::var("AF_KEEP_EXISTING_SECRETS")
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
            password,
            delete_data,
            keep_existing_secrets,
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
            password: None,
            delete_data: false,
            keep_existing_secrets: false,
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
        validate_filesystem_path(&resolved, self.env_cfg_fs_root())?;
        Ok(resolved)
    }

    fn env_cfg_fs_root(&self) -> Option<&Path> {
        self.fs_root.as_deref()
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
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update => "install",
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
        DeclarativeStep::PurgeSystemUser {
            username, home_dir, ..
        } => {
            if !SAFE_USERNAME.is_match(username) || username == "root" || username == "www-data" {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "disallowed system username for purge: {:?}",
                    username
                )));
            }
            if let Some(ref hd) = home_dir {
                validate_chown_target_path(hd)?;
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
        DeclarativeStep::MergeIniSettings {
            path, section, settings, ..
        } => {
            validate_managed_path(path)?;
            if section.is_empty() || section.contains(['\n', '\r', '[', ']'])
                || settings.is_empty() || settings.iter().any(|(key, value)| {
                    key.is_empty() || key.contains(['\n', '\r', '=', '[', ']'])
                        || value.contains(['\n', '\r'])
                })
            {
                return Err(PackageExecutorError::Validation("invalid INI settings".into()));
            }
            Ok(())
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
        DeclarativeStep::RunCommand { program, args, .. } => {
            if program.trim().is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RunCommand requires a non-empty program".into(),
                ));
            }
            if args.is_empty() {
                return Err(PackageExecutorError::Validation(
                    "RunCommand requires at least one argument".into(),
                ));
            }
            Ok(())
        }
        DeclarativeStep::WaitForHttpReady { path, .. } => {
            if !path.starts_with('/') || path.contains(['\0', '\n', '\r', ' ']) {
                return Err(PackageExecutorError::Validation(format!(
                    "WaitForHttpReady requires an absolute path starting with '/': {:?}",
                    path
                )));
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

#[derive(Debug, Clone)]
struct DirectorySnapshot {
    target_dir: PathBuf,
    backup_dir: PathBuf,
}

fn is_version_receipt_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name == ".af-version")
        .unwrap_or(false)
}

fn is_transient_af_artifact_name(name: &str) -> bool {
    name == ".af-version"
        || name.starts_with(".af-version.bak-af.")
        || name.contains(".bak-af.")
        || name.contains(".bak-af-state.")
        || name.contains(".af-tmp-")
        || name.contains(".af-restore-")
        || name.contains(".af-old-")
}

fn backup_dir_path_for(target_dir: &Path) -> PathBuf {
    let mut os = target_dir.as_os_str().to_os_string();
    os.push(format!(".bak-af-state.{}", uuid::Uuid::new_v4()));
    PathBuf::from(os)
}

fn copy_dir_snapshot_recursive(
    src_dir: &Path,
    dst_dir: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(src_dir, root_bound)?;
    validate_filesystem_path(dst_dir, root_bound)?;
    let src_meta = fs::symlink_metadata(src_dir)?;
    if src_meta.file_type().is_symlink() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to snapshot symlink directory: {}",
            src_dir.display()
        )));
    }
    fs::create_dir_all(dst_dir)?;
    let _ = fs::set_permissions(dst_dir, src_meta.permissions());

    for entry_res in fs::read_dir(src_dir)? {
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
            copy_dir_snapshot_recursive(&child_src, &child_dst, root_bound)?;
        } else if meta.is_file() {
            let mut src_file = File::open(&child_src)?;
            let mut dst_file = open_new_private_file(&child_dst, 0o600)?;
            std::io::copy(&mut src_file, &mut dst_file)?;
            dst_file.set_permissions(meta.permissions())?;
            dst_file.sync_all()?;
        }
    }
    Ok(())
}

fn restore_directory_snapshot_atomic(
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
    let staging_dir = target_dir.with_file_name(format!(
        ".{}.af-restore-{}",
        dir_name,
        uuid::Uuid::new_v4()
    ));
    let old_dir = target_dir.with_file_name(format!(
        ".{}.af-old-{}",
        dir_name,
        uuid::Uuid::new_v4()
    ));
    validate_filesystem_path(&staging_dir, root_bound)?;
    validate_filesystem_path(&old_dir, root_bound)?;

    copy_dir_snapshot_recursive(backup_dir, &staging_dir, root_bound)?;

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
                            if let (Ok(mut s), Ok(mut d)) =
                                (File::open(&src_path), open_new_private_file(&dst_path, 0o600))
                            {
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
struct RollbackJournal {
    entries: Vec<RollbackEntry>,
    restorable_services: Vec<String>,
    touched_services: Vec<String>,
    dir_snapshots: Vec<DirectorySnapshot>,
    apt_downgrades: Vec<(String, String)>,
    pre_existing_version: Option<String>,
    has_existing_installation: bool,
    incomplete_rollback_error: Option<String>,
    temp_files: Vec<PathBuf>,
    fs_root: Option<PathBuf>,
}

impl RollbackJournal {
    fn new(fs_root: Option<PathBuf>) -> Self {
        Self { fs_root, ..Self::default() }
    }

    fn stage_directory_snapshot(&mut self, target_dir: &Path) -> Result<(), PackageExecutorError> {
        validate_filesystem_path(target_dir, self.fs_root.as_deref())?;
        if self.dir_snapshots.iter().any(|s| s.target_dir == target_dir) {
            return Ok(());
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
                    let backup_dir = backup_dir_path_for(target_dir);
                    validate_filesystem_path(&backup_dir, self.fs_root.as_deref())?;
                    copy_dir_snapshot_recursive(
                        target_dir,
                        &backup_dir,
                        self.fs_root.as_deref(),
                    )?;
                    self.dir_snapshots.push(DirectorySnapshot {
                        target_dir: target_dir.to_path_buf(),
                        backup_dir,
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(PackageExecutorError::Io(err)),
        }
        Ok(())
    }

    fn record_touched_service(&mut self, unit_name: &str) {
        let norm = normalize_unit_filename(unit_name);
        if !norm.is_empty() && !self.touched_services.iter().any(|u| u == &norm) {
            self.touched_services.push(norm);
        }
    }

    fn record_apt_upgrade(&mut self, package: &str, prior_version: &str) {
        let pkg = package.trim();
        let ver = prior_version.trim();
        if !pkg.is_empty()
            && !ver.is_empty()
            && !self.apt_downgrades.iter().any(|(p, _)| p == pkg)
        {
            self.apt_downgrades.push((pkg.to_string(), ver.to_string()));
        }
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

    fn record_restorable_systemd_service(&mut self, unit_name: &str) {
        let norm = normalize_unit_filename(unit_name);
        if !self.restorable_services.iter().any(|u| u == &norm) {
            self.restorable_services.push(norm);
        }
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

    /// Commits the transaction: removes `.bak-af` backup files, state snapshots, and temporary downloads.
    fn commit(&mut self) {
        self.cleanup_temp_files();
        self.restorable_services.clear();
        self.touched_services.clear();
        self.apt_downgrades.clear();
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
    }

    /// Rolls back all staged mutations in reverse order, validating all ancestor paths before
    /// restoring backups or unlinking created files.
    async fn rollback<R: CommandRunner>(&mut self, runner: &R) -> Vec<String> {
        let mut notes = Vec::new();
        let mut incomplete_errors = Vec::new();
        self.incomplete_rollback_error = None;
        self.cleanup_temp_files();
        let noop_cancel = CancellationToken::new();

        // 1. Stop any service units touched/started by the recipe and verify quiescence BEFORE
        //    restoring any files or mutable state directories.
        let mut service_quiescence_failed = false;
        let touched_units: Vec<String> = self.touched_services.drain(..).rev().collect();
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
                Ok(out) => matches!(
                    out.stdout.trim(),
                    "active" | "activating" | "reloading"
                ),
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
                            let result = runner.run_command(
                                "chown",
                                &[
                                    "-h".to_string(),
                                    format!("{}:{}", owner_uid, owner_gid),
                                    backup.to_string_lossy().to_string(),
                                ],
                                &[],
                                &noop_cancel,
                            ).await;
                            if !matches!(result, Ok(output) if output.success()) {
                                let msg = format!("failed to restore ownership for {}", target.display());
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

        // 4. Critical receipt honesty rule: only restore the prior `.af-version` receipt if
        //    service stop, state restoration, AND package version restoration all succeeded.
        if !service_quiescence_failed && !state_restore_failed && !package_downgrade_failed {
            for entry in deferred_receipt_entries {
                match entry {
                    RollbackEntry::RestorableFile { target, backup, ownership } => {
                        if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref())
                            .and_then(|_| validate_filesystem_path(&backup, self.fs_root.as_deref()))
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
                        if validate_filesystem_path(&target, self.fs_root.as_deref()).is_ok()
                            && target.is_file()
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

/// Returns `true` when the native Rust package engine is enabled via
/// `AETHERFLOW_ENABLE_RUST_PACKAGES` and not overridden by `AETHERFLOW_FORCE_BASH_PACKAGES`.
pub fn is_rust_package_engine_enabled() -> bool {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    rust_enabled && !force_bash
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
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/fail2ban".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Configuring /etc/fail2ban/jail.local...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "fail2ban".to_string(),
            fallback_version: "1.0.2".to_string(),
            version_file_path: Some("/etc/fail2ban/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 50,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::ProbeSshPort {
            progress_pct: 55,
            description: "Inspecting /etc/ssh/sshd_config for active SSH port...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/fail2ban/jail.local".to_string(),
            content_template: "[DEFAULT]\nbantime  = 1h\nfindtime = 10m\nmaxretry = 5\nbackend  = systemd\n\n[sshd]\nenabled = true\nport    = {{SSH_PORT}},ssh\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 66,
            description: "Seeding initial /etc/fail2ban/jail.local when absent...".to_string(),
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
                paths: vec![
                    "/etc/fail2ban/.af-version".to_string(),
                    "/run/fail2ban".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 85,
                description: "Removing Fail2ban runtime directory and version marker...".to_string(),
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
    let install_steps = vec![
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
            overwrite: false,
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
    ];
    DeclarativePackageRecipe {
        package_id: "quassel".to_string(),
        label: "Quassel".to_string(),
        default_port: 0,
        service_name: "quasselcore".to_string(),
        lock_file: "/install/.quassel.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
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
                    "/var/lib/quassel/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 75,
                description: "Removing Quassel runtime metadata files...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/default/quasselcore".to_string(),
                    "/var/lib/quassel".to_string(),
                    "/var/log/quassel".to_string(),
                    "/var/log/quasselcore.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 84,
                description: "Conditionally purging Quassel SQLite database and TLS certificate (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "quasselcore".to_string(),
                home_dir: Some("/var/lib/quassel".to_string()),
                progress_pct: 88,
                description: "Removing quasselcore system user...".to_string(),
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

pub fn resolve_threadfin_target_version() -> String {
    if resolve_threadfin_sha256_override().is_some() {
        for var_name in [
            "AETHERFLOW_THREADFIN_VERSION",
            "THREADFIN_VERSION",
            "AF_THREADFIN_VERSION",
            "AF_TARGET_VERSION",
            "AETHERFLOW_PACKAGE_VERSION_OVERRIDE",
        ] {
            if let Ok(val) = env::var(var_name) {
                let trimmed = val.trim().trim_start_matches('v').trim_start_matches('V');
                if !trimmed.is_empty() && SAFE_VERSION_TAG.is_match(trimmed) {
                    return trimmed.to_string();
                }
            }
        }
    }
    THREADFIN_PINNED_VERSION.to_string()
}

pub fn resolve_threadfin_sha256_override() -> Option<String> {
    for var_name in [
        "AETHERFLOW_THREADFIN_SHA256",
        "THREADFIN_SHA256",
        "AF_THREADFIN_SHA256",
        "AETHERFLOW_PACKAGE_SHA256_OVERRIDE",
    ] {
        if let Ok(val) = env::var(var_name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn build_threadfin_recipe() -> DeclarativePackageRecipe {
    let target_version = resolve_threadfin_target_version();
    let sha_override = resolve_threadfin_sha256_override();
    let default_arch_sha256 = if sha_override.is_some() {
        None
    } else {
        Some(ArchAssetMap {
            amd64: format!(
                "{}|{}",
                THREADFIN_AMD64_COMPAT_SHA256, THREADFIN_AMD64_PLAIN_SHA256
            ),
            arm64: THREADFIN_ARM64_SHA256.to_string(),
            armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
        })
    };

    let install_steps = vec![
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
            url_template: "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}".to_string(),
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
                expected_sha256: sha_override.clone(),
                arch_sha256: default_arch_sha256.clone(),
                require_gzip_magic: false,
                require_elf_magic: true,
            },
            progress_pct: 65,
            description: format!(
                "Downloading and verifying pinned Threadfin {} binary...",
                target_version
            ),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/threadfin/.af-version".to_string(),
            content_template: "{{VERSION}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 75,
            description: "Writing /var/lib/threadfin/.af-version metadata...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "threadfin.service".to_string(),
            content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind=127.0.0.1 -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
        DeclarativeStep::WaitForHttpReady {
            path: "/status".to_string(),
            progress_pct: 99,
            description: "Verifying Threadfin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/status...".to_string(),
        },
    ];
    let update_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 10,
            description: "Updating APT package indexes for Threadfin update...".to_string(),
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
            description: "Ensuring Threadfin runtime dependencies (curl, wget, ca-certificates, ffmpeg, vlc-bin)...".to_string(),
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
            description: "Ensuring /var/lib/threadfin state and configuration directories...".to_string(),
        },
        DeclarativeStep::DownloadBinary {
            url_template: "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}".to_string(),
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
                expected_sha256: sha_override,
                arch_sha256: default_arch_sha256,
                require_gzip_magic: false,
                require_elf_magic: true,
            },
            progress_pct: 65,
            description: format!(
                "Downloading and verifying target Threadfin {} binary for update...",
                target_version
            ),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/threadfin/.af-version".to_string(),
            content_template: "{{VERSION}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 75,
            description: "Updating /var/lib/threadfin/.af-version metadata...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "threadfin.service".to_string(),
            content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind=127.0.0.1 -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
            description: "Restarting threadfin.service to apply the updated binary and configuration...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/status".to_string(),
            progress_pct: 99,
            description: "Verifying Threadfin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/status...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "threadfin".to_string(),
        label: "Threadfin".to_string(),
        default_port: 34400,
        service_name: "threadfin".to_string(),
        lock_file: "/install/.threadfin.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps,
        install_steps,
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
                home_dir: Some("/var/lib/threadfin".to_string()),
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
            content_template: "Version = {{ZNC_CONF_VERSION}}\n<Listener l>\n    AllowIRC = true\n    AllowWeb = true\n    Port = {{APP_PORT}}\n    IPv4 = true\n    IPv6 = false\n    SSL = false\n    Host = 127.0.0.1\n</Listener>\nLoadModule = webadmin\n\n<User {{MASTER_USER}}>\n    Pass       = sha256#{{ZNC_PASS_HASH}}#{{ZNC_SALT}}#\n    Admin      = true\n    Nick       = {{MASTER_USER}}\n    AltNick    = {{MASTER_USER}}_\n    Ident      = {{MASTER_USER}}\n    RealName   = {{MASTER_USER}}\n</User>\n".to_string(),
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
        DeclarativeStep::WaitForHttpReady {
            path: "/".to_string(),
            progress_pct: 98,
            description: "Verifying ZNC webadmin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/...".to_string(),
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
                paths: vec!["/var/lib/znc/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 70,
                description: "Removing ZNC runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/znc".to_string(),
                    "/opt/AetherFlow/logs/znc_credentials.txt".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /var/lib/znc data directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "znc".to_string(),
                home_dir: Some("/var/lib/znc".to_string()),
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
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/xrdp".to_string(), "/var/lib/xrdp".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 60,
            description: "Ensuring /etc/xrdp and /var/lib/xrdp configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "xrdp".to_string(),
            fallback_version: "0.9.24".to_string(),
            version_file_path: Some("/var/lib/xrdp/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/xrdp/startwm.sh".to_string(),
            content_template: "#!/bin/sh\nif [ -r /etc/default/locale ]; then\n  . /etc/default/locale\n  export LANG LANGUAGE\nfi\nunset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR\nexec startxfce4\n".to_string(),
            mode: 0o755,
            overwrite: false,
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
            unit: Some("xrdp-sesman.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 88,
            description: "Enabling and starting xrdp-sesman.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
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
                progress_pct: 20,
                description: "Stopping and disabling xrdp.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "xrdp-sesman.service".to_string(),
                progress_pct: 35,
                description: "Stopping and disabling xrdp-sesman.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["xrdp".to_string(), "xorgxrdp".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging xrdp APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/xrdp/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing XRDP runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/xrdp".to_string(),
                    "/var/lib/xrdp".to_string(),
                    "/var/log/xrdp.log".to_string(),
                    "/var/log/xrdp-sesman.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing XRDP configuration, state, and logs...".to_string(),
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
                "python3-websockify".to_string(),
                "tigervnc-standalone-server".to_string(),
                "dbus-x11".to_string(),
                "xfce4".to_string(),
            ],
            progress_pct: 40,
            description: "Installing novnc, python3-websockify, tigervnc-standalone-server, and dbus-x11...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "novnc".to_string(),
            home_dir: "/var/lib/novnc".to_string(),
            create_home: true,
            progress_pct: 50,
            description: "Ensuring dedicated novnc system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/novnc".to_string(),
                "/var/lib/novnc".to_string(),
            ],
            mode: 0o750,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 55,
            description: "Ensuring /etc/novnc and /var/lib/novnc directories...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/novnc/.vnc".to_string(),
            ],
            mode: 0o700,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 58,
            description: "Ensuring /var/lib/novnc/.vnc directory...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "novnc".to_string(),
            fallback_version: "1.4.0".to_string(),
            version_file_path: Some("/etc/novnc/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 63,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/novnc/.vnc/xstartup".to_string(),
            content_template: "#!/bin/sh\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4\n".to_string(),
            mode: 0o755,
            overwrite: false,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 68,
            description: "Writing /var/lib/novnc/.vnc/xstartup XFCE4 session launcher...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/novnc/.vnc/passwd".to_string(),
            content_template: "<MASTER_PASS>\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 71,
            description: "Writing /var/lib/novnc/.vnc/passwd VNC authentication secret...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc-xvnc.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow TigerVNC Desktop Server for noVNC\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=novnc\nGroup=novnc\nEnvironment=HOME=/var/lib/novnc\nWorkingDirectory=/var/lib/novnc\nExecStart=/usr/bin/Xtigervnc :1 -geometry 1280x800 -depth 24 -localhost yes -rfbport 5901 -PasswordFile /var/lib/novnc/.vnc/passwd -SecurityTypes VncAuth,TLSVnc -fg\nExecStartPost=/bin/sh /var/lib/novnc/.vnc/xstartup\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 74,
            description: "Writing novnc-xvnc.service VNC backend unit...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow noVNC Websockify Proxy\nAfter=network-online.target novnc-xvnc.service\nWants=network-online.target\nRequires=novnc-xvnc.service\n\n[Service]\nType=simple\nUser=novnc\nGroup=novnc\nExecStart=/usr/bin/websockify --web=/usr/share/novnc/ 127.0.0.1:{{APP_PORT}} 127.0.0.1:5901\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 80,
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
            unit: Some("novnc-xvnc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 89,
            description: "Enabling and starting novnc-xvnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 93,
            description: "Enabling and starting novnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting novnc.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/vnc.html".to_string(),
            progress_pct: 98,
            description: "Verifying noVNC HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/vnc.html...".to_string(),
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
                progress_pct: 20,
                description: "Stopping and removing novnc.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc-xvnc.service".to_string(),
                progress_pct: 35,
                description: "Stopping and removing novnc-xvnc.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "novnc".to_string(),
                    "python3-websockify".to_string(),
                    "tigervnc-standalone-server".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging novnc and python3-websockify APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/novnc/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing noVNC runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/novnc".to_string(),
                    "/var/lib/novnc".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 82,
                description: "Removing /var/lib/novnc state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "novnc".to_string(),
                home_dir: Some("/var/lib/novnc".to_string()),
                progress_pct: 88,
                description: "Removing novnc system user...".to_string(),
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
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/x2go".to_string(), "/var/lib/x2go".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Ensuring /etc/x2go and /var/lib/x2go directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "x2goserver".to_string(),
            fallback_version: "4.1.0.3".to_string(),
            version_file_path: Some("/var/lib/x2go/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 72,
            description: "Recording the installed Debian package version...".to_string(),
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
                paths: vec![
                    "/var/lib/x2go/.af-version".to_string(),
                    "/etc/x2go/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing X2Go runtime version marker...".to_string(),
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
            packages: vec![
                "prometheus".to_string(),
                "prometheus-node-exporter".to_string(),
            ],
            progress_pct: 45,
            description: "Installing prometheus and prometheus-node-exporter APT packages...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/prometheus".to_string(),
                "/var/lib/prometheus".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 55,
            description: "Ensuring /etc/prometheus and /var/lib/prometheus directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "prometheus".to_string(),
            fallback_version: "2.53.0".to_string(),
            version_file_path: Some("/etc/prometheus/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 62,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/default/prometheus".to_string(),
            content_template: "ARGS=\"--web.listen-address=127.0.0.1:{{APP_PORT}} --storage.tsdb.path=/var/lib/prometheus/metrics2 --config.file=/etc/prometheus/prometheus.yml\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 70,
            description: "Writing /etc/default/prometheus listen configuration...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/prometheus/prometheus.yml".to_string(),
            content_template: "global:\n  scrape_interval: 15s\n  evaluation_interval: 15s\n\nscrape_configs:\n  - job_name: 'prometheus'\n    static_configs:\n      - targets: ['127.0.0.1:{{APP_PORT}}']\n  - job_name: 'node'\n    static_configs:\n      - targets: ['127.0.0.1:9100']\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 76,
            description: "Ensuring /etc/prometheus/prometheus.yml scrape config...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "node_exporter.service".to_string(),
            content_template: "[Unit]\nDescription=Prometheus Node Exporter\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=prometheus\nGroup=prometheus\nExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=127.0.0.1:9100\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 80,
            description: "Writing node_exporter.service companion systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus-node-exporter.service".to_string()),
            operation: SystemctlOp::Stop,
            ignore_errors: true,
            progress_pct: 82,
            description: "Stopping stock prometheus-node-exporter.service to avoid port 9100 conflict...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus-node-exporter.service".to_string()),
            operation: SystemctlOp::Disable,
            ignore_errors: true,
            progress_pct: 84,
            description: "Disabling stock prometheus-node-exporter.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 86,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("node_exporter.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 89,
            description: "Enabling and starting node_exporter.service...".to_string(),
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
        DeclarativeStep::WaitForHttpReady {
            path: "/-/healthy".to_string(),
            progress_pct: 98,
            description: "Verifying Prometheus HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/-/healthy...".to_string(),
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
                progress_pct: 20,
                description: "Stopping and disabling prometheus.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "node_exporter.service".to_string(),
                progress_pct: 32,
                description: "Stopping and disabling node_exporter.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "prometheus".to_string(),
                    "prometheus-node-exporter".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging prometheus APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/prometheus/.af-version".to_string(),
                    "/usr/local/bin/prometheus".to_string(),
                    "/usr/local/bin/node_exporter".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 65,
                description: "Removing Prometheus runtime version marker and binary symlinks...".to_string(),
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
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/netdata".to_string(),
                "/var/lib/netdata".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 55,
            description: "Ensuring /etc/netdata and /var/lib/netdata directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "netdata".to_string(),
            fallback_version: "1.47.0".to_string(),
            version_file_path: Some("/etc/netdata/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 62,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::MergeIniSettings {
            path: "/etc/netdata/netdata.conf".to_string(),
            section: "web".to_string(),
            settings: vec![
                ("bind to".to_string(), "127.0.0.1".to_string()),
                ("default port".to_string(), "{{APP_PORT}}".to_string()),
            ],
            mode: 0o644,
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
        DeclarativeStep::WaitForHttpReady {
            path: "/api/v1/info".to_string(),
            progress_pct: 98,
            description: "Verifying Netdata HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/api/v1/info...".to_string(),
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
                paths: vec!["/etc/netdata/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 65,
                description: "Removing Netdata runtime version marker...".to_string(),
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
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/mnt/mergerfs".to_string(),
                "/mnt/local".to_string(),
                "/mnt/remote".to_string(),
                "/mnt/unionfs".to_string(),
                "/etc/mergerfs".to_string(),
                "/var/lib/mergerfs".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 58,
            description: "Ensuring /mnt/unionfs and union mount directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "mergerfs".to_string(),
            fallback_version: "2.40.2".to_string(),
            version_file_path: Some("/var/lib/mergerfs/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 66,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/mergerfs/mergerfs.conf".to_string(),
            content_template: "BRANCHES=\"/mnt/local=RW:/mnt/remote=NC\"\nMOUNTPOINT=\"/mnt/unionfs\"\nOPTIONS=\"defaults,allow_other,use_ino,category.create=ff,moveonenospc=true,dropcacheonclose=true\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/mergerfs/mergerfs.conf...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "mergerfs.service".to_string(),
            content_template: "[Unit]\nDescription=MergerFS Union Filesystem Mount\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=\"BRANCHES=/mnt/local=RW:/mnt/remote=NC\"\nEnvironment=\"MOUNTPOINT=/mnt/unionfs\"\nEnvironment=\"OPTIONS=defaults,allow_other,use_ino,category.create=ff,moveonenospc=true,dropcacheonclose=true\"\nEnvironmentFile=-/etc/mergerfs/mergerfs.conf\nExecStart=/usr/bin/mergerfs -o ${OPTIONS} ${BRANCHES} ${MOUNTPOINT}\nExecStop=/bin/fusermount -uz ${MOUNTPOINT}\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 96,
            description: "Enabling and starting mergerfs.service...".to_string(),
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
                paths: vec![
                    "/var/lib/mergerfs/.af-version".to_string(),
                    "/etc/mergerfs/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 70,
                description: "Removing MergerFS runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/mergerfs".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /etc/mergerfs configuration...".to_string(),
            },
            DeclarativeStep::RunCommand {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "for mp in /mnt/unionfs /mnt/mergerfs; do if mountpoint -q \"$mp\" 2>/dev/null; then fusermount -u \"$mp\" 2>/dev/null || fusermount -uz \"$mp\" 2>/dev/null || umount -l \"$mp\" 2>/dev/null || true; if mountpoint -q \"$mp\" 2>/dev/null; then exit 1; fi; fi; done".to_string(),
                ],
                only_if_delete_data: true,
                ignore_errors: false,
                progress_pct: 84,
                description: "Unmounting active MergerFS FUSE mountpoints (/mnt/unionfs, /mnt/mergerfs) before directory removal...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/mnt/unionfs".to_string(),
                    "/mnt/mergerfs".to_string(),
                    "/var/lib/mergerfs".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing /mnt/unionfs, /mnt/mergerfs, and /var/lib/mergerfs directories (when DELETE_DATA=true)...".to_string(),
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
            progress_pct: 58,
            description: "Ensuring /var/lib/rclone and /etc/rclone directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "rclone".to_string(),
            fallback_version: "1.68.1".to_string(),
            version_file_path: Some("/var/lib/rclone/.af-version".to_string()),
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 64,
            description: "Recording the installed Debian package version...".to_string(),
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
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/rclone/rclone.env".to_string(),
            content_template: "RCLONE_RC_USER=\"{{MASTER_USER}}\"\nRCLONE_RC_PASS=\"{{MASTER_PASS}}\"\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 74,
            description: "Ensuring /etc/rclone/rclone.env exists...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone RC Web GUI Service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=rclone\nGroup=rclone\nWorkingDirectory=/var/lib/rclone\nEnvironmentFile=-/etc/rclone/rclone.env\nExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --config=/etc/rclone/rclone.conf\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 79,
            description: "Writing rclone.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone-vfs.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone VFS FUSE Mount Daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStartPre=-/bin/mkdir -p /mnt/remote\nExecStart=/usr/bin/rclone mount remote: /mnt/remote --config=/etc/rclone/rclone.conf --vfs-cache-mode=full --allow-other --dir-cache-time=72h\nExecStop=/bin/fusermount -uz /mnt/remote\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 83,
            description: "Writing rclone-vfs.service companion systemd unit...".to_string(),
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
        DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone RC HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/metrics...".to_string(),
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
                unit_name: "rclone-vfs.service".to_string(),
                progress_pct: 18,
                description: "Stopping and removing rclone-vfs.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "rclone.service".to_string(),
                progress_pct: 30,
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
                paths: vec![
                    "/var/lib/rclone/.af-version".to_string(),
                    "/etc/rclone/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 64,
                description: "Removing Rclone runtime version marker...".to_string(),
            },
            DeclarativeStep::RunCommand {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "for mp in /mnt/remote; do if mountpoint -q \"$mp\" 2>/dev/null; then fusermount -u \"$mp\" 2>/dev/null || fusermount -uz \"$mp\" 2>/dev/null || umount -l \"$mp\" 2>/dev/null || true; if mountpoint -q \"$mp\" 2>/dev/null; then exit 1; fi; fi; done".to_string(),
                ],
                only_if_delete_data: true,
                ignore_errors: false,
                progress_pct: 70,
                description: "Unmounting active Rclone FUSE mountpoint (/mnt/remote) before directory removal...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/rclone".to_string(),
                    "/var/lib/rclone".to_string(),
                    "/mnt/remote".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing Rclone state directories (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "rclone".to_string(),
                home_dir: Some("/var/lib/rclone".to_string()),
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
        DeclarativeStep::EnsureSystemUser {
            username: "syncthing".to_string(),
            home_dir: "/var/lib/syncthing".to_string(),
            create_home: true,
            progress_pct: 50,
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
            progress_pct: 60,
            description: "Preparing /var/lib/syncthing configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "syncthing".to_string(),
            fallback_version: "1.28.0".to_string(),
            version_file_path: Some("/var/lib/syncthing/.af-version".to_string()),
            owner: Some("syncthing".to_string()),
            group: Some("syncthing".to_string()),
            progress_pct: 68,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "syncthing.service".to_string(),
            content_template: "[Unit]\nDescription=Syncthing - Open Source Continuous File Synchronization\nAfter=network.target\n\n[Service]\nUser=syncthing\nGroup=syncthing\nWorkingDirectory=/var/lib/syncthing\nExecStart=/usr/bin/syncthing serve --no-browser --no-restart --gui-address=127.0.0.1:{{APP_PORT}} --home=/var/lib/syncthing\nRestart=on-failure\nRestartSec=5\nSuccessExitStatus=3 4\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
        DeclarativeStep::WaitForHttpReady {
            path: "/rest/noauth/health".to_string(),
            progress_pct: 98,
            description: "Verifying Syncthing HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/rest/noauth/health...".to_string(),
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
                paths: vec!["/var/lib/syncthing/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 68,
                description: "Removing Syncthing runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/syncthing".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /var/lib/syncthing state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "syncthing".to_string(),
                home_dir: Some("/var/lib/syncthing".to_string()),
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

fn recipe_mutable_state_dirs(recipe: &DeclarativePackageRecipe) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut push_unique = |path: &str| {
        let trimmed = path.trim_end_matches('/');
        if !trimmed.is_empty() && trimmed != "/" && !dirs.iter().any(|d| d == trimmed) {
            dirs.push(trimmed.to_string());
        }
    };

    for step in recipe.install_steps.iter().chain(recipe.update_steps.iter()) {
        match step {
            DeclarativeStep::EnsureDirectories { paths, .. } => {
                for path in paths {
                    if path.starts_with("/var/lib/")
                        || path.starts_with("/etc/")
                        || path.contains("/.config/")
                        || path.contains("/.local/share/")
                    {
                        push_unique(path);
                    }
                }
            }
            DeclarativeStep::WriteTemplateFile { path, .. }
            | DeclarativeStep::MergeIniSettings { path, .. } => {
                if (path.starts_with("/var/lib/")
                    || path.starts_with("/etc/")
                    || path.contains("/.config/")
                    || path.contains("/.local/share/"))
                    && !path.starts_with("/etc/systemd/")
                    && !path.starts_with("/etc/apt/")
                    && !path.starts_with("/etc/nginx/")
                    && !path.starts_with("/etc/sudoers")
                    && !path.starts_with("/etc/cron")
                {
                    if let Some(parent) = Path::new(path).parent().and_then(|p| p.to_str()) {
                        if parent != "/etc" && parent != "/var/lib" && parent != "/var" {
                            push_unique(parent);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    match recipe.package_id.as_str() {
        "syncthing" => {
            push_unique("/var/lib/syncthing");
            push_unique("/etc/syncthing");
        }
        "quassel" => {
            push_unique("/var/lib/quassel");
            push_unique("/etc/quassel");
        }
        "znc" => {
            push_unique("/var/lib/znc");
            push_unique("/etc/znc");
        }
        "thelounge" => {
            push_unique("/var/lib/thelounge");
            push_unique("/etc/thelounge");
        }
        "weechat" => {
            push_unique("/var/lib/weechat");
            push_unique("/etc/weechat");
        }
        "jellyfin" => {
            push_unique("/var/lib/jellyfin");
            push_unique("/etc/jellyfin");
        }
        "plex" => {
            push_unique("/var/lib/plexmediaserver");
        }
        "prometheus" => {
            push_unique("/var/lib/prometheus");
            push_unique("/etc/prometheus");
        }
        "tailscale" => {
            push_unique("/var/lib/tailscale");
        }
        "wireguard" => {
            push_unique("/etc/wireguard");
        }
        _ => {}
    }

    dirs
}

fn recipe_version_file_logical_path(recipe: &DeclarativePackageRecipe) -> Option<String> {
    for step in recipe.install_steps.iter().chain(recipe.update_steps.iter()) {
        if let DeclarativeStep::CaptureDpkgVersion {
            version_file_path: Some(version_file),
            ..
        } = step
        {
            return Some(version_file.clone());
        }
    }
    Some(format!("/opt/{}/.af-version", recipe.package_id))
}

fn recipe_primary_apt_package(recipe: &DeclarativePackageRecipe, packages: &[String]) -> Option<String> {
    for step in recipe.install_steps.iter().chain(recipe.update_steps.iter()) {
        if let DeclarativeStep::CaptureDpkgVersion { package, .. } = step {
            if packages.iter().any(|p| p == package) {
                return Some(package.clone());
            }
        }
    }
    packages.last().cloned()
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
            runner: TokioCommandRunner::default(),
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
                    "-h".to_string(),
                    format!("{}:{}", owner_name, group_name),
                    path.to_string_lossy().to_string(),
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

        if matches!(
            action,
            PackageAction::Install | PackageAction::Update | PackageAction::Reinstall
        ) {
            let mut pre_existing_ver = None;
            if let Some(vf_logical) = recipe_version_file_logical_path(recipe) {
                if let Ok(vf_resolved) = self.env_cfg.resolve_path(&vf_logical) {
                    if let Ok(raw) = fs::read_to_string(&vf_resolved) {
                        let trimmed = raw.trim().to_string();
                        if !trimmed.is_empty() {
                            pre_existing_ver = Some(trimmed);
                        }
                    }
                }
            }
            for state_dir in recipe_mutable_state_dirs(recipe) {
                if let Ok(resolved_dir) = self.env_cfg.resolve_path(&state_dir) {
                    if resolved_dir.is_dir() {
                        journal.stage_directory_snapshot(&resolved_dir)?;
                    }
                }
            }
            journal.has_existing_installation = pre_existing_ver.is_some()
                || lock_file_path.is_file()
                || (matches!(action, PackageAction::Update | PackageAction::Reinstall)
                    && !journal.dir_snapshots.is_empty());
            journal.pre_existing_version = pre_existing_ver;
        }

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
            if action == PackageAction::Update
                && resolve_threadfin_sha256_override().is_none()
                && self.env_cfg.fs_root.is_none()
                && self.env_cfg.artifact_cache_dir.is_none()
            {
                self.resolve_github_tag(
                    "Threadfin/Threadfin",
                    &resolve_threadfin_target_version(),
                    true,
                )
                .await
            } else {
                resolve_threadfin_target_version()
            }
        } else {
            "unknown".to_string()
        };

        let (master_user, mut master_pass) =
            resolve_master_credentials(self.env_cfg.fs_root.as_deref());
        if let Some(explicit_pass) = self.resolve_explicit_password() {
            master_pass = explicit_pass;
        }
        let znc_salt = uuid::Uuid::new_v4().simple().to_string();
        let znc_hash = hex::encode(Sha256::digest(
            format!("{}{}", master_pass, znc_salt).as_bytes(),
        ));

        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("PACKAGE_ID".to_string(), recipe.package_id.clone());
        vars.insert("APP_NAME".to_string(), recipe.package_id.clone());
        vars.insert("APP_LABEL".to_string(), recipe.label.clone());
        vars.insert("APP_PORT".to_string(), effective_port.to_string());
        vars.insert("LISTEN_PORT".to_string(), listen_port.to_string());
        vars.insert("SSH_PORT".to_string(), "ssh".to_string());
        vars.insert("MASTER_USER".to_string(), master_user);
        vars.insert("MASTER_PASS".to_string(), master_pass);
        vars.insert("ZNC_SALT".to_string(), znc_salt);
        vars.insert("ZNC_PASS_HASH".to_string(), znc_hash);
        vars.insert("VERSION".to_string(), initial_version.clone());
        vars.insert(
            "ZNC_CONF_VERSION".to_string(),
            format_znc_major_minor(&initial_version),
        );
        vars.insert(
            "TAG".to_string(),
            if initial_version == "unknown" {
                "unknown".to_string()
            } else {
                format!("v{}", initial_version)
            },
        );
        vars.insert("ARCH".to_string(), self.env_cfg.effective_arch());
        vars.insert("LIFECYCLE_ACTION".to_string(), action.as_str().to_string());

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
        let should_apply_sandbox = matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && recipe.apply_systemd_sandbox;
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

        // Persist or remove completion receipt BEFORE committing the rollback journal so any
        // receipt write/remove failure triggers compensating rollback of prior config/service mutations.
        if exec_err.is_none() {
            let finalize_res: Result<(), PackageExecutorError> = (|| {
                match action {
                    PackageAction::Install | PackageAction::Reinstall | PackageAction::Update => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        if let Some(parent) = lock_file_path.parent() {
                            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                            fs::create_dir_all(parent)?;
                        }
                        journal.stage_file_mutation(&lock_file_path)?;
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
                    }
                    PackageAction::Remove => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        journal.stage_file_mutation(&lock_file_path)?;
                        match fs::remove_file(&lock_file_path) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                Ok(())
            })();
            if let Err(err) = finalize_res {
                exec_err = Some(err);
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
            let final_err = if let Some(incomplete_reason) = journal.incomplete_rollback_error.take() {
                match err {
                    PackageExecutorError::StepFailed { step, reason } => {
                        PackageExecutorError::StepFailed {
                            step,
                            reason: format!("{reason}; incomplete rollback/recovery: {incomplete_reason}"),
                        }
                    }
                    other => PackageExecutorError::StepFailed {
                        step: "rollback_journal".to_string(),
                        reason: format!("{other}; incomplete rollback/recovery: {incomplete_reason}"),
                    },
                }
            } else {
                err
            };
            self.emit_event(
                &recipe.package_id,
                action,
                phase,
                completed_steps,
                total_steps,
                99,
                format!("Package {} {} failed: {}", recipe.package_id, action.as_str(), final_err),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            return Err(final_err);
        }

        // Commit rollback journal ONLY after all steps, sandboxing, and lockfile persistence succeeded
        journal.commit();
        if matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && self.env_cfg.fs_root.is_none()
        {
            trigger_certbot_sync_best_effort(&recipe.package_id);
        }

        let done_msg = match action {
            PackageAction::Install => format!("{} installed successfully.", recipe.label),
            PackageAction::Reinstall => format!("{} reinstalled successfully.", recipe.label),
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
                "--property=UnitFileState".to_string(),
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
        let unit_file_state = state.stdout.lines()
            .find_map(|line| line.strip_prefix("UnitFileState="));
        let known_inactive = state.success()
            && active_state == Some("inactive")
            && matches!(load_state, Some("loaded" | "masked" | "not-found"));
        let disable_or_reset_ok = matches!(load_state, Some("not-found" | "masked"))
            || matches!(
                unit_file_state,
                Some("disabled" | "static" | "indirect" | "masked")
            );
        if known_inactive && (operation == "stop" || disable_or_reset_ok) {
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
                let primary_pkg = recipe_primary_apt_package(recipe, packages);
                let mut prior_pkg_version = None;
                if journal.has_existing_installation {
                    if let Some(pkg_name) = primary_pkg.as_deref() {
                        let dpkg_args = vec![
                            "-W".to_string(),
                            "-f=${Version}".to_string(),
                            pkg_name.to_string(),
                        ];
                        if let Ok(dpkg_out) = self
                            .runner
                            .run_command("dpkg-query", &dpkg_args, &[], cancel)
                            .await
                        {
                            if dpkg_out.success() {
                                let queried = dpkg_out.stdout.trim().to_string();
                                if !queried.is_empty() {
                                    prior_pkg_version = Some(queried);
                                }
                            }
                        }
                        if let Some(pre_ver) = journal.pre_existing_version.as_ref() {
                            if prior_pkg_version.is_none()
                                || prior_pkg_version.as_deref() != Some(pre_ver.as_str())
                            {
                                prior_pkg_version = Some(pre_ver.clone());
                            }
                        }
                    }
                }

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
                if let (Some(pkg_name), Some(old_ver)) = (primary_pkg, prior_pkg_version) {
                    journal.record_apt_upgrade(&pkg_name, &old_ver);
                    if !recipe.service_name.is_empty() {
                        journal.record_touched_service(&recipe.service_name);
                    }
                }
                if recipe.package_id == "prometheus" {
                    for (src, dst) in [
                        ("/usr/bin/prometheus", "/usr/local/bin/prometheus"),
                        ("/usr/bin/prometheus-node-exporter", "/usr/local/bin/node_exporter"),
                    ] {
                        let src_resolved = self.env_cfg.resolve_readonly_path(src);
                        let dst_resolved = self.env_cfg.resolve_path(dst)?;
                        match fs::symlink_metadata(&src_resolved) {
                            Ok(meta) => {
                                if meta.file_type().is_symlink() {
                                    if let Some(parent) = src_resolved.parent() {
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                    }
                                    continue;
                                }
                                if meta.is_file() {
                                    validate_filesystem_path(
                                        &src_resolved,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    if let Some(parent) = dst_resolved.parent() {
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                        fs::create_dir_all(parent)?;
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                    }
                                    journal.stage_file_mutation(&dst_resolved)?;
                                    let bytes = fs::read(&src_resolved)?;
                                    write_file_atomic_with_mode_bounded(
                                        &dst_resolved,
                                        &bytes,
                                        0o755,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                }
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(err) => return Err(PackageExecutorError::Io(err)),
                        }
                    }
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
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-R".to_string(),
                                        "-h".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "ensure_directories".to_string(),
                                    reason: format!(
                                        "chown -R -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
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
                if !out.success() || out.stdout.trim().is_empty() {
                    let detail = if out.stderr.trim().is_empty() {
                        "dpkg-query failed or returned empty version".to_string()
                    } else {
                        out.stderr.trim().to_string()
                    };
                    return Err(PackageExecutorError::StepFailed {
                        step: "capture_dpkg_version".to_string(),
                        reason: format!(
                            "dpkg-query {:?} exited with {}: {}",
                            args, out.exit_code, detail
                        ),
                    });
                }
                let resolved_ver = normalize_dpkg_version(&out.stdout, fallback_version);
                vars.insert("VERSION".to_string(), resolved_ver.clone());
                vars.insert(
                    "ZNC_CONF_VERSION".to_string(),
                    format_znc_major_minor(&resolved_ver),
                );
                vars.insert(
                    "TAG".to_string(),
                    format!("v{}", resolved_ver.trim_start_matches('v')),
                );

                if let Some(ref vp) = version_file_path {
                    let resolved_path = self.env_cfg.resolve_path(vp)?;
                    if !is_downgrade_allowed() {
                        if let Ok(existing_raw) = fs::read_to_string(&resolved_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            let clean_ver = resolved_ver.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
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
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-h".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved_path.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "capture_dpkg_version".to_string(),
                                    reason: format!(
                                        "chown -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved_path.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
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
                if !is_downgrade_allowed() {
                    let ver_marker_logical = format!("/var/lib/{}/.af-version", recipe.package_id);
                    if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical) {
                        if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, &clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                }
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
                if !is_downgrade_allowed() {
                    if let Some(target_ver) = vars.get("VERSION").cloned() {
                        let clean_ver = target_ver.trim().trim_start_matches('v');
                        let ver_marker_logical =
                            format!("/var/lib/{}/.af-version", recipe.package_id);
                        if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical)
                        {
                            if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                                let existing_ver = existing_raw.trim().trim_start_matches('v');
                               if is_semver_strictly_greater(existing_ver, clean_ver) {
                                    return Err(PackageExecutorError::Validation(format!(
                                        "refusing to downgrade {} from installed version {} to {}",
                                        recipe.package_id, existing_ver, clean_ver
                                    )));
                                }
                            }
                        }
                    }
                }
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
                let mut effective_verification = verification.clone();
                if recipe.package_id == "threadfin" {
                    if let Some(sha_override) = resolve_threadfin_sha256_override() {
                        effective_verification.expected_sha256 = Some(sha_override);
                        effective_verification.arch_sha256 = None;
                    }
                }
                let sha256 = verify_artifact_file_for_arch(&tmp_artifact, &effective_verification, Some(&arch))?;

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

            DeclarativeStep::MergeIniSettings { path, section, settings, mode, .. } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                journal.stage_file_mutation(&resolved)?;
                let original = match fs::read_to_string(&resolved) {
                    Ok(contents) => contents,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.into()),
                };
                let rendered_settings = settings.iter().map(|(key, value)| {
                    (key.clone(), interpolate_template(value, vars))
                }).collect::<Vec<_>>();
                let rendered = merge_ini_settings(&original, section, &rendered_settings);
                write_file_atomic_with_mode_bounded(
                    &resolved, rendered.as_bytes(), *mode, self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("merged managed INI settings in {}", path))
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
                let rendered = if path.ends_with(".env") || path.starts_with("/etc/default/") {
                    let mut escaped_vars = vars.clone();
                    if let Some(u) = escaped_vars.get("MASTER_USER").cloned() {
                        escaped_vars.insert("MASTER_USER".to_string(), escape_systemd_env_quoted(&u));
                    }
                    if let Some(p) = escaped_vars.get("MASTER_PASS").cloned() {
                        escaped_vars.insert("MASTER_PASS".to_string(), escape_systemd_env_quoted(&p));
                    }
                    interpolate_template(content_template, &escaped_vars)
                } else if path == "/var/lib/znc/configs/znc.conf" {
                    let mut znc_vars = vars.clone();
                    if let Some(ver) = znc_vars.get("VERSION").cloned() {
                        let mm = format_znc_major_minor(&ver);
                        znc_vars.insert("VERSION".to_string(), mm.clone());
                        znc_vars.insert("ZNC_CONF_VERSION".to_string(), mm);
                    }
                    interpolate_template(content_template, &znc_vars)
                } else {
                    interpolate_template(content_template, vars)
                };

                if path == "/var/lib/novnc/.vnc/passwd" {
                    let pw = rendered.trim_end_matches(&['\r', '\n'][..]);
                    if !*overwrite && resolved.exists() {
                        if let Ok(existing_bytes) = fs::read(&resolved) {
                            let is_valid_retained = existing_bytes.len() == 8
                                && existing_bytes != rendered.as_bytes()
                                && decode_tigervnc_passwd(&existing_bytes).is_some_and(|decoded| {
                                    decoded.len() >= 6
                                        && decoded.as_bytes().iter().all(|b| b.is_ascii_graphic() || *b == b' ')
                                });
                            if is_valid_retained {
                                return Ok(format!("preserved existing file {}", path));
                            }
                        }
                    }
                    let encoded_bytes = encode_tigervnc_passwd(pw);
                    journal.stage_file_mutation(&resolved)?;
                    write_file_atomic_with_mode_bounded(
                        &resolved,
                        &encoded_bytes,
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-h".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "write_template_file".to_string(),
                                    reason: format!(
                                        "chown -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
                        }
                    }
                    return Ok(format!("wrote configuration file {}", path));
                }

                if !*overwrite && resolved.is_file() {
                    if path == "/etc/rclone/rclone.env" {
                        let lifecycle_action = vars
                            .get("LIFECYCLE_ACTION")
                            .map(String::as_str)
                            .unwrap_or("install");
                        let keep_secrets = self.env_cfg.keep_existing_secrets
                            || env::var("AF_KEEP_EXISTING_SECRETS")
                                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                                .unwrap_or(false)
                            || (matches!(lifecycle_action, "update" | "reinstall")
                                && env::var("AF_KEEP_EXISTING_SECRETS")
                                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                                    .unwrap_or(true));
                        if !keep_secrets {
                            if let Some(explicit_pass) = self.resolve_explicit_password() {
                                if let Ok(existing) = fs::read_to_string(&resolved) {
                                    let updated =
                                        update_preserved_rclone_env_pass(&existing, &explicit_pass);
                                    if updated != existing {
                                        journal.stage_file_mutation(&resolved)?;
                                        write_file_atomic_with_mode_bounded(
                                            &resolved,
                                            updated.as_bytes(),
                                            *mode,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                        self.apply_file_metadata(
                                            &resolved,
                                            *mode,
                                            owner.as_deref(),
                                            group.as_deref(),
                                            cancel,
                                        )
                                        .await?;
                                        return Ok(format!(
                                            "updated RCLONE_RC_PASS in existing file {}",
                                            path
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    let port_var = if path == "/etc/default/quasselcore" {
                        vars.get("LISTEN_PORT").or_else(|| vars.get("APP_PORT"))
                    } else {
                        vars.get("APP_PORT")
                    };
                    if let Some(app_port) = port_var {
                        if let Ok(existing) = fs::read_to_string(&resolved) {
                            if let Some(updated) = update_preserved_template_port(
                                path, &existing, &rendered, app_port,
                            ) {
                                if updated != existing {
                                    journal.stage_file_mutation(&resolved)?;
                                    write_file_atomic_with_mode_bounded(
                                        &resolved,
                                        updated.as_bytes(),
                                        *mode,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    self.apply_file_metadata(
                                        &resolved,
                                        *mode,
                                        owner.as_deref(),
                                        group.as_deref(),
                                        cancel,
                                    )
                                    .await?;
                                    return Ok(format!(
                                        "updated port in existing file {}",
                                        path
                                    ));
                                }
                            }
                        }
                    }
                    return Ok(format!("preserved existing file {}", path));
                }
                journal.stage_file_mutation(&resolved)?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;

                if path == "/var/lib/znc/configs/znc.conf" {
                    let creds_path = self
                        .env_cfg
                        .resolve_path("/opt/AetherFlow/logs/znc_credentials.txt")?;
                    journal.stage_file_mutation(&creds_path)?;
                    let master_user = vars
                        .get("MASTER_USER")
                        .map(String::as_str)
                        .unwrap_or("admin");
                    let master_pass = vars.get("MASTER_PASS").map(String::as_str).unwrap_or("");
                    let creds_body = format!(
                        "ZNC Admin User: {}\nZNC Admin Password: {}\n",
                        master_user, master_pass
                    );
                    write_file_atomic_with_mode_bounded(
                        &creds_path,
                        creds_body.as_bytes(),
                        0o600,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                }

                if let Some(ref o) = owner {
                    let grp = group.as_deref().unwrap_or(o.as_str());
                    if self.env_cfg.fs_root.is_none() {
                        let out = self
                            .runner
                            .run_command(
                                "chown",
                                &[
                                    "-h".to_string(),
                                    format!("{}:{}", o, grp),
                                    resolved.to_string_lossy().to_string(),
                                ],
                                &[],
                                cancel,
                            )
                            .await?;
                        if !out.success() {
                            return Err(PackageExecutorError::StepFailed {
                                step: "write_template_file".to_string(),
                                reason: format!(
                                    "chown -h {}:{} {} exited with {}: {}",
                                    o,
                                    grp,
                                    resolved.display(),
                                    out.exit_code,
                                    out.combined_output()
                                ),
                            });
                        }
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
                if existed {
                    journal.record_restorable_systemd_service(&norm);
                } else {
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
                    let norm_unit = normalize_unit_filename(unit.as_deref().unwrap_or_default());
                    if matches!(operation, SystemctlOp::Stop | SystemctlOp::Disable)
                        && !norm_unit.is_empty()
                    {
                        let unit_logical = format!("/etc/systemd/system/{}", norm_unit);
                        if self
                            .env_cfg
                            .resolve_path(&unit_logical)
                            .map(|p| p.is_file())
                            .unwrap_or(false)
                        {
                            journal.record_restorable_systemd_service(&norm_unit);
                        }
                    }
                    let operation_name = match operation {
                        SystemctlOp::Stop => "stop",
                        SystemctlOp::Disable => "disable",
                        _ => "reset-failed",
                    };
                    self.teardown_systemctl(
                        operation_name,
                        &norm_unit,
                        cancel,
                    )
                    .await?;
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
                    && (!*ignore_errors || matches!(operation, SystemctlOp::DaemonReload))
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
                if out.success()
                    && matches!(
                        operation,
                        SystemctlOp::EnableNow | SystemctlOp::Start | SystemctlOp::Restart
                    )
                {
                    if let Some(unit_name) = unit.as_ref().filter(|u| !u.is_empty()) {
                        journal.record_touched_service(unit_name);
                        let verify_args = vec![
                            "is-active".to_string(),
                            "--quiet".to_string(),
                            "--".to_string(),
                            unit_name.clone(),
                        ];
                        let active_out = self
                            .runner
                            .run_command("systemctl", &verify_args, &[], cancel)
                            .await?;
                        if !active_out.success() && !*ignore_errors {
                            return Err(PackageExecutorError::StepFailed {
                                step: format!("systemctl is-active {}", unit_name),
                                reason: format!(
                                    "service {} failed post-activation readiness check (systemctl is-active exited with {}): {}",
                                    unit_name,
                                    active_out.exit_code,
                                    active_out.combined_output()
                                ),
                            });
                        }
                    }
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
                                if self.is_active_mountpoint(logical, &resolved) {
                                    return Err(PackageExecutorError::SecurityViolation(format!(
                                        "refusing to remove active mountpoint directory: {}",
                                        resolved.display()
                                    )));
                                }
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

            DeclarativeStep::RunCommand {
                program,
                args,
                only_if_delete_data,
                ignore_errors,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped command (DELETE_DATA=false)".to_string());
                }
                let out = self
                    .runner
                    .run_command(program, args, &[], cancel)
                    .await?;
                if !out.success() && !*ignore_errors {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("run_command {}", program),
                        reason: format!(
                            "{} {:?} exited with {}: {}",
                            program,
                            args,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok(format!("executed command {}", program))
            }

            DeclarativeStep::WaitForHttpReady { path, .. } => {
                let port = vars
                    .get("APP_PORT")
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(recipe.default_port as u16);
                let url = format!("http://127.0.0.1:{}{}", port, path);
                let curl_args = vec![
                    "-fsSL".to_string(),
                    "--max-time".to_string(),
                    "5".to_string(),
                    url.clone(),
                ];
                let max_attempts = env::var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS")
                    .ok()
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .filter(|&n| n >= 1)
                    .unwrap_or(if self.env_cfg.fs_root.is_some() { 5 } else { 15 });
                let retry_delay_ms = env::var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS")
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(if self.env_cfg.fs_root.is_some() { 15 } else { 500 });
                let deadline = Instant::now()
                    + Duration::from_secs(if self.env_cfg.fs_root.is_some() { 5 } else { 30 });
                let mut last_reason = String::new();
                for attempt in 1..=max_attempts {
                    cancel.check(&recipe.package_id)?;
                    let out = self
                        .runner
                        .run_command("curl", &curl_args, &[], cancel)
                        .await?;
                    if out.success() {
                        let require_live = env::var("AETHERFLOW_REQUIRE_LIVE_LISTENER")
                            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false)
                            || (!out.stdout.starts_with("ok: curl ")
                                && !out.stdout.starts_with("[dry-run] curl "));
                        if require_live {
                            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                            match std::net::TcpStream::connect_timeout(
                                &addr,
                                Duration::from_millis(250),
                            ) {
                                Ok(_) => return Ok(format!("verified HTTP readiness at {}", url)),
                                Err(err) => {
                                    last_reason = format!(
                                        "application listener on 127.0.0.1:{} is not accepting TCP connections: {}",
                                        port, err
                                    );
                                }
                            }
                        } else {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "application readiness check failed for {}: {}",
                            url,
                            out.combined_output()
                        );
                    }
                    if attempt == max_attempts || Instant::now() >= deadline {
                        break;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(retry_delay_ms)) => {}
                        _ = wait_for_cancellation(cancel) => {
                            return Err(PackageExecutorError::Cancelled(
                                recipe.package_id.clone(),
                            ));
                        }
                    }
                }
                Err(PackageExecutorError::StepFailed {
                    step: format!("wait_for_http_ready {}", url),
                    reason: last_reason,
                })
            }
        }
    }

    fn resolve_explicit_password(&self) -> Option<String> {
        if self.env_cfg.keep_existing_secrets {
            return None;
        }
        self.env_cfg
            .password
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin")
            .or_else(|| {
                env::var("AF_PASS")
                    .or_else(|_| env::var("AETHERFLOW_MASTER_PASS"))
                    .or_else(|_| env::var("MASTER_PASS"))
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty() && v != "adminadmin")
            })
    }

    fn is_active_mountpoint(&self, logical: &str, resolved: &Path) -> bool {
        let norm_logical = logical.trim().trim_end_matches('/');
        let norm_resolved = resolved.to_string_lossy().trim_end_matches('/').to_string();

        let mut mount_tables = vec![
            self.env_cfg.resolve_readonly_path("/proc/mounts"),
            self.env_cfg.resolve_readonly_path("/proc/self/mountinfo"),
        ];
        if self.env_cfg.fs_root.is_none() {
            mount_tables.push(PathBuf::from("/proc/mounts"));
        }

        for table_path in mount_tables {
            if let Ok(contents) = fs::read_to_string(&table_path) {
                for line in contents.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    let mp_candidates: Vec<&str> = if table_path.ends_with("mountinfo") {
                        fields.get(4).copied().into_iter().collect()
                    } else {
                        fields.get(1).copied().into_iter().collect()
                    };
                    for raw_mp in mp_candidates {
                        let unescaped = raw_mp.replace("\\040", " ");
                        let mp = unescaped.trim_end_matches('/');
                        if !mp.is_empty()
                            && mp != "/"
                            && (mp == norm_logical || mp == norm_resolved)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if matches!(norm_logical, "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote")
                || norm_logical.starts_with("/mnt/")
            {
                if let (Ok(meta), Some(parent)) =
                    (fs::symlink_metadata(resolved), resolved.parent())
                {
                    if let Ok(parent_meta) = fs::symlink_metadata(parent) {
                        if meta.dev() != parent_meta.dev() {
                            return true;
                        }
                    }
                }
            }
        }

        if self.env_cfg.fs_root.is_none() && cfg!(target_os = "linux") {
            if matches!(norm_logical, "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote")
                || norm_logical.starts_with("/mnt/")
            {
                if let Ok(status) = std::process::Command::new("mountpoint")
                    .arg("-q")
                    .arg(resolved)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                {
                    if status.success() {
                        return true;
                    }
                }
            }
        }

        false
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
        | DeclarativeStep::MergeIniSettings {
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
        }
        | DeclarativeStep::RunCommand {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WaitForHttpReady {
            progress_pct,
            description,
            ..
        } => (*progress_pct, description.as_str()),
    }
}

fn format_znc_major_minor(version: &str) -> String {
    let clean = version.trim().trim_start_matches('v');
    let core = clean
        .split(['-', '+', '~', ':'])
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(clean);
    let mut parts = core.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor))
            if !major.is_empty()
                && !minor.is_empty()
                && major.chars().all(|c| c.is_ascii_digit()) =>
        {
            let minor_digits: String = minor.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !minor_digits.is_empty() {
                format!("{}.{}", major, minor_digits)
            } else {
                "1.9".to_string()
            }
        }
        _ => "1.9".to_string(),
    }
}

fn update_preserved_rclone_env_pass(existing: &str, raw_pass: &str) -> String {
    let escaped = escape_systemd_env_quoted(raw_pass);
    let new_line = format!("RCLONE_RC_PASS=\"{}\"", escaped);
    static RCLONE_PASS_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^[ \t]*RCLONE_RC_PASS[ \t]*=.*$").unwrap());
    if RCLONE_PASS_RE.is_match(existing) {
        RCLONE_PASS_RE
            .replace_all(existing, new_line.as_str())
            .into_owned()
    } else {
        let mut out = existing.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_line);
        out.push('\n');
        out
    }
}

fn parse_semver_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let clean = raw.trim().trim_start_matches('v');
    let core = clean.split(['-', '+']).next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    Some((major, minor, patch))
}

fn is_semver_strictly_greater(a: &str, b: &str) -> bool {
    match (parse_semver_tuple(a), parse_semver_tuple(b)) {
        (Some(ta), Some(tb)) => ta > tb,
        _ => false,
    }
}

fn is_downgrade_allowed() -> bool {
    env::var("AF_ALLOW_DOWNGRADE")
        .ok()
        .map(|v| {
            let trimmed = v.trim();
            trimmed == "1" || trimmed.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn merge_ini_settings(original: &str, section: &str, settings: &[(String, String)]) -> String {
    let mut remaining = settings.to_vec();
    let mut output = String::new();
    let mut in_section = false;
    let mut found_section = false;
    for line in original.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_section {
                for (key, value) in remaining.drain(..) {
                    output.push_str(&format!("    {key} = {value}\n"));
                }
            }
            in_section = trimmed == format!("[{section}]");
            found_section |= in_section;
        }
        if in_section {
            if let Some((key, _)) = trimmed.split_once('=') {
                if let Some((managed_key, value)) = settings.iter().find(|(managed_key, _)| managed_key == key.trim()) {
                    let indentation = &line[..line.len() - line.trim_start().len()];
                    if let Some((lhs, _)) = line.split_once('=') {
                        if lhs.ends_with(' ') || lhs.ends_with('\t') {
                            output.push_str(&format!("{lhs}= {value}\n"));
                        } else {
                            output.push_str(&format!("{indentation}{managed_key} = {value}\n"));
                        }
                    } else {
                        output.push_str(&format!("{indentation}{managed_key} = {value}\n"));
                    }
                    remaining.retain(|(pending, _)| pending != managed_key);
                    continue;
                }
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    if !found_section {
        output.push_str(&format!("\n[{section}]\n"));
    }
    for (key, value) in remaining {
        output.push_str(&format!("    {key} = {value}\n"));
    }
    output
}

fn escape_systemd_env_quoted(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 8);
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out
}

fn interpolate_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        let placeholder = format!("{{{{{}}}}}", k);
        out = out.replace(&placeholder, v);
        let angle_placeholder = format!("<{}>", k);
        out = out.replace(&angle_placeholder, v);
    }
    out
}

/// Classic RFB / TigerVNC fixed DES obfuscation key (`[23, 82, 107, 6, 35, 78, 88, 7]`).
const TIGERVNC_FIXED_KEY: [u8; 8] = [23, 82, 107, 6, 35, 78, 88, 7];

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

const DES_SBOX: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn des_permute(src: u64, src_bits: u8, table: &[u8]) -> u64 {
    let mut dst = 0u64;
    for (i, &pos) in table.iter().enumerate() {
        let bit = (src >> (src_bits - pos)) & 1;
        dst |= bit << (table.len() - 1 - i);
    }
    dst
}

fn des_subkeys_vnc() -> [u64; 16] {
    let mut rev_key = [0u8; 8];
    for (i, &b) in TIGERVNC_FIXED_KEY.iter().enumerate() {
        rev_key[i] = b.reverse_bits();
    }
    let key_u64 = u64::from_be_bytes(rev_key);
    let cd = des_permute(key_u64, 64, &DES_PC1);
    let mut c = ((cd >> 28) & 0x0fff_ffff) as u32;
    let mut d = (cd & 0x0fff_ffff) as u32;
    let mut subkeys = [0u64; 16];
    for (round, &shift) in DES_SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fff_ffff;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fff_ffff;
        let combined = ((c as u64) << 28) | (d as u64);
        subkeys[round] = des_permute(combined, 56, &DES_PC2);
    }
    subkeys
}

fn des_feistel(r: u32, k: u64) -> u32 {
    let er = des_permute(r as u64, 32, &DES_E) ^ k;
    let mut s_out = 0u32;
    for i in 0..8 {
        let chunk = ((er >> (42 - 6 * i)) & 0x3f) as u8;
        let row = (((chunk >> 5) & 1) << 1) | (chunk & 1);
        let col = (chunk >> 1) & 0x0f;
        let val = DES_SBOX[i][row as usize][col as usize];
        s_out = (s_out << 4) | (val as u32);
    }
    des_permute(s_out as u64, 32, &DES_P) as u32
}

fn des_block_crypt(block: [u8; 8], decrypt: bool) -> [u8; 8] {
    let subkeys = des_subkeys_vnc();
    let ip = des_permute(u64::from_be_bytes(block), 64, &DES_IP);
    let mut l = (ip >> 32) as u32;
    let mut r = (ip & 0xffff_ffff) as u32;
    for i in 0..16 {
        let k = if decrypt { subkeys[15 - i] } else { subkeys[i] };
        let next_l = r;
        let next_r = l ^ des_feistel(r, k);
        l = next_l;
        r = next_r;
    }
    let preoutput = ((r as u64) << 32) | (l as u64);
    des_permute(preoutput, 64, &DES_FP).to_be_bytes()
}

/// Obfuscates a plaintext password into the 8-byte binary format expected by
/// TigerVNC `Xtigervnc -PasswordFile` (`vncpasswd -f` / `rfb::obfuscate`).
pub fn encode_tigervnc_passwd(password: &str) -> [u8; 8] {
    let mut plain = [0u8; 8];
    let bytes = password.as_bytes();
    let take = bytes.len().min(8);
    plain[..take].copy_from_slice(&bytes[..take]);
    des_block_crypt(plain, false)
}

/// Deobfuscates an 8-byte TigerVNC `PasswordFile` block into its UTF-8 password prefix
/// (up to 8 characters, stripping trailing NUL padding), returning `None` if `obfuscated`
/// is not 8 bytes or does not decode to valid UTF-8.
pub fn decode_tigervnc_passwd(obfuscated: &[u8]) -> Option<String> {
    let block: [u8; 8] = obfuscated.try_into().ok()?;
    let decrypted = des_block_crypt(block, true);
    let end = decrypted.iter().position(|&b| b == 0).unwrap_or(8);
    if decrypted[end..].iter().any(|&b| b != 0) {
        return None;
    }
    std::str::from_utf8(&decrypted[..end])
        .ok()
        .map(str::to_string)
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

fn collect_package_version_receipt_logical_paths(pkg: &af_models::Package, pkg_id: &str) -> Vec<String> {
    static AF_VERSION_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(/[A-Za-z0-9_./-]*/\.af-version)").unwrap());
    let mut paths = Vec::new();
    for token in &pkg.version_command {
        for cap in AF_VERSION_RE.captures_iter(token) {
            if let Some(m) = cap.get(1) {
                let p = m.as_str().to_string();
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        let candidate = format!("{}/{}/.af-version", prefix, pkg_id);
        if !paths.contains(&candidate) {
            paths.push(candidate);
        }
        if !pkg.name.is_empty() && pkg.name != pkg_id {
            let alt = format!("{}/{}/.af-version", prefix, pkg.name);
            if !paths.contains(&alt) {
                paths.push(alt);
            }
        }
    }
    paths
}

/// Ensures systemd sandbox drop-ins (`aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf`)
/// are written on `"install"`, `"reinstall"`, and `"update"`, and removed (along with stale
/// `.af-version` receipts) on `"remove"` / `"uninstall"` across both synthetic roots and live `/`.
pub fn ensure_package_sandbox_dropin_under_root(
    install_root: Option<&Path>,
    pkg_id: &str,
    action: &str,
) -> Result<(), PackageExecutorError> {
    let effective_root: Option<PathBuf> = install_root.map(Path::to_path_buf).or_else(|| {
        env::var("AETHERFLOW_INSTALL_ROOT")
            .or_else(|_| env::var("AETHERFLOW_PACKAGE_FS_ROOT"))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v != "/")
            .map(PathBuf::from)
    });
    let systemd_root = env::var("AETHERFLOW_SYSTEMD_ROOT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| match effective_root.as_deref() {
            Some(root) => root.join("etc/systemd/system"),
            None => PathBuf::from("/etc/systemd/system"),
        });

    let action_lower = action.trim().to_ascii_lowercase();
    match action_lower.as_str() {
        "install" | "reinstall" | "update" => {
            apply_sandbox_in_root_with_journal(
                pkg_id,
                &systemd_root,
                None,
                effective_root.as_deref(),
            )?;
        }
        "remove" | "uninstall" => {
            if let Some(pkg) = crate::get_runner_package_definition(pkg_id) {
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
                    let _ = fs::remove_file(dropin_dir.join("aetherflow-sandbox.conf"));
                    let _ = fs::remove_file(dropin_dir.join("10-aetherflow-sandbox.conf"));
                    if let Ok(mut entries) = fs::read_dir(&dropin_dir) {
                        if entries.next().is_none() {
                            let _ = fs::remove_dir(&dropin_dir);
                        }
                    }
                }
                for logical_version_path in collect_package_version_receipt_logical_paths(&pkg, pkg_id) {
                    let resolved = match effective_root.as_deref() {
                        Some(root) => root.join(logical_version_path.trim_start_matches('/')),
                        None => PathBuf::from(&logical_version_path),
                    };
                    let _ = fs::remove_file(resolved);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Unified Runner Stream Dispatcher (Declarative Rust + Legacy Bash Fallback)
// -----------------------------------------------------------------------------

/// Validates that `script_name` canonically matches `package_id` and `action`
/// so one package's request can never resolve or execute another package's script.
pub fn script_matches_package_identity(action: &str, package_id: &str, script_name: &str) -> bool {
    let pkg = package_id.trim().to_ascii_lowercase();
    let script = Path::new(script_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if pkg.is_empty() || script.is_empty() {
        return false;
    }

    let prefixes: &[&str] = match action.trim().to_ascii_lowercase().as_str() {
        "install" | "reinstall" => &["installpackage-"],
        "remove" | "uninstall" => &["removepackage-"],
        "update" => &["updatepackage-", "installpackage-"],
        _ => return false,
    };

    let Some(script_stem) = prefixes.iter().find_map(|p| script.strip_prefix(p)) else {
        return false;
    };
    if script_stem.is_empty() {
        return false;
    }

    let mut allowed_stems = vec![pkg.as_str()];
    match pkg.as_str() {
        "calibre-web" => allowed_stems.push("calibreweb"),
        "calibreweb" => allowed_stems.push("calibre-web"),
        "uptime-kuma" => allowed_stems.push("uptimekuma"),
        "uptimekuma" => allowed_stems.push("uptime-kuma"),
        "pyload-ng" => allowed_stems.push("pyload"),
        "pyload" => allowed_stems.push("pyload-ng"),
        "adguard-home" => allowed_stems.push("adguardhome"),
        "adguardhome" => allowed_stems.push("adguard-home"),
        _ => {}
    }

    if allowed_stems.contains(&script_stem) {
        return true;
    }

    // Allow synthetic non-catalog test fixtures (e.g. `package_id = "fixture"` with
    // `installpackage-overflow-fixture` or `installpackage-hillclimb-<uuid>`) in isolated tests.
    if pkg == "fixture"
        && (script_stem.ends_with("-fixture")
            || script_stem.starts_with("fixture-")
            || script_stem.starts_with("hillclimb-")
            || script_stem.starts_with("polling-"))
    {
        return true;
    }

    false
}

/// Resolves whether a `PackageRunnerRequest` can be satisfied by either a built-in
/// declarative Rust recipe or a legacy Bash script on disk.
pub fn can_resolve_package_operation(action: &str, pkg_id: &str, script_name: &str) -> bool {
    if PackageAction::parse(action).is_none() {
        return false;
    }
    if !script_matches_package_identity(action, pkg_id, script_name) {
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

/// Parses master username and password from JSON credential stores, `/install/.aetherflow.conf`,
/// `/etc/aetherflow/master.Indexed`, or `/root/.aetherflow_master`.
fn parse_master_credentials_content(raw: &str) -> (Option<String>, Option<String>) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) {
        let user = val
            .get("username")
            .or_else(|| val.get("user"))
            .or_else(|| val.get("MASTER_USER"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let pass = val
            .get("password")
            .or_else(|| val.get("passwd"))
            .or_else(|| val.get("pass"))
            .or_else(|| val.get("MASTER_PASS"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin");
        return (user, pass);
    }

    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("MASTER_USER=")
            .or_else(|| line.strip_prefix("username="))
        {
            let v = rest.trim().trim_matches('"').trim_matches('\'').trim();
            if !v.is_empty() {
                user = Some(v.to_string());
            }
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("MASTER_PASS=")
            .or_else(|| line.strip_prefix("password="))
            .or_else(|| line.strip_prefix("passwd="))
        {
            let v = rest.trim().trim_matches('"').trim_matches('\'').trim();
            if !v.is_empty() && v != "adminadmin" {
                pass = Some(v.to_string());
            }
            continue;
        }
        if user.is_none() && pass.is_none() && !line.contains('=') {
            if let Some((u, p)) = line.split_once(':') {
                let u = u.trim();
                let p = p.trim();
                if !u.is_empty() {
                    user = Some(u.to_string());
                }
                if !p.is_empty() && p != "adminadmin" {
                    pass = Some(p.to_string());
                }
            } else {
                user = Some(line.to_string());
            }
        }
    }
    (user, pass)
}

/// Resolves `(MASTER_USER, MASTER_PASS)` from process environment or credential files,
/// generating and persisting a cryptographically unique fallback secret when absent.
fn resolve_master_credentials(fs_root: Option<&Path>) -> (String, String) {
    let env_user = env::var("AETHERFLOW_MASTER_USER")
        .or_else(|_| env::var("MASTER_USER"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let env_pass = env::var("AETHERFLOW_MASTER_PASS")
        .or_else(|_| env::var("MASTER_PASS"))
        .or_else(|_| env::var("AF_PASS"))
        .or_else(|_| env::var("AETHERFLOW_VNC_PASSWORD"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "adminadmin");

    if let Some(pass) = env_pass {
        return (env_user.unwrap_or_else(|| "admin".to_string()), pass);
    }

    let rebase_path = |logical: &str| -> PathBuf {
        let p = Path::new(logical);
        match fs_root {
            Some(root) => {
                if p.starts_with(root) {
                    p.to_path_buf()
                } else if logical.starts_with('/') {
                    root.join(logical.trim_start_matches('/'))
                } else {
                    p.to_path_buf()
                }
            }
            None => p.to_path_buf(),
        }
    };

    let mut candidate_paths = Vec::new();
    if let Ok(custom_file) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        let trimmed = custom_file.trim();
        if !trimmed.is_empty() {
            candidate_paths.push(rebase_path(trimmed));
        }
    }
    for default_logical in [
        "/var/lib/aetherflow/.master.creds",
        "/opt/AetherFlow/backend/data/.master.creds",
        "/etc/aetherflow/master.Indexed",
        "/install/.aetherflow.conf",
        "/root/.aetherflow_master",
    ] {
        candidate_paths.push(rebase_path(default_logical));
    }

    let mut file_user: Option<String> = None;
    let mut file_pass: Option<String> = None;
    for candidate in candidate_paths {
        if let Ok(contents) = fs::read_to_string(&candidate) {
            let (u, p) = parse_master_credentials_content(&contents);
            if file_user.is_none() {
                file_user = u;
            }
            if file_pass.is_none() && p.is_some() {
                file_pass = p;
                break;
            }
        }
    }

    let master_user = env_user
        .or(file_user)
        .unwrap_or_else(|| "admin".to_string());
    let master_pass = match file_pass {
        Some(pass) => pass,
        None => {
            let generated = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let persist_path = rebase_path("/var/lib/aetherflow/.master.creds");
            let payload = serde_json::json!({
                "username": master_user,
                "password": generated,
            })
            .to_string();
            let _ = write_file_atomic_with_mode_bounded(
                &persist_path,
                payload.as_bytes(),
                0o600,
                fs_root,
            );
            generated
        }
    };
    (master_user, master_pass)
}

/// Updates listening/scrape port in-place on preserved package configuration files
/// without clobbering existing operator credentials or custom settings.
fn update_preserved_template_port(
    logical_path: &str,
    existing: &str,
    rendered: &str,
    app_port: &str,
) -> Option<String> {
    if logical_path.ends_with("/etc/default/prometheus")
        || rendered.contains("--web.listen-address=")
    {
        static PROM_DEFAULT_PORT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(--web\.listen-address=(?:[^\s\x22':]+)?):[0-9]+").unwrap()
        });
        if PROM_DEFAULT_PORT_RE.is_match(existing) {
            let replacement = format!("${{1}}:{}", app_port);
            let updated = PROM_DEFAULT_PORT_RE
                .replace_all(existing, replacement.as_str())
                .into_owned();
            return (updated != existing).then_some(updated);
        }

        static RENDERED_LISTEN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"--web\.listen-address=([^\s\x22':]+):[0-9]+").unwrap()
        });
        let listen_flag = if let Some(caps) = RENDERED_LISTEN_RE.captures(rendered) {
            let host = caps.get(1).map(|m| m.as_str()).unwrap_or("127.0.0.1");
            format!("--web.listen-address={}:{}", host, app_port)
        } else {
            format!("--web.listen-address=127.0.0.1:{}", app_port)
        };

        static ARGS_LINE_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?m)^([ \t]*ARGS[ \t]*=[ \t]*)(.*)$").unwrap());
        let updated = if let Some(caps) = ARGS_LINE_RE.captures(existing) {
            let full_match = caps.get(0).unwrap();
            let prefix = caps.get(1).unwrap().as_str();
            let raw_rhs = caps.get(2).unwrap().as_str().trim_end();
            let new_rhs = if raw_rhs.starts_with('"') && raw_rhs.ends_with('"') && raw_rhs.len() >= 2
            {
                let inner = raw_rhs[1..raw_rhs.len() - 1].trim();
                if inner.is_empty() {
                    format!("\"{}\"", listen_flag)
                } else {
                    format!("\"{} {}\"", inner, listen_flag)
                }
            } else if raw_rhs.starts_with('\'') && raw_rhs.ends_with('\'') && raw_rhs.len() >= 2 {
                let inner = raw_rhs[1..raw_rhs.len() - 1].trim();
                if inner.is_empty() {
                    format!("'{}'", listen_flag)
                } else {
                    format!("'{} {}'", inner, listen_flag)
                }
            } else if raw_rhs.is_empty() {
                format!("\"{}\"", listen_flag)
            } else {
                format!("\"{} {}\"", raw_rhs, listen_flag)
            };
            let mut out = String::with_capacity(existing.len() + listen_flag.len() + 8);
            out.push_str(&existing[..full_match.start()]);
            out.push_str(prefix);
            out.push_str(&new_rhs);
            out.push_str(&existing[full_match.end()..]);
            out
        } else {
            let mut out = existing.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("ARGS=\"{}\"\n", listen_flag));
            out
        };
        return (updated != existing).then_some(updated);
    }

    match logical_path {
        "/etc/default/quasselcore" => {
            static QUASSEL_PORT_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?m)^([ \t]*PORT[ \t]*=[ \t]*)(?:"[0-9]+"|'[0-9]+'|[0-9]+)([ \t]*)$"#)
                    .unwrap()
            });
            if QUASSEL_PORT_RE.is_match(existing) {
                let replacement = format!("${{1}}\"{}\"${{2}}", app_port);
                Some(
                    QUASSEL_PORT_RE
                        .replace_all(existing, replacement.as_str())
                        .into_owned(),
                )
            } else {
                None
            }
        }
        "/var/lib/znc/configs/znc.conf" => {
            static ZNC_PORT_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(?m)^[ \t]*Port[ \t]*=[ \t]*\d+([ \t]*)$").unwrap());
            if ZNC_PORT_RE.is_match(existing) {
                let replacement = format!("    Port = {}$1", app_port);
                Some(
                    ZNC_PORT_RE
                        .replace(existing, replacement.as_str())
                        .into_owned(),
                )
            } else {
                None
            }
        }
        "/etc/prometheus/prometheus.yml" => {
            static PROM_JOB_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(?m)job_name:\s*['\x22]?prometheus['\x22]?").unwrap());
            static PROM_TARGET_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(127\.0\.0\.1|localhost):(\d+)").unwrap());
            if let Some(job_match) = PROM_JOB_RE.find(existing) {
                let after = &existing[job_match.end()..];
                if let Some(caps) = PROM_TARGET_RE.captures(after) {
                    let full = caps.get(0).unwrap();
                    let host = caps.get(1).unwrap().as_str();
                    let abs_start = job_match.end() + full.start();
                    let abs_end = job_match.end() + full.end();
                    let mut out = String::with_capacity(existing.len() + 8);
                    out.push_str(&existing[..abs_start]);
                    out.push_str(&format!("{}:{}", host, app_port));
                    out.push_str(&existing[abs_end..]);
                    return Some(out);
                }
            }
            for caps in PROM_TARGET_RE.captures_iter(existing) {
                let port = caps.get(2).unwrap().as_str();
                if port != "9100" {
                    let full = caps.get(0).unwrap();
                    let host = caps.get(1).unwrap().as_str();
                    let mut out = String::with_capacity(existing.len() + 8);
                    out.push_str(&existing[..full.start()]);
                    out.push_str(&format!("{}:{}", host, app_port));
                    out.push_str(&existing[full.end()..]);
                    return Some(out);
                }
            }
            None
        }
        _ => None,
    }
}

/// Whether a request explicitly asks a removal to purge retained application
/// data. Install and update never purge, and the runner's own `DELETE_DATA`
/// environment is deliberately ignored so a stray daemon setting cannot turn
/// every ordinary uninstall into a destructive one.
pub(crate) fn package_request_deletes_data(req: &PackageRunnerRequest) -> bool {
    req.delete_data && req.action == "remove"
}

const EMBEDDED_AUTOMATION_FOR_EXECUTOR: &str =
    include_str!("../../../../config/package_automation.json");

fn resolve_package_lock_name(pkg_id: &str) -> &str {
    let trimmed = pkg_id.trim();
    if trimmed == "autodl" {
        "autodlirssi"
    } else {
        trimmed
    }
}

/// Returns whether `config/package_automation.json` configures `require_download_sha256: true`
/// for `pkg_id`.
pub fn package_requires_download_sha256(pkg_id: &str) -> bool {
    let raw = if let Ok(explicit) = env::var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            fs::read_to_string(trimmed).ok()
        } else {
            None
        }
    } else {
        None
    }
    .or_else(|| {
        for candidate in [
            "/opt/AetherFlow/current/config/package_automation.json",
            "/opt/AetherFlow/current/backend/config/package_automation.json",
            "config/package_automation.json",
            "../config/package_automation.json",
            "/opt/AetherFlow/config/package_automation.json",
            "backend/config/package_automation.json",
            "../backend/config/package_automation.json",
            "/opt/AetherFlow/backend/config/package_automation.json",
        ] {
            if let Ok(s) = fs::read_to_string(candidate) {
                return Some(s);
            }
        }
        None
    })
    .unwrap_or_else(|| EMBEDDED_AUTOMATION_FOR_EXECUTOR.to_string());

    let map: HashMap<String, af_models::PackageAutomation> =
        serde_json::from_str(&raw).unwrap_or_default();
    let clean = resolve_package_lock_name(pkg_id);
    map.get(clean)
        .or_else(|| map.get(pkg_id.trim()))
        .map(|a| a.require_download_sha256)
        .unwrap_or(false)
}

fn parse_port_from_runner_lockfile(raw: &str) -> Option<i32> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(p) = trimmed.parse::<i32>() {
            if (1024..=65535).contains(&p) {
                return Some(p);
            }
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let key = lhs.trim();
            if matches!(
                key,
                "PORT" | "AF_APP_PORT" | "AETHERFLOW_APP_PORT" | "listen_port" | "port"
            ) {
                let clean_rhs = rhs.trim().trim_matches('"').trim_matches('\'').trim();
                if let Ok(p) = clean_rhs.parse::<i32>() {
                    if (1024..=65535).contains(&p) {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Resolves the effective listen port for `install` / `reinstall` / `update` when `req.app_port`
/// was not explicitly supplied (`<= 0`), checking persisted SQLite ingress (`app_ingress_configs`
/// and `retained_app_ingress_configs`), native runtime config, lockfile, and catalog `default_port`.
pub fn resolve_effective_runner_app_port(
    action: &str,
    pkg_id: &str,
    requested_port: i32,
) -> i32 {
    let action_lower = action.trim().to_ascii_lowercase();
    if action_lower == "remove" || action_lower == "uninstall" {
        return 0;
    }
    if (1024..=65535).contains(&requested_port) {
        return requested_port;
    }

    let clean_id = resolve_package_lock_name(pkg_id);
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(Some(cfg)) = af_db::load_lifecycle_ingress(&conn, clean_id)
            .or_else(|_| af_db::load_lifecycle_ingress(&conn, pkg_id.trim()))
        {
            if (1024..=65535).contains(&cfg.listen_port) {
                return cfg.listen_port;
            }
        }
    }

    let env_cfg = PackageExecutionEnv::default();
    if env_cfg.fs_root.is_none() {
        let meta = crate::extract_app_runtime_meta_local(clean_id);
        if (1024..=65535).contains(&meta.configured_port) {
            return meta.configured_port;
        }
    }

    let lock_logical = format!("/install/.{}.lock", clean_id);
    if let Ok(lock_path) = env_cfg.resolve_path(&lock_logical) {
        if let Ok(raw_lock) = fs::read_to_string(&lock_path) {
            if let Some(p) = parse_port_from_runner_lockfile(&raw_lock) {
                return p;
            }
        }
    }

    crate::get_runner_package_definition(clean_id)
        .or_else(|| crate::get_runner_package_definition(pkg_id.trim()))
        .map(|p| p.default_port)
        .filter(|p| (1024..=65535).contains(p))
        .unwrap_or(0)
}

fn write_config_atomic_preserving_meta(
    file_path: &Path,
    content: &[u8],
    fs_root: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(file_path, fs_root)?;
    let existing_meta = match fs::symlink_metadata(file_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return Err(PackageExecutorError::SecurityViolation(format!(
                    "refusing to overwrite non-regular config file {}",
                    file_path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing to overwrite hardlinked config file {} (nlink={})",
                        file_path.display(),
                        meta.nlink()
                    )));
                }
            }
            Some(meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        existing_meta
            .as_ref()
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o600)
    };
    #[cfg(not(unix))]
    let mode = 0o600;

    write_file_atomic_with_mode_bounded(file_path, content, mode, fs_root)?;

    #[cfg(unix)]
    if let Some(meta) = existing_meta {
        use std::os::unix::fs::{chown, MetadataExt};
        let _ = chown(file_path, Some(meta.uid()), Some(meta.gid()));
        let _ = fs::set_permissions(file_path, meta.permissions());
    }
    Ok(())
}

fn runner_candidate_exists_or_symlink(p: &Path) -> Result<bool, PackageExecutorError> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect required blueprint config {}: {}",
            p.display(),
            err
        ))),
    }
}

fn validate_regular_config_candidate(
    file_path: &Path,
    fs_root: Option<&Path>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(file_path, fs_root)?;
    let meta = fs::symlink_metadata(file_path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to use non-regular config file {}",
            file_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to use hardlinked config file {} (nlink={})",
                file_path.display(),
                meta.nlink()
            )));
        }
    }
    Ok(())
}

fn runner_mutate_xml_tag(
    file_path: &Path,
    tag_name: &str,
    new_value: &str,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let root_tag = if existing.contains("<NetworkConfiguration") {
        "NetworkConfiguration"
    } else if existing.contains("<ServerConfiguration") {
        "ServerConfiguration"
    } else {
        "Config"
    };
    let escaped_tag = regex::escape(tag_name);
    if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
        let escaped_val = regex::escape(new_value.trim());
        let check_re = Regex::new(&format!(
            r"(?is)<KnownProxies>\s*<string>\s*{}\s*</string>\s*</KnownProxies>",
            escaped_val
        ))
        .unwrap();
        if check_re.is_match(&existing) {
            return Ok(false);
        }
    } else {
        let extract_re =
            Regex::new(&format!(r"(?is)<{0}>\s*([^<]*?)\s*</{0}>", escaped_tag)).unwrap();
        if let Some(caps) = extract_re.captures(&existing) {
            if caps.get(1).map(|m| m.as_str().trim()) == Some(new_value.trim()) {
                return Ok(false);
            }
        }
    }

    let mut content = existing.clone();
    let closing_tag = format!("</{}>", root_tag);
    if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
        let re_known =
            Regex::new(r"(?s)<KnownProxies\s*/>|<KnownProxies>.*?</KnownProxies>").unwrap();
        let replacement = format!(
            "<KnownProxies>\n    <string>{}</string>\n  </KnownProxies>",
            new_value
        );
        if re_known.is_match(&content) {
            content = re_known.replace_all(&content, replacement.as_str()).into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", replacement));
        }
    } else {
        let re_tag =
            Regex::new(&format!(r"(?s)<{0}>.*?</{0}>|<{0}\s*/>", escaped_tag)).unwrap();
        let new_elem = format!("<{0}>{1}</{0}>", tag_name, new_value);
        if re_tag.is_match(&content) {
            content = re_tag.replace_all(&content, new_elem.as_str()).into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", new_elem));
        }
    }
    if content == existing {
        return Ok(false);
    }
    write_config_atomic_preserving_meta(file_path, content.as_bytes(), fs_root)?;
    Ok(true)
}

fn runner_mutate_ini_key(
    file_path: &Path,
    section: &str,
    key: &str,
    new_value: &str,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let key_trimmed = key.trim();
    let section_trimmed = section.trim();
    let want_sec_lower = section_trimmed.to_lowercase();
    let mut current_section = String::new();
    let mut found_section = want_sec_lower.is_empty();
    let mut key_updated = false;
    let mut output_lines: Vec<String> = Vec::new();
    let mut insert_after_section_idx: Option<usize> = None;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            output_lines.push(line.to_string());
            if !want_sec_lower.is_empty() && current_section == want_sec_lower {
                found_section = true;
                insert_after_section_idx = Some(output_lines.len());
            }
            continue;
        }
        let in_matching_section = want_sec_lower.is_empty()
            || current_section == want_sec_lower
            || current_section.is_empty();
        if !key_updated && in_matching_section && !trimmed.starts_with('#') && !trimmed.starts_with(';') {
            if let Some((lhs, rhs)) = line.split_once('=') {
                if lhs.trim().eq_ignore_ascii_case(key_trimmed) {
                    if rhs.trim() == new_value.trim() {
                        return Ok(false);
                    }
                    output_lines.push(format!("{}={}", lhs, new_value));
                    key_updated = true;
                    continue;
                }
            }
        }
        output_lines.push(line.to_string());
        if !want_sec_lower.is_empty() && current_section == want_sec_lower {
            insert_after_section_idx = Some(output_lines.len());
        }
    }

    if !key_updated {
        let new_line = format!("{}={}", key_trimmed, new_value);
        if let Some(idx) = insert_after_section_idx {
            output_lines.insert(idx, new_line);
        } else if !found_section && !want_sec_lower.is_empty() {
            if !output_lines.is_empty() && !output_lines.last().unwrap().trim().is_empty() {
                output_lines.push(String::new());
            }
            output_lines.push(format!("[{}]", section_trimmed));
            output_lines.push(new_line);
        } else {
            output_lines.push(new_line);
        }
    }

    let final_content = format!("{}\n", output_lines.join("\n"));
    if final_content == existing {
        return Ok(false);
    }
    write_config_atomic_preserving_meta(file_path, final_content.as_bytes(), fs_root)?;
    Ok(true)
}

fn runner_mutate_json_key(
    file_path: &Path,
    key: &str,
    new_value: serde_json::Value,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    if !runner_candidate_exists_or_symlink(file_path)? {
        return Ok(false);
    }
    validate_regular_config_candidate(file_path, fs_root)?;
    let existing = fs::read_to_string(file_path)?;
    let mut root = serde_json::from_str::<serde_json::Value>(&existing).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "invalid JSON config {}: {}",
            file_path.display(),
            err
        ))
    })?;
    let Some(obj) = root.as_object_mut() else {
        return Err(PackageExecutorError::VerificationFailed(format!(
            "JSON config {} root is not an object",
            file_path.display()
        )));
    };
    let mut changed = false;
    if let Some((parent_key, child_key)) = key.split_once('.') {
        if obj.contains_key(key) {
            if obj.get(key) != Some(&new_value) {
                obj.insert(key.to_string(), new_value);
                changed = true;
            }
        } else {
            let entry = obj
                .entry(parent_key.to_string())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            let Some(sub) = entry.as_object_mut() else {
                return Err(PackageExecutorError::VerificationFailed(format!(
                    "JSON config {} key '{}' is not an object",
                    file_path.display(),
                    parent_key
                )));
            };
            if sub.get(child_key) != Some(&new_value) {
                sub.insert(child_key.to_string(), new_value);
                changed = true;
            }
        }
    } else if obj.get(key) != Some(&new_value) {
        obj.insert(key.to_string(), new_value);
        changed = true;
    }
    if !changed {
        return Ok(false);
    }
    let serialized = serde_json::to_string_pretty(&root).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "failed to serialize JSON config {}: {}",
            file_path.display(),
            err
        ))
    })?;
    let final_content = format!("{}\n", serialized);
    write_config_atomic_preserving_meta(file_path, final_content.as_bytes(), fs_root)?;
    Ok(true)
}

/// Applies post-install blueprint config mutations inside the privileged runner process so that
/// root-owned or service-user-owned config files under `/etc` and `/var/lib` are updated with
/// preserved ownership and permissions before control returns to the unprivileged API process.
pub fn apply_runner_blueprint_app_config(
    fs_root: Option<&Path>,
    pkg_id: &str,
    listen_port: i32,
) {
    let _ = try_apply_runner_blueprint_app_config(fs_root, pkg_id, listen_port);
}

/// Fallible variant of [`apply_runner_blueprint_app_config`] that validates candidate config files
/// against symlinks/hardlinks and propagates any config mutation or verification errors.
pub fn try_apply_runner_blueprint_app_config(
    fs_root: Option<&Path>,
    pkg_id: &str,
    listen_port: i32,
) -> Result<(), PackageExecutorError> {
    try_apply_runner_blueprint_app_config_with_ingress(fs_root, pkg_id, listen_port, |canonical| {
        let conn = af_db::get_conn().map_err(|err| {
            PackageExecutorError::VerificationFailed(format!(
                "failed to load blueprint ingress for {}: {}",
                canonical, err
            ))
        })?;
        load_runner_blueprint_ingress(&conn, canonical)
    })
}

fn load_runner_blueprint_ingress(
    conn: &rusqlite::Connection,
    canonical: &str,
) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError> {
    af_db::load_lifecycle_ingress(conn, canonical).map_err(|err| {
        PackageExecutorError::VerificationFailed(format!(
            "failed to load blueprint ingress for {}: {}",
            canonical, err
        ))
    })
}

struct RunnerBlueprintConfigBackup {
    path: PathBuf,
    previous: Option<(Vec<u8>, fs::Metadata)>,
}

impl RunnerBlueprintConfigBackup {
    fn read(path: &Path, fs_root: Option<&Path>) -> Result<Self, PackageExecutorError> {
        validate_filesystem_path(path, fs_root)?;
        let previous = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_regular_config_candidate(path, fs_root)?;
                let content = fs::read(path).map_err(|err| {
                    PackageExecutorError::VerificationFailed(format!(
                        "failed to read blueprint config {}: {}",
                        path.display(),
                        err
                    ))
                })?;
                Some((content, metadata))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PackageExecutorError::VerificationFailed(format!(
                    "failed to inspect blueprint config {}: {}",
                    path.display(),
                    err
                )));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            previous,
        })
    }

    fn restore(&self, fs_root: Option<&Path>) -> Result<(), PackageExecutorError> {
        let current = Self::read(&self.path, fs_root)?;
        match &self.previous {
            Some((content, metadata)) => {
                if current.previous.as_ref().map(|(raw, _)| raw) != Some(content) {
                    #[cfg(unix)]
                    let mode = {
                        use std::os::unix::fs::PermissionsExt;
                        metadata.permissions().mode() & 0o7777
                    };
                    #[cfg(not(unix))]
                    let mode = 0o644;
                    write_file_atomic_with_mode_bounded(&self.path, content, mode, fs_root)?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{chown, MetadataExt};
                    let current_metadata = fs::symlink_metadata(&self.path)?;
                    if current_metadata.uid() != metadata.uid()
                        || current_metadata.gid() != metadata.gid()
                    {
                        chown(&self.path, Some(metadata.uid()), Some(metadata.gid()))?;
                    }
                }
                if fs::symlink_metadata(&self.path)?.permissions() != metadata.permissions() {
                    fs::set_permissions(&self.path, metadata.permissions())?;
                }
            }
            None if current.previous.is_some() => fs::remove_file(&self.path)?,
            None => {}
        }
        Ok(())
    }
}

struct RunnerBlueprintConfigChanges<'a> {
    fs_root: Option<&'a Path>,
    backups: Vec<RunnerBlueprintConfigBackup>,
}

impl RunnerBlueprintConfigChanges<'_> {
    fn capture(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
        if !self.backups.iter().any(|backup| backup.path == path) {
            self.backups
                .push(RunnerBlueprintConfigBackup::read(path, self.fs_root)?);
        }
        Ok(())
    }

    fn write_vhost(&mut self, path: &Path, content: &str) -> Result<(), PackageExecutorError> {
        self.capture(path)?;
        write_file_atomic_with_mode_bounded(path, content.as_bytes(), 0o644, self.fs_root).map_err(
            |err| {
                PackageExecutorError::VerificationFailed(format!(
                    "failed to write required Apache vhost {}: {}",
                    path.display(),
                    err
                ))
            },
        )
    }

    fn remove_vhost(&mut self, path: &Path) -> Result<(), PackageExecutorError> {
        self.capture(path)?;
        validate_regular_config_candidate(path, self.fs_root)?;
        fs::remove_file(path).map_err(|err| {
            PackageExecutorError::VerificationFailed(format!(
                "failed to remove required Apache vhost {}: {}",
                path.display(),
                err
            ))
        })
    }

    fn rollback(self, error: PackageExecutorError) -> PackageExecutorError {
        if self.backups.is_empty() {
            return error;
        }
        let mut failures = Vec::new();
        for backup in self.backups.into_iter().rev() {
            if let Err(err) = backup.restore(self.fs_root) {
                failures.push(format!(
                    "failed to restore {}: {}",
                    backup.path.display(),
                    err
                ));
            }
        }
        if failures.is_empty() {
            PackageExecutorError::VerificationFailed(format!(
                "{}; restored previous blueprint configuration",
                error
            ))
        } else {
            PackageExecutorError::VerificationFailed(format!(
                "{}; incomplete rollback: {}",
                error,
                failures.join("; ")
            ))
        }
    }
}

fn try_apply_runner_blueprint_app_config_with_ingress(
    fs_root: Option<&Path>,
    pkg_id: &str,
    listen_port: i32,
    load_ingress: impl FnOnce(&str) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError>,
) -> Result<(), PackageExecutorError> {
    let mut changes = RunnerBlueprintConfigChanges {
        fs_root,
        backups: Vec::new(),
    };
    apply_runner_blueprint_app_config_changes(&mut changes, pkg_id, listen_port, load_ingress)
        .map_err(|err| changes.rollback(err))
}

fn apply_runner_blueprint_app_config_changes(
    changes: &mut RunnerBlueprintConfigChanges<'_>,
    pkg_id: &str,
    listen_port: i32,
    load_ingress: impl FnOnce(&str) -> Result<Option<af_models::AppIngressConfig>, PackageExecutorError>,
) -> Result<(), PackageExecutorError> {
    if !(1024..=65535).contains(&listen_port) {
        return Ok(());
    }
    let fs_root = changes.fs_root;
    let canonical = resolve_package_lock_name(pkg_id);
    let rebase = |logical: &str| -> PathBuf {
        match fs_root {
            Some(root) => root.join(logical.trim_start_matches('/')),
            None => PathBuf::from(logical),
        }
    };
    let port_str = listen_port.to_string();

    match canonical {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "whisparr" | "listenarr" => {
            static BIND_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(?is)<BindAddress>\s*([^<]*?)\s*</BindAddress>").unwrap());
            for candidate in [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/.config/{}/config.xml", canonical, canonical),
            ] {
                let p = rebase(&candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_bind = BIND_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    runner_mutate_xml_tag(&p, "Port", &port_str, fs_root)?;
                    if !has_bind {
                        runner_mutate_xml_tag(&p, "BindAddress", "127.0.0.1", fs_root)?;
                    }
                    runner_mutate_xml_tag(&p, "AuthenticationMethod", "Forms", fs_root)?;
                    runner_mutate_xml_tag(&p, "AnalyticsEnabled", "False", fs_root)?;
                }
            }
        }
        "jellyfin" => {
            static REMOTE_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?is)<EnableRemoteAccess>\s*([^<]*?)\s*</EnableRemoteAccess>").unwrap()
            });
            static KNOWN_PROXIES_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?is)<KnownProxies>\s*(.*?)\s*</KnownProxies>").unwrap()
            });
            for candidate in ["/etc/jellyfin/network.xml", "/var/lib/jellyfin/config/network.xml"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_remote_access = REMOTE_ACCESS_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    let has_known_proxies = KNOWN_PROXIES_RE
                        .captures(&existing)
                        .and_then(|c| c.get(1))
                        .is_some_and(|m| !m.as_str().trim().is_empty());
                    runner_mutate_xml_tag(&p, "InternalHttpPort", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "PublicHttpPort", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "EnableIPV4", "true", fs_root)?;
                    if !has_remote_access {
                        runner_mutate_xml_tag(&p, "EnableRemoteAccess", "true", fs_root)?;
                    }
                    if !has_known_proxies {
                        runner_mutate_xml_tag(&p, "KnownProxies", "127.0.0.1", fs_root)?;
                    }
                }
            }
        }
        "emby" => {
            for candidate in ["/var/lib/emby/config/system.xml", "/var/lib/emby/system.xml"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_xml_tag(&p, "HttpServerPortNumber", &port_str, fs_root)?;
                    runner_mutate_xml_tag(&p, "PublicPort", &port_str, fs_root)?;
                }
            }
        }
        "qbittorrent" => {
            for candidate in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/qBittorrent.conf",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_addr = existing.lines().any(|line| {
                        let t = line.trim();
                        !t.starts_with('#')
                            && !t.starts_with(';')
                            && t.split_once('=').is_some_and(|(k, v)| {
                                k.trim().eq_ignore_ascii_case(r"WebUI\Address")
                                    && !v.trim().is_empty()
                            })
                    });
                    runner_mutate_ini_key(&p, "Preferences", r"WebUI\Port", &port_str, fs_root)?;
                    if !has_addr {
                        runner_mutate_ini_key(
                            &p,
                            "Preferences",
                            r"WebUI\Address",
                            "127.0.0.1",
                            fs_root,
                        )?;
                    }
                }
            }
        }
        "sabnzbd" => {
            for candidate in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    let existing = fs::read_to_string(&p)?;
                    let has_host = existing.lines().any(|line| {
                        let t = line.trim();
                        !t.starts_with('#')
                            && !t.starts_with(';')
                            && t.split_once('=').is_some_and(|(k, v)| {
                                k.trim().eq_ignore_ascii_case("host") && !v.trim().is_empty()
                            })
                    });
                    runner_mutate_ini_key(&p, "misc", "port", &port_str, fs_root)?;
                    if !has_host {
                        runner_mutate_ini_key(&p, "misc", "host", "127.0.0.1", fs_root)?;
                    }
                }
            }
        }
        "tautulli" => {
            for candidate in ["/var/lib/tautulli/config.ini", "/opt/Tautulli/config.ini"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_ini_key(&p, "General", "http_port", &port_str, fs_root)?;
                }
            }
        }
        "gitea" => {
            for candidate in ["/etc/gitea/app.ini", "/var/lib/gitea/custom/conf/app.ini"] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_ini_key(&p, "server", "HTTP_PORT", &port_str, fs_root)?;
                }
            }
        }
        "transmission" => {
            for candidate in [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
                "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_json_key(
                        &p,
                        "rpc-port",
                        serde_json::json!(listen_port),
                        fs_root,
                    )?;
                }
            }
        }
        "overseerr" | "jellyseerr" => {
            for candidate in [
                format!("/var/lib/{}/config/settings.json", canonical),
                format!("/opt/{}/config/settings.json", canonical),
            ] {
                let p = rebase(&candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_json_key(
                        &p,
                        "main.port",
                        serde_json::json!(listen_port),
                        fs_root,
                    )?;
                }
            }
        }
        "jackett" => {
            for candidate in [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ] {
                let p = rebase(candidate);
                if runner_candidate_exists_or_symlink(&p)? {
                    changes.capture(&p)?;
                    runner_mutate_json_key(
                        &p,
                        "Port",
                        serde_json::json!(listen_port),
                        fs_root,
                    )?;
                }
            }
        }
        _ => {}
    }

    let clean_app: String = canonical
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let sites_avail = rebase("/etc/apache2/sites-available");
    let sites_en = rebase("/etc/apache2/sites-enabled");
    let sites_avail_exists =
        !clean_app.is_empty() && runner_apache_directory_exists(&sites_avail, fs_root)?;
    let sites_en_exists =
        !clean_app.is_empty() && runner_apache_directory_exists(&sites_en, fs_root)?;
    if sites_avail_exists || sites_en_exists {
        let mut candidate_vhosts = Vec::new();
        for (dir, exists) in [
            (&sites_avail, sites_avail_exists),
            (&sites_en, sites_en_exists),
        ] {
            if exists {
                candidate_vhosts.push(dir.join(format!("aetherflow-app-{}.conf", clean_app)));
                candidate_vhosts.push(dir.join(format!("aetherflow-ext-{}.conf", clean_app)));
                candidate_vhosts.push(dir.join(format!("{}.conf", clean_app)));
            }
        }
        let preserved_blocks =
            extract_runner_apache_custom_blocks(&candidate_vhosts, fs_root, &sites_en)?;
        let existing_ingress = load_ingress(canonical)?;

        let mut modified_any = false;

        if sites_avail_exists {
            let int_dom = format!("{}.aether.local", clean_app);
            let default_vhost = format!(
                "# Managed by AetherFlow v3.2.6\n<VirtualHost *:80>\n    ServerName {int_dom}\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:{listen_port}/$1 [P,L]\n    ProxyPass / http://127.0.0.1:{listen_port}/\n    ProxyPassReverse / http://127.0.0.1:{listen_port}/\n    RequestHeader set X-Forwarded-Proto \"http\"\n</VirtualHost>\n"
            );
            let conf_file = sites_avail.join(format!("aetherflow-app-{}.conf", clean_app));
            let prev_int = read_runner_apache_vhost(&conf_file, fs_root, false)?;
            let vhost = render_or_update_runner_apache_vhost(
                prev_int.as_deref(),
                &default_vhost,
                Some(&int_dom),
                listen_port,
                &preserved_blocks,
            );
            if prev_int.as_deref() != Some(vhost.as_str()) {
                changes.write_vhost(&conf_file, &vhost)?;
                modified_any = true;
            }
        }

        let ext_conf_file = sites_avail.join(format!("aetherflow-ext-{}.conf", clean_app));
        let prev_ext = read_runner_apache_vhost(&ext_conf_file, fs_root, false)?;
        if let Some(ing) = existing_ingress {
            let pub_dom = ing.public_domain.trim().to_ascii_lowercase();
            let valid_dom = !pub_dom.is_empty()
                && pub_dom.contains('.')
                && pub_dom
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if ing.external_access_enabled && valid_dom && sites_avail_exists {
                let default_ext_vhost = format!(
                    "# Managed by AetherFlow v3.2.6 (External Ingress)\n<VirtualHost *:80>\n    ServerName {pub_dom}\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:{listen_port}/$1 [P,L]\n    ProxyPass / http://127.0.0.1:{listen_port}/\n    ProxyPassReverse / http://127.0.0.1:{listen_port}/\n</VirtualHost>\n"
                );
                let ext_vhost = render_or_update_runner_apache_vhost(
                    prev_ext.as_deref(),
                    &default_ext_vhost,
                    Some(&pub_dom),
                    listen_port,
                    &preserved_blocks,
                );
                if prev_ext.as_deref() != Some(ext_vhost.as_str()) {
                    changes.write_vhost(&ext_conf_file, &ext_vhost)?;
                    modified_any = true;
                }
            } else if prev_ext.is_some() {
                changes.remove_vhost(&ext_conf_file)?;
                modified_any = true;
            }
        } else if let Some(prev_ext) = prev_ext {
            let ext_vhost = render_or_update_runner_apache_vhost(
                Some(&prev_ext),
                &prev_ext,
                None,
                listen_port,
                &preserved_blocks,
            );
            if prev_ext != ext_vhost {
                changes.write_vhost(&ext_conf_file, &ext_vhost)?;
                modified_any = true;
            }
        }

        // Also update any existing regular (non-symlink) vhost files for this app in sites-available or sites-enabled
        let extra_existing_paths = [
            sites_avail.join(format!("{}.conf", clean_app)),
            sites_en.join(format!("aetherflow-app-{}.conf", clean_app)),
            sites_en.join(format!("aetherflow-ext-{}.conf", clean_app)),
            sites_en.join(format!("{}.conf", clean_app)),
        ];
        for path in extra_existing_paths {
            if let Some(prev_raw) =
                read_runner_apache_vhost(&path, fs_root, path.parent() == Some(sites_en.as_path()))?
            {
                let updated = render_or_update_runner_apache_vhost(
                    Some(&prev_raw),
                    &prev_raw,
                    None,
                    listen_port,
                    &preserved_blocks,
                );
                if prev_raw != updated {
                    changes.write_vhost(&path, &updated)?;
                    modified_any = true;
                }
            }
        }

        if modified_any && fs_root.is_none() {
            match fs::metadata("/etc/apache2/apache2.conf") {
                Ok(metadata) if metadata.is_file() => {
                    verify_runner_apache_configtest().map_err(|err| {
                        PackageExecutorError::VerificationFailed(format!(
                            "apache2ctl configtest failed for {}: {}",
                            clean_app, err
                        ))
                    })?;
                }
                Ok(_) => {
                    return Err(PackageExecutorError::VerificationFailed(
                        "Apache configuration /etc/apache2/apache2.conf is not a regular file"
                            .to_string(),
                    ));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(PackageExecutorError::VerificationFailed(format!(
                        "failed to inspect Apache configuration /etc/apache2/apache2.conf: {}",
                        err
                    )));
                }
            }
        }
    }

    if fs_root.is_none() {
        let internal_domain = format!("{}.aether.local", canonical);
        let _ = crate::update_hosts_file_local(&[internal_domain], false);
    }
    Ok(())
}

fn rewrite_runner_apache_proxy_url_port(token: &str, listen_port: i32) -> Option<String> {
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        if let Some(rest) = token.strip_prefix(scheme) {
            for host in ["127.0.0.1:", "localhost:", "0.0.0.0:", "[::1]:"] {
                if let Some(after_host) = rest.strip_prefix(host) {
                    let digit_len = after_host
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .count();
                    if digit_len > 0 {
                        let suffix = &after_host[digit_len..];
                        return Some(format!("{scheme}{host}{listen_port}{suffix}"));
                    }
                }
            }
        }
    }
    None
}

fn runner_apache_directory_exists(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    validate_filesystem_path(path, fs_root)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(PackageExecutorError::VerificationFailed(format!(
            "required Apache configuration directory is not a directory: {}",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect Apache configuration directory {}: {}",
            path.display(),
            err
        ))),
    }
}

fn read_runner_apache_vhost(
    path: &Path,
    fs_root: Option<&Path>,
    allow_enabled_alias: bool,
) -> Result<Option<String>, PackageExecutorError> {
    if let Some(parent) = path.parent() {
        validate_filesystem_path(parent, fs_root)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if allow_enabled_alias && metadata.file_type().is_symlink() => Ok(None),
        Ok(_) => {
            validate_regular_config_candidate(path, fs_root)?;
            fs::read_to_string(path).map(Some).map_err(|err| {
                PackageExecutorError::VerificationFailed(format!(
                    "failed to read required Apache vhost {}: {}",
                    path.display(),
                    err
                ))
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect required Apache vhost {}: {}",
            path.display(),
            err
        ))),
    }
}

fn extract_runner_apache_custom_blocks(
    paths: &[PathBuf],
    fs_root: Option<&Path>,
    sites_en: &Path,
) -> Result<Vec<String>, PackageExecutorError> {
    let mut blocks = Vec::new();
    for path in paths {
        let source = match fs::symlink_metadata(path) {
            Ok(metadata)
                if path.parent() == Some(sites_en) && metadata.file_type().is_symlink() =>
            {
                validate_filesystem_path(sites_en, fs_root)?;
                match fs::canonicalize(path) {
                    Ok(target) => target,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(PackageExecutorError::VerificationFailed(format!(
                            "failed to resolve Apache vhost alias {}: {}",
                            path.display(),
                            err
                        )));
                    }
                }
            }
            _ => path.clone(),
        };
        let Some(raw) = read_runner_apache_vhost(&source, fs_root, false)? else {
            continue;
        };
        let mut current_block: Option<(String, Vec<String>)> = None;
        for line in raw.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            if let Some((ref end_tag, ref mut buf)) = current_block {
                buf.push(line.to_string());
                if lower.starts_with(end_tag.as_str()) {
                    let joined = buf.join("\n");
                    if !blocks.iter().any(|b: &String| b.trim() == joined.trim()) {
                        blocks.push(joined);
                    }
                    current_block = None;
                }
                continue;
            }
            if lower.starts_with("<location") {
                current_block = Some(("</location>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<directory") {
                current_block = Some(("</directory>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<requireall") {
                current_block = Some(("</requireall>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<requireany") {
                current_block = Some(("</requireany>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<files") {
                current_block = Some(("</files>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("authtype ")
                || lower.starts_with("authname ")
                || lower.starts_with("authuserfile ")
                || lower.starts_with("authgroupfile ")
                || lower.starts_with("authbasicprovider ")
                || lower.starts_with("require ")
                || lower.starts_with("include ")
                || lower.starts_with("includeoptional ")
            {
                let single = line.to_string();
                if !blocks.iter().any(|b: &String| b.trim() == single.trim()) {
                    blocks.push(single);
                }
            }
        }
    }
    Ok(blocks)
}

fn render_or_update_runner_apache_vhost(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    preserved_blocks: &[String],
) -> String {
    let base = match existing_raw {
        Some(raw) if raw.to_ascii_lowercase().contains("<virtualhost") => {
            let mut out_lines = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim_start();
                let indent = &line[..line.len() - trimmed.len()];
                let lower = trimmed.to_ascii_lowercase();
                if let Some(dom) = desired_server_name {
                    if lower.starts_with("servername ") || lower.starts_with("servername\t") {
                        out_lines.push(format!("{indent}ServerName {dom}"));
                        continue;
                    }
                }
                if lower.starts_with("proxypass ")
                    || lower.starts_with("proxypass\t")
                    || lower.starts_with("proxypassreverse ")
                    || lower.starts_with("proxypassreverse\t")
                    || lower.starts_with("rewriterule ")
                    || lower.starts_with("rewriterule\t")
                {
                    let tokens: Vec<String> = trimmed
                        .split_whitespace()
                        .map(|tok| {
                            rewrite_runner_apache_proxy_url_port(tok, listen_port)
                                .unwrap_or_else(|| tok.to_string())
                        })
                        .collect();
                    out_lines.push(format!("{indent}{}", tokens.join(" ")));
                } else {
                    out_lines.push(line.to_string());
                }
            }
            let mut joined = out_lines.join("\n");
            joined.push('\n');
            joined
        }
        _ => default_template.to_string(),
    };

    if preserved_blocks.is_empty() {
        return base;
    }

    let mut missing = Vec::new();
    for block in preserved_blocks {
        let trimmed_block = block.trim();
        if !trimmed_block.is_empty() && !base.contains(trimmed_block) {
            missing.push(block.clone());
        }
    }
    if missing.is_empty() {
        return base;
    }

    let mut final_lines = Vec::new();
    let mut inserted = false;
    for line in base.lines() {
        if !inserted && line.trim().eq_ignore_ascii_case("</virtualhost>") {
            for block in &missing {
                final_lines.push(block.clone());
            }
            inserted = true;
        }
        final_lines.push(line.to_string());
    }
    if !inserted {
        for block in &missing {
            final_lines.push(block.clone());
        }
    }
    let mut out = final_lines.join("\n");
    out.push('\n');
    out
}

fn verify_runner_apache_configtest() -> Result<(), String> {
    for bin in ["/usr/sbin/apache2ctl", "/usr/sbin/apachectl", "apache2ctl", "apachectl"] {
        match std::process::Command::new(bin).arg("-t").output() {
            Ok(out) => {
                if out.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                return Err(format!("{} {}", stderr.trim(), stdout.trim()).trim().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("failed to execute {}: {}", bin, err)),
        }
    }
    Err("no Apache configtest command is available".to_string())
}

/// Sets the lifecycle contract environment for a legacy Bash package script.
/// `DELETE_DATA` is always set explicitly so an inherited runner value can
/// never turn an ordinary removal into a purge.
pub(crate) fn apply_legacy_package_environment(cmd: &mut Command, req: &PackageRunnerRequest) {
    let action_lower = req.action.trim().to_ascii_lowercase();
    let keep_existing_secrets = if action_lower == "remove" || action_lower == "uninstall" {
        false
    } else if action_lower == "update" || action_lower == "reinstall" {
        true
    } else {
        PackageExecutionEnv::default().keep_existing_secrets
    };
    cmd.env("DEBIAN_FRONTEND", "noninteractive")
        .env("AF_PACKAGE_ACTION", req.action.as_str())
        .env("AF_LIFECYCLE_ACTION", req.action.as_str())
        .env(
            "DELETE_DATA",
            if package_request_deletes_data(req) {
                "true"
            } else {
                "false"
            },
        )
        .env(
            "AF_KEEP_EXISTING_SECRETS",
            if keep_existing_secrets { "1" } else { "0" },
        )
        .env("DPKG_LOCK_TIMEOUT", "120");
    if package_requires_download_sha256(&req.package_id) {
        cmd.env("AF_REQUIRE_DOWNLOAD_SHA256", "1");
    }
    cmd.env_remove("AF_CONFIG_PASS");
    cmd.env_remove("AF_CONFIG_USER");
    if keep_existing_secrets {
        cmd.env_remove("AF_PASS");
    }
    let effective_port =
        resolve_effective_runner_app_port(&req.action, &req.package_id, req.app_port);
    if (1024..=65535).contains(&effective_port) {
        cmd.env("AF_APP_PORT", effective_port.to_string());
        cmd.env("AETHERFLOW_APP_PORT", effective_port.to_string());
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
        if !script_matches_package_identity(&req.action, &req.package_id, &req.script_name) {
            yield Ok(format!(
                "__RUNNER_EXIT_ERROR__:validation failed: script '{}' does not match package '{}' for action '{}'\n",
                req.script_name, req.package_id, req.action
            ));
            return;
        }

        let declarative_recipe = if select_package_engine(&req.package_id) == PackageEngineMode::DeclarativeRust {
            get_declarative_recipe(&req.package_id)
        } else {
            None
        };
        let legacy_script_path = if declarative_recipe.is_none() {
            let Some(p) = resolve_package_script_path(&req.action, &req.script_name) else {
                yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
                return;
            };
            Some(p)
        } else {
            None
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
        let default_env = PackageExecutionEnv::default();
        let _flock_guard =
            match CrossProcessLockGuard::acquire_with_cancel(&default_env, &req.package_id, &cancel)
                .await
            {
                Ok(g) => g,
                Err(e) => {
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                    return;
                }
            };

        let maintenance_guard = match crate::acquire_package_maintenance_guard(
            default_env.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&req.package_id),
            &req.lifecycle_job_id,
            Some(&req.action),
        )
        .await
        {
            Ok(guard) => Arc::new(guard),
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };

        let effective_app_port =
            resolve_effective_runner_app_port(&req.action, &req.package_id, req.app_port);

        if let Some(recipe) = declarative_recipe {
            if let Err(err) = recipe.validate() {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                return;
            }
            if let Err(err) = cancel.check(&recipe.package_id) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                return;
            }
            let fs_root_clone = default_env.fs_root.clone();
            let keep_existing_secrets = if matches!(action, PackageAction::Remove) {
                false
            } else if matches!(action, PackageAction::Update | PackageAction::Reinstall) {
                true
            } else {
                default_env.keep_existing_secrets
            };
            let env_cfg = PackageExecutionEnv {
                app_port: effective_app_port,
                lifecycle_job_id: req.lifecycle_job_id.clone(),
                // Purge is an explicit request property, never ambient
                // runner environment.
                delete_data: package_request_deletes_data(&req),
                keep_existing_secrets,
                ..default_env
            };
            let executor = Arc::new(DeclarativePackageExecutor::new(env_cfg));
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let lease_for_task = maintenance_guard.clone();
            let cancel_for_task = cancel.clone();
            let exec_handle = tokio::spawn(async move {
                crate::PACKAGE_MAINTENANCE_LEASE
                    .scope(
                        lease_for_task,
                        executor.execute_reserved_recipe(&recipe, action, cancel_for_task, move |ev| {
                            let _ = tx.send(format!("{}\n", ev.to_wire_line()));
                        }),
                    )
                    .await
            });

            let mut saw_error = false;
            while let Some(line) = rx.recv().await {
                if line.starts_with("__RUNNER_EXIT_ERROR__:") {
                    saw_error = true;
                }
                yield Ok(line);
            }

            match exec_handle.await {
                Ok(Ok(_outcome)) => {}
                Ok(Err(err)) => {
                    saw_error = true;
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                }
                Err(join_err) => {
                    saw_error = true;
                    yield Ok(format!(
                        "__RUNNER_EXIT_ERROR__:declarative task failed: {}\n",
                        join_err
                    ));
                }
            }

            if !saw_error
                && matches!(
                    action,
                    PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
                )
            {
                if let Err(err) = try_apply_runner_blueprint_app_config(
                    fs_root_clone.as_deref(),
                    &req.package_id,
                    effective_app_port,
                ) {
                    yield Ok(format!(
                        "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                        err
                    ));
                    return;
                }
            }
            return;
        }

        // Legacy Bash fallback for unported recipes
        let Some(script_path) = legacy_script_path else {
            yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
            return;
        };
        let env_cfg = default_env;

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
        if env_cfg.fs_root.is_some() {
            let (master_user, master_pass) = resolve_master_credentials(env_cfg.fs_root.as_deref());
            cmd.env("MASTER_USER", master_user)
                .env("MASTER_PASS", master_pass);
        }

        #[cfg(unix)]
        if let Err(error) = maintenance_guard.preserve_in_child(cmd.as_std_mut()) {
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
                let status = tokio::select! {
                    biased;
                    _ = wait_for_cancellation(&cancel) => {
                        terminate_child_process_group(&mut child).await;
                        yield Ok(format!(
                            "__RUNNER_EXIT_ERROR__:operation cancelled for package '{}'\n",
                            req.package_id
                        ));
                        return;
                    }
                    status = child.wait() => status,
                };
                match status {
                    Ok(status) if !status.success() => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:exit status {}\n", status));
                    }
                    Err(error) => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
                    }
                    Ok(_) => {
                        if let Err(error) = ensure_package_sandbox_dropin_under_root(
                            env_cfg.fs_root.as_deref(),
                            &req.package_id,
                            &req.action,
                        ) {
                            yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", error));
                            return;
                        }
                        if matches!(
                            action,
                            PackageAction::Install
                                | PackageAction::Reinstall
                                | PackageAction::Update
                        ) {
                            if let Err(err) = try_apply_runner_blueprint_app_config(
                                env_cfg.fs_root.as_deref(),
                                &req.package_id,
                                effective_app_port,
                            ) {
                                yield Ok(format!(
                                    "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                                    err
                                ));
                                return;
                            }
                        }
                        if env_cfg.fs_root.is_none()
                            && matches!(
                                action,
                                PackageAction::Install
                                    | PackageAction::Reinstall
                                    | PackageAction::Update
                            )
                        {
                            let _ = crate::apply_package_sandbox_reserved(
                                &req.package_id,
                                &maintenance_guard,
                            )
                            .await;
                        }
                    }
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
        assert_eq!(
            env.get("AF_KEEP_EXISTING_SECRETS"),
            Some(&Some("0".to_string()))
        );
        assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
        assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));
        assert_eq!(env.get("AF_APP_PORT"), Some(&None));
        let env = legacy_env(&request("remove", true));
        assert_eq!(env.get("DELETE_DATA"), Some(&Some("true".to_string())));
        let mut update = request("update", true);
        update.app_port = 18989;
        let env = legacy_env(&update);
        assert_eq!(env.get("DELETE_DATA"), Some(&Some("false".to_string())));
        assert_eq!(
            env.get("AF_KEEP_EXISTING_SECRETS"),
            Some(&Some("1".to_string()))
        );
        assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
        assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));
        assert_eq!(env.get("AF_APP_PORT"), Some(&Some("18989".to_string())));
        assert_eq!(
            env.get("AETHERFLOW_APP_PORT"),
            Some(&Some("18989".to_string()))
        );

        let reinstall = request("reinstall", false);
        let env = legacy_env(&reinstall);
        assert_eq!(
            env.get("AF_KEEP_EXISTING_SECRETS"),
            Some(&Some("1".to_string()))
        );

        let install = request("install", false);
        let env = legacy_env(&install);
        assert_eq!(
            env.get("AF_KEEP_EXISTING_SECRETS"),
            Some(&Some("0".to_string()))
        );
        assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
        assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));

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
                            && (content_template.trim() == THREADFIN_PINNED_VERSION
                                || content_template.trim() == "{{VERSION}}")
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

    /// Serializes async execution tests that share process-global `PACKAGE_MUTEX`,
    /// `ACTIVE_CANCELLATIONS`, or environment variable state (`ENV_TEST_MUTEX`).
    pub(super) use crate::ENV_TEST_MUTEX as TEST_EXECUTION_SERIALIZER;

    /// Deterministic mock command runner that records every command invocation and never executes
    /// live privileged OS commands.
    #[derive(Clone, Default)]
    struct MockCommandRunner {
        recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
        fail_on_call: Option<usize>,
        fail_program: Option<String>,
        cancel_on_call: Option<(usize, CancellationToken)>,
        call_counter: Arc<AtomicUsize>,
        dpkg_version_stdout: Option<String>,
        fail_systemctl_is_active: bool,
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

                if self.fail_systemctl_is_active
                    && program == "systemctl"
                    && args.first().map(String::as_str) == Some("is-active")
                {
                    return Ok(CommandOutput {
                        exit_code: 3,
                        stdout: "inactive\n".to_string(),
                        stderr: String::new(),
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
                        stdout: self
                            .dpkg_version_stdout
                            .clone()
                            .unwrap_or_else(|| "1:0.14.2-1ubuntu2\n".to_string()),
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
        for step in recipe
            .install_steps
            .iter_mut()
            .chain(recipe.update_steps.iter_mut())
        {
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
            home_dir: None,
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

        // Previous jail.local must be preserved and no .bak-af left behind
        let restored = fs::read_to_string(&jail_path).unwrap();
        assert_eq!(restored, "# previous user custom config\nmaxretry = 9\n");
        assert!(!root.join("etc/fail2ban/jail.local.bak-af").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_write_template_file_overwrite_true_rolls_back_from_bak_af_on_later_failure() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("rollback-overwrite-template");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        let target_path = root.join("etc/fail2ban/jail.local");
        fs::create_dir_all(target_path.parent().unwrap()).unwrap();
        fs::write(&target_path, "# operator prior config\nmaxretry = 12\n").unwrap();

        let recipe = DeclarativePackageRecipe {
            package_id: "fail2ban".to_string(),
            label: "Fail2ban".to_string(),
            default_port: 0,
            service_name: "fail2ban".to_string(),
            lock_file: "/install/.fail2ban.lock".to_string(),
            apply_systemd_sandbox: false,
            install_steps: vec![
                DeclarativeStep::WriteTemplateFile {
                    path: "/etc/fail2ban/jail.local".to_string(),
                    content_template: "[sshd]\nenabled = true\n".to_string(),
                    mode: 0o644,
                    overwrite: true,
                    owner: None,
                    group: None,
                    progress_pct: 50,
                    description: "Overwriting config before failure...".to_string(),
                },
                DeclarativeStep::Systemctl {
                    unit: Some("fail2ban.service".to_string()),
                    operation: SystemctlOp::Restart,
                    ignore_errors: false,
                    progress_pct: 90,
                    description: "Restarting fail2ban.service...".to_string(),
                },
            ],
            update_steps: Vec::new(),
            remove_steps: Vec::new(),
        };

        let mock = MockCommandRunner {
            fail_on_call: Some(0),
            ..Default::default()
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("systemctl"));
        assert!(!root.join("install/.fail2ban.lock").exists());
        assert_eq!(
            fs::read_to_string(&target_path).unwrap(),
            "# operator prior config\nmaxretry = 12\n"
        );

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

    #[tokio::test]
    async fn test_duplicate_concurrent_package_registration_rejected() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
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
        let runner = TokioCommandRunner {
            respect_dry_run_env: false,
        };

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

        // 3. AFM-004: Supervised rollback grace window allows Bash TERM/EXIT traps to spawn
        // cp/mv and restore backups (~100ms) cleanly before SIGKILL is ever sent.
        let trap_dir = create_isolated_test_dir("afm-004-trap-grace");
        let live_state = trap_dir.join("live.state");
        let backup_state = trap_dir.join("backup.state");
        let marker_file = trap_dir.join("rollback.marker");
        fs::write(&live_state, "schema-v1-stable\n").unwrap();
        fs::write(&backup_state, "schema-v1-stable\n").unwrap();

        let script = format!(
            r#"
set -e
rollback_done=0
rollback() {{
    if [ "$rollback_done" -eq 1 ]; then return; fi
    rollback_done=1
    echo "rollback_started=true" > "{marker}"
    sleep 0.08
    cp "{backup}" "{live}.tmp"
    mv "{live}.tmp" "{live}"
    echo "rollback_completed=true" >> "{marker}"
}}
trap rollback TERM EXIT
echo "schema-v2-migrated" > "{live}"
sleep 30
"#,
            marker = marker_file.display(),
            backup = backup_state.display(),
            live = live_state.display()
        );

        let trap_cancel = CancellationToken::new();
        let trap_cancel_trigger = trap_cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            trap_cancel_trigger.cancel();
        });

        let trap_args = vec!["-c".to_string(), script];
        let trap_res = runner
            .run_command("bash", &trap_args, &[], &trap_cancel)
            .await;
        assert!(matches!(trap_res, Err(PackageExecutorError::Cancelled(_))));
        let marker_contents = fs::read_to_string(&marker_file).unwrap_or_default();
        assert!(
            marker_contents.contains("rollback_started=true")
                && marker_contents.contains("rollback_completed=true"),
            "expected TERM/EXIT trap to complete rollback within grace window, got: {marker_contents:?}"
        );
        assert_eq!(
            fs::read_to_string(&live_state).unwrap(),
            "schema-v1-stable\n"
        );
        let _ = fs::remove_dir_all(&trap_dir);
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

        // Seed custom certificate, SQLite database, and custom /etc/default/quasselcore settings
        // to verify preservation across reinstall/update/remove while updating PORT in-place.
        let custom_cert = b"-----BEGIN CERTIFICATE-----\nEXISTING_USER_CERT_DO_NOT_OVERWRITE\n-----END CERTIFICATE-----\n";
        fs::write(&cert_path, custom_cert).unwrap();
        let sqlite_db = root.join("var/lib/quassel/quassel-storage.sqlite");
        fs::write(&sqlite_db, b"SQLite format 3 user backlog data").unwrap();
        let defaults_file = root.join("etc/default/quasselcore");
        fs::write(
            &defaults_file,
            "# Custom operator Quassel settings\nSTART=\"true\"\nUSER=\"quasselcore\"\nLOGLEVEL=\"Debug\"\nLISTEN=\"127.0.0.1\"\nPORT=4249\nEXTRA_OPTS=\"--oidentd\"\n",
        )
        .unwrap();

        // Clear recorded commands and run Update with a new port
        runner.recorded.lock().unwrap().clear();
        env_cfg.app_port = 4255;
        let update_executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
        let update_outcome = update_executor
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
        let updated_defaults = fs::read_to_string(&defaults_file).unwrap();
        assert!(
            updated_defaults.contains("LOGLEVEL=\"Debug\"")
                && updated_defaults.contains("LISTEN=\"127.0.0.1\"")
                && updated_defaults.contains("EXTRA_OPTS=\"--oidentd\"")
                && updated_defaults.contains("PORT=\"4255\""),
            "custom /etc/default/quasselcore lines must be preserved on update while PORT is updated in-place: {updated_defaults}"
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

        // Remove with delete_data = false (default): must remove /var/lib/quassel/.af-version, lock, and sandbox drop-in,
        // but PRESERVE /etc/default/quasselcore, /var/lib/quassel & cert
        let remove_command_start = runner.recorded.lock().unwrap().len();
        let remove_preserve = update_executor
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
        assert!(!remove_commands.iter().any(|command| command.program == "userdel"));
        assert!(!root.join("install/.quassel.lock").exists());
        assert!(!root.join("var/lib/quassel/.af-version").exists());
        assert!(
            root.join("etc/default/quasselcore").is_file(),
            "/etc/default/quasselcore must be preserved on remove when delete_data=false"
        );
        assert_eq!(
            fs::read(&cert_path).unwrap(),
            custom_cert,
            "quasselCert.pem must be preserved on remove when delete_data=false"
        );
        assert!(
            sqlite_db.is_file(),
            "quassel SQLite database must be preserved on remove when delete_data=false"
        );

        // Remove with delete_data = true: must purge /etc/default/quasselcore, /var/lib/quassel, /var/log/quassel, and user quasselcore
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
        assert!(!root.join("etc/default/quasselcore").exists());
        assert!(!root.join("var/lib/quassel").exists());
        assert!(!root.join("var/log/quassel").exists());
        let purge_commands = runner.recorded.lock().unwrap()[purge_command_start..].to_vec();
        assert!(purge_commands.iter().any(|command| {
            command.program == "apt-get"
                && command.args.contains(&"purge".to_string())
                && command.args.contains(&"quassel-core".to_string())
        }));
        assert!(purge_commands.iter().any(|command| {
            command.program == "userdel" && command.args.contains(&"quasselcore".to_string())
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
                    "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}"
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
        for step in recipe
            .install_steps
            .iter_mut()
            .chain(recipe.update_steps.iter_mut())
        {
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
            "ExecStart=/usr/local/bin/threadfin -port=34409 -bind=127.0.0.1 -config=/var/lib/threadfin/conf"
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
        assert!(update_systemctl_commands
            .iter()
            .any(|command| command == "restart -- threadfin.service"));
        assert_eq!(
            update_systemctl_commands.last().map(String::as_str),
            Some("is-active --quiet -- threadfin.service")
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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_sol_02_lock_finalization_failure_rolls_back_mutated_config_and_preserves_old_receipt(
    ) {
        use std::os::unix::fs::PermissionsExt;
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("sol-02-lock-finalization");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        let netdata_conf = root.join("etc/netdata/netdata.conf");
        fs::create_dir_all(netdata_conf.parent().unwrap()).unwrap();
        fs::write(&netdata_conf, "OLD OPERATOR CONFIG\n").unwrap();

        let install_dir = root.join("install");
        fs::create_dir_all(&install_dir).unwrap();
        let lock_file = install_dir.join(".netdata.lock");
        fs::write(&lock_file, "OLD RECEIPT\n").unwrap();

        // Pre-create .af-package-executor.flock while `install` is still writable so flock
        // acquisition can open the existing inode, then set `install` to 0o555 so creating
        // `.netdata.lock.bak-af.*` or `.netdata.lock.af-tmp-*` fails with EACCES.
        {
            let _guard = CrossProcessLockGuard::try_acquire(&env_cfg, "netdata").unwrap();
        }
        fs::set_permissions(&install_dir, fs::Permissions::from_mode(0o555)).unwrap();

        let recipe = DeclarativePackageRecipe {
            package_id: "netdata".to_string(),
            label: "Netdata".to_string(),
            default_port: 19999,
            service_name: "netdata".to_string(),
            lock_file: "/install/.netdata.lock".to_string(),
            apply_systemd_sandbox: false,
            install_steps: Vec::new(),
            update_steps: vec![DeclarativeStep::WriteTemplateFile {
                path: "/etc/netdata/netdata.conf".to_string(),
                content_template: "NEW CONFIG\n".to_string(),
                mode: 0o644,
                overwrite: true,
                owner: None,
                group: None,
                progress_pct: 50,
                description: "Updating netdata.conf...".to_string(),
            }],
            remove_steps: Vec::new(),
        };

        let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
        let res = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await;

        // Restore 0o755 on `install` before asserting so test cleanup always succeeds
        fs::set_permissions(&install_dir, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            res.is_err(),
            "lock finalization failure on read-only /install must return Err"
        );
        assert_eq!(
            fs::read_to_string(&netdata_conf).unwrap(),
            "OLD OPERATOR CONFIG\n",
            "mutated config must be rolled back when lock receipt persistence fails"
        );
        assert_eq!(
            fs::read_to_string(&lock_file).unwrap(),
            "OLD RECEIPT\n",
            "existing lock receipt must remain intact when lock finalization fails"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_sol_03_inactive_systemd_service_after_start_or_restart_fails_and_rolls_back() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

        #[derive(Clone, Default)]
        struct InactiveServiceRunner;

        impl CommandRunner for InactiveServiceRunner {
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
                    if cancel.is_cancelled() {
                        return Err(PackageExecutorError::Cancelled(program.to_string()));
                    }
                    if program == "systemctl" && args.first().map(String::as_str) == Some("is-active") {
                        return Ok(CommandOutput {
                            exit_code: 3,
                            stdout: "inactive\n".to_string(),
                            stderr: String::new(),
                        });
                    }
                    if program == "dpkg-query" {
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "1.0.2-1\n".to_string(),
                            stderr: String::new(),
                        });
                    }
                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                })
            }
        }

        for pkg_id in ["netdata", "fail2ban"] {
            let root = create_isolated_test_dir(&format!("sol-03-inactive-{pkg_id}"));
            let env_cfg = PackageExecutionEnv::isolated(&root);
            let recipe = get_declarative_recipe(pkg_id).unwrap();
            let executor = DeclarativePackageExecutor::with_runner(env_cfg, InactiveServiceRunner);

            let err = executor
                .execute_recipe(
                    &recipe,
                    PackageAction::Install,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap_err();

            match &err {
                PackageExecutorError::StepFailed { step, reason } => {
                    assert!(
                        step.starts_with("systemctl is-active"),
                        "unexpected step in StepFailed for {pkg_id}: {step}"
                    );
                    assert!(
                        reason.contains("failed post-activation readiness check"),
                        "unexpected reason for {pkg_id}: {reason}"
                    );
                }
                other => panic!("expected StepFailed for {pkg_id}, got: {other:?}"),
            }

            let lock_rel = recipe.lock_file.trim_start_matches('/');
            assert!(
                !root.join(lock_rel).exists(),
                "completion receipt must not be written when service is inactive after start/restart ({pkg_id})"
            );
            assert!(
                !root.join(format!("etc/{pkg_id}/.af-version")).exists(),
                "staged .af-version file must be rolled back when service fails post-activation check ({pkg_id})"
            );

            let _ = fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn test_sol_04_fail2ban_update_preserves_operator_jail_local_policy_byte_for_byte() {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("sol-04-fail2ban-policy");
        let env_cfg = PackageExecutionEnv::isolated(&root);

        let operator_jail = "[DEFAULT]\nmaxretry = 20\n[sshd]\nenabled = false\nport = 2222\n";
        let jail_path = root.join("etc/fail2ban/jail.local");
        fs::create_dir_all(jail_path.parent().unwrap()).unwrap();
        fs::write(&jail_path, operator_jail).unwrap();

        let sshd_cfg = root.join("etc/ssh/sshd_config");
        fs::create_dir_all(sshd_cfg.parent().unwrap()).unwrap();
        fs::write(&sshd_cfg, "Port 2200\n").unwrap();

        let recipe = get_declarative_recipe("fail2ban").unwrap();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());

        for action in [PackageAction::Update, PackageAction::Install] {
            let outcome = executor
                .execute_recipe(&recipe, action, CancellationToken::new(), |_| {})
                .await
                .unwrap();
            assert!(outcome.lock_present);
            let actual = fs::read_to_string(&jail_path).unwrap();
            assert_eq!(
                actual, operator_jail,
                "fail2ban {:?} must preserve operator /etc/fail2ban/jail.local byte-for-byte",
                action
            );
        }

        let _ = fs::remove_dir_all(&root);
    }
    fn version_rel_path_for_recipe(pkg_id: &str) -> &'static str {
        match pkg_id {
            "fail2ban" => "etc/fail2ban/.af-version",
            "quassel" => "var/lib/quassel/.af-version",
            "threadfin" => "var/lib/threadfin/.af-version",
            "znc" => "var/lib/znc/.af-version",
            "xrdp" => "var/lib/xrdp/.af-version",
            "novnc" => "etc/novnc/.af-version",
            "x2go" => "var/lib/x2go/.af-version",
            "prometheus" => "etc/prometheus/.af-version",
            "netdata" => "etc/netdata/.af-version",
            "mergerfs" => "var/lib/mergerfs/.af-version",
            "rclone" => "var/lib/rclone/.af-version",
            "syncthing" => "var/lib/syncthing/.af-version",
            other => panic!("unexpected recipe id: {other}"),
        }
    }

    fn stage_threadfin_cached_binary(
        env_cfg: &PackageExecutionEnv,
        recipe: &mut DeclarativePackageRecipe,
        payload_byte: u8,
    ) {
        let mut elf_bytes = create_mock_elf_payload_for_arch(1_100_000, 62);
        elf_bytes[512] = payload_byte;
        let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        for name in [
            "Threadfin_linux_amd64_glibc_2.31_compat",
            "Threadfin_linux_amd64_compat",
            "Threadfin_linux_amd64",
        ] {
            fs::write(cache_dir.join(name), &elf_bytes).unwrap();
        }
        let digest = hex::encode(Sha256::digest(&elf_bytes));
        for step in recipe
            .install_steps
            .iter_mut()
            .chain(recipe.update_steps.iter_mut())
        {
            if let DeclarativeStep::DownloadBinary { verification, .. } = step {
                verification.expected_sha256 = Some(digest.clone());
                verification.arch_sha256 = Some(ArchAssetMap {
                    amd64: digest.clone(),
                    arm64: digest.clone(),
                    armhf: Some(digest.clone()),
                });
            }
        }
    }

    fn seed_operator_state_for_recipe(root: &Path, pkg_id: &str) -> Vec<(PathBuf, String)> {
        let write_sentinel = |rel: &str, content: &str, token: &str| -> (PathBuf, String) {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            (path, token.to_string())
        };

        match pkg_id {
            "fail2ban" => vec![write_sentinel(
                "etc/fail2ban/jail.local",
                "[DEFAULT]\nbantime = 7200\n# operator-fail2ban-sentinel\n[sshd]\nenabled = true\nport = ssh\n",
                "operator-fail2ban-sentinel",
            )],
            "quassel" => vec![
                write_sentinel(
                    "etc/default/quasselcore",
                    "START=\"true\"\nUSER=\"quasselcore\"\nLISTEN=\"127.0.0.1\"\nPORT=\"18100\"\nCUSTOM_FLAG=\"--operator-quassel-sentinel\"\n",
                    "--operator-quassel-sentinel",
                ),
                write_sentinel(
                    "var/lib/quassel/quasselCert.pem",
                    "-----BEGIN CERTIFICATE-----\noperator-quassel-cert-sentinel\n-----END CERTIFICATE-----\n",
                    "operator-quassel-cert-sentinel",
                ),
            ],
            "threadfin" => vec![write_sentinel(
                "var/lib/threadfin/conf/settings.json",
                "{\n  \"bindIpAddress\": \"127.0.0.1\",\n  \"custom\": {\n    \"playlist\": \"operator-threadfin-sentinel\"\n  },\n  \"version\": \"0.5.0\"\n}",
                "operator-threadfin-sentinel",
            )],
            "znc" => {
                let znc_conf_path = root.join("var/lib/znc/configs/znc.conf");
                let mut existing = fs::read_to_string(&znc_conf_path).unwrap();
                existing.push_str("\n// operator-znc-conf-sentinel\n");
                fs::write(&znc_conf_path, &existing).unwrap();
                vec![
                    (znc_conf_path, "operator-znc-conf-sentinel".to_string()),
                    write_sentinel(
                        "var/lib/znc/znc.pem",
                        "-----BEGIN CERTIFICATE-----\noperator-znc-pem-sentinel\n-----END CERTIFICATE-----\n",
                        "operator-znc-pem-sentinel",
                    ),
                ]
            }
            "xrdp" => vec![
                write_sentinel(
                    "etc/xrdp/startwm.sh",
                    "#!/bin/sh\n# operator-xrdp-startwm-sentinel\nexec startxfce4\n",
                    "operator-xrdp-startwm-sentinel",
                ),
                write_sentinel(
                    "etc/xrdp/xrdp.ini",
                    "[Globals]\nport=3389\n; operator-xrdp-ini-sentinel\n",
                    "operator-xrdp-ini-sentinel",
                ),
            ],
            "novnc" => {
                let passwd_path = root.join("var/lib/novnc/.vnc/passwd");
                fs::create_dir_all(passwd_path.parent().unwrap()).unwrap();
                let encoded = encode_tigervnc_passwd("OpVncS3c");
                fs::write(&passwd_path, &encoded).unwrap();
                vec![
                    (passwd_path, hex::encode(encoded)),
                    write_sentinel(
                        "var/lib/novnc/.vnc/xstartup",
                        "#!/bin/sh\n# operator-novnc-xstartup-sentinel\nexec startxfce4\n",
                        "operator-novnc-xstartup-sentinel",
                    ),
                ]
            }
            "x2go" => vec![write_sentinel(
                "etc/x2go/x2goserver.conf",
                "[limit users]\n# operator-x2go-sentinel\n",
                "operator-x2go-sentinel",
            )],
            "prometheus" => {
                let prom_yml_path = root.join("etc/prometheus/prometheus.yml");
                let mut existing_yml = fs::read_to_string(&prom_yml_path).unwrap();
                existing_yml.push_str("# operator-prometheus-yml-sentinel\n");
                fs::write(&prom_yml_path, &existing_yml).unwrap();
                vec![
                    write_sentinel(
                        "etc/default/prometheus",
                        "ARGS=\"--web.listen-address=127.0.0.1:18100 --storage.tsdb.path=/var/lib/prometheus/metrics2 --operator-prometheus-default-sentinel\"\n",
                        "--operator-prometheus-default-sentinel",
                    ),
                    (prom_yml_path, "operator-prometheus-yml-sentinel".to_string()),
                ]
            }
            "netdata" => vec![write_sentinel(
                "etc/netdata/netdata.conf",
                "[global]\n    history = 86400\n    # operator-netdata-sentinel\n[web]\n    bind to = 127.0.0.1\n    default port = 18100\n",
                "operator-netdata-sentinel",
            )],
            "mergerfs" => vec![write_sentinel(
                "etc/mergerfs/mergerfs.conf",
                "BRANCHES=\"/mnt/mergerfs/local=RW:/mnt/operator-mergerfs-sentinel=RO\"\n",
                "operator-mergerfs-sentinel",
            )],
            "rclone" => vec![
                write_sentinel(
                    "etc/rclone/rclone.conf",
                    "[remote]\ntype = drive\ntoken = operator-rclone-conf-sentinel\n",
                    "operator-rclone-conf-sentinel",
                ),
                write_sentinel(
                    "etc/rclone/rclone.env",
                    "RCLONE_RC_USER=\"operator-rclone-env-sentinel\"\n",
                    "operator-rclone-env-sentinel",
                ),
            ],
            "syncthing" => vec![write_sentinel(
                "var/lib/syncthing/.config/syncthing/config.xml",
                "<configuration><gui><apikey>operator-syncthing-sentinel</apikey></gui></configuration>\n",
                "operator-syncthing-sentinel",
            )],
            other => panic!("unexpected recipe id: {other}"),
        }
    }

    #[tokio::test]
    async fn test_all_12_native_recipes_in_place_reinstall_preserves_operator_state_and_updates_version_and_port(
    ) {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let recipe_ids = list_declarative_recipe_ids();
        assert_eq!(recipe_ids.len(), 12);

        for pkg_id in recipe_ids {
            let root = create_isolated_test_dir(&format!("reinstall-12-{pkg_id}"));
            let mut env_cfg = PackageExecutionEnv::isolated(&root);
            env_cfg.app_port = 18100;

            let mut recipe = get_declarative_recipe(&pkg_id).unwrap();
            if pkg_id == "threadfin" {
                stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x11);
            }

            let initial_runner = MockCommandRunner {
                dpkg_version_stdout: Some("2.1.0\n".to_string()),
                ..Default::default()
            };
            let initial_exec =
                DeclarativePackageExecutor::with_runner(env_cfg.clone(), initial_runner);
            let initial_outcome = initial_exec
                .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
                .await
                .unwrap_or_else(|e| panic!("initial install of {pkg_id} failed: {e}"));
            assert!(initial_outcome.lock_present, "{pkg_id}");

            let lock_path = root.join(recipe.lock_file.trim_start_matches('/'));
            let version_path = root.join(version_rel_path_for_recipe(&pkg_id));
            assert!(lock_path.is_file(), "{pkg_id} lock receipt must exist");
            assert!(version_path.is_file(), "{pkg_id} .af-version must exist");

            if pkg_id != "threadfin" {
                assert_eq!(
                    fs::read_to_string(&version_path).unwrap().trim(),
                    "2.1.0",
                    "{pkg_id} initial .af-version"
                );
                assert!(
                    fs::read_to_string(&lock_path)
                        .unwrap()
                        .contains("version=2.1.0"),
                    "{pkg_id} initial lock version"
                );
            }

            let sentinels = seed_operator_state_for_recipe(&root, &pkg_id);

            // In-place reinstall without removing the package (lock receipt and operator state remain on disk)
            assert!(
                lock_path.is_file(),
                "{pkg_id} lock receipt must remain present prior to in-place reinstall"
            );
            env_cfg.app_port = 18200;
            if pkg_id == "threadfin" {
                stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x22);
            }
            let reinstall_runner = MockCommandRunner {
                dpkg_version_stdout: Some("2.2.0\n".to_string()),
                ..Default::default()
            };
            let reinstall_exec =
                DeclarativePackageExecutor::with_runner(env_cfg.clone(), reinstall_runner.clone());
            let reinstall_outcome = reinstall_exec
                .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
                .await
                .unwrap_or_else(|e| panic!("in-place reinstall of {pkg_id} failed: {e}"));
            assert!(reinstall_outcome.lock_present, "{pkg_id}");

            // 1. Verify operator-customized state/secrets were preserved across in-place reinstall
            for (sentinel_path, expected_token) in &sentinels {
                let raw_bytes = fs::read(sentinel_path).unwrap_or_else(|e| {
                    panic!(
                        "failed to read preserved state {} for {pkg_id}: {e}",
                        sentinel_path.display()
                    )
                });
                let matches_sentinel = String::from_utf8_lossy(&raw_bytes).contains(expected_token)
                    || hex::encode(&raw_bytes) == *expected_token;
                assert!(
                    matches_sentinel,
                    "{pkg_id} in-place reinstall clobbered operator sentinel {expected_token:?} in {}",
                    sentinel_path.display()
                );
            }

            // 2. Verify updated version receipt in .af-version and /install/.<pkg>.lock
            let expected_version = if pkg_id == "threadfin" {
                THREADFIN_PINNED_VERSION
            } else {
                "2.2.0"
            };
            assert_eq!(
                reinstall_outcome.resolved_version.as_deref(),
                Some(expected_version),
                "{pkg_id} resolved_version after reinstall"
            );
            assert_eq!(
                fs::read_to_string(&version_path).unwrap().trim(),
                expected_version,
                "{pkg_id} .af-version after reinstall"
            );
            let lock_body = fs::read_to_string(&lock_path).unwrap();
            assert!(
                lock_body.contains(&format!("version={expected_version}")),
                "{pkg_id} lock receipt must record version={expected_version}, got:\n{lock_body}"
            );

            // 3. Verify updated APP_PORT / LISTEN_PORT (18200) is reflected in config/unit files
            match pkg_id.as_str() {
                "quassel" => {
                    let default_cfg =
                        fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
                    let unit_cfg =
                        fs::read_to_string(root.join("etc/systemd/system/quasselcore.service"))
                            .unwrap();
                    assert!(default_cfg.contains("PORT=\"18200\""));
                    assert!(unit_cfg.contains("--port=18200"));
                }
                "threadfin" => {
                    let unit_cfg =
                        fs::read_to_string(root.join("etc/systemd/system/threadfin.service"))
                            .unwrap();
                    assert!(unit_cfg.contains("-port=18200"));
                }
                "znc" => {
                    let znc_cfg =
                        fs::read_to_string(root.join("var/lib/znc/configs/znc.conf")).unwrap();
                    assert!(znc_cfg.contains("Port = 18200"));
                }
                "novnc" => {
                    let unit_cfg =
                        fs::read_to_string(root.join("etc/systemd/system/novnc.service")).unwrap();
                    assert!(unit_cfg.contains("127.0.0.1:18200"));
                }
                "prometheus" => {
                    let default_cfg =
                        fs::read_to_string(root.join("etc/default/prometheus")).unwrap();
                    let yml_cfg =
                        fs::read_to_string(root.join("etc/prometheus/prometheus.yml")).unwrap();
                    assert!(default_cfg.contains("127.0.0.1:18200"));
                    assert!(yml_cfg.contains("127.0.0.1:18200"));
                }
                "netdata" => {
                    let netdata_cfg =
                        fs::read_to_string(root.join("etc/netdata/netdata.conf")).unwrap();
                    assert!(netdata_cfg.contains("default port = 18200"));
                    assert!(netdata_cfg.contains("bind to = 127.0.0.1"));
                }
                "rclone" => {
                    let unit_cfg =
                        fs::read_to_string(root.join("etc/systemd/system/rclone.service")).unwrap();
                    assert!(unit_cfg.contains("--rc-addr=127.0.0.1:18200"));
                }
                "syncthing" => {
                    let unit_cfg =
                        fs::read_to_string(root.join("etc/systemd/system/syncthing.service"))
                            .unwrap();
                    assert!(unit_cfg.contains("--gui-address=127.0.0.1:18200"));
                }
                _ => {}
            }

            // 4. Verify `systemctl is-active --quiet` was executed after service activation
            let primary_unit = normalize_unit_filename(&recipe.service_name);
            let cmds = reinstall_runner.recorded_commands();
            assert!(
                cmds.iter().any(|cmd| {
                    cmd.program == "systemctl"
                        && cmd.args
                            == vec![
                                "is-active".to_string(),
                                "--quiet".to_string(),
                                "--".to_string(),
                                primary_unit.clone(),
                            ]
                }),
                "{pkg_id} reinstall must verify post-activation readiness via systemctl is-active --quiet -- {primary_unit}"
            );

            let _ = fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn test_all_12_native_recipes_in_place_reinstall_failure_injection_rolls_back_and_retains_prior_state(
    ) {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let recipe_ids = list_declarative_recipe_ids();
        assert_eq!(recipe_ids.len(), 12);

        for pkg_id in recipe_ids {
            let root = create_isolated_test_dir(&format!("reinstall-fail-12-{pkg_id}"));
            let mut env_cfg = PackageExecutionEnv::isolated(&root);
            env_cfg.app_port = 18100;

            let mut recipe = get_declarative_recipe(&pkg_id).unwrap();
            if pkg_id == "threadfin" {
                stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x11);
            }

            let initial_runner = MockCommandRunner {
                dpkg_version_stdout: Some("2.1.0\n".to_string()),
                ..Default::default()
            };
            let initial_exec =
                DeclarativePackageExecutor::with_runner(env_cfg.clone(), initial_runner);
            let initial_outcome = initial_exec
                .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
                .await
                .unwrap_or_else(|e| panic!("initial install of {pkg_id} failed: {e}"));
            assert!(initial_outcome.lock_present, "{pkg_id}");

            let sentinels = seed_operator_state_for_recipe(&root, &pkg_id);
            let lock_path = root.join(recipe.lock_file.trim_start_matches('/'));
            let version_path = root.join(version_rel_path_for_recipe(&pkg_id));

            let mut tracked_paths: Vec<PathBuf> = vec![lock_path.clone(), version_path.clone()];
            for (sentinel_path, _) in &sentinels {
                if !tracked_paths.contains(sentinel_path) {
                    tracked_paths.push(sentinel_path.clone());
                }
            }
            for unit_rel in [
                "etc/systemd/system/quasselcore.service",
                "etc/systemd/system/threadfin.service",
                "etc/systemd/system/znc.service",
                "etc/systemd/system/novnc.service",
                "etc/systemd/system/novnc-xvnc.service",
                "etc/systemd/system/node_exporter.service",
                "etc/systemd/system/mergerfs.service",
                "etc/systemd/system/rclone.service",
                "etc/systemd/system/rclone-vfs.service",
                "etc/systemd/system/syncthing.service",
                "usr/local/bin/threadfin",
            ] {
                let candidate = root.join(unit_rel);
                if candidate.is_file() {
                    tracked_paths.push(candidate);
                }
            }

            let snapshots_before: Vec<(PathBuf, Vec<u8>)> = tracked_paths
                .into_iter()
                .map(|p| {
                    let bytes = fs::read(&p).unwrap_or_else(|e| {
                        panic!("failed to snapshot {} for {pkg_id}: {e}", p.display())
                    });
                    (p, bytes)
                })
                .collect();

            // Attempt an in-place reinstall with changed port (18200) and updated version (2.2.0),
            // injecting a post-activation readiness check failure (`systemctl is-active` exit code 3).
            env_cfg.app_port = 18200;
            if pkg_id == "threadfin" {
                stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x99);
            }
            let failing_runner = MockCommandRunner {
                dpkg_version_stdout: Some("2.2.0\n".to_string()),
                fail_systemctl_is_active: true,
                ..Default::default()
            };
            let failing_exec =
                DeclarativePackageExecutor::with_runner(env_cfg.clone(), failing_runner);
            let err = failing_exec
                .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
                .await
                .expect_err(&format!(
                    "in-place reinstall of {pkg_id} must fail when systemctl is-active returns 3"
                ));

            match &err {
                PackageExecutorError::StepFailed { step, reason } => {
                    assert!(
                        step.starts_with("systemctl is-active"),
                        "expected systemctl is-active failure for {pkg_id}, got step={step}"
                    );
                    assert!(
                        reason.contains("failed post-activation readiness check"),
                        "unexpected failure reason for {pkg_id}: {reason}"
                    );
                }
                other => panic!("expected StepFailed for {pkg_id}, got: {other:?}"),
            }

            // Verify rollback restored all mutated files (version, configs, units, binary) and retained prior lock receipt
            for (path, expected_bytes) in &snapshots_before {
                assert!(
                    path.is_file(),
                    "{pkg_id} rollback must retain pre-existing file {}",
                    path.display()
                );
                let actual_bytes = fs::read(path).unwrap();
                assert_eq!(
                    &actual_bytes,
                    expected_bytes,
                    "{pkg_id} rollback must restore exact prior bytes for {}",
                    path.display()
                );
            }

            let _ = fs::remove_dir_all(&root);
        }
    }

    #[tokio::test]
    async fn test_afmp005_wait_for_http_ready_retries_transient_failure_and_succeeds_within_deadline(
    ) {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
        let root = create_isolated_test_dir("afmp005-http-retry");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let curl_attempts = Arc::new(AtomicUsize::new(0));
        let curl_attempts_clone = curl_attempts.clone();

        #[derive(Clone)]
        struct TransientCurlRunner {
            curl_attempts: Arc<AtomicUsize>,
        }

        impl CommandRunner for TransientCurlRunner {
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
                    if cancel.is_cancelled() {
                        return Err(PackageExecutorError::Cancelled(program.to_string()));
                    }
                    if program == "curl" {
                        let n = self.curl_attempts.fetch_add(1, Ordering::SeqCst);
                        if n < 2 {
                            return Ok(CommandOutput {
                                exit_code: 7,
                                stdout: String::new(),
                                stderr: format!("curl: (7) Failed to connect on attempt {}", n + 1),
                            });
                        }
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: format!("ok: {} {}", program, args.join(" ")),
                            stderr: String::new(),
                        });
                    }
                    if program == "dpkg-query" {
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "1.27.0\n".to_string(),
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

        let recipe = get_declarative_recipe("syncthing").unwrap();
        let executor = DeclarativePackageExecutor::with_runner(
            env_cfg,
            TransientCurlRunner {
                curl_attempts: curl_attempts_clone,
            },
        );
        let outcome = executor
            .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
            .await
            .expect("WaitForHttpReady must succeed when attempt 3 returns 200 OK after 2 transient failures");
        assert!(outcome.lock_present);
        assert_eq!(curl_attempts.load(Ordering::SeqCst), 3);

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_afmp002_native_failed_update_stops_service_restores_state_downgrades_pkg_and_enforces_receipt_honesty(
    ) {
        let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

        #[derive(Clone)]
        struct UpdateRollbackRunner {
            recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
            state_dir: PathBuf,
            fail_stop: bool,
            fail_downgrade: bool,
        }

        impl CommandRunner for UpdateRollbackRunner {
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

                    // Simulate service restart migrating the application database to schema-v2
                    if program == "systemctl"
                        && args.first().map(String::as_str) == Some("restart")
                    {
                        let _ = fs::write(self.state_dir.join("index-v0.14.0.db"), b"schema-v2-migrated");
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }

                    // Simulate WaitForHttpReady failing after service restart
                    if program == "curl" {
                        return Ok(CommandOutput {
                            exit_code: 7,
                            stdout: String::new(),
                            stderr: "curl: (7) Failed to connect".to_string(),
                        });
                    }

                    if program == "systemctl" && args.first().map(String::as_str) == Some("stop") {
                        if self.fail_stop {
                            return Ok(CommandOutput {
                                exit_code: 1,
                                stdout: String::new(),
                                stderr: "Failed to stop syncthing.service".to_string(),
                            });
                        }
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }

                    if program == "systemctl"
                        && args.first().map(String::as_str) == Some("is-active")
                    {
                        // During forward step (`--quiet`), return 0 (active); during rollback quiescence check (no `--quiet`), return 3 (inactive) unless fail_stop
                        let is_quiet = args.iter().any(|a| a == "--quiet");
                        if is_quiet || self.fail_stop {
                            return Ok(CommandOutput {
                                exit_code: 0,
                                stdout: "active\n".to_string(),
                                stderr: String::new(),
                            });
                        }
                        return Ok(CommandOutput {
                            exit_code: 3,
                            stdout: "inactive\n".to_string(),
                            stderr: String::new(),
                        });
                    }

                    if program == "apt-get" && args.iter().any(|a| a == "--allow-downgrades") {
                        if self.fail_downgrade {
                            return Ok(CommandOutput {
                                exit_code: 100,
                                stdout: String::new(),
                                stderr: "E: Version '1.0.0' for 'syncthing' was not found".to_string(),
                            });
                        }
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "downgraded syncthing to 1.0.0\n".to_string(),
                            stderr: String::new(),
                        });
                    }

                    if program == "dpkg-query" {
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "2.0.0\n".to_string(),
                            stderr: String::new(),
                        });
                    }

                    Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                })
            }
        }

        env::set_var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS", "2");
        env::set_var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS", "5");

        let recipe = get_declarative_recipe("syncthing").unwrap();

        // Case 1: Full clean rollback (stop succeeds, state restore succeeds, package downgrade succeeds -> receipt restored to 1.0.0)
        {
            let root = create_isolated_test_dir("afmp002-clean-rollback");
            let mut env_cfg = PackageExecutionEnv::isolated(&root);
            env_cfg.app_port = 18384;

            let state_dir = root.join("var/lib/syncthing");
            fs::create_dir_all(&state_dir).unwrap();
            fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
            fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
            let lock_path = root.join("install/.syncthing.lock");
            fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
            fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
            let unit_path = root.join("etc/systemd/system/syncthing.service");
            fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
            fs::write(&unit_path, "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n").unwrap();

            let recorded = Arc::new(StdMutex::new(Vec::new()));
            let runner = UpdateRollbackRunner {
                recorded: recorded.clone(),
                state_dir: state_dir.clone(),
                fail_stop: false,
                fail_downgrade: false,
            };
            let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
            let err = executor
                .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
                .await
                .expect_err("update must fail when WaitForHttpReady fails");
            assert!(!err.to_string().contains("incomplete rollback/recovery"));

            // Verify service was stopped before state restoration, state was restored to schema-v1, package was downgraded, and .af-version is 1.0.0
            assert_eq!(
                fs::read(&state_dir.join("index-v0.14.0.db")).unwrap(),
                b"schema-v1-original"
            );
            assert_eq!(
                fs::read_to_string(state_dir.join(".af-version")).unwrap().trim(),
                "1.0.0"
            );
            let cmds = recorded.lock().unwrap().clone();
            let stop_pos = cmds
                .iter()
                .position(|c| {
                    c.program == "systemctl"
                        && c.args == vec!["stop", "--", "syncthing.service"]
                })
                .expect("rollback must stop syncthing.service");
            let downgrade_pos = cmds
                .iter()
                .position(|c| {
                    c.program == "apt-get"
                        && c.args.contains(&"--allow-downgrades".to_string())
                        && c.args.contains(&"syncthing=1.0.0".to_string())
                })
                .expect("rollback must downgrade syncthing to 1.0.0");
            assert!(stop_pos < downgrade_pos);

            let _ = fs::remove_dir_all(&root);
        }

        // Case 2: Package downgrade fails -> receipt honesty gate refuses to restore stale 1.0.0 .af-version receipt
        {
            let root = create_isolated_test_dir("afmp002-downgrade-fails");
            let mut env_cfg = PackageExecutionEnv::isolated(&root);
            env_cfg.app_port = 18384;

            let state_dir = root.join("var/lib/syncthing");
            fs::create_dir_all(&state_dir).unwrap();
            fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
            fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
            let lock_path = root.join("install/.syncthing.lock");
            fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
            fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
            let unit_path = root.join("etc/systemd/system/syncthing.service");
            fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
            fs::write(&unit_path, "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n").unwrap();

            let recorded = Arc::new(StdMutex::new(Vec::new()));
            let runner = UpdateRollbackRunner {
                recorded,
                state_dir: state_dir.clone(),
                fail_stop: false,
                fail_downgrade: true,
            };
            let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
            let err = executor
                .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
                .await
                .expect_err("update must fail with incomplete rollback error when downgrade fails");
            assert!(
                err.to_string().contains("incomplete rollback/recovery"),
                "expected incomplete rollback error, got: {err}"
            );

            // Receipt honesty rule: since binary downgrade to 1.0.0 failed, .af-version must NOT claim 1.0.0!
            assert_eq!(
                fs::read_to_string(state_dir.join(".af-version")).unwrap().trim(),
                "2.0.0",
                "receipt honesty gate must not restore stale 1.0.0 receipt when binary downgrade failed"
            );

            let _ = fs::remove_dir_all(&root);
        }

        // Case 3: Service stop fails -> refuses to overwrite live mutable state directory and refuses to restore stale .af-version
        {
            let root = create_isolated_test_dir("afmp002-stop-fails");
            let mut env_cfg = PackageExecutionEnv::isolated(&root);
            env_cfg.app_port = 18384;

            let state_dir = root.join("var/lib/syncthing");
            fs::create_dir_all(&state_dir).unwrap();
            fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
            fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
            let lock_path = root.join("install/.syncthing.lock");
            fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
            fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
            let unit_path = root.join("etc/systemd/system/syncthing.service");
            fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
            fs::write(&unit_path, "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n").unwrap();

            let recorded = Arc::new(StdMutex::new(Vec::new()));
            let runner = UpdateRollbackRunner {
                recorded,
                state_dir: state_dir.clone(),
                fail_stop: true,
                fail_downgrade: false,
            };
            let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
            let err = executor
                .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
                .await
                .expect_err("update must fail with incomplete rollback error when service stop fails");
            assert!(
                err.to_string().contains("incomplete rollback/recovery"),
                "expected incomplete rollback error, got: {err}"
            );

            // Live mutable state directory must not be overwritten while service is still active, and recovery backup is preserved
            assert_eq!(
                fs::read(&state_dir.join("index-v0.14.0.db")).unwrap(),
                b"schema-v2-migrated"
            );
            assert_eq!(
                fs::read_to_string(state_dir.join(".af-version")).unwrap().trim(),
                "2.0.0"
            );

            let _ = fs::remove_dir_all(&root);
        }

        env::remove_var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS");
        env::remove_var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS");
    }

    #[test]
    fn test_afmp004_runner_jellyfin_blueprint_preserves_operator_remote_access_and_known_proxies() {
        let root = create_isolated_test_dir("afmp004-jellyfin-runner");
        let net_xml = root.join("etc/jellyfin/network.xml");
        fs::create_dir_all(net_xml.parent().unwrap()).unwrap();
        let initial_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <InternalHttpPort>8096</InternalHttpPort>
  <PublicHttpPort>8096</PublicHttpPort>
  <EnableIPV4>true</EnableIPV4>
  <EnableRemoteAccess>false</EnableRemoteAccess>
  <KnownProxies><string>10.20.30.40</string></KnownProxies>
</NetworkConfiguration>
"#;
        fs::write(&net_xml, initial_xml).unwrap();

        apply_runner_blueprint_app_config(Some(&root), "jellyfin", 18096);

        let updated = fs::read_to_string(&net_xml).unwrap();
        assert!(updated.contains("<InternalHttpPort>18096</InternalHttpPort>"));
        assert!(updated.contains("<PublicHttpPort>18096</PublicHttpPort>"));
        assert!(
            updated.contains("<EnableRemoteAccess>false</EnableRemoteAccess>"),
            "must preserve explicit EnableRemoteAccess=false, got:\n{updated}"
        );
        assert!(
            updated.contains("<KnownProxies><string>10.20.30.40</string></KnownProxies>"),
            "must preserve custom KnownProxies, got:\n{updated}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_afmp_sol_001_runner_blueprint_preserves_apache_access_policy() {
        let root = create_isolated_test_dir("afmp-sol-001-runner-apache");
        let sites_avail = root.join("etc/apache2/sites-available");
        let sites_en = root.join("etc/apache2/sites-enabled");
        fs::create_dir_all(&sites_avail).unwrap();
        fs::create_dir_all(&sites_en).unwrap();

        let int_conf = sites_avail.join("aetherflow-app-qui.conf");
        let ext_conf = sites_avail.join("aetherflow-ext-qui.conf");
        let en_ext_conf = sites_en.join("aetherflow-ext-qui.conf");

        let existing_int = "\
# Managed by AetherFlow v3.2.6
<VirtualHost *:80>
    ServerName qui.aether.local
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    RequestHeader set X-Forwarded-Proto \"http\"
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
        let existing_ext = "\
# Managed by AetherFlow v3.2.6 (External Ingress)
<VirtualHost *:80>
    ServerName qui.example.com
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
        fs::write(&int_conf, existing_int).unwrap();
        fs::write(&ext_conf, existing_ext).unwrap();
        fs::write(&en_ext_conf, existing_ext).unwrap();

        try_apply_runner_blueprint_app_config_with_ingress(
            Some(&root),
            "qui",
            18376,
            |_| Ok(None),
        )
        .unwrap();

        for path in [&int_conf, &ext_conf, &en_ext_conf] {
            let updated = fs::read_to_string(path).unwrap();
            assert!(
                updated.contains("ws://127.0.0.1:18376/$1"),
                "must update websocket RewriteRule port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("ProxyPass / http://127.0.0.1:18376/"),
                "must update ProxyPass port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("ProxyPassReverse / http://127.0.0.1:18376/"),
                "must update ProxyPassReverse port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("<Location /qui>"),
                "must preserve <Location /qui> block in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("AuthType Basic"),
                "must preserve AuthType Basic in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("Require ip 192.0.2.0/24"),
                "must preserve Require ip 192.0.2.0/24 in {}: {updated}",
                path.display()
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn blueprint_vhost_rejects_required_directory_target() {
        let root = create_isolated_test_dir("blueprint-vhost-directory");
        let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
        fs::create_dir_all(&target).unwrap();

        let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
        assert!(
            result.is_err(),
            "required managed vhost directory must not be silently skipped: {result:?}"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains(&target.display().to_string()));
        assert!(target.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_vhost_rejects_required_symlink_target() {
        let root = create_isolated_test_dir("blueprint-vhost-symlink");
        let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
        let operator_config = root.join("operator.conf");
        let original = "<VirtualHost *:80>\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&operator_config, original).unwrap();
        std::os::unix::fs::symlink(&operator_config, &target).unwrap();

        let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
        assert!(
            result.is_err(),
            "required managed vhost symlink must not be silently skipped: {result:?}"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains(&target.display().to_string()));
        assert!(fs::symlink_metadata(target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(operator_config).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }

    const BLUEPRINT_VHOST_FIXTURE: &str = "<VirtualHost *:80>\n    ServerName sonarr.example.com\n    ProxyPass / http://127.0.0.1:8989/\n    ProxyPassReverse / http://127.0.0.1:8989/\n</VirtualHost>\n";
    const BLUEPRINT_APP_CONFIG_FIXTURE: &str = "<Config><Port>8989</Port><BindAddress>127.0.0.1</BindAddress><AuthenticationMethod>Forms</AuthenticationMethod><AnalyticsEnabled>False</AnalyticsEnabled></Config>\n";

    fn blueprint_ingress_fixture(root: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(root.join("ingress.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE app_ingress_configs (
                app_name TEXT PRIMARY KEY, public_domain TEXT NOT NULL,
                external_access_enabled INTEGER NOT NULL, listen_port INTEGER NOT NULL,
                tls_enabled INTEGER NOT NULL, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE retained_app_ingress_configs (
                app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_vhost_app_inspection_failure_restores_earlier_mutation() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = create_isolated_test_dir("blueprint-app-inspection-failure");
        let app_config = root.join("var/lib/sonarr/config.xml");
        let later_config = root.join("var/lib/sonarr/.config/sonarr/config.xml");
        let inaccessible = root.join("var/lib/sonarr/.config");
        fs::create_dir_all(later_config.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::write(&later_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        let permissions = fs::metadata(&inaccessible).unwrap().permissions();
        fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o000)).unwrap();

        let result = try_apply_runner_blueprint_app_config(Some(&root), "sonarr", 18989);
        fs::set_permissions(&inaccessible, permissions).unwrap();
        let error = result.unwrap_err().to_string();

        assert!(
            error.contains("failed to inspect required blueprint config"),
            "{error}"
        );
        assert!(
            error.contains(&later_config.display().to_string()),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::read_to_string(later_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blueprint_vhost_read_failure_restores_app_config() {
        let root = create_isolated_test_dir("blueprint-vhost-read-failure");
        let app_config = root.join("var/lib/sonarr/config.xml");
        let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
        let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(app_config.parent().unwrap()).unwrap();
        fs::create_dir_all(internal.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
        fs::write(&external, [0xff, 0xfe]).unwrap();

        let error =
            try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "sonarr", 18989, |_| {
                panic!("invalid vhost must fail before ingress lookup")
            })
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("failed to read required Apache vhost"),
            "{error}"
        );
        assert!(error.contains(&external.display().to_string()), "{error}");
        assert_eq!(
            fs::read_to_string(app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::read_to_string(internal).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert_eq!(fs::read(external).unwrap(), [0xff, 0xfe]);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_vhost_failed_late_write_rolls_back_updates_creates_and_deletes() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for existing_internal in [false, true] {
            let root = create_isolated_test_dir("blueprint-vhost-late-write");
            let app_config = root.join("var/lib/sonarr/config.xml");
            let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
            let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
            let enabled = root.join("etc/apache2/sites-enabled/aetherflow-app-sonarr.conf");
            fs::create_dir_all(app_config.parent().unwrap()).unwrap();
            fs::create_dir_all(internal.parent().unwrap()).unwrap();
            fs::create_dir_all(enabled.parent().unwrap()).unwrap();
            fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
            fs::set_permissions(&app_config, fs::Permissions::from_mode(0o640)).unwrap();
            if existing_internal {
                fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
                fs::set_permissions(&internal, fs::Permissions::from_mode(0o600)).unwrap();
            }
            fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();
            fs::set_permissions(&external, fs::Permissions::from_mode(0o640)).unwrap();
            fs::write(&enabled, BLUEPRINT_VHOST_FIXTURE).unwrap();
            let enabled_directory = enabled.parent().unwrap();
            let permissions = fs::metadata(enabled_directory).unwrap().permissions();
            fs::set_permissions(enabled_directory, fs::Permissions::from_mode(0o555)).unwrap();

            let result = try_apply_runner_blueprint_app_config_with_ingress(
                Some(&root),
                "sonarr",
                18989,
                |_| Ok(Some(af_models::AppIngressConfig::default())),
            );
            fs::set_permissions(enabled_directory, permissions).unwrap();
            let error = result.unwrap_err().to_string();

            assert!(
                error.contains("failed to write required Apache vhost"),
                "{error}"
            );
            assert!(error.contains(&enabled.display().to_string()), "{error}");
            assert!(
                error.contains("restored previous blueprint configuration"),
                "{error}"
            );
            assert!(!error.contains("incomplete rollback"), "{error}");
            assert_eq!(
                fs::read_to_string(&app_config).unwrap(),
                BLUEPRINT_APP_CONFIG_FIXTURE
            );
            assert_eq!(
                fs::metadata(app_config).unwrap().permissions().mode() & 0o777,
                0o640
            );
            if existing_internal {
                assert_eq!(
                    fs::read_to_string(&internal).unwrap(),
                    BLUEPRINT_VHOST_FIXTURE
                );
                assert_eq!(
                    fs::metadata(internal).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            } else {
                assert!(!internal.exists());
            }
            assert_eq!(
                fs::read_to_string(&external).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            assert_eq!(
                fs::metadata(external).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert_eq!(
                fs::read_to_string(enabled).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_vhost_failed_delete_is_explicit_and_preserves_original() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = create_isolated_test_dir("blueprint-vhost-delete-failure");
        let target = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, BLUEPRINT_VHOST_FIXTURE).unwrap();
        let directory = target.parent().unwrap();
        let permissions = fs::metadata(directory).unwrap().permissions();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
        let mut changes = RunnerBlueprintConfigChanges {
            fs_root: Some(&root),
            backups: Vec::new(),
        };
        let result = changes.remove_vhost(&target);
        fs::set_permissions(directory, permissions).unwrap();
        let error = changes.rollback(result.unwrap_err()).to_string();

        assert!(
            error.contains("failed to remove required Apache vhost"),
            "{error}"
        );
        assert!(error.contains(&target.display().to_string()), "{error}");
        assert_eq!(fs::read_to_string(target).unwrap(), BLUEPRINT_VHOST_FIXTURE);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blueprint_vhost_incomplete_rollback_is_honest_and_continues_other_restores() {
        for previously_existed in [false, true] {
            let root = create_isolated_test_dir("blueprint-vhost-incomplete-rollback");
            let restored = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
            let blocked = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
            fs::create_dir_all(restored.parent().unwrap()).unwrap();
            fs::write(&restored, BLUEPRINT_VHOST_FIXTURE).unwrap();
            if previously_existed {
                fs::write(&blocked, BLUEPRINT_VHOST_FIXTURE).unwrap();
            }
            let mut changes = RunnerBlueprintConfigChanges {
                fs_root: Some(&root),
                backups: Vec::new(),
            };
            changes
                .write_vhost(&restored, "updated internal config")
                .unwrap();
            changes
                .write_vhost(&blocked, "updated external config")
                .unwrap();
            fs::remove_file(&blocked).unwrap();
            fs::create_dir(&blocked).unwrap();

            let error = changes
                .rollback(PackageExecutorError::VerificationFailed(
                    "fixture configtest failure".to_string(),
                ))
                .to_string();

            assert!(error.contains("fixture configtest failure"), "{error}");
            assert!(error.contains("incomplete rollback"), "{error}");
            assert!(error.contains(&blocked.display().to_string()), "{error}");
            assert!(!error.contains("restored previous"), "{error}");
            assert_eq!(
                fs::read_to_string(restored).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            assert!(blocked.is_dir());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn blueprint_vhost_ingress_lookup_errors_restore_app_config_without_changing_ingress() {
        for corrupt_retained in [false, true] {
            let root = create_isolated_test_dir("blueprint-vhost-ingress-error");
            let conn = blueprint_ingress_fixture(&root);
            if corrupt_retained {
                conn.execute(
                    "INSERT INTO retained_app_ingress_configs VALUES ('sonarr', 'invalid JSON')",
                    [],
                )
                .unwrap();
            } else {
                conn.execute("DROP TABLE app_ingress_configs", []).unwrap();
            }
            let app_config = root.join("var/lib/sonarr/config.xml");
            let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
            fs::create_dir_all(app_config.parent().unwrap()).unwrap();
            fs::create_dir_all(external.parent().unwrap()).unwrap();
            fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
            fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();

            let error = try_apply_runner_blueprint_app_config_with_ingress(
                Some(&root),
                "sonarr",
                18989,
                |canonical| load_runner_blueprint_ingress(&conn, canonical),
            )
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("failed to load blueprint ingress for sonarr"),
                "{error}"
            );
            assert_eq!(
                fs::read_to_string(app_config).unwrap(),
                BLUEPRINT_APP_CONFIG_FIXTURE
            );
            assert_eq!(
                fs::read_to_string(external).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            assert!(!root
                .join("etc/apache2/sites-available/aetherflow-app-sonarr.conf")
                .exists());
            drop(conn);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_vhost_absent_ingress_preserves_external_domain_aliases_and_custom_blocks() {
        let root = create_isolated_test_dir("blueprint-vhost-enabled-aliases");
        let conn = blueprint_ingress_fixture(&root);
        let available = root.join("etc/apache2/sites-available");
        let enabled = root.join("etc/apache2/sites-enabled");
        fs::create_dir_all(&available).unwrap();
        fs::create_dir_all(&enabled).unwrap();
        let external = available.join("aetherflow-ext-qui.conf");
        let original = "<VirtualHost *:443>\n    ServerName operator.example.com\n    SSLEngine on\n    SSLCertificateFile /operator/certificate.pem\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
        fs::write(&external, original).unwrap();
        let policy = available.join("operator-policy.conf");
        let custom =
            "<Location /private>\n    AuthType Basic\n    Require ip 192.0.2.0/24\n</Location>\n";
        fs::write(&policy, custom).unwrap();
        let aliases = [
            (
                "aetherflow-app-qui.conf",
                "../sites-available/aetherflow-app-qui.conf",
            ),
            (
                "aetherflow-ext-qui.conf",
                "../sites-available/aetherflow-ext-qui.conf",
            ),
            ("qui.conf", "../sites-available/operator-policy.conf"),
        ];
        for (name, target) in aliases {
            std::os::unix::fs::symlink(target, enabled.join(name)).unwrap();
        }

        try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "qui", 18376, |canonical| {
            load_runner_blueprint_ingress(&conn, canonical)
        })
        .unwrap();

        let updated_external = fs::read_to_string(external).unwrap();
        assert!(updated_external.contains("ServerName operator.example.com"));
        assert!(updated_external.contains("<VirtualHost *:443>"));
        assert!(updated_external.contains("SSLCertificateFile /operator/certificate.pem"));
        assert!(updated_external.contains("http://127.0.0.1:18376/"));
        assert!(updated_external.contains(custom.trim()));
        assert!(
            fs::read_to_string(available.join("aetherflow-app-qui.conf"))
                .unwrap()
                .contains(custom.trim())
        );
        assert_eq!(fs::read_to_string(policy).unwrap(), custom);
        for (name, target) in aliases {
            assert_eq!(
                fs::read_link(enabled.join(name)).unwrap(),
                Path::new(target)
            );
        }
        assert!(load_runner_blueprint_ingress(&conn, "qui")
            .unwrap()
            .is_none());
        drop(conn);
        fs::remove_dir_all(root).unwrap();
    }

    include!("native_catalog_regressions.rs");
}
