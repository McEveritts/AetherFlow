use super::*;

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
    AptUpdate {
        progress_pct: u8,
        description: String,
    },
    /// Runs `apt-get install -y -qq <packages>` with validated package identifiers.
    AptInstall {
        packages: Vec<String>,
        progress_pct: u8,
        description: String,
    },
    /// Runs `apt-get remove -y -qq <packages>` when `delete_data == false`, or
    /// `apt-get purge -y -qq <packages>` (plus optional `autoremove`) when `delete_data == true`.
    #[serde(alias = "apt_purge")]
    AptRemove {
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
    ProbeSshPort {
        progress_pct: u8,
        description: String,
    },
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
    EnsureThreadfinConfig {
        progress_pct: u8,
        description: String,
    },
    /// Downloads and installs official Rclone binary matching GitHub release discovery.
    InstallRcloneBinary {
        progress_pct: u8,
        description: String,
    },
    /// Removes AetherFlow's Rclone runtime and, on purge, its credential files and archives.
    RemoveRcloneFiles {
        progress_pct: u8,
        description: String,
    },
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
    /// Unmounts active mountpoints directly without invoking a shell (`fusermount -u`, falling back
    /// to `umount` without `-l`), failing closed if any target path remains mounted afterward.
    UnmountPaths {
        paths: Vec<String>,
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
    TryRestart,
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
    #[error("execution error: {0}")]
    ExecutionError(String),
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

    pub fn check_cancelled(&self) -> Result<(), PackageExecutorError> {
        if self.is_cancelled() {
            Err(PackageExecutorError::Cancelled(
                "operation cancelled".to_string(),
            ))
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
