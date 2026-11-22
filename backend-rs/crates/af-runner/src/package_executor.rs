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
//!      with both the legacy Go scanner and the Rust
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

use crate::legacy_stream_output::BoundedLines;
use crate::package_lifecycle::snapshot_policy::{
    configured_max_snapshot_bytes, ensure_snapshot_free_space, snapshot_filesystem_capacity,
    SnapshotBudget, SNAPSHOT_RESERVE_BYTES,
};
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
    "19183013ec8da826e556bde3b511d9f93b9269f6d7eddd78a9df128529f45e4e";

pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validates Threadfin's pinned version and override environment contract before
/// any state mutation. Returns `(resolved_version, validated_sha256_override)`.
pub fn validate_threadfin_target_policy(
    expected_target_version: Option<&str>,
) -> Result<(String, Option<String>), PackageExecutorError> {
    let mut sha_override: Option<String> = None;
    for var_name in [
        "AETHERFLOW_THREADFIN_SHA256",
        "THREADFIN_SHA256",
        "AF_THREADFIN_SHA256",
        "AETHERFLOW_PACKAGE_SHA256_OVERRIDE",
    ] {
        if let Ok(raw) = env::var(var_name) {
            let trimmed = raw.trim();
            if !is_valid_sha256_hex(trimmed) {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid Threadfin SHA-256 override in {}: expected 64-character hexadecimal SHA-256 digest",
                    var_name
                )));
            }
            if sha_override.is_none() {
                sha_override = Some(trimmed.to_ascii_lowercase());
            }
        }
    }

    let mut version_override: Option<String> = None;
    for var_name in [
        "AETHERFLOW_THREADFIN_VERSION",
        "THREADFIN_VERSION",
        "AF_THREADFIN_VERSION",
        "AETHERFLOW_PACKAGE_VERSION_OVERRIDE",
    ] {
        if let Ok(raw) = env::var(var_name) {
            let trimmed = raw.trim();
            let clean = af_release::lifecycle::strip_version_prefix(trimmed);
            if clean.is_empty()
                || !SAFE_VERSION_TAG.is_match(clean)
                || !af_release::lifecycle::validate_target_version(trimmed)
            {
                return Err(PackageExecutorError::Validation(format!(
                    "invalid Threadfin version override in {}: '{}'",
                    var_name, raw
                )));
            }
            if version_override.is_none() {
                version_override = Some(clean.to_string());
            }
        }
    }

    if let Some(ref custom_ver) = version_override {
        if custom_ver != THREADFIN_PINNED_VERSION && sha_override.is_none() {
            return Err(PackageExecutorError::Validation(format!(
                "Threadfin is pinned to version {}; overriding to '{}' requires an explicit 64-hex SHA-256 override",
                THREADFIN_PINNED_VERSION, custom_ver
            )));
        }
    }

    let resolved_version = version_override.unwrap_or_else(|| THREADFIN_PINNED_VERSION.to_string());

    if let Some(raw_target) = expected_target_version
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !af_release::lifecycle::validate_target_version(raw_target) {
            return Err(PackageExecutorError::Validation(format!(
                "invalid Threadfin target version '{}'",
                raw_target
            )));
        }
        let clean_target = af_release::lifecycle::strip_version_prefix(raw_target);
        if clean_target != resolved_version {
            return Err(PackageExecutorError::Validation(format!(
                "Threadfin is pinned to version {}; requested target version '{}' is unsupported without a matching version and SHA-256 override",
                resolved_version, raw_target
            )));
        }
    }

    Ok((resolved_version, sha_override))
}

/// Maps a host architecture identifier to Listenarr's official Linux release ZIP suffix.
/// Official `Listenarrs/Listenarr` releases currently publish Linux x64 (`amd64`) ZIPs only.
pub fn listenarr_release_asset_suffix_for_arch(arch: &str) -> Result<&'static str, String> {
    match arch.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => Ok("linux-x64.zip"),
        "aarch64" | "arm64" => Err(
            "Package 'listenarr' is unsupported on architecture 'arm64': official Listenarrs/Listenarr releases publish Linux x64 (amd64) ZIP archives only and currently provide zero Linux ARM64 assets."
                .to_string(),
        ),
        other => Err(format!(
            "Package 'listenarr' is unsupported on architecture '{}': official Listenarrs/Listenarr releases publish Linux x64 (amd64) ZIP archives only.",
            other
        )),
    }
}

/// Validates that a Listenarr release asset download URL belongs to the official
/// `Listenarrs/Listenarr` release download path for `tag_name` and `asset_name`.
pub fn listenarr_is_official_download_url(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
) -> bool {
    let clean_tag = tag_name.trim();
    let clean_name = asset_name.trim();
    let clean_url = download_url.trim();
    if clean_tag.is_empty()
        || clean_name.is_empty()
        || clean_url.is_empty()
        || clean_url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Some(rest) = clean_url.strip_prefix("https://github.com/") else {
        return false;
    };
    let Some((owner_repo, after_download)) = rest.split_once("/releases/download/") else {
        return false;
    };
    if !owner_repo.eq_ignore_ascii_case("Listenarrs/Listenarr") {
        return false;
    }
    let Some((url_tag, url_asset)) = after_download.split_once('/') else {
        return false;
    };
    !url_asset.contains('/') && url_tag == clean_tag && url_asset == clean_name
}

/// Returns whether a GitHub release asset entry is an official checksum companion
/// for Listenarr release `tag_name`.
pub fn listenarr_is_official_checksum_companion(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
) -> bool {
    let lower = asset_name.trim().to_ascii_lowercase();
    (lower.contains("checksum") || lower.contains("sha256"))
        && listenarr_is_official_download_url(tag_name, asset_name, download_url)
}

/// Returns whether a GitHub release asset entry is an eligible official Listenarr archive
/// for `asset_suffix` with an official download URL and either a valid `sha256:` digest
/// or an official checksum companion.
pub fn listenarr_release_asset_is_eligible(
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
    digest: Option<&str>,
    has_checksum_companion: bool,
    asset_suffix: &str,
) -> bool {
    let clean_tag = tag_name.trim();
    let clean_name = asset_name.trim();
    if clean_tag.is_empty() || !clean_name.ends_with(asset_suffix) {
        return false;
    }
    if !listenarr_is_official_download_url(clean_tag, clean_name, download_url) {
        return false;
    }
    match digest.map(str::trim).filter(|d| !d.is_empty()) {
        Some(raw) => raw.strip_prefix("sha256:").is_some_and(is_valid_sha256_hex),
        None => has_checksum_companion,
    }
}

/// Validates exact-version and architecture policy for pinned, vendor, and Listenarr packages
/// before any lifecycle admission, sandbox write, or installer execution.
pub fn validate_package_target_policy(
    package_id: &str,
    update_source: &str,
    update_package: &str,
    action: &str,
    expected_target_version: Option<&str>,
) -> Result<(), String> {
    validate_package_target_policy_for_arch(
        package_id,
        update_source,
        update_package,
        action,
        expected_target_version,
        env::consts::ARCH,
    )
}

/// Architecture-parameterized variant of [`validate_package_target_policy`].
pub fn validate_package_target_policy_for_arch(
    package_id: &str,
    update_source: &str,
    update_package: &str,
    action: &str,
    expected_target_version: Option<&str>,
    host_arch: &str,
) -> Result<(), String> {
    let action_lower = action.trim().to_ascii_lowercase();
    if action_lower == "remove" || action_lower == "uninstall" {
        return Ok(());
    }
    let src = update_source.trim().to_ascii_lowercase();
    if src == "vendor" {
        if action_lower == "update" {
            return Err(format!(
                "Package '{}' uses a multi-component vendor installer and does not support exact-version updates; use reinstall or the vendor updater instead.",
                package_id
            ));
        }
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Err(format!(
                "Package '{}' uses a multi-component vendor installer and cannot honor exact target version '{}'; omit the target version to run the official vendor installer.",
                package_id, target
            ));
        }
        return Ok(());
    }
    if package_id.eq_ignore_ascii_case("threadfin") {
        validate_threadfin_target_policy(expected_target_version)
            .map(|_| ())
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if package_id.eq_ignore_ascii_case("listenarr") {
        listenarr_release_asset_suffix_for_arch(host_arch)?;
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_target_version(target) {
                return Err(format!(
                    "Invalid target version '{}' for package '{}'",
                    target, package_id
                ));
            }
        }
        return Ok(());
    }
    if src == "apt" {
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_exact_apt_version(target) {
                return Err(format!(
                    "Invalid exact Debian/APT target version '{}' for package '{}'",
                    target, package_id
                ));
            }
        }
        return Ok(());
    }
    if src == "pinned" {
        let pinned = af_release::lifecycle::strip_version_prefix(update_package.trim());
        if let Some(target) = expected_target_version
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !af_release::lifecycle::validate_target_version(target) {
                return Err(format!(
                    "Invalid target version '{}' for pinned package '{}'",
                    target, package_id
                ));
            }
            if !pinned.is_empty() && af_release::lifecycle::strip_version_prefix(target) != pinned {
                return Err(format!(
                    "Pinned package '{}' can only target version '{}', got '{}'",
                    package_id, pinned, target
                ));
            }
        }
    }
    Ok(())
}

/// Default Quassel IRC core listen port when no custom `app_port` is requested.
pub const QUASSEL_DEFAULT_LISTEN_PORT: i32 = 4242;

pub(crate) const RCLONE_BIN: &str = "/opt/AetherFlow/apps/rclone/rclone";
pub(crate) const RCLONE_BIN_OWNER: &str = "/opt/AetherFlow/apps/rclone/.af-owner";
pub(crate) const RCLONE_ENV: &str = "/etc/rclone/rclone.env";
pub(crate) const RCLONE_LEGACY_ENV: &str = "/etc/aetherflow/rclone.env";

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
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    >;

    fn run_command_with_stdin<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        stdin_data: &'a [u8],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        let _ = stdin_data;
        self.run_command(program, args, env_vars, cancel)
    }
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
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        self.run_command_with_stdin(program, args, env_vars, &[], cancel)
    }

    fn run_command_with_stdin<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        stdin_data: &'a [u8],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        let stdin_bytes = stdin_data.to_vec();
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
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            if stdin_bytes.is_empty() {
                cmd.stdin(Stdio::null());
            } else {
                cmd.stdin(Stdio::piped());
            }

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

            if !stdin_bytes.is_empty() {
                if let Some(mut stdin_pipe) = child.stdin.take() {
                    let to_write = stdin_bytes.clone();
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let _ = stdin_pipe.write_all(&to_write).await;
                        let _ = stdin_pipe.flush().await;
                        drop(stdin_pipe);
                    });
                }
            }

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

/// Trusted persistent recovery root for privileged root-run marketplace updates.
/// Kept outside `/tmp` and `/var/tmp` so rollback material remains accessible to
/// operators and survives systemd `PrivateTmp=yes` restarts.
pub const DEFAULT_PRIVILEGED_RECOVERY_ROOT: &str = "/var/backups/aetherflow-recovery";

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
    /// Disposable download/staging directory (`/var/tmp` or `TMPDIR` by default).
    pub temp_dir: PathBuf,
    /// Optional persistent recovery backup root (`AETHERFLOW_RECOVERY_ROOT` / `AF_RECOVERY_ROOT`).
    /// Distinct from disposable download/staging (`temp_dir`, `scratch_root`).
    pub recovery_root: Option<PathBuf>,
    /// Override architecture (`amd64`, `arm64`, `armhf`) or auto-detected at runtime.
    pub arch_override: Option<String>,
    /// Allocated application port (`1024..=65535` or `0`).
    pub app_port: i32,
    /// Optional explicit Rclone RC API secondary port override (`1..=65535`).
    pub rclone_api_port: Option<u16>,
    /// Optional explicit password override (`AF_PASS`) supplied for install/reinstall.
    pub password: Option<String>,
    /// Whether `DELETE_DATA=true` is enabled during `remove`.
    pub delete_data: bool,
    /// Whether `AF_KEEP_EXISTING_SECRETS=1` was explicitly requested via environment.
    pub keep_existing_secrets: bool,
    /// Optional local artifact override directory (`AETHERFLOW_ARTIFACT_CACHE_DIR`) for offline/airgapped or test runs.
    pub artifact_cache_dir: Option<PathBuf>,
    /// Expected target version (`AF_TARGET_VERSION`) for declarative jobs.
    pub expected_target_version: Option<String>,
    /// Disposable scratch root (`AF_JOB_SCRATCH_ROOT`) for declarative jobs.
    pub scratch_root: Option<PathBuf>,
    /// Whether dry-run mode is active for this execution context.
    pub dry_run: bool,
}

impl Default for PackageExecutionEnv {
    fn default() -> Self {
        let fs_root = crate::package_fs_root_override();
        let lock_dir = env::var("LOCK_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/install"));
        let log_dir = PathBuf::from("/var/log/aetherflow");
        let temp_dir = env::var("AETHERFLOW_RUNNER_TEMP_DIR")
            .or_else(|_| env::var("AF_RUNNER_TEMP_DIR"))
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let var_tmp = Path::new("/var/tmp");
                if var_tmp.is_dir() {
                    var_tmp.to_path_buf()
                } else {
                    env::temp_dir()
                }
            });
        let recovery_root = env::var("AETHERFLOW_RECOVERY_ROOT")
            .or_else(|_| env::var("AF_RECOVERY_ROOT"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
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
        let dry_run = env::var("AETHERFLOW_PACKAGE_DRY_RUN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            lifecycle_job_id: crate::current_package_job_id(),
            fs_root,
            lock_dir,
            log_dir,
            temp_dir,
            recovery_root,
            arch_override: None,
            app_port: 0,
            rclone_api_port: None,
            password,
            delete_data,
            keep_existing_secrets,
            artifact_cache_dir,
            expected_target_version: env::var("AF_TARGET_VERSION")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            scratch_root: Some(PathBuf::from("/var/tmp/aetherflow-scratch")),
            dry_run,
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
            recovery_root: Some(root.join("var/backups/aetherflow-recovery")),
            arch_override: Some("amd64".to_string()),
            app_port: 0,
            rclone_api_port: None,
            password: None,
            delete_data: false,
            keep_existing_secrets: false,
            artifact_cache_dir: Some(root.join("artifacts")),
            expected_target_version: env::var("AF_TARGET_VERSION")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            scratch_root: Some(root.join("var/tmp/aetherflow-scratch")),
            dry_run: false,
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
    pub fn resolve_lock_file(
        &self,
        recipe: &DeclarativePackageRecipe,
    ) -> Result<PathBuf, PackageExecutorError> {
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
    pub fn resolve_log_file(
        &self,
        action: PackageAction,
        pkg_id: &str,
    ) -> Result<PathBuf, PackageExecutorError> {
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
    let check_exact = if normalized.is_empty() {
        "/"
    } else {
        normalized
    };
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

/// Validates that a symlink target path has no '..' traversal and that all ancestor directories
/// are legitimate non-symlink paths within `root_bound`. The leaf target itself is permitted to be a symlink.
pub fn validate_filesystem_symlink_path(
    target: &Path,
    root_bound: Option<&Path>,
) -> Result<(), PackageExecutorError> {
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
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            validate_filesystem_path(parent, root_bound)?;
        }
    }
    Ok(())
}

/// Validates that a directory path is safe for ownership change (`chown`) and is not a shared system root.
pub fn validate_chown_target_path(logical_path: &str) -> Result<(), PackageExecutorError> {
    validate_managed_path(logical_path)?;
    let normalized = logical_path.trim().trim_end_matches('/');
    let check_exact = if normalized.is_empty() {
        "/"
    } else {
        normalized
    };
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
        | DeclarativeStep::EnsureThreadfinConfig { .. }
        | DeclarativeStep::InstallRcloneBinary { .. }
        | DeclarativeStep::RemoveRcloneFiles { .. } => Ok(()),
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
            path,
            section,
            settings,
            ..
        } => {
            validate_managed_path(path)?;
            if section.is_empty()
                || section.contains(['\n', '\r', '[', ']'])
                || settings.is_empty()
                || settings.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.contains(['\n', '\r', '=', '[', ']'])
                        || value.contains(['\n', '\r'])
                })
            {
                return Err(PackageExecutorError::Validation(
                    "invalid INI settings".into(),
                ));
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
        62 => Some("amd64"),    // EM_X86_64
        183 => Some("arm64"),   // EM_AARCH64
        40 => Some("armhf"),    // EM_ARM
        3 => Some("i386"),      // EM_386
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
            verify_elf_header_architecture(
                &header[..head_read],
                arch,
                &path.display().to_string(),
            )?;
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
    CreatedFile { target: PathBuf },
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

fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn scan_dir_snapshot_bytes(
    src_dir: &Path,
    root_bound: Option<&Path>,
    cumulative_bytes: &mut u64,
    limit: u64,
    cancel: Option<(&CancellationToken, &str)>,
) -> Result<u64, PackageExecutorError> {
    if let Some((token, pkg_id)) = cancel {
        token.check(pkg_id)?;
    }
    validate_filesystem_path(src_dir, root_bound)?;
    let src_meta = fs::symlink_metadata(src_dir)?;
    if src_meta.file_type().is_symlink() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to snapshot symlink directory: {}",
            src_dir.display()
        )));
    }
    if !src_meta.is_dir() {
        return Ok(0);
    }

    let mut dir_bytes = 0_u64;
    for entry_res in fs::read_dir(src_dir)? {
        if let Some((token, pkg_id)) = cancel {
            token.check(pkg_id)?;
        }
        let entry = entry_res?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if is_transient_af_artifact_name(&name_str) {
            continue;
        }
        let child_src = entry.path();
        let meta = fs::symlink_metadata(&child_src)?;
        if meta.file_type().is_symlink() {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing to snapshot symlink entry: {}",
                child_src.display()
            )));
        }
        if meta.is_dir() {
            let sub_bytes =
                scan_dir_snapshot_bytes(&child_src, root_bound, cumulative_bytes, limit, cancel)?;
            dir_bytes = dir_bytes.saturating_add(sub_bytes);
        } else if meta.is_file() {
            let len = meta.len();
            *cumulative_bytes = cumulative_bytes.saturating_add(len);
            dir_bytes = dir_bytes.saturating_add(len);
            if *cumulative_bytes > limit {
                return Err(PackageExecutorError::ExecutionError(format!(
                    "Declarative rollback snapshot exceeds the {limit}-byte copy ceiling (at least {cumulative_bytes} bytes)"
                )));
            }
        }
    }
    Ok(dir_bytes)
}

fn copy_dir_snapshot_recursive(
    src_dir: &Path,
    dst_dir: &Path,
    root_bound: Option<&Path>,
    mut budget: Option<&mut SnapshotBudget>,
    cancel: Option<(&CancellationToken, &str)>,
) -> Result<(), PackageExecutorError> {
    if let Some((token, pkg_id)) = cancel {
        token.check(pkg_id)?;
    }
    validate_filesystem_path(src_dir, root_bound)?;
    validate_filesystem_path(dst_dir, root_bound)?;
    let src_meta = fs::symlink_metadata(src_dir)?;
    if src_meta.file_type().is_symlink() {
        return Err(PackageExecutorError::SecurityViolation(format!(
            "refusing to snapshot symlink directory: {}",
            src_dir.display()
        )));
    }
    create_dir_all_0755(dst_dir)?;

    for entry_res in fs::read_dir(src_dir)? {
        if let Some((token, pkg_id)) = cancel {
            token.check(pkg_id)?;
        }
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
            copy_dir_snapshot_recursive(
                &child_src,
                &child_dst,
                root_bound,
                budget.as_deref_mut(),
                cancel,
            )?;
        } else if meta.is_file() {
            if let Some(budget) = budget.as_deref_mut() {
                budget
                    .charge(&child_src, meta.len())
                    .map_err(PackageExecutorError::ExecutionError)?;
            }
            let mut src_file = open_read_nofollow(&child_src)?;
            let mut dst_file = open_new_private_file(&child_dst, 0o600)?;
            let copied = std::io::copy(&mut src_file, &mut dst_file)?;
            if copied > meta.len() {
                if let Some(budget) = budget.as_deref_mut() {
                    budget
                        .charge(&child_src, copied - meta.len())
                        .map_err(PackageExecutorError::ExecutionError)?;
                }
            }
            dst_file.set_permissions(meta.permissions())?;
            dst_file.sync_all()?;
        }
    }
    let _ = fs::set_permissions(dst_dir, src_meta.permissions());
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
    let staging_dir =
        target_dir.with_file_name(format!(".{}.af-restore-{}", dir_name, uuid::Uuid::new_v4()));
    let old_dir =
        target_dir.with_file_name(format!(".{}.af-old-{}", dir_name, uuid::Uuid::new_v4()));
    validate_filesystem_path(&staging_dir, root_bound)?;
    validate_filesystem_path(&old_dir, root_bound)?;

    if let Err(err) = copy_dir_snapshot_recursive(backup_dir, &staging_dir, root_bound, None, None)
    {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(err);
    }

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
                            if let (Ok(mut s), Ok(mut d)) = (
                                File::open(&src_path),
                                open_new_private_file(&dst_path, 0o600),
                            ) {
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
pub(crate) struct RollbackJournal {
    entries: Vec<RollbackEntry>,
    restorable_services: Vec<String>,
    touched_services: Vec<String>,
    dir_snapshots: Vec<DirectorySnapshot>,
    apt_downgrades: Vec<(String, String)>,
    apt_removals: Vec<String>,
    pre_existing_version: Option<String>,
    has_existing_installation: bool,
    incomplete_rollback_error: Option<String>,
    temp_files: Vec<PathBuf>,
    fs_root: Option<PathBuf>,
    staged_snapshot_bytes: u64,
}

impl RollbackJournal {
    fn new(fs_root: Option<PathBuf>) -> Self {
        Self {
            fs_root,
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.restorable_services.is_empty()
            && self.touched_services.is_empty()
            && self.dir_snapshots.is_empty()
            && self.apt_downgrades.is_empty()
            && self.apt_removals.is_empty()
            && self.temp_files.is_empty()
    }

    fn stage_directory_snapshots_with_cancel(
        &mut self,
        target_dirs: &[PathBuf],
        cancel: Option<(&CancellationToken, &str)>,
    ) -> Result<(), PackageExecutorError> {
        let mut candidate_dirs: Vec<PathBuf> = Vec::new();
        for target_dir in target_dirs {
            if let Some((token, pkg_id)) = cancel {
                token.check(pkg_id)?;
            }
            validate_filesystem_path(target_dir, self.fs_root.as_deref())?;
            if self
                .dir_snapshots
                .iter()
                .any(|s| s.target_dir == *target_dir)
                || candidate_dirs.iter().any(|d| d == target_dir)
            {
                continue;
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
                        candidate_dirs.push(target_dir.to_path_buf());
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(PackageExecutorError::Io(err)),
            }
        }

        // Sort shallowest-first so nested subtrees (e.g. /var/lib/novnc/.vnc under /var/lib/novnc)
        // are not double-counted or double-snapshotted once their ancestor is covered.
        candidate_dirs.sort_by_key(|p| p.components().count());
        let mut pending_dirs: Vec<PathBuf> = Vec::new();
        for dir in candidate_dirs {
            let covered_by_existing = self
                .dir_snapshots
                .iter()
                .any(|s| dir.starts_with(&s.target_dir));
            let covered_by_pending = pending_dirs.iter().any(|p| dir.starts_with(p));
            if !covered_by_existing && !covered_by_pending {
                pending_dirs.push(dir);
            }
        }

        if pending_dirs.is_empty() {
            return Ok(());
        }

        let limit =
            configured_max_snapshot_bytes().map_err(PackageExecutorError::ExecutionError)?;
        let mut cumulative_bytes = self.staged_snapshot_bytes;
        if cumulative_bytes > limit {
            return Err(PackageExecutorError::ExecutionError(format!(
                "Declarative rollback snapshot exceeds the {limit}-byte copy ceiling (at least {cumulative_bytes} bytes)"
            )));
        }

        struct SnapshotPlan {
            target_dir: PathBuf,
            backup_dir: PathBuf,
        }

        let mut plans = Vec::with_capacity(pending_dirs.len());
        let mut per_dev_usage: HashMap<u64, (u64, u64)> = HashMap::new();

        for target_dir in pending_dirs {
            let backup_dir = backup_dir_path_for(&target_dir);
            validate_filesystem_path(&backup_dir, self.fs_root.as_deref())?;
            let dir_bytes = scan_dir_snapshot_bytes(
                &target_dir,
                self.fs_root.as_deref(),
                &mut cumulative_bytes,
                limit,
                cancel,
            )?;
            let (dev, available) = snapshot_filesystem_capacity(&backup_dir)
                .map_err(PackageExecutorError::ExecutionError)?;
            let entry = per_dev_usage.entry(dev).or_insert((0, available));
            entry.0 = entry.0.saturating_add(dir_bytes);
            entry.1 = available;
            plans.push(SnapshotPlan {
                target_dir,
                backup_dir,
            });
        }

        for (needed_bytes, available) in per_dev_usage.values() {
            ensure_snapshot_free_space(*needed_bytes, *available)
                .map_err(PackageExecutorError::ExecutionError)?;
        }

        let batch_start_idx = self.dir_snapshots.len();
        let initial_staged_bytes = self.staged_snapshot_bytes;

        for plan in plans {
            let copy_res = (|| -> Result<u64, PackageExecutorError> {
                if let Some((token, pkg_id)) = cancel {
                    token.check(pkg_id)?;
                }
                let (_dev, available_now) = snapshot_filesystem_capacity(&plan.backup_dir)
                    .map_err(PackageExecutorError::ExecutionError)?;
                if available_now < SNAPSHOT_RESERVE_BYTES {
                    ensure_snapshot_free_space(0, available_now)
                        .map_err(PackageExecutorError::ExecutionError)?;
                }
                let remaining_global = limit.saturating_sub(self.staged_snapshot_bytes);
                let budget_cap =
                    remaining_global.min(available_now.saturating_sub(SNAPSHOT_RESERVE_BYTES));
                let mut budget = SnapshotBudget::new(budget_cap);
                copy_dir_snapshot_recursive(
                    &plan.target_dir,
                    &plan.backup_dir,
                    self.fs_root.as_deref(),
                    Some(&mut budget),
                    cancel,
                )?;
                Ok(budget_cap.saturating_sub(budget.remaining()))
            })();

            match copy_res {
                Ok(copied_bytes) => {
                    self.staged_snapshot_bytes =
                        self.staged_snapshot_bytes.saturating_add(copied_bytes);
                    self.dir_snapshots.push(DirectorySnapshot {
                        target_dir: plan.target_dir,
                        backup_dir: plan.backup_dir,
                    });
                }
                Err(err) => {
                    if validate_filesystem_path(&plan.backup_dir, self.fs_root.as_deref()).is_ok() {
                        let _ = fs::remove_dir_all(&plan.backup_dir);
                    }
                    for staged in self.dir_snapshots.drain(batch_start_idx..) {
                        if validate_filesystem_path(&staged.backup_dir, self.fs_root.as_deref())
                            .is_ok()
                        {
                            let _ = fs::remove_dir_all(&staged.backup_dir);
                        }
                    }
                    self.staged_snapshot_bytes = initial_staged_bytes;
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn stage_directory_snapshot(&mut self, target_dir: &Path) -> Result<(), PackageExecutorError> {
        self.stage_directory_snapshots_with_cancel(&[target_dir.to_path_buf()], None)
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
        if !pkg.is_empty() && !ver.is_empty() && !self.apt_downgrades.iter().any(|(p, _)| p == pkg)
        {
            self.apt_downgrades.push((pkg.to_string(), ver.to_string()));
        }
    }

    fn record_apt_install(&mut self, package: &str) {
        let pkg = package.trim();
        if !pkg.is_empty()
            && !self.apt_downgrades.iter().any(|(p, _)| p == pkg)
            && !self.apt_removals.iter().any(|p| p == pkg)
        {
            self.apt_removals.push(pkg.to_string());
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
                            {
                                None
                            }
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
        self.apt_removals.clear();
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
        self.staged_snapshot_bytes = 0;
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
        let mut touched_units: Vec<String> = self.touched_services.drain(..).rev().collect();
        af_release::lifecycle::sort_units_for_stop(&mut touched_units);
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
                Ok(out) => matches!(out.stdout.trim(), "active" | "activating" | "reloading"),
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
                    if let Err(err) = validate_filesystem_path(&unit_path, self.fs_root.as_deref())
                    {
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
                RollbackEntry::RestorableFile {
                    target,
                    backup,
                    ownership,
                } => {
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
                                let msg =
                                    format!("failed to restore ownership for {}", target.display());
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
                    if let Err(err) =
                        validate_filesystem_symlink_path(&target, self.fs_root.as_deref())
                    {
                        notes.push(format!(
                            "skipped unsafe rollback removal for {}: {}",
                            target.display(),
                            err
                        ));
                        continue;
                    }
                    if target.is_file() || fs::symlink_metadata(&target).is_ok() {
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
        let removals: Vec<String> = self.apt_removals.drain(..).rev().collect();
        for pkg in removals {
            let remove_args = vec![
                "-o".to_string(),
                "DPkg::Lock::Timeout=120".to_string(),
                "remove".to_string(),
                "-y".to_string(),
                "-qq".to_string(),
                "--no-auto-remove".to_string(),
                pkg.clone(),
            ];
            let remove_res = runner
                .run_command("apt-get", &remove_args, &apt_env, &noop_cancel)
                .await;
            match remove_res {
                Ok(out) if out.success() => {
                    notes.push(format!("removed newly installed APT package {}", pkg));
                }
                Ok(out) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to remove newly installed APT package {} (exit {}): {}",
                        pkg,
                        out.exit_code,
                        out.combined_output()
                    );
                    notes.push(msg.clone());
                    incomplete_errors.push(msg);
                }
                Err(err) => {
                    package_downgrade_failed = true;
                    let msg = format!(
                        "incomplete recovery: failed to remove newly installed APT package {}: {}",
                        pkg, err
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
                    RollbackEntry::RestorableFile {
                        target,
                        backup,
                        ownership,
                    } => {
                        if let Err(err) = validate_filesystem_path(&target, self.fs_root.as_deref())
                            .and_then(|_| {
                                validate_filesystem_path(&backup, self.fs_root.as_deref())
                            })
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
                        if validate_filesystem_symlink_path(&target, self.fs_root.as_deref())
                            .is_ok()
                            && (target.is_file() || fs::symlink_metadata(&target).is_ok())
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
                self.staged_snapshot_bytes = 0;
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
    write_file_atomic_with_file_owner(target, content, mode, root_bound, None)
}

fn write_file_atomic_with_file_owner(
    target: &Path,
    content: &[u8],
    mode: u32,
    root_bound: Option<&Path>,
    owner: Option<(u32, u32)>,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(target, root_bound)?;
    if let Some(parent) = target.parent() {
        validate_filesystem_path(parent, root_bound)?;
        create_dir_all_0755(parent)?;
        validate_filesystem_path(parent, root_bound)?;
    }
    validate_filesystem_path(target, root_bound)?;

    let filename = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let temporary = target.with_file_name(format!(".{}.af-tmp-{}", filename, uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), PackageExecutorError> {
        let mut file = open_new_private_file(&temporary, mode)?;
        file.write_all(content)?;
        if let Some((uid, gid)) = owner {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
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

fn create_dir_all_0755(path: &Path) -> std::io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all_0755(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)?;
            directory.set_permissions(fs::Permissions::from_mode(0o755))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
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
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(file)
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
            crate::create_package_lock_directory(parent)?;
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

mod declarative_recipes;
pub use declarative_recipes::*;

mod apache_ingress;
pub use apache_ingress::*;

mod legacy_readiness;
pub(crate) use legacy_readiness::*;

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
        .split_once('+')
        .map(|(upstream, _)| upstream)
        .unwrap_or(
            without_epoch
                .split_once('-')
                .map_or(without_epoch, |(u, _)| u),
        )
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
        | DeclarativeStep::InstallRcloneBinary {
            progress_pct,
            description,
        }
        | DeclarativeStep::RemoveRcloneFiles {
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
    let without_epoch = match clean.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => clean,
    };
    let core = without_epoch
        .split(['-', '+', '~'])
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(without_epoch);
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

fn add_missing_rclone_env_aliases(mut content: String) -> String {
    let settings = af_models::parse_key_value_env_str(&content);
    for (key, other) in [
        ("RCLONE_RC_USER", "RCLONE_USER"),
        ("RCLONE_USER", "RCLONE_RC_USER"),
        ("RCLONE_RC_PASS", "RCLONE_PASS"),
        ("RCLONE_PASS", "RCLONE_RC_PASS"),
    ] {
        if let Some(value) = settings.get(other).filter(|_| !settings.contains_key(key)) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            let escaped = escape_systemd_env_quoted(value);
            content.push_str(&format!("{key}=\"{escaped}\"\n"));
        }
    }
    content
}

fn update_preserved_rclone_env_pass(existing: &str, raw_pass: &str) -> String {
    let escaped = escape_systemd_env_quoted(raw_pass);
    static RCLONE_PASS_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^[ \t]*(RCLONE_RC_PASS|RCLONE_PASS)[ \t]*=.*$").unwrap());
    let mut out = RCLONE_PASS_RE
        .replace_all(existing, |caps: &regex::Captures<'_>| {
            format!("{}=\"{}\"", &caps[1], escaped)
        })
        .into_owned();
    for key in ["RCLONE_RC_PASS", "RCLONE_PASS"] {
        if !af_models::parse_key_value_env_str(&out).contains_key(key) {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("{key}=\"{escaped}\"\n"));
        }
    }
    out
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
                if let Some((managed_key, value)) = settings
                    .iter()
                    .find(|(managed_key, _)| managed_key == key.trim())
                {
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
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
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
    for (i, sbox) in DES_SBOX.iter().enumerate() {
        let chunk = ((er >> (42 - 6 * i)) & 0x3f) as u8;
        let row = (((chunk >> 5) & 1) << 1) | (chunk & 1);
        let col = (chunk >> 1) & 0x0f;
        let val = sbox[row as usize][col as usize];
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
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(f.as_raw_fd(), libc::LOCK_SH);
            }
        }
        let _ = writeln!(f, "[{}] {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), line);
        let _ = f.flush();
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Mirrors the legacy installer's certificate expansion after writing the install lock.
fn trigger_certbot_sync_best_effort() {
    if !["/usr/local/bin/af-certbot-sync", "/usr/bin/af-certbot-sync"]
        .iter()
        .any(|path| Path::new(path).is_file())
    {
        return;
    }
    tokio::spawn(async {
        if let Err(err) = crate::sync_certbot_and_managed_ingress().await {
            tracing::warn!(error = %err, "post-install certbot sync failed");
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

    let mut found: HashMap<String, bool> =
        wanted_binaries.iter().map(|b| (b.clone(), false)).collect();

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
        if !matches!(
            entry_type,
            tar::EntryType::Regular | tar::EntryType::GNUSparse
        ) {
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

        if !norm.ends_with(".service")
            || pkg.sandbox_profile == "privileged"
            || pkg.sandbox_profile == "none"
            || crate::is_exempt_sandbox_unit(&norm)
        {
            if let Some(ref mut j) = journal {
                if dropin_aether.exists() {
                    j.stage_file_mutation(&dropin_aether)?;
                }
                if dropin_10.exists() {
                    j.stage_file_mutation(&dropin_10)?;
                }
            }
            let _ = fs::remove_file(&dropin_aether);
            let _ = fs::remove_file(&dropin_10);
            continue;
        }
        create_dir_all_0755(&dropin_dir)?;
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

fn collect_package_version_receipt_logical_paths(
    pkg: &af_models::Package,
    pkg_id: &str,
) -> Vec<String> {
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

fn resolve_package_sandbox_roots(install_root: Option<&Path>) -> (Option<PathBuf>, PathBuf) {
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
    (effective_root, systemd_root)
}

/// Ensures systemd sandbox drop-ins (`aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf`)
/// are written on `"install"`, `"reinstall"`, and `"update"`, and removed (along with stale
/// `.af-version` receipts) on `"remove"` / `"uninstall"` across both synthetic roots and live `/`.
pub fn ensure_package_sandbox_dropin_under_root(
    install_root: Option<&Path>,
    pkg_id: &str,
    action: &str,
) -> Result<(), PackageExecutorError> {
    ensure_package_sandbox_dropin_under_root_with_journal(install_root, pkg_id, action, None)
}

pub(crate) fn ensure_package_sandbox_dropin_under_root_with_journal(
    install_root: Option<&Path>,
    pkg_id: &str,
    action: &str,
    journal: Option<&mut RollbackJournal>,
) -> Result<(), PackageExecutorError> {
    let (effective_root, systemd_root) = resolve_package_sandbox_roots(install_root);

    let action_lower = action.trim().to_ascii_lowercase();
    match action_lower.as_str() {
        "install" | "reinstall" | "update" => {
            apply_sandbox_in_root_with_journal(
                pkg_id,
                &systemd_root,
                journal,
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
                for logical_version_path in
                    collect_package_version_receipt_logical_paths(&pkg, pkg_id)
                {
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
    pkg == "fixture"
        && (script_stem.ends_with("-fixture")
            || script_stem.starts_with("fixture-")
            || script_stem.starts_with("hillclimb-")
            || script_stem.starts_with("polling-"))
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
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| af_db::decrypt_secret_if_needed(s).ok())
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
/// Fails closed if an existing encrypted `.master.creds` cannot be decrypted or if
/// configured `AES_MASTER_KEY` encryption fails, preventing silent plaintext clobbering.
pub(crate) fn try_resolve_master_credentials(
    fs_root: Option<&Path>,
) -> anyhow::Result<(String, String)> {
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
        return Ok((env_user.unwrap_or_else(|| "admin".to_string()), pass));
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

    let persist_path = match env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        Ok(custom) if !custom.trim().is_empty() => rebase_path(custom.trim()),
        _ => rebase_path("/var/lib/aetherflow/.master.creds"),
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
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&contents) {
                for field in ["password", "passwd", "pass", "MASTER_PASS", "ha1"] {
                    if let Some(raw_secret) = val.get(field).and_then(|v| v.as_str()) {
                        let trimmed_secret = raw_secret.trim();
                        if trimmed_secret.starts_with("enc:v1:") {
                            af_db::decrypt_secret_if_needed(trimmed_secret).map_err(|err| {
                                anyhow::anyhow!(
                                    "refusing to overwrite undecryptable master credentials at {}: {}",
                                    candidate.display(),
                                    err
                                )
                            })?;
                        }
                    }
                }
            } else if contents.contains("enc:v1:") {
                anyhow::bail!(
                    "refusing to overwrite corrupted encrypted master credentials at {}",
                    candidate.display()
                );
            }
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
            if let Ok(existing_persist) = fs::read_to_string(&persist_path) {
                if existing_persist.contains("enc:v1:") {
                    anyhow::bail!(
                        "refusing to overwrite existing encrypted master credentials at {}",
                        persist_path.display()
                    );
                }
            }
            let generated = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let stored_password = af_db::encrypt_secret_if_configured(&generated)?;
            let ha1 = hex::encode(af_models::md5::md5_digest(
                format!("{master_user}:Welcome to AetherFlow:{generated}").as_bytes(),
            ));
            let payload = serde_json::json!({
                "username": master_user,
                "password": stored_password,
                "ha1": af_db::encrypt_secret_if_configured(&ha1)?,
            })
            .to_string();
            let owner = if fs_root.is_none() && unsafe { libc::geteuid() } == 0 {
                Some((
                    crate::lookup_passwd_uid_reentrant("aetherflow")
                        .ok_or_else(|| anyhow::anyhow!("aetherflow user is unavailable"))?,
                    crate::lookup_group_gid("aetherflow")
                        .ok_or_else(|| anyhow::anyhow!("aetherflow group is unavailable"))?,
                ))
            } else {
                None
            };
            write_file_atomic_with_file_owner(
                &persist_path,
                payload.as_bytes(),
                0o600,
                fs_root,
                owner,
            )?;
            generated
        }
    };
    Ok((master_user, master_pass))
}

#[cfg(test)]
fn resolve_master_credentials(fs_root: Option<&Path>) -> (String, String) {
    try_resolve_master_credentials(fs_root)
        .expect("resolve_master_credentials failed in test fixture")
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
        static PROM_DEFAULT_PORT_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(--web\.listen-address=(?:[^\s\x22':]+)?):[0-9]+").unwrap());
        if PROM_DEFAULT_PORT_RE.is_match(existing) {
            let replacement = format!("${{1}}:{}", app_port);
            let updated = PROM_DEFAULT_PORT_RE
                .replace_all(existing, replacement.as_str())
                .into_owned();
            return (updated != existing).then_some(updated);
        }

        static RENDERED_LISTEN_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"--web\.listen-address=([^\s\x22':]+):[0-9]+").unwrap());
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
            let new_rhs =
                if raw_rhs.starts_with('"') && raw_rhs.ends_with('"') && raw_rhs.len() >= 2 {
                    let inner = raw_rhs[1..raw_rhs.len() - 1].trim();
                    if inner.is_empty() {
                        format!("\"{}\"", listen_flag)
                    } else {
                        format!("\"{} {}\"", inner, listen_flag)
                    }
                } else if raw_rhs.starts_with('\'') && raw_rhs.ends_with('\'') && raw_rhs.len() >= 2
                {
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
    af_models::resolve_package_lock_name(pkg_id)
}

/// Returns whether `config/package_automation.json` configures `require_download_sha256: true`
/// for `pkg_id`. Fails closed (`true`) if a config candidate is a symlink or unreadable.
pub fn package_requires_download_sha256(pkg_id: &str) -> bool {
    let raw = match crate::try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_FOR_EXECUTOR,
    ) {
        Ok(s) => s,
        Err(_) => return true,
    };

    let Ok(map) = serde_json::from_str::<HashMap<String, af_models::PackageAutomation>>(&raw)
    else {
        return true;
    };
    let clean = resolve_package_lock_name(pkg_id);
    map.get(clean)
        .or_else(|| map.get(pkg_id.trim()))
        .map(|a| a.require_download_sha256)
        .unwrap_or(false)
}

/// Resolves the effective listen port for `install` / `reinstall` / `update` when `req.app_port`
/// was not explicitly supplied (`<= 0`), checking persisted SQLite ingress (`app_ingress_configs`
/// and `retained_app_ingress_configs`), native runtime config, lockfile, and catalog `default_port`.
pub fn resolve_effective_runner_app_port(action: &str, pkg_id: &str, requested_port: i32) -> i32 {
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

    let pkg_def = crate::get_runner_package_definition(clean_id)
        .or_else(|| crate::get_runner_package_definition(pkg_id.trim()));
    if let Ok(Some(p)) = af_models::read_package_receipt_port(
        clean_id,
        pkg_def
            .as_ref()
            .map(|p| p.lock_file.as_str())
            .filter(|s| !s.trim().is_empty()),
        env_cfg.fs_root.as_deref(),
    ) {
        return p;
    }

    pkg_def
        .map(|p| p.default_port)
        .filter(|p| (1024..=65535).contains(p))
        .unwrap_or(0)
}

fn legacy_sandbox_units(pkg_id: &str) -> Vec<String> {
    let Some(pkg) = crate::get_runner_package_definition(pkg_id) else {
        return Vec::new();
    };
    if (!pkg.service_type.is_empty() && pkg.service_type != "systemd")
        || matches!(pkg.sandbox_profile.as_str(), "" | "privileged" | "none")
    {
        return Vec::new();
    }
    let mut units = pkg.sandbox_service_ids;
    if units.is_empty() {
        units.push(if pkg.service_name.is_empty() {
            pkg_id.to_string()
        } else {
            pkg.service_name
        });
    }
    let mut out = Vec::new();
    for raw in units {
        let norm = normalize_unit_filename(&raw);
        if norm.ends_with(".service")
            && !crate::is_exempt_sandbox_unit(&norm)
            && !out.contains(&norm)
        {
            out.push(norm);
        }
    }
    out
}

fn legacy_unit_snapshot_in_root(
    unit: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<Vec<Option<fs::Metadata>>> {
    [
        "etc/systemd/system",
        "usr/local/lib/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ]
    .iter()
    .map(|rel| {
        let path = match fs_root {
            Some(root) => root.join(rel).join(unit),
            None => Path::new("/").join(rel).join(unit),
        };
        match fs::metadata(&path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    })
    .collect()
}

fn legacy_unit_changed(before: &[Option<fs::Metadata>], after: &[Option<fs::Metadata>]) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.iter().zip(after).any(|(before, after)| {
        let identity =
            |stat: &fs::Metadata| (stat.dev(), stat.ino(), stat.ctime(), stat.ctime_nsec());
        before.as_ref().map(identity) != after.as_ref().map(identity)
    })
}

async fn rollback_legacy_sandbox_with_lease(
    guard: &Arc<af_release::ReleaseLockGuard>,
    sandbox_journal: &mut RollbackJournal,
    sandbox_units: &[String],
    systemd_root: &Path,
    live_sandbox: bool,
) -> Result<bool, String> {
    let runner = TokioCommandRunner {
        respect_dry_run_env: false,
    };
    crate::PACKAGE_MAINTENANCE_LEASE
        .scope(
            guard.clone(),
            rollback_legacy_sandbox(
                sandbox_journal,
                sandbox_units,
                systemd_root,
                live_sandbox,
                &runner,
            ),
        )
        .await
}

fn format_error_with_sandbox_rollback(base: String, rollback_res: Result<bool, String>) -> String {
    match rollback_res {
        Err(rb) => format!("__RUNNER_EXIT_ERROR__:{base}; incomplete rollback: {rb}\n"),
        Ok(_) => format!("__RUNNER_EXIT_ERROR__:{base}\n"),
    }
}

fn format_post_commit_sandbox_error(base: String, rollback_res: Result<bool, String>) -> String {
    match rollback_res {
        Ok(true) => format!(
            "__RUNNER_EXIT_ERROR__:{base}; managed sandbox drop-in changes restored (package installer had already committed)\n"
        ),
        Ok(false) => format!("__RUNNER_EXIT_ERROR__:{base}\n"),
        Err(rb) => format!(
            "__RUNNER_EXIT_ERROR__:{base}; incomplete rollback: failed to restore managed sandbox drop-in changes ({rb})\n"
        ),
    }
}

/// Sets the lifecycle contract environment for a legacy Bash package script.
/// `DELETE_DATA` is always set explicitly so an inherited runner value can
/// never turn an ordinary removal into a purge.
pub(crate) fn apply_legacy_package_environment(cmd: &mut Command, req: &PackageRunnerRequest) {
    let default_env = PackageExecutionEnv::default();
    let action_lower = req.action.trim().to_ascii_lowercase();
    let keep_existing_secrets = if action_lower == "remove" || action_lower == "uninstall" {
        false
    } else if action_lower == "update" || action_lower == "reinstall" {
        true
    } else {
        default_env.keep_existing_secrets
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
    cmd.env_remove("AF_RCLONE_API_PORT");
    cmd.env_remove("AF_RCLONE_API_PORT_ERROR");
    if req.package_id == "rclone"
        && matches!(action_lower.as_str(), "install" | "reinstall" | "update")
        && (1..=65535).contains(&req.secondary_port)
    {
        cmd.env("RCLONE_API_PORT", req.secondary_port.to_string());
    } else if req.package_id != "rclone" || action_lower == "remove" || action_lower == "uninstall"
    {
        cmd.env_remove("RCLONE_API_PORT");
    }
    if let Some(target) = req
        .expected_target_version
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        cmd.env("AF_TARGET_VERSION", target.trim());
    } else {
        cmd.env_remove("AF_TARGET_VERSION");
    }
    let recovery_root = default_env
        .recovery_root
        .clone()
        .or_else(|| {
            default_env
                .fs_root
                .as_ref()
                .map(|root| root.join("var/backups/aetherflow-recovery"))
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_RECOVERY_ROOT));
    cmd.env("AF_RECOVERY_ROOT", &recovery_root);
    cmd.env("AF_TRANSACTION_ROOT", &recovery_root);
    if default_env.fs_root.is_none() {
        cmd.env_remove("AF_FIXTURE_ROOT");
        cmd.env_remove("TEST_ROOT");
    }
    cmd.env("AF_JOB_SCRATCH_ROOT", "/var/tmp/aetherflow-scratch");
}

pub(crate) fn configure_legacy_rclone_api_port_env(
    cmd: &mut Command,
    req: &PackageRunnerRequest,
    fs_root: Option<&Path>,
    effective_app_port: i32,
) {
    let gui_port = if (1..=65535).contains(&effective_app_port) {
        effective_app_port as u16
    } else {
        5572
    };
    let explicit_rc_port = if (1..=65535).contains(&req.secondary_port) {
        Some(req.secondary_port.to_string())
    } else {
        env::var("RCLONE_API_PORT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    match declarative_recipes::resolve_and_reserve_rclone_api_port(
        fs_root,
        gui_port,
        explicit_rc_port.as_deref(),
        &req.lifecycle_job_id,
        Some(&req.action),
    ) {
        Ok(api_port) => {
            cmd.env("AF_RCLONE_API_PORT", api_port.to_string());
            cmd.env_remove("AF_RCLONE_API_PORT_ERROR");
            if explicit_rc_port.is_some() {
                cmd.env("RCLONE_API_PORT", api_port.to_string());
            } else {
                cmd.env_remove("RCLONE_API_PORT");
            }
        }
        Err(err) => {
            cmd.env_remove("AF_RCLONE_API_PORT");
            cmd.env_remove("RCLONE_API_PORT");
            cmd.env("AF_RCLONE_API_PORT_ERROR", err.to_string());
        }
    }
}

#[cfg(unix)]
pub fn check_disk_space(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut check_path = path.to_path_buf();
    while !check_path.exists() {
        if let Some(parent) = check_path.parent() {
            check_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    let c_path = match CString::new(check_path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Failed to inspect filesystem capacity on {}: {}",
            check_path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let block_size = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    let avail_bytes = (stat.f_bavail as u64).saturating_mul(block_size);
    let avail_inodes = stat.f_favail as u64;

    // Inspect filesystem type via statfs (for magic number) and df -PT
    let mut statfs_buf = unsafe { std::mem::zeroed::<libc::statfs>() };
    let _ = unsafe { libc::statfs(c_path.as_ptr(), &mut statfs_buf) };
    let f_type_u64 = statfs_buf.f_type as u64;
    let is_magic_tmpfs = f_type_u64 == 0x01021994;
    let is_magic_ramfs = f_type_u64 == 0x858458f6 || (f_type_u64 as u32) == 0x858458f6;

    let df_out = std::process::Command::new("df")
        .args(["-PT", &check_path.to_string_lossy()])
        .output();

    let fs_type = match df_out {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.lines()
                .nth(1)
                .and_then(|line| line.split_whitespace().nth(1))
                .map(|t| t.to_ascii_lowercase())
                .unwrap_or_default()
        }
        _ => String::new(),
    };

    if fs_type.is_empty() {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Staging directory {} is on tmpfs filesystem or filesystem type is unknown (unknown)",
            check_path.display()
        )));
    }

    let orig_str = path.to_string_lossy();
    let check_str = check_path.to_string_lossy();
    let is_var_tmp = |s: &str| {
        s == "/var/tmp"
            || s.starts_with("/var/tmp/")
            || s.ends_with("/var/tmp")
            || s.contains("/var/tmp/")
            || s.ends_with("var/tmp")
            || s.contains("var/tmp/")
    };

    let reject_tmpfs = is_var_tmp(&orig_str)
        || is_var_tmp(&check_str)
        || std::env::var("AF_REJECT_TMPFS_STAGING").as_deref() == Ok("1");

    if reject_tmpfs
        && (fs_type == "tmpfs" || fs_type == "ramfs" || is_magic_tmpfs || is_magic_ramfs)
    {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Staging directory {} is on tmpfs filesystem or filesystem type is unknown ({})",
            check_path.display(),
            if !fs_type.is_empty() {
                &fs_type
            } else {
                "tmpfs"
            }
        )));
    }

    if avail_bytes < min_free_bytes {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Insufficient free disk space on {}: {} MB available, {} MB required",
            path.display(),
            avail_bytes / (1024 * 1024),
            min_free_bytes / (1024 * 1024)
        )));
    }

    if avail_inodes < min_free_inodes {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Insufficient free inodes on {}: {} available, {} required",
            path.display(),
            avail_inodes,
            min_free_inodes
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn check_disk_space(
    _path: &Path,
    _min_free_bytes: u64,
    _min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    Ok(())
}

pub fn ensure_sufficient_disk_space(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    check_disk_space(path, min_free_bytes, min_free_inodes)
}

pub fn check_filesystem_capacity_and_inodes(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), String> {
    check_disk_space(path, min_free_bytes, min_free_inodes).map_err(|e| match e {
        PackageExecutorError::ExecutionError(msg) => msg,
        other => other.to_string(),
    })
}

pub fn preflight_check_disk_and_inodes(fs_root: Option<&Path>) -> Result<(), String> {
    const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
    const MIN_FREE_INODES: u64 = 4096;

    for target in ["/var/tmp", "/var/backups", "/opt"] {
        let p = if let Some(root) = fs_root {
            root.join(target.trim_start_matches('/'))
        } else {
            PathBuf::from(target)
        };
        check_filesystem_capacity_and_inodes(&p, MIN_FREE_BYTES, MIN_FREE_INODES)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let scratch_path = if let Some(root) = fs_root {
            root.join("var/tmp/aetherflow-scratch")
        } else {
            PathBuf::from("/var/tmp/aetherflow-scratch")
        };

        let is_root = unsafe { libc::geteuid() == 0 };
        let mut check_capacity = false;

        match std::fs::symlink_metadata(&scratch_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Scratch root {} must not be a symlink",
                        scratch_path.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "Scratch root {} is not a directory",
                        scratch_path.display()
                    ));
                }
                let mode = meta.mode() & 0o777;
                if mode != 0o700 {
                    return Err(format!(
                        "Scratch root {} has permissions 0o{:o}, expected 0o700",
                        scratch_path.display(),
                        mode
                    ));
                }
                if is_root && meta.uid() != 0 {
                    return Err(format!(
                        "Scratch root {} is owned by uid {}, expected 0 (root)",
                        scratch_path.display(),
                        meta.uid()
                    ));
                }
                check_capacity = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                if let Some(parent) = scratch_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&scratch_path) {
                    Ok(()) => {
                        check_capacity = true;
                    }
                    Err(create_err) => {
                        if !is_root && create_err.kind() == std::io::ErrorKind::PermissionDenied {
                            // Unprivileged test runs fallback to checking /var/tmp
                        } else {
                            return Err(format!(
                                "Failed to create scratch root {}: {}",
                                scratch_path.display(),
                                create_err
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read metadata for scratch root {}: {}",
                    scratch_path.display(),
                    e
                ));
            }
        }

        if check_capacity && scratch_path.exists() {
            check_filesystem_capacity_and_inodes(&scratch_path, MIN_FREE_BYTES, MIN_FREE_INODES)?;
        }
    }

    Ok(())
}

pub(crate) fn format_exit_failure_diagnostics(
    code: i32,
    diag_failure: Option<&serde_json::Value>,
    saw_incomplete_rollback_line: Option<&str>,
) -> Option<String> {
    if let Some(diag) = diag_failure {
        let mut stage = diag
            .get("stage")
            .or_else(|| diag.get("failed_stage"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut category = diag
            .get("category")
            .or_else(|| diag.get("failure_category"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut summary = diag
            .get("summary")
            .or_else(|| diag.get("sanitized_summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut updated_diag = diag.clone();
        if let Some(inc_line) = saw_incomplete_rollback_line {
            if !summary.contains("incomplete-rollback") && !summary.contains("incomplete rollback")
            {
                if !summary.is_empty() {
                    summary.push_str("; ");
                }
                summary.push_str(inc_line);
            }
        }
        let is_incomplete = saw_incomplete_rollback_line.is_some()
            || category.contains("incomplete_rollback")
            || category.contains("incomplete-rollback");
        if is_incomplete {
            stage = "rollback";
            if !category.contains("incomplete_rollback")
                && !category.contains("incomplete-rollback")
            {
                category = "incomplete_rollback".to_string();
            }
            if let Some(obj) = updated_diag.as_object_mut() {
                obj.insert(
                    "stage".to_string(),
                    serde_json::Value::String("rollback".to_string()),
                );
                obj.insert(
                    "category".to_string(),
                    serde_json::Value::String("incomplete_rollback".to_string()),
                );
                obj.insert(
                    "summary".to_string(),
                    serde_json::Value::String(summary.clone()),
                );
            }
        }
        let diag_json = serde_json::to_string(&updated_diag).unwrap_or_default();
        Some(format!(
            "__RUNNER_EXIT_ERROR__:exit status {} [STAGE:{}] [CATEGORY:{}] [SUMMARY:{}] | AF_DIAG_FAILURE={}\n",
            code, stage, category, summary, diag_json
        ))
    } else {
        saw_incomplete_rollback_line.map(|inc_line| format!(
            "__RUNNER_EXIT_ERROR__:exit status {} [STAGE:rollback] [CATEGORY:incomplete_rollback] [SUMMARY:{}] | incomplete-rollback\n",
            code, inc_line
        ))
    }
}

fn parse_apt_cache_candidate_version(apt_policy_stdout: &str) -> Option<String> {
    af_release::lifecycle::parse_apt_policy_candidate(apt_policy_stdout)
        .map(|candidate| normalize_dpkg_version(candidate, candidate))
}

fn apt_candidate_satisfies_target(apt_package: &str, target_version: &str) -> bool {
    let Ok(out) = std::process::Command::new("apt-cache")
        .args(["policy", apt_package])
        .output()
    else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_apt_cache_candidate_version(&stdout).is_some_and(|candidate| {
        af_release::lifecycle::versions_match_target(&candidate, target_version)
    })
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
        };

        let effective_expected_target = req
            .expected_target_version
            .clone()
            .or_else(|| env::var("AF_TARGET_VERSION").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if let Some(pkg_def) = crate::get_runner_package_definition(&req.package_id) {
            if let Err(reason) = validate_package_target_policy(
                &req.package_id,
                &pkg_def.update_source,
                &pkg_def.update_package,
                &req.action,
                effective_expected_target.as_deref(),
            ) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", reason));
                return;
            }
        } else if req.package_id.eq_ignore_ascii_case("threadfin") {
            if let Err(reason) = validate_package_target_policy(
                &req.package_id,
                "pinned",
                THREADFIN_PINNED_VERSION,
                &req.action,
                effective_expected_target.as_deref(),
            ) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", reason));
                return;
            }
        }

        let mut declarative_recipe =
            if select_package_engine(&req.package_id) == PackageEngineMode::DeclarativeRust {
                get_declarative_recipe(&req.package_id)
            } else {
                None
            };
        let mut legacy_script_path = if declarative_recipe.is_none() {
            let Some(p) = resolve_package_script_path(&req.action, &req.script_name) else {
                yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
                return;
            };
            Some(p)
        } else {
            None
        };

        if req.package_id == "prometheus" && matches!(action, PackageAction::Update) {
            if let Some(ref target) = effective_expected_target {
                if !apt_candidate_satisfies_target("prometheus", target) {
                    if let Some(fallback_script) =
                        resolve_package_script_path(&req.action, &req.script_name)
                    {
                        tracing::info!(
                            package = "prometheus",
                            target_version = %target,
                            script = %fallback_script.display(),
                            "APT prometheus candidate does not satisfy upstream target version; falling back to validated upstream installer"
                        );
                        declarative_recipe = None;
                        legacy_script_path = Some(fallback_script);
                    }
                }
            }
        }

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
                rclone_api_port: (req.package_id == "rclone"
                    && (1..=65535).contains(&req.secondary_port))
                .then_some(req.secondary_port as u16),
                lifecycle_job_id: req.lifecycle_job_id.clone(),
                // Purge is an explicit request property, never ambient
                // runner environment.
                delete_data: package_request_deletes_data(&req),
                keep_existing_secrets,
                expected_target_version: req.expected_target_version.clone().or_else(|| {
                    env::var("AF_TARGET_VERSION").ok().filter(|s| !s.trim().is_empty())
                }),
                scratch_root: Some(PathBuf::from("/var/tmp/aetherflow-scratch")),
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
                let defer_blueprint = std::env::var("AETHERFLOW_DEFER_BLUEPRINT_SYNC")
                    .map(|v| v == "1")
                    .unwrap_or(false)
                    || req.expected_target_version.is_some()
                    || !req.lifecycle_job_id.is_empty();

                if !defer_blueprint {
                    if let Err(err) = crate::PACKAGE_MAINTENANCE_LEASE.scope(
                        maintenance_guard.clone(),
                        apply_runner_blueprint_in_background(fs_root_clone, req.package_id.clone(), effective_app_port),
                    ).await {
                        yield Ok(format!(
                            "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                            err
                        ));
                        return;
                    }
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

        let installs = matches!(action, PackageAction::Install | PackageAction::Reinstall | PackageAction::Update);
        let sandbox_units = legacy_sandbox_units(&req.package_id);
        let test_live_sandbox = {
            #[cfg(test)]
            {
                env::var("AETHERFLOW_TEST_LIVE_SANDBOX")
                    .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        let live_sandbox = ((env_cfg.fs_root.is_none()
            && env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none())
            || test_live_sandbox)
            && !env::var("AETHERFLOW_SANDBOX_DRY_RUN").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            && cfg!(target_os = "linux");
        let (sandbox_effective_root, sandbox_systemd_root) =
            resolve_package_sandbox_roots(env_cfg.fs_root.as_deref());
        let mut sandbox_journal = RollbackJournal::new(sandbox_effective_root);
        let sandbox_runner = TokioCommandRunner {
            respect_dry_run_env: false,
        };
        let readiness_config = {
            #[cfg(test)]
            {
                LegacyReadinessConfig::from_test_env()
            }
            #[cfg(not(test))]
            {
                LegacyReadinessConfig::default()
            }
        };
        let mut unit_snapshots = Vec::new();
        if installs && !sandbox_units.is_empty() {
            if let Err(error) = ensure_package_sandbox_dropin_under_root_with_journal(
                env_cfg.fs_root.as_deref(),
                &req.package_id,
                &req.action,
                Some(&mut sandbox_journal),
            ) {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(
                    format!("pre-install sandbox failed: {error}"),
                    rb,
                ));
                return;
            }
            if live_sandbox {
                for unit in &sandbox_units {
                    match legacy_unit_snapshot_in_root(unit, env_cfg.fs_root.as_deref()) {
                        Ok(snapshot) => unit_snapshots.push((unit, snapshot)),
                        Err(error) => {
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(
                                format!("cannot snapshot {unit}: {error}"),
                                rb,
                            ));
                            return;
                        }
                    }
                }
                if let Err(error) = crate::PACKAGE_MAINTENANCE_LEASE
                    .scope(
                        maintenance_guard.clone(),
                        run_systemctl_bounded(
                            &sandbox_runner,
                            &["daemon-reload"],
                            &cancel,
                            readiness_config.systemctl_timeout,
                        ),
                    )
                    .await
                {
                    let rb = rollback_legacy_sandbox_with_lease(
                        &maintenance_guard,
                        &mut sandbox_journal,
                        &sandbox_units,
                        &sandbox_systemd_root,
                        live_sandbox,
                    )
                    .await;
                    let base = match error {
                        PackageExecutorError::Cancelled(_) => {
                            format!("operation cancelled for package '{}'", req.package_id)
                        }
                        other => format!("pre-install sandbox failed: {other}"),
                    };
                    yield Ok(format_error_with_sandbox_rollback(base, rb));
                    return;
                }
            }
        }

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
        if req.package_id == "rclone" && installs {
            configure_legacy_rclone_api_port_env(
                &mut cmd,
                &req,
                env_cfg.fs_root.as_deref(),
                effective_app_port,
            );
        }
        let verify_sandbox = installs && live_sandbox && !sandbox_units.is_empty();
        if verify_sandbox {
            cmd.env("AF_EMIT_READINESS_RECORD", "1");
        } else {
            cmd.env_remove("AF_EMIT_READINESS_RECORD");
        }
        match try_resolve_master_credentials(env_cfg.fs_root.as_deref()) {
            Ok((master_user, master_pass)) => {
                cmd.env("MASTER_USER", master_user)
                    .env("MASTER_PASS", master_pass);
            }
            Err(error) => {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                return;
            }
        }

        #[cfg(unix)]
        if let Err(error) = maintenance_guard.preserve_in_child(cmd.as_std_mut()) {
            let rb = rollback_legacy_sandbox_with_lease(
                &maintenance_guard,
                &mut sandbox_journal,
                &sandbox_units,
                &sandbox_systemd_root,
                live_sandbox,
            )
            .await;
            yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
            return;
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let mut stdout = BoundedLines::new(child.stdout.take().unwrap());
                let mut stderr = BoundedLines::new(child.stderr.take().unwrap());
                let mut stdout_open = true;
                let mut stderr_open = true;
                let mut diag_failure: Option<serde_json::Value> = None;
                let mut saw_incomplete_rollback_line: Option<String> = None;
                let mut recorded_readiness_probes: HashMap<String, Vec<RecordedReadinessProbe>> =
                    HashMap::new();
                while stdout_open || stderr_open {
                    if cancel.is_cancelled() {
                        terminate_child_process_group(&mut child).await;
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(
                            format!("operation cancelled for package '{}'", req.package_id),
                            rb,
                        ));
                        return;
                    }
                    let (is_stdout, result) = tokio::select! {
                        _ = wait_for_cancellation(&cancel) => {
                            terminate_child_process_group(&mut child).await;
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(
                                format!("operation cancelled for package '{}'", req.package_id),
                                rb,
                            ));
                            return;
                        }
                        result = stdout.next_line(), if stdout_open => (true, result),
                        result = stderr.next_line(), if stderr_open => (false, result),
                    };
                    match result {
                        Ok(Some(line)) => {
                            if line.trim_start().starts_with(AF_READINESS_PROBE_PREFIX) {
                                if verify_sandbox && !is_stdout {
                                    if let Some(probe) =
                                        parse_readiness_probe_record(&line, &sandbox_units)
                                    {
                                        record_readiness_probe(
                                            &mut recorded_readiness_probes,
                                            probe,
                                        );
                                    }
                                }
                                continue;
                            }
                            if let Some(pos) = line.find("AF_DIAG_FAILURE=") {
                                let json_slice = &line[pos + "AF_DIAG_FAILURE=".len()..];
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_slice.trim()) {
                                    diag_failure = Some(v);
                                }
                            }
                            let lower = line.to_ascii_lowercase();
                            if crate::package_lifecycle::is_incomplete_rollback_error(&line)
                                || lower.contains("incomplete-rollback")
                                || lower.contains("incomplete rollback")
                                || lower.contains("recovery backup preserved")
                            {
                                saw_incomplete_rollback_line = Some(crate::package_lifecycle::sanitize_lifecycle_field(line.trim()));
                            }
                            yield Ok(format!("{}\n", line));
                        }
                        Ok(None) if is_stdout => stdout_open = false,
                        Ok(None) => stderr_open = false,
                        Err(error) => {
                            terminate_child_process_group(&mut child).await;
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                            return;
                        }
                    }
                }
                let status = tokio::select! {
                    biased;
                    _ = wait_for_cancellation(&cancel) => {
                        terminate_child_process_group(&mut child).await;
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(
                            format!("operation cancelled for package '{}'", req.package_id),
                            rb,
                        ));
                        return;
                    }
                    status = child.wait() => status,
                };
                match status {
                    Ok(status) if !status.success() => {
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        if let Err(rb_err) = rb {
                            let combined = match saw_incomplete_rollback_line.take() {
                                Some(existing) => format!("{existing}; {rb_err}"),
                                None => format!("incomplete rollback: {rb_err}"),
                            };
                            saw_incomplete_rollback_line = Some(
                                crate::package_lifecycle::sanitize_lifecycle_field(&combined),
                            );
                        }
                        let code = status.code().unwrap_or(1);
                        if let Some(formatted) = format_exit_failure_diagnostics(
                            code,
                            diag_failure.as_ref(),
                            saw_incomplete_rollback_line.as_deref(),
                        ) {
                            yield Ok(formatted);
                        } else {
                            yield Ok(format!("__RUNNER_EXIT_ERROR__:exit status {}\n", status));
                        }
                    }
                    Err(error) => {
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                    }
                    Ok(_) => {
                        let activation = async {
                            let post_script_dropins = verify_sandbox
                                .then(|| snapshot_sandbox_dropin_bytes(&sandbox_systemd_root, &sandbox_units))
                                .transpose()?;
                            ensure_package_sandbox_dropin_under_root_with_journal(
                                env_cfg.fs_root.as_deref(),
                                &req.package_id,
                                &req.action,
                                Some(&mut sandbox_journal),
                            )?;
                            let Some(post_script_dropins) = post_script_dropins else {
                                return Ok(Vec::new());
                            };
                            let final_dropins =
                                snapshot_sandbox_dropin_bytes(&sandbox_systemd_root, &sandbox_units)?;
                            let mut units_needing_restart = Vec::new();
                            for (unit, before) in &unit_snapshots {
                                let after = legacy_unit_snapshot_in_root(
                                    unit,
                                    env_cfg.fs_root.as_deref(),
                                )
                                .map_err(|err| {
                                        PackageExecutorError::ExecutionError(format!(
                                            "cannot inspect {unit}: {err}"
                                        ))
                                })?;
                                let dropin_changed =
                                    post_script_dropins.get(*unit) != final_dropins.get(*unit);
                                if legacy_unit_changed(before, &after) || dropin_changed {
                                    units_needing_restart.push((*unit).clone());
                                }
                            }
                            crate::PACKAGE_MAINTENANCE_LEASE
                                .scope(
                                    maintenance_guard.clone(),
                                    activate_and_verify_legacy_sandbox(
                                        &req.package_id,
                                        &units_needing_restart,
                                        &recorded_readiness_probes,
                                        &sandbox_runner,
                                        &cancel,
                                        &readiness_config,
                                    ),
                                )
                                .await
                        }.await;
                        match activation {
                            Ok(notes) => {
                                for note in notes {
                                    yield Ok(format!("{note}\n"));
                                }
                            }
                            Err(error) => {
                                let rollback = rollback_legacy_sandbox_with_lease(
                                    &maintenance_guard,
                                    &mut sandbox_journal,
                                    &sandbox_units,
                                    &sandbox_systemd_root,
                                    live_sandbox,
                                )
                                .await;
                                let message = match error {
                                    PackageExecutorError::Cancelled(_) => format!(
                                        "operation cancelled for package '{}'",
                                        req.package_id
                                    ),
                                    other => format!("post-install sandbox failed: {other}"),
                                };
                                yield Ok(format_post_commit_sandbox_error(message, rollback));
                                return;
                            }
                        }
                        sandbox_journal.commit();
                        let defer_blueprint = std::env::var("AETHERFLOW_DEFER_BLUEPRINT_SYNC")
                            .map(|v| v == "1")
                            .unwrap_or(false)
                            || req.expected_target_version.is_some()
                            || !req.lifecycle_job_id.is_empty();

                        if !defer_blueprint
                            && matches!(
                                action,
                                PackageAction::Install
                                    | PackageAction::Reinstall
                                    | PackageAction::Update
                            )
                        {
                            if let Err(err) = crate::PACKAGE_MAINTENANCE_LEASE.scope(
                                maintenance_guard.clone(),
                                apply_runner_blueprint_in_background(env_cfg.fs_root.clone(), req.package_id.clone(), effective_app_port),
                            ).await {
                                yield Ok(format!(
                                    "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                                    err
                                ));
                                return;
                            }
                        }

                    }
                }
            }
            Err(error) => {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Focused Unit & Integration Tests (Isolated Temp Paths & Mocked Commands)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests;
