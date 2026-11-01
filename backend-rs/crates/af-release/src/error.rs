//! Typed error taxonomy and exit-code contract for `af-release`.
//!
//! Mirrors `deploy/release-manager.sh` failure semantics while providing
//! structured programmatic classification for runner IPC and administrative callers.

use std::path::PathBuf;
use thiserror::Error;

/// Canonical exit codes aligned with `deploy/release-manager.sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Operation completed successfully (`0`).
    Success = 0,
    /// Stage 1 / Stage 1.5 failure before symlink swap (artifact pull, checksum, or snapshot failure) (`1`).
    PreSwapFailure = 1,
    /// Stage 3 readiness probe failed; Stage 4 rollback was triggered (`2`).
    HealthProbeFailedRollback = 2,
    /// Rollback itself encountered a fatal unrecoverable error (`3`).
    RollbackFailed = 3,
    /// Fatal configuration, argument validation, or unsupported mode error (`4`).
    ConfigurationOrUsageError = 4,
    /// Concurrent release operation already holds the exclusive engine lock (`5`).
    LockContention = 5,
}

impl ExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Comprehensive error contract for the AetherFlow Rust Release Engine.
#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("path validation failed for '{path}': {reason}")]
    PathValidation { path: PathBuf, reason: String },

    #[error("unsupported release operation: {0}")]
    Unsupported(String),

    #[error("release lock contention at '{lock_path}': {reason}")]
    LockBusy { lock_path: PathBuf, reason: String },

    #[error("release tag resolution failed for channel '{channel}': {reason}")]
    TagResolution { channel: String, reason: String },

    #[error("artifact download or verification failed: {0}")]
    ArtifactVerification(String),

    #[error("SHA-256 digest mismatch for '{artifact}': expected {expected}, got {actual}")]
    ChecksumMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },

    #[error("archive extraction failed for '{archive}': {reason}")]
    ArchiveExtraction { archive: PathBuf, reason: String },

    #[error("SQLite state snapshot failed for '{db_path}': {reason}")]
    Snapshot { db_path: PathBuf, reason: String },

    #[error("SQLite integrity check failed for '{db_path}': {result}")]
    IntegrityFailed { db_path: PathBuf, result: String },

    #[error("atomic symlink swap failed for '{link}' -> '{target}': {reason}")]
    SymlinkSwap {
        link: PathBuf,
        target: PathBuf,
        reason: String,
    },

    #[error("systemd lifecycle operation '{action}' failed: {reason}")]
    Systemd { action: String, reason: String },

    #[error("deep readiness probe failed after {attempts} attempts against '{endpoint}': {last_error}")]
    HealthProbeFailed {
        endpoint: String,
        attempts: u32,
        last_error: String,
    },

    #[error("readiness probe failed ({probe_error}); automatic rollback to '{reverted_to}' completed (db_restored={db_restored})")]
    RolledBackAfterProbeFailure {
        probe_error: String,
        reverted_to: PathBuf,
        db_restored: bool,
    },

    #[error("rollback failed: {0}")]
    Rollback(String),

    #[error("I/O error during {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl ReleaseError {
    /// Maps any `ReleaseError` to its deterministic `deploy/release-manager.sh` exit code.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            ReleaseError::Config(_)
            | ReleaseError::PathValidation { .. }
            | ReleaseError::Unsupported(_) => ExitCode::ConfigurationOrUsageError,
            ReleaseError::LockBusy { .. } => ExitCode::LockContention,
            ReleaseError::TagResolution { .. }
            | ReleaseError::ArtifactVerification(_)
            | ReleaseError::ChecksumMismatch { .. }
            | ReleaseError::ArchiveExtraction { .. }
            | ReleaseError::Snapshot { .. }
            | ReleaseError::IntegrityFailed { .. }
            | ReleaseError::SymlinkSwap { .. }
            | ReleaseError::Systemd { .. }
            | ReleaseError::Io { .. } => ExitCode::PreSwapFailure,
            ReleaseError::HealthProbeFailed { .. }
            | ReleaseError::RolledBackAfterProbeFailure { .. } => {
                ExitCode::HealthProbeFailedRollback
            }
            ReleaseError::Rollback(_) => ExitCode::RollbackFailed,
        }
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

pub type ReleaseResult<T> = Result<T, ReleaseError>;
