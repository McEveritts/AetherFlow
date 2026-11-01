//! Typed error taxonomy for `af-host` backup, snapshot, verification, and restore planning.
//!
//! Provides deterministic classification so administrative callers (`af-api`, `af-services`,
//! `af-runner`, and CLI wrappers) can distinguish validation/traversal failures, checksum
//! mismatches, schema/version incompatibilities, SQLite snapshot failures, and explicitly
//! unsupported destructive restore execution.

use std::path::PathBuf;
use thiserror::Error;

/// Comprehensive error contract for AetherFlow host backup & maintenance foundations.
#[derive(Debug, Error)]
pub enum HostBackupError {
    #[error("invalid backup configuration: {0}")]
    InvalidConfig(String),

    #[error("path validation failed for '{path}': {reason}")]
    PathValidation { path: PathBuf, reason: String },

    #[error("unsafe path traversal rejected in '{path}': {reason}")]
    TraversalRejected { path: String, reason: String },

    #[error("symlink entry rejected at '{path}': {reason}")]
    SymlinkRejected { path: PathBuf, reason: String },

    #[error("unsafe overwrite rejected for '{target}': {reason}")]
    UnsafeOverwriteRejected { target: PathBuf, reason: String },

    #[error("manifest validation failed: {0}")]
    InvalidManifest(String),

    #[error("incompatible backup manifest (found schema v{found}, supported v{min}..=v{max}): {reason}")]
    IncompatibleManifest {
        found: u32,
        min: u32,
        max: u32,
        reason: String,
    },

    #[error("incompatible application version '{backup_version}' for host '{host_version}': {reason}")]
    IncompatibleVersion {
        backup_version: String,
        host_version: String,
        reason: String,
    },

    #[error("SHA-256 verification failed for '{artifact}': expected {expected}, got {actual}")]
    ChecksumMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },

    #[error("missing required checksum sidecar '{sidecar_path}' for '{artifact}'")]
    MissingChecksumSidecar {
        artifact: PathBuf,
        sidecar_path: PathBuf,
    },

    #[error("SQLite consistent snapshot failed for '{db_path}': {reason}")]
    SqliteSnapshot { db_path: PathBuf, reason: String },

    #[error("SQLite integrity check failed for '{db_path}': {detail}")]
    SqliteIntegrity { db_path: PathBuf, detail: String },

    #[error("chunk assembly or splitting failed for '{artifact}': {reason}")]
    ChunkError { artifact: PathBuf, reason: String },

    #[error("archive inspection or packaging error for '{archive}': {reason}")]
    Archive { archive: PathBuf, reason: String },

    #[error("destructive restore execution is explicitly unsupported in af-host v1 ({reason}); use plan_restore / preflight_restore for non-destructive verification")]
    DestructiveRestoreUnsupported { reason: String },

    #[error("I/O error during {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl HostBackupError {
    /// Helper for constructing contextualized I/O errors.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Returns `true` if this error represents a security boundary violation
    /// (path traversal, symlink escape, or unsafe overwrite).
    pub const fn is_security_rejection(&self) -> bool {
        matches!(
            self,
            Self::PathValidation { .. }
                | Self::TraversalRejected { .. }
                | Self::SymlinkRejected { .. }
                | Self::UnsafeOverwriteRejected { .. }
        )
    }

    /// Returns `true` if this error represents a cryptographic digest or integrity failure.
    pub const fn is_integrity_failure(&self) -> bool {
        matches!(
            self,
            Self::ChecksumMismatch { .. }
                | Self::MissingChecksumSidecar { .. }
                | Self::SqliteIntegrity { .. }
        )
    }
}

/// Canonical result alias for `af-host` operations.
pub type HostBackupResult<T> = Result<T, HostBackupError>;
