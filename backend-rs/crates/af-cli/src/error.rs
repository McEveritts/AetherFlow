//! Typed error taxonomy and deterministic exit codes for the `af` administrative CLI (`af-cli`).
//!
//! Aligns with `af_release::ExitCode` and `af_host::HostBackupError` so both human operators
//! and automation wrappers receive structured status codes and machine-readable JSON envelopes.

use af_host::HostBackupError;
use af_release::{ExitCode as ReleaseExitCode, ReleaseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Deterministic process exit codes emitted by the `af` CLI binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum CliExitCode {
    /// Operation completed successfully (`0`).
    Ok = 0,
    /// Invalid CLI syntax, unknown flag, or failed input validation (`2`).
    UsageOrValidation = 2,
    /// Privileged runner socket unreachable, timed out, or returned an execution error (`3`).
    RunnerIpcFailure = 3,
    /// Release or provisioning preflight/lock/integrity check failed (`4`).
    PreflightOrIntegrityFailure = 4,
    /// Insufficient local privileges for a direct host operation when runner IPC is bypassed (`5`).
    PrivilegeRequired = 5,
    /// Operation is intentionally unsupported or not yet migrated to a safe Rust contract (`6`).
    UnsupportedOperation = 6,
    /// Filesystem, SQLite, or runtime execution error (`7`).
    ExecutionFailure = 7,
}

impl CliExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn code_slug(self) -> &'static str {
        match self {
            CliExitCode::Ok => "ok",
            CliExitCode::UsageOrValidation => "usage_or_validation_error",
            CliExitCode::RunnerIpcFailure => "runner_ipc_failure",
            CliExitCode::PreflightOrIntegrityFailure => "preflight_or_integrity_failure",
            CliExitCode::PrivilegeRequired => "privilege_required",
            CliExitCode::UnsupportedOperation => "unsupported_operation",
            CliExitCode::ExecutionFailure => "execution_failure",
        }
    }
}

impl From<ReleaseExitCode> for CliExitCode {
    fn from(code: ReleaseExitCode) -> Self {
        match code {
            ReleaseExitCode::Success => CliExitCode::Ok,
            ReleaseExitCode::ConfigurationOrUsageError => CliExitCode::UsageOrValidation,
            ReleaseExitCode::PreSwapFailure
            | ReleaseExitCode::HealthProbeFailedRollback
            | ReleaseExitCode::LockContention => CliExitCode::PreflightOrIntegrityFailure,
            ReleaseExitCode::RollbackFailed => CliExitCode::ExecutionFailure,
        }
    }
}

/// Comprehensive error type for `af-cli` parsing, IPC, release, backup, and provisioning operations.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("usage error: {0}")]
    Usage(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("runner socket IPC error ({endpoint}): {message}")]
    RunnerIpc { endpoint: String, message: String },

    #[error("privilege required: {0}")]
    PrivilegeRequired(String),

    #[error("preflight or integrity failure: {0}")]
    PreflightOrIntegrity(String),

    #[error("unsupported operation '{operation}': {reason}")]
    Unsupported { operation: String, reason: String },

    #[error("release engine error: {0}")]
    Release(#[from] ReleaseError),

    #[error("host backup error: {0}")]
    Backup(#[from] HostBackupError),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("I/O error ({context}): {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl CliError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Maps this error to its canonical [`CliExitCode`].
    pub fn exit_code(&self) -> CliExitCode {
        match self {
            CliError::Usage(_) | CliError::Validation(_) => CliExitCode::UsageOrValidation,
            CliError::RunnerIpc { .. } => CliExitCode::RunnerIpcFailure,
            CliError::PrivilegeRequired(_) => CliExitCode::PrivilegeRequired,
            CliError::PreflightOrIntegrity(_) => CliExitCode::PreflightOrIntegrityFailure,
            CliError::Unsupported { .. } => CliExitCode::UnsupportedOperation,
            CliError::Release(err) => CliExitCode::from(err.exit_code()),
            CliError::Backup(err) => match err {
                HostBackupError::DestructiveRestoreUnsupported { .. } => {
                    CliExitCode::UnsupportedOperation
                }
                HostBackupError::InvalidConfig(_)
                | HostBackupError::PathValidation { .. }
                | HostBackupError::TraversalRejected { .. }
                | HostBackupError::SymlinkRejected { .. }
                | HostBackupError::UnsafeOverwriteRejected { .. } => {
                    CliExitCode::UsageOrValidation
                }
                HostBackupError::ChecksumMismatch { .. }
                | HostBackupError::MissingChecksumSidecar { .. }
                | HostBackupError::SqliteIntegrity { .. }
                | HostBackupError::InvalidManifest(_)
                | HostBackupError::IncompatibleManifest { .. }
                | HostBackupError::IncompatibleVersion { .. } => {
                    CliExitCode::PreflightOrIntegrityFailure
                }
                HostBackupError::SqliteSnapshot { .. }
                | HostBackupError::ChunkError { .. }
                | HostBackupError::Archive { .. }
                | HostBackupError::ServiceQuiescenceFailed { .. }
                | HostBackupError::RestoreRolledBack { .. }
                | HostBackupError::RestoreRollbackFailed { .. }
                | HostBackupError::Io { .. } => CliExitCode::ExecutionFailure,
            },
            CliError::Execution(_) | CliError::Io { .. } => CliExitCode::ExecutionFailure,
        }
    }

    /// Formats the error as a structured [`CliResponseEnvelope`] for `--json` mode or programmatic inspection.
    pub fn to_error_envelope(&self, domain: &str, action: &str) -> CliResponseEnvelope {
        let code = self.exit_code();
        CliResponseEnvelope {
            status: "error".to_string(),
            domain: domain.to_string(),
            action: action.to_string(),
            exit_code: code.as_i32(),
            error_kind: Some(code.code_slug().to_string()),
            message: self.to_string(),
            data: None,
        }
    }
}

/// Canonical result alias for `af-cli`.
pub type CliResult<T> = Result<T, CliError>;

/// Standardized JSON/human response envelope emitted by `af` commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliResponseEnvelope {
    /// `"ok"` or `"error"`.
    pub status: String,
    /// Functional domain (`"package"`, `"service"`, `"quota"`, `"sandbox"`, `"release"`, `"backup"`, `"provision"`, `"help"`).
    pub domain: String,
    /// Specific subcommand action (`"install"`, `"status"`, `"set"`, `"apply"`, `"restore-preflight"`, etc.).
    pub action: String,
    /// Numeric exit code (`0` on success).
    pub exit_code: i32,
    /// Optional machine-readable error classification slug when `status == "error"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Human-readable summary message.
    pub message: String,
    /// Optional structured JSON payload for the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CliResponseEnvelope {
    pub fn success(
        domain: impl Into<String>,
        action: impl Into<String>,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            domain: domain.into(),
            action: action.into(),
            exit_code: CliExitCode::Ok.as_i32(),
            error_kind: None,
            message: message.into(),
            data,
        }
    }

    /// Renders either pretty JSON (when `json_mode == true`) or concise human-readable text.
    pub fn render(&self, json_mode: bool) -> String {
        if json_mode {
            serde_json::to_string_pretty(self).unwrap_or_else(|_| {
                format!(
                    "{{\"status\":{:?},\"exit_code\":{},\"message\":{:?}}}",
                    self.status, self.exit_code, self.message
                )
            })
        } else if self.status == "ok" {
            self.message.clone()
        } else {
            format!(
                "ERROR [{}] (exit {}): {}",
                self.error_kind.as_deref().unwrap_or("error"),
                self.exit_code,
                self.message
            )
        }
    }
}
