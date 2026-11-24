//! Privileged NFS media export, `nfsd` tunnel-binding, sentinel, and systemd `.mount` lifecycle
//! management for Peer Clustering (Phase P7).
//!
//! Security and isolation invariants:
//! - Dormant at daemon startup: performs zero host probing, file writes, or unit mutations until
//!   an explicit `/v1/peer-storage` request arrives.
//! - Derives and validates every managed path, unit name, export option list, and tunnel address
//!   at the privileged boundary; never trusts caller-supplied mount options or raw unit names.
//! - Uses FD-anchored directory traversal (`ReceiptDirectory` with `O_NOFOLLOW`) and atomic
//!   `renameat` writes, refusing symlinks, `..` traversal, hard links (`nlink != 1`), and
//!   ambiguous overwrites of unmanaged host files.
//! - Preserves unrelated host exports (`/etc/exports`, other `/etc/exports.d/*`), NFS config
//!   (`/etc/nfs.conf`, other `/etc/nfs.conf.d/*`), systemd units, and WireGuard networking.

use crate::job_receipts::{c_name, entry_at, verify_entry, ReceiptDirectory};
use crate::package_executor::{
    CancellationToken, CommandOutput, CommandRunner, CrossProcessLockGuard, PackageExecutionEnv,
    PackageExecutorError, TokioCommandRunner,
};
use crate::peer_network::{
    redact_secrets, DEFAULT_PEER_STATE_DIR, DEFAULT_PEER_TUNNEL_CIDR, PEER_ERROR_CODE_HEADER,
    PEER_WG_SERVICE_UNIT,
};
use af_models::RunnerResponse;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tokio::time::Instant;

#[cfg(test)]
mod tests;

pub const PEER_STORAGE_PACKAGES: [&str; 2] = ["nfs-kernel-server", "nfs-common"];
pub const PEER_NFSD_SERVICE_UNIT: &str = "nfs-server.service";
pub const DEFAULT_PEER_EXPORTS_DIR: &str = "/etc/exports.d";
pub const DEFAULT_PEER_NFS_CONF_DIR: &str = "/etc/nfs.conf.d";
pub const DEFAULT_PEER_SYSTEMD_DIR: &str = "/etc/systemd/system";
pub const DEFAULT_PEER_MOUNTS_ROOT: &str = "/mnt/af-peers";
pub const PEER_NFSD_CONF_NAME: &str = "aetherflow-peers.conf";
pub const PEER_SENTINEL_FILE_NAME: &str = ".af-peer-sentinel";
pub const PEER_MANAGED_HEADER: &str =
    "# Managed by AetherFlow Peer Clustering. Do not edit manually.";
pub const DEFAULT_SENTINEL_PROBE_TIMEOUT_MS: u64 = 5_000;

const PEER_STORAGE_LOCK_FILE_NAME: &str = ".aetherflow-peer-storage.lock";
const PEER_EXPORT_FILE_PREFIX: &str = "aetherflow-peer-";
const PEER_EXPORT_FILE_SUFFIX: &str = ".exports";
const MANAGED_MOUNT_UNIT_PREFIX: &str = r"mnt-af\x2dpeers-";
const MAX_EXPORTS_PER_LINK: usize = 64;
const MAX_EXPORT_PATH_BYTES: usize = 4096;
const MAX_MANAGED_FILE_BYTES: usize = 256 * 1024;
const MAX_SENTINEL_BYTES: usize = 4096;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_SYSTEMD_UNIT_NAME_BYTES: usize = 255;
const MIN_SENTINEL_PROBE_TIMEOUT_MS: u64 = 100;
const MAX_SENTINEL_PROBE_TIMEOUT_MS: u64 = 15_000;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(35);
const STORAGE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const PACKAGE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const MAINTENANCE_ADMISSION_BUDGET_SECS: u64 = 15;
const APT_STEP_TIMEOUT: Duration = Duration::from_secs(180);
const COMMAND_TEARDOWN_GRACE_SECS: u64 = 5;

/// Worst-case runner work for `EnsurePackages`:
/// 6x dpkg-query (90s) + bounded lock wait (10s) + maintenance admission (15s) +
/// apt-get update (180s) + apt-get install (180s) + teardown grace (5s) = 480s.
pub(crate) const STORAGE_ENSURE_PACKAGES_MAX_SERVER_DURATION: Duration = Duration::from_secs(
    (6 * COMMAND_TIMEOUT.as_secs())
        + PACKAGE_LOCK_TIMEOUT.as_secs()
        + MAINTENANCE_ADMISSION_BUDGET_SECS
        + (2 * APT_STEP_TIMEOUT.as_secs())
        + COMMAND_TEARDOWN_GRACE_SECS,
);

/// Worst-case runner work for storage mutations (including rollback):
/// lock (5s) + up to 3 mount/service commands (105s) + teardown grace (5s) = 115s.
pub(crate) const STORAGE_MUTATION_MAX_SERVER_DURATION: Duration = Duration::from_secs(
    STORAGE_LOCK_TIMEOUT.as_secs()
        + (3 * MOUNT_COMMAND_TIMEOUT.as_secs())
        + COMMAND_TEARDOWN_GRACE_SECS,
);

pub(crate) const STORAGE_ENSURE_PACKAGES_CLIENT_TIMEOUT: Duration =
    Duration::from_secs(STORAGE_ENSURE_PACKAGES_MAX_SERVER_DURATION.as_secs() + 30);
pub(crate) const STORAGE_DEFAULT_CLIENT_TIMEOUT: Duration =
    Duration::from_secs(STORAGE_MUTATION_MAX_SERVER_DURATION.as_secs() + 15);
pub(crate) const STORAGE_PROBE_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn client_timeout_for_request(req: &PeerStorageRequest) -> Duration {
    match req {
        PeerStorageRequest::EnsurePackages => STORAGE_ENSURE_PACKAGES_CLIENT_TIMEOUT,
        PeerStorageRequest::ProbeSentinel { .. } => STORAGE_PROBE_CLIENT_TIMEOUT,
        _ => STORAGE_DEFAULT_CLIENT_TIMEOUT,
    }
}

static SAFE_LINK_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("constant peer storage link id regex")
});

static SAFE_MOUNT_SEGMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
        .expect("constant peer storage mount segment regex")
});

type PeerStorageLockMap = HashMap<PathBuf, Arc<RwLock<()>>>;

static PEER_STORAGE_LOCKS: Lazy<StdMutex<PeerStorageLockMap>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn peer_storage_lock_for(state_dir: &Path) -> Arc<RwLock<()>> {
    let mut map = PEER_STORAGE_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(state_dir.to_path_buf())
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

/// One NFS export entry in a per-link exports file (`/etc/exports.d/aetherflow-peer-<link>.exports`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStorageExportSpec {
    pub path: String,
    #[serde(default)]
    pub writable: bool,
    #[serde(default)]
    pub squash_uid: Option<u32>,
    #[serde(default)]
    pub squash_gid: Option<u32>,
}

/// Request payload dispatched over `/v1/peer-storage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerStorageRequest {
    /// Ensures `nfs-kernel-server` and `nfs-common` are installed via runner apt serialization.
    EnsurePackages,
    /// Writes `/etc/nfs.conf.d/aetherflow-peers.conf` (`[nfsd]\nhost=<tunnel_ip>\n`) and restarts `nfs-server.service`.
    ConfigureNfsd { tunnel_ip: String },
    /// Writes `/etc/exports.d/aetherflow-peer-<link>.exports` restricted to `tunnel_ip` and runs `exportfs -ra`.
    /// When `exports` is empty, removes the managed exports file (if present) and runs `exportfs -ra`.
    WriteExports {
        link: String,
        tunnel_ip: String,
        exports: Vec<PeerStorageExportSpec>,
    },
    /// Removes `/etc/exports.d/aetherflow-peer-<link>.exports` (if present) and runs `exportfs -ra`.
    RemoveExports { link: String },
    /// Verifies `path` is a real non-symlinked directory, ensures `.af-peer-sentinel` (0644),
    /// and returns authoritative `(owner_uid, owner_gid)`.
    /// When `require_non_root_owner` is true, rejects `owner_uid == 0 || owner_gid == 0` before writing.
    EnsureSentinel {
        path: String,
        #[serde(default)]
        require_non_root_owner: bool,
    },
    /// Probes `<mount_path>/.af-peer-sentinel` with a bounded timeout (default 5000 ms, range 100..=15000 ms).
    ProbeSentinel {
        mount_path: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Derives `unit_name` from `mount_path` (`/mnt/af-peers/<link>/<export>`), validates `tunnel_ip`
    /// and `remote_path`, writes constrained NFSv4.2 `.mount` unit, and runs `systemctl daemon-reload`.
    WriteMount {
        mount_path: String,
        tunnel_ip: String,
        remote_path: String,
        #[serde(default)]
        writable: bool,
    },
    /// Derives `unit_name` from `mount_path` (`/mnt/af-peers/<link>/<export>`), validates local
    /// `source_path`, writes constrained bind `.mount` unit (used in P9), and runs `systemctl daemon-reload`.
    WriteBindMount {
        source_path: String,
        mount_path: String,
        #[serde(default)]
        writable: bool,
    },
    /// Stops, disables, removes the managed `.mount` unit for `mount_path`, runs `daemon-reload`,
    /// and safely removes empty mountpoint directories.
    RemoveMount { mount_path: String },
    /// Starts the managed `.mount` unit for `mount_path` (`systemctl start <unit>`).
    StartMount { mount_path: String },
    /// Stops the managed `.mount` unit for `mount_path` (`systemctl stop <unit>`) and removes the
    /// empty leaf mountpoint directory if unmounted so media apps see a missing folder, never an empty one.
    StopMount { mount_path: String },
    /// Queries managed `.mount` unit existence and `systemctl is-active` state.
    MountStatus { mount_path: String },
}

impl PeerStorageRequest {
    pub(crate) fn is_mutating(&self) -> bool {
        !matches!(self, Self::MountStatus { .. } | Self::ProbeSentinel { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStoragePackagesResponse {
    pub installed: bool,
    pub already_installed: bool,
    pub packages: Vec<String>,
    pub versions: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNfsdConfigResponse {
    pub config_path: String,
    pub tunnel_ip: String,
    pub service_unit: String,
    pub service_state: String,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerExportsWriteResponse {
    pub link: String,
    pub exports_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_ip: Option<String>,
    pub export_count: usize,
    pub changed: bool,
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSentinelResponse {
    pub path: String,
    pub sentinel_path: String,
    pub created: bool,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSentinelProbeResponse {
    pub mount_path: String,
    pub sentinel_path: String,
    pub healthy: bool,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMountWriteResponse {
    pub unit_name: String,
    pub mount_path: String,
    pub what: String,
    pub fs_type: String,
    pub options: String,
    pub writable: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMountRemoveResponse {
    pub unit_name: String,
    pub mount_path: String,
    pub removed: bool,
    pub stopped: bool,
    pub mount_dir_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMountStateResponse {
    pub unit_name: String,
    pub mount_path: String,
    pub exists: bool,
    pub active: bool,
    pub unit_state: String,
}

/// Typed response returned by `dispatch_peer_storage` and `execute_peer_storage_local`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStorageResponse {
    Packages(PeerStoragePackagesResponse),
    NfsdConfigured(PeerNfsdConfigResponse),
    ExportsWritten(PeerExportsWriteResponse),
    SentinelEnsured(PeerSentinelResponse),
    SentinelProbed(PeerSentinelProbeResponse),
    MountWritten(PeerMountWriteResponse),
    MountRemoved(PeerMountRemoveResponse),
    MountState(PeerMountStateResponse),
}

impl PeerStorageResponse {
    pub fn into_packages(self) -> Result<PeerStoragePackagesResponse, PeerStorageError> {
        match self {
            Self::Packages(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected packages)".to_string(),
            )),
        }
    }

    pub fn into_nfsd_configured(self) -> Result<PeerNfsdConfigResponse, PeerStorageError> {
        match self {
            Self::NfsdConfigured(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected nfsd_configured)".to_string(),
            )),
        }
    }

    pub fn into_exports_written(self) -> Result<PeerExportsWriteResponse, PeerStorageError> {
        match self {
            Self::ExportsWritten(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected exports_written)".to_string(),
            )),
        }
    }

    pub fn into_sentinel_ensured(self) -> Result<PeerSentinelResponse, PeerStorageError> {
        match self {
            Self::SentinelEnsured(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected sentinel_ensured)".to_string(),
            )),
        }
    }

    pub fn into_sentinel_probed(self) -> Result<PeerSentinelProbeResponse, PeerStorageError> {
        match self {
            Self::SentinelProbed(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected sentinel_probed)".to_string(),
            )),
        }
    }

    pub fn into_mount_written(self) -> Result<PeerMountWriteResponse, PeerStorageError> {
        match self {
            Self::MountWritten(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected mount_written)".to_string(),
            )),
        }
    }

    pub fn into_mount_removed(self) -> Result<PeerMountRemoveResponse, PeerStorageError> {
        match self {
            Self::MountRemoved(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected mount_removed)".to_string(),
            )),
        }
    }

    pub fn into_mount_state(self) -> Result<PeerMountStateResponse, PeerStorageError> {
        match self {
            Self::MountState(v) => Ok(v),
            _ => Err(PeerStorageError::Runtime(
                "Unexpected peer-storage response variant (expected mount_state)".to_string(),
            )),
        }
    }

    fn serialize_wire_output(&self) -> Result<String, PeerStorageError> {
        let encoded = match self {
            Self::Packages(v) => serde_json::to_string(v),
            Self::NfsdConfigured(v) => serde_json::to_string(v),
            Self::ExportsWritten(v) => serde_json::to_string(v),
            Self::SentinelEnsured(v) => serde_json::to_string(v),
            Self::SentinelProbed(v) => serde_json::to_string(v),
            Self::MountWritten(v) => serde_json::to_string(v),
            Self::MountRemoved(v) => serde_json::to_string(v),
            Self::MountState(v) => serde_json::to_string(v),
        };
        encoded.map_err(|_| {
            PeerStorageError::Runtime("Failed serializing peer-storage response".to_string())
        })
    }
}

pub(crate) fn decode_peer_storage_response(
    req: &PeerStorageRequest,
    output: &str,
) -> Result<PeerStorageResponse, PeerStorageError> {
    let parse_err = || {
        PeerStorageError::Runtime(
            "Invalid typed response payload from peer-storage runner".to_string(),
        )
    };
    match req {
        PeerStorageRequest::EnsurePackages => Ok(PeerStorageResponse::Packages(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerStorageRequest::ConfigureNfsd { .. } => Ok(PeerStorageResponse::NfsdConfigured(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerStorageRequest::WriteExports { .. } | PeerStorageRequest::RemoveExports { .. } => {
            Ok(PeerStorageResponse::ExportsWritten(
                serde_json::from_str(output).map_err(|_| parse_err())?,
            ))
        }
        PeerStorageRequest::EnsureSentinel { .. } => Ok(PeerStorageResponse::SentinelEnsured(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerStorageRequest::ProbeSentinel { .. } => Ok(PeerStorageResponse::SentinelProbed(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerStorageRequest::WriteMount { .. } | PeerStorageRequest::WriteBindMount { .. } => {
            Ok(PeerStorageResponse::MountWritten(
                serde_json::from_str(output).map_err(|_| parse_err())?,
            ))
        }
        PeerStorageRequest::RemoveMount { .. } => Ok(PeerStorageResponse::MountRemoved(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerStorageRequest::StartMount { .. }
        | PeerStorageRequest::StopMount { .. }
        | PeerStorageRequest::MountStatus { .. } => Ok(PeerStorageResponse::MountState(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
    }
}

/// Typed error returned by peer-storage runner operations and preserved across the Unix socket.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerStorageError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Busy(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Runtime(String),
}

impl PeerStorageError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Self::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::Busy(_) => "busy",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Runtime(_) => "runtime",
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    pub fn is_invalid_input(&self) -> bool {
        matches!(self, Self::InvalidInput(_))
    }

    pub(crate) fn from_http_response(
        status: StatusCode,
        code: Option<&str>,
        error: String,
    ) -> Self {
        let msg = {
            let redacted = redact_secrets(error.trim());
            if redacted.is_empty() {
                format!("Runner returned HTTP {}", status.as_u16())
            } else {
                redacted
            }
        };
        if let Some(code) = code {
            match code {
                "invalid_input" => return Self::InvalidInput(msg),
                "busy" => return Self::Busy(msg),
                "not_found" => return Self::NotFound(msg),
                "conflict" => return Self::Conflict(msg),
                "runtime" => return Self::Runtime(msg),
                _ => {}
            }
        }
        match status {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => Self::InvalidInput(msg),
            StatusCode::SERVICE_UNAVAILABLE => Self::Busy(msg),
            StatusCode::NOT_FOUND => Self::NotFound(msg),
            StatusCode::CONFLICT => Self::Conflict(msg),
            _ => Self::Runtime(msg),
        }
    }

    pub(crate) fn into_http_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        let error = redact_secrets(&self.to_string());
        let body = serde_json::to_vec(&RunnerResponse {
            success: false,
            output: String::new(),
            error,
        })
        .unwrap_or_else(|_| {
            br#"{"success":false,"error":"Internal peer-storage serialization error"}"#.to_vec()
        });
        let mut response = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()));
        response
            .headers_mut()
            .insert(PEER_ERROR_CODE_HEADER, HeaderValue::from_static(error_code));
        response
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation, Path Derivation & Systemd Unit Escaping Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StorageTunnelCidr {
    ip: IpAddr,
    prefix: u8,
}

impl StorageTunnelCidr {
    fn parse_subnet(raw: &str) -> Result<Self, PeerStorageError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            return Err(PeerStorageError::InvalidInput(
                "Tunnel CIDR must not be empty".to_string(),
            ));
        }
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            PeerStorageError::InvalidInput("Tunnel CIDR must use address/prefix format".to_string())
        })?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| PeerStorageError::InvalidInput("Invalid tunnel CIDR IP".to_string()))?;
        let prefix: u8 = prefix_str.parse().map_err(|_| {
            PeerStorageError::InvalidInput("Invalid tunnel CIDR prefix".to_string())
        })?;
        let valid = match ip {
            IpAddr::V4(_) => (1..=30).contains(&prefix),
            IpAddr::V6(_) => (1..=126).contains(&prefix),
        };
        if !valid {
            return Err(PeerStorageError::InvalidInput(
                "Tunnel CIDR prefix must allow multiple peer host addresses".to_string(),
            ));
        }
        Ok(Self { ip, prefix })
    }

    fn ip_bits(ip: IpAddr) -> u128 {
        match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        }
    }

    fn bits(&self) -> u128 {
        match self.ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    fn mask(&self) -> u128 {
        let host_bits = self.bits() - (self.prefix as u128);
        let full = if self.bits() == 32 {
            u32::MAX as u128
        } else {
            u128::MAX
        };
        (full << host_bits) & full
    }

    fn network_bits(&self) -> u128 {
        Self::ip_bits(self.ip) & self.mask()
    }

    fn broadcast_bits(&self) -> u128 {
        let full = if self.bits() == 32 {
            u32::MAX as u128
        } else {
            u128::MAX
        };
        self.network_bits() | (!self.mask() & full)
    }

    fn network_string(&self) -> String {
        let net_ip = match self.ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(self.network_bits() as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(self.network_bits())),
        };
        format!("{net_ip}/{}", self.prefix)
    }

    fn contains_ip(&self, candidate: IpAddr) -> bool {
        matches!(
            (self.ip, candidate),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        ) && (Self::ip_bits(candidate) & self.mask()) == self.network_bits()
    }

    fn is_usable_host(&self, candidate: IpAddr) -> bool {
        if !self.contains_ip(candidate) {
            return false;
        }
        let bits = Self::ip_bits(candidate);
        bits != self.network_bits() && bits != self.broadcast_bits()
    }
}

fn validate_tunnel_ip(raw: &str, cidr: &StorageTunnelCidr) -> Result<IpAddr, PeerStorageError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains(',')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PeerStorageError::InvalidInput(
            "Tunnel IP must be a single bare IP address without a CIDR prefix".to_string(),
        ));
    }
    let ip: IpAddr = trimmed.parse().map_err(|_| {
        PeerStorageError::InvalidInput("Tunnel IP is not a valid IP address".into())
    })?;
    if !cidr.contains_ip(ip) {
        return Err(PeerStorageError::InvalidInput(format!(
            "Tunnel IP {ip} is outside the configured peer tunnel CIDR {}",
            cidr.network_string()
        )));
    }
    if !cidr.is_usable_host(ip) {
        return Err(PeerStorageError::InvalidInput(format!(
            "Tunnel IP {ip} cannot be a subnet network or broadcast address"
        )));
    }
    Ok(ip)
}

/// Validates a peer link identifier used in managed export filenames and mount paths.
pub fn validate_peer_storage_link_id(link: &str) -> Result<&str, PeerStorageError> {
    if SAFE_LINK_ID_RE.is_match(link) {
        Ok(link)
    } else {
        Err(PeerStorageError::InvalidInput(
            "Peer link identifier must be 1-64 ASCII alphanumeric, underscore, or hyphen characters starting with an alphanumeric character"
                .to_string(),
        ))
    }
}

/// Validates one path segment under `/mnt/af-peers/<link>/<export>`.
pub fn validate_peer_mount_segment(segment: &str) -> Result<&str, PeerStorageError> {
    if SAFE_MOUNT_SEGMENT_RE.is_match(segment) && !segment.contains("..") {
        Ok(segment)
    } else {
        Err(PeerStorageError::InvalidInput(
            "Peer mount path segment must be 1-64 safe characters without '..' traversal"
                .to_string(),
        ))
    }
}

/// Derives the managed `/etc/exports.d/` filename for `link`.
pub fn derive_peer_export_file_name(link: &str) -> Result<String, PeerStorageError> {
    let valid = validate_peer_storage_link_id(link)?;
    Ok(format!(
        "{PEER_EXPORT_FILE_PREFIX}{valid}{PEER_EXPORT_FILE_SUFFIX}"
    ))
}

/// Derives the canonical peer mountpoint path `/mnt/af-peers/<link>/<export_segment>`.
pub fn derive_peer_mount_path(
    link: &str,
    export_segment: &str,
) -> Result<String, PeerStorageError> {
    let valid_link = validate_peer_mount_segment(link)?;
    let valid_export = validate_peer_mount_segment(export_segment)?;
    let path = format!("{DEFAULT_PEER_MOUNTS_ROOT}/{valid_link}/{valid_export}");
    // Verify the resulting systemd unit name fits systemd's UNIT_NAME_MAX.
    let _ = systemd_escape_mount_unit(&path)?;
    Ok(path)
}

/// Validates that `mount_path` is strictly `/mnt/af-peers/<link_segment>/<export_segment>` and
/// returns `(link_segment, export_segment)`.
pub fn validate_peer_mount_path(mount_path: &str) -> Result<(String, String), PeerStorageError> {
    if mount_path.is_empty()
        || mount_path.len() > MAX_EXPORT_PATH_BYTES
        || mount_path.chars().any(char::is_control)
        || mount_path.contains("//")
        || mount_path.ends_with('/')
    {
        return Err(PeerStorageError::InvalidInput(
            "Peer mount path must be a canonical path under /mnt/af-peers/<link>/<export>"
                .to_string(),
        ));
    }
    let Some(rest) = mount_path.strip_prefix(&format!("{DEFAULT_PEER_MOUNTS_ROOT}/")) else {
        return Err(PeerStorageError::InvalidInput(format!(
            "Peer mount path must live directly under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
        )));
    };
    let mut parts = rest.split('/');
    let link_seg = parts.next().unwrap_or("");
    let export_seg = parts.next().unwrap_or("");
    if parts.next().is_some() || link_seg.is_empty() || export_seg.is_empty() {
        return Err(PeerStorageError::InvalidInput(format!(
            "Peer mount path must have exactly two segments under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
        )));
    }
    validate_peer_mount_segment(link_seg)?;
    validate_peer_mount_segment(export_seg)?;
    Ok((link_seg.to_string(), export_seg.to_string()))
}

const FORBIDDEN_EXPORT_PREFIXES: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/boot",
    "/root",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/usr",
    "/mnt/af-peers",
    "/var/lib/aetherflow",
    "/var/run",
    "/opt/AetherFlow",
];

const FORBIDDEN_EXPORT_EXACT: &[&str] = &["/", "/tmp", "/var/tmp", "/var", "/home"];

/// Validates canonical absolute export or bind-source directory path syntax.
///
/// Rejects relative paths, `..`/`.` traversal, duplicate or trailing slashes, control or
/// config-injection characters, and sensitive system directories (including `/mnt/af-peers`).
pub fn validate_export_path_syntax(path: &str) -> Result<String, PeerStorageError> {
    if path.is_empty() || path.len() > MAX_EXPORT_PATH_BYTES {
        return Err(PeerStorageError::InvalidInput(
            "Export path must be a non-empty canonical absolute path".to_string(),
        ));
    }
    if path.trim() != path {
        return Err(PeerStorageError::InvalidInput(
            "Export path must not have leading or trailing whitespace".to_string(),
        ));
    }
    if !path.starts_with('/') {
        return Err(PeerStorageError::InvalidInput(
            "Export path must be an absolute path starting with '/'".to_string(),
        ));
    }
    if path == "/" || path.ends_with('/') || path.contains("//") {
        return Err(PeerStorageError::InvalidInput(
            "Export path must be a canonical non-root path without duplicate or trailing slashes"
                .to_string(),
        ));
    }
    if path.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '"' | '\'' | '\\' | '#' | ';' | ',' | ':' | '(' | ')' | '*' | '?' | '[' | ']'
            )
    }) {
        return Err(PeerStorageError::InvalidInput(
            "Export path contains disallowed control or config-syntax characters".to_string(),
        ));
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." || segment.len() > 255 {
            return Err(PeerStorageError::InvalidInput(
                "Export path must not contain empty, '.', '..', or oversized segments".to_string(),
            ));
        }
    }
    if FORBIDDEN_EXPORT_EXACT.contains(&path) {
        return Err(PeerStorageError::InvalidInput(format!(
            "Refusing to export or bind sensitive top-level directory '{path}'"
        )));
    }
    for prefix in FORBIDDEN_EXPORT_PREFIXES {
        if path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(PeerStorageError::InvalidInput(format!(
                "Refusing to export or bind restricted system path '{path}'"
            )));
        }
    }
    Ok(path.to_string())
}

/// Rust equivalent of `systemd-escape --path <path>` matching systemd's `unit_name_path_escape`.
pub fn systemd_escape_path(path: &str) -> Result<String, PeerStorageError> {
    if path.is_empty() || !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(PeerStorageError::InvalidInput(
            "Path for systemd escaping must be a non-empty absolute path without control characters"
                .to_string(),
        ));
    }
    let mut normalized_parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(PeerStorageError::InvalidInput(
                "Path for systemd escaping must not contain '.' or '..' segments".to_string(),
            ));
        }
        normalized_parts.push(part);
    }
    if normalized_parts.is_empty() {
        return Ok("-".to_string());
    }
    let normalized = normalized_parts.join("/");
    let mut out = String::with_capacity(normalized.len() + 16);
    for (idx, &byte) in normalized.as_bytes().iter().enumerate() {
        match byte {
            b'/' => out.push('-'),
            b'.' if idx == 0 => out.push_str(r"\x2e"),
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b':' | b'_' | b'.' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{other:02x}");
            }
        }
    }
    Ok(out)
}

/// Validates a managed peer mount path (`/mnt/af-peers/<link>/<export>`) and derives its exact
/// systemd `.mount` unit name via `systemd_escape_path`.
pub fn systemd_escape_mount_unit(mount_path: &str) -> Result<String, PeerStorageError> {
    let _ = validate_peer_mount_path(mount_path)?;
    let escaped = systemd_escape_path(mount_path)?;
    let unit = format!("{escaped}.mount");
    if unit.len() > MAX_SYSTEMD_UNIT_NAME_BYTES {
        return Err(PeerStorageError::InvalidInput(format!(
            "Derived systemd mount unit name exceeds {MAX_SYSTEMD_UNIT_NAME_BYTES} bytes"
        )));
    }
    debug_assert!(is_managed_peer_mount_unit(&unit));
    Ok(unit)
}

/// Returns `true` iff `unit` is a syntactically valid AetherFlow peer mount unit name
/// (`mnt-af\x2dpeers-<escaped>.mount`).
pub fn is_managed_peer_mount_unit(unit: &str) -> bool {
    if unit.len() > MAX_SYSTEMD_UNIT_NAME_BYTES
        || !unit.starts_with(MANAGED_MOUNT_UNIT_PREFIX)
        || !unit.ends_with(".mount")
        || unit.contains('/')
        || unit.contains("..")
    {
        return false;
    }
    let inner = &unit[MANAGED_MOUNT_UNIT_PREFIX.len()..unit.len() - ".mount".len()];
    if inner.is_empty() || !inner.contains('-') {
        return false;
    }
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b':' | b'_' | b'.' | b'-' => i += 1,
            b'\\' => {
                if i + 3 >= bytes.len()
                    || bytes[i + 1] != b'x'
                    || !bytes[i + 2].is_ascii_hexdigit()
                    || !bytes[i + 3].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 4;
            }
            _ => return false,
        }
    }
    true
}

/// Returns `<dir>/.af-peer-sentinel`.
pub fn peer_sentinel_path(dir: &Path) -> PathBuf {
    dir.join(PEER_SENTINEL_FILE_NAME)
}

fn escape_systemd_specifiers(value: &str) -> String {
    value.replace('%', "%%")
}

fn validate_export_specs(
    exports: &[PeerStorageExportSpec],
) -> Result<Vec<PeerStorageExportSpec>, PeerStorageError> {
    if exports.len() > MAX_EXPORTS_PER_LINK {
        return Err(PeerStorageError::InvalidInput(format!(
            "Too many exports for one peer link (maximum {MAX_EXPORTS_PER_LINK})"
        )));
    }
    let mut seen = HashSet::with_capacity(exports.len());
    let mut validated = Vec::with_capacity(exports.len());
    for spec in exports {
        let canonical = validate_export_path_syntax(&spec.path)?;
        if !seen.insert(canonical.clone()) {
            return Err(PeerStorageError::InvalidInput(format!(
                "Duplicate peer export path '{canonical}'"
            )));
        }
        if spec.writable {
            match (spec.squash_uid, spec.squash_gid) {
                (Some(uid), Some(gid)) if uid > 0 && gid > 0 => {}
                (Some(_), Some(_)) => {
                    return Err(PeerStorageError::InvalidInput(format!(
                        "Writable export '{canonical}' must use non-root squash_uid and squash_gid"
                    )));
                }
                _ => {
                    return Err(PeerStorageError::InvalidInput(format!(
                        "Writable export '{canonical}' requires both squash_uid and squash_gid"
                    )));
                }
            }
        } else if spec.squash_uid.is_some() || spec.squash_gid.is_some() {
            return Err(PeerStorageError::InvalidInput(format!(
                "Read-only export '{canonical}' must not specify squash_uid or squash_gid"
            )));
        }
        validated.push(PeerStorageExportSpec {
            path: canonical,
            writable: spec.writable,
            squash_uid: spec.squash_uid,
            squash_gid: spec.squash_gid,
        });
    }
    validated.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(validated)
}

fn render_export_line(tunnel_ip: IpAddr, spec: &PeerStorageExportSpec) -> String {
    let path_token = if spec.path.contains(' ') {
        format!("\"{}\"", spec.path)
    } else {
        spec.path.clone()
    };
    let options = if spec.writable {
        let uid = spec.squash_uid.expect("validated writable squash_uid");
        let gid = spec.squash_gid.expect("validated writable squash_gid");
        format!("rw,all_squash,anonuid={uid},anongid={gid},secure,no_subtree_check")
    } else {
        "ro,root_squash,secure,no_subtree_check".to_string()
    };
    format!("{path_token} {tunnel_ip}({options})")
}

fn render_exports_file(tunnel_ip: IpAddr, exports: &[PeerStorageExportSpec]) -> String {
    let mut out = format!("{PEER_MANAGED_HEADER}\n");
    for spec in exports {
        out.push_str(&render_export_line(tunnel_ip, spec));
        out.push('\n');
    }
    out
}

fn render_nfsd_conf(tunnel_ip: IpAddr) -> String {
    format!("{PEER_MANAGED_HEADER}\n[nfsd]\nhost={tunnel_ip}\n")
}

fn render_nfs_mount_unit(
    mount_path: &str,
    tunnel_ip: IpAddr,
    remote_path: &str,
    writable: bool,
) -> (String, String, String) {
    let what = match tunnel_ip {
        IpAddr::V4(v4) => format!("{v4}:{remote_path}"),
        IpAddr::V6(v6) => format!("[{v6}]:{remote_path}"),
    };
    let rw_mode = if writable { "rw" } else { "ro" };
    let options = format!(
        "vers=4.2,soft,timeo=100,retrans=2,{rw_mode},nosuid,nodev,_netdev,x-systemd.requires={PEER_WG_SERVICE_UNIT}"
    );
    let desc_path = escape_systemd_specifiers(mount_path);
    let what_escaped = escape_systemd_specifiers(&what);
    let where_escaped = escape_systemd_specifiers(mount_path);
    let content = format!(
        "{PEER_MANAGED_HEADER}\n\
         [Unit]\n\
         Description=AetherFlow Peer NFS Mount ({desc_path})\n\
         After=network-online.target {PEER_WG_SERVICE_UNIT}\n\
         Wants=network-online.target\n\
         Requires={PEER_WG_SERVICE_UNIT}\n\
         PartOf={PEER_WG_SERVICE_UNIT}\n\
         \n\
         [Mount]\n\
         What={what_escaped}\n\
         Where={where_escaped}\n\
         Type=nfs4\n\
         Options={options}\n\
         DirectoryMode=0755\n\
         TimeoutSec=30\n\
         ForceUnmount=yes\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    (what, options, content)
}

fn render_bind_mount_unit(source_path: &str, mount_path: &str, writable: bool) -> (String, String) {
    let rw_mode = if writable { "rw" } else { "ro" };
    let options = format!("bind,{rw_mode},nosuid,nodev");
    let desc_path = escape_systemd_specifiers(mount_path);
    let what_escaped = escape_systemd_specifiers(source_path);
    let where_escaped = escape_systemd_specifiers(mount_path);
    let content = format!(
        "{PEER_MANAGED_HEADER}\n\
         [Unit]\n\
         Description=AetherFlow Peer Bind Mount ({desc_path})\n\
         After=local-fs.target\n\
         \n\
         [Mount]\n\
         What={what_escaped}\n\
         Where={where_escaped}\n\
         Type=none\n\
         Options={options}\n\
         DirectoryMode=0755\n\
         TimeoutSec=15\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    (options, content)
}

/// Probes `<mount_dir>/.af-peer-sentinel` with a bounded timeout, rejecting symlinks and
/// non-regular sentinel files.
///
/// Safe for direct non-privileged use in `af-api`'s 15-second peer health loop and local tests.
pub async fn probe_sentinel_file(mount_dir: &Path, timeout: Duration) -> PeerSentinelProbeResponse {
    probe_sentinel_file_for_display(mount_dir, &mount_dir.to_string_lossy(), timeout).await
}

async fn probe_sentinel_file_for_display(
    resolved_mount_dir: &Path,
    display_mount_path: &str,
    timeout: Duration,
) -> PeerSentinelProbeResponse {
    let display_sentinel = format!(
        "{}/{PEER_SENTINEL_FILE_NAME}",
        display_mount_path.trim_end_matches('/')
    );
    if !resolved_mount_dir.is_absolute()
        || resolved_mount_dir
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return PeerSentinelProbeResponse {
            mount_path: display_mount_path.to_string(),
            sentinel_path: display_sentinel,
            healthy: false,
            timed_out: false,
            error: Some(
                "Mount directory for sentinel probe must be an absolute path without '..'"
                    .to_string(),
            ),
        };
    }

    let target_dir = resolved_mount_dir.to_path_buf();
    let probe_task = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let Some(dir) = ReceiptDirectory::open_existing(&target_dir)
            .map_err(|err| format!("Mount directory is unsafe or inaccessible: {err}"))?
        else {
            return Err("Mount directory does not exist".to_string());
        };
        let stat = entry_at(dir.file(), OsStr::new(PEER_SENTINEL_FILE_NAME)).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                "Peer sentinel file is missing".to_string()
            } else {
                format!("Cannot stat peer sentinel file: {err}")
            }
        })?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err("Peer sentinel entry is not a regular file".to_string());
        }
        Ok(())
    });

    match tokio::time::timeout(timeout, probe_task).await {
        Ok(Ok(Ok(()))) => PeerSentinelProbeResponse {
            mount_path: display_mount_path.to_string(),
            sentinel_path: display_sentinel,
            healthy: true,
            timed_out: false,
            error: None,
        },
        Ok(Ok(Err(message))) => PeerSentinelProbeResponse {
            mount_path: display_mount_path.to_string(),
            sentinel_path: display_sentinel,
            healthy: false,
            timed_out: false,
            error: Some(message),
        },
        Ok(Err(_)) => PeerSentinelProbeResponse {
            mount_path: display_mount_path.to_string(),
            sentinel_path: display_sentinel,
            healthy: false,
            timed_out: false,
            error: Some("Sentinel probe worker terminated unexpectedly".to_string()),
        },
        Err(_) => PeerSentinelProbeResponse {
            mount_path: display_mount_path.to_string(),
            sentinel_path: display_sentinel,
            healthy: false,
            timed_out: true,
            error: Some(format!(
                "Sentinel probe timed out after {}ms",
                timeout.as_millis()
            )),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Confined Filesystem, Locking & Bounded Subprocess Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn enforce_root_ownership_and_mode(file: &File, mode: u32) -> std::io::Result<()> {
    if running_as_root() {
        let meta = file.metadata()?;
        if (meta.uid() != 0 || meta.gid() != 0)
            && unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

struct ConfinedLockGuard {
    _dir: ReceiptDirectory,
    file: File,
}

impl Drop for ConfinedLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn validate_lock_file_metadata(
    file: &File,
    lock_name: &str,
    expected_uid: Option<u32>,
) -> Result<(), PeerStorageError> {
    let meta = file.metadata().map_err(|err| {
        PeerStorageError::Runtime(format!("Cannot stat peer storage lock {lock_name}: {err}"))
    })?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(PeerStorageError::Runtime(format!(
            "Refusing non-regular or hard-linked peer storage lock {lock_name}"
        )));
    }
    if let Some(uid) = expected_uid {
        if meta.uid() != uid || meta.gid() != 0 {
            return Err(PeerStorageError::Runtime(format!(
                "Refusing peer storage lock {lock_name} not owned by expected uid {uid}:0"
            )));
        }
    }
    let perm = meta.mode() & 0o7777;
    if perm != 0o600 {
        return Err(PeerStorageError::Runtime(format!(
            "Refusing peer storage lock {lock_name} with non-strict mode {perm:04o} (expected 0600)"
        )));
    }
    Ok(())
}

async fn poll_flock_until(
    file: &File,
    lock_op: libc::c_int,
    deadline: Instant,
    busy_message: &str,
) -> Result<(), PeerStorageError> {
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), lock_op | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            let now = Instant::now();
            if now >= deadline {
                return Err(PeerStorageError::Busy(busy_message.to_string()));
            }
            let remaining = deadline.saturating_duration_since(now);
            tokio::time::sleep(Duration::from_millis(15).min(remaining)).await;
            continue;
        }
        return Err(PeerStorageError::Runtime(format!(
            "Failed acquiring peer storage advisory lock: {err}"
        )));
    }
}

struct CmdOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> Result<Vec<u8>, PeerStorageError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await.map_err(|err| {
            PeerStorageError::Runtime(format!("Command stream read failed: {err}"))
        })?;
        if n == 0 {
            return Ok(out);
        }
        if n > limit.saturating_sub(out.len()) {
            return Err(PeerStorageError::Runtime(
                "Peer storage command output exceeded its size limit".to_string(),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn kill_process_group(pgid: Option<u32>) {
    if let Some(pgid) = pgid.filter(|id| *id > 0) {
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
    }
}

struct ProcessGroupKillGuard(Option<u32>);

impl ProcessGroupKillGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupKillGuard {
    fn drop(&mut self) {
        kill_process_group(self.0);
    }
}

fn format_duration_human(d: Duration) -> String {
    if d.as_secs() > 0 && d.subsec_millis() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_string()).collect()
}

fn map_directory_open_error(display_path: &str, err: std::io::Error) -> PeerStorageError {
    if err.kind() == std::io::ErrorKind::NotFound {
        return PeerStorageError::NotFound(format!("Directory '{display_path}' does not exist"));
    }
    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
        || err.kind() == std::io::ErrorKind::InvalidInput
    {
        return PeerStorageError::InvalidInput(format!(
            "Refusing symlink or non-directory path '{display_path}': {err}"
        ));
    }
    PeerStorageError::Runtime(format!(
        "Cannot safely open directory '{display_path}': {err}"
    ))
}

fn validate_sentinel_owner(
    canonical: &str,
    owner_uid: u32,
    owner_gid: u32,
    require_non_root_owner: bool,
) -> Result<(), PeerStorageError> {
    if require_non_root_owner && (owner_uid == 0 || owner_gid == 0) {
        return Err(PeerStorageError::InvalidInput(format!(
            "Writable peer export directory '{canonical}' must be owned by a non-root user and group (found uid={owner_uid}, gid={owner_gid})"
        )));
    }
    Ok(())
}

fn managed_header_matches(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .is_some_and(|text| text.starts_with(PEER_MANAGED_HEADER))
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerStorageManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages privileged NFS exports, `nfsd` tunnel binding, export sentinels, and systemd `.mount`
/// units for Peer Clustering.
#[derive(Clone, Debug)]
pub struct PeerStorageManager {
    exports_dir: PathBuf,
    nfs_conf_dir: PathBuf,
    systemd_dir: PathBuf,
    mounts_root: PathBuf,
    state_dir: PathBuf,
    bin: Option<PathBuf>,
    fs_root: Option<PathBuf>,
    tunnel_cidr: StorageTunnelCidr,
    command_timeout: Duration,
    mount_command_timeout: Duration,
    apt_timeout: Duration,
    lock_timeout: Duration,
    package_lock_timeout: Duration,
    expected_uid: Option<u32>,
}

impl PeerStorageManager {
    /// Builds the production manager from operator configuration env vars (`AF_PEER_TUNNEL_CIDR`).
    /// Performs no filesystem or OS side effects.
    pub fn from_env() -> Result<Self, PeerStorageError> {
        let cidr_raw = env::var("AF_PEER_TUNNEL_CIDR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PEER_TUNNEL_CIDR.to_string());
        let tunnel_cidr = StorageTunnelCidr::parse_subnet(&cidr_raw)?;

        Ok(Self {
            exports_dir: PathBuf::from(DEFAULT_PEER_EXPORTS_DIR),
            nfs_conf_dir: PathBuf::from(DEFAULT_PEER_NFS_CONF_DIR),
            systemd_dir: PathBuf::from(DEFAULT_PEER_SYSTEMD_DIR),
            mounts_root: PathBuf::from(DEFAULT_PEER_MOUNTS_ROOT),
            state_dir: PathBuf::from(DEFAULT_PEER_STATE_DIR),
            bin: None,
            fs_root: None,
            tunnel_cidr,
            command_timeout: COMMAND_TIMEOUT,
            mount_command_timeout: MOUNT_COMMAND_TIMEOUT,
            apt_timeout: APT_STEP_TIMEOUT,
            lock_timeout: STORAGE_LOCK_TIMEOUT,
            package_lock_timeout: PACKAGE_LOCK_TIMEOUT,
            expected_uid: running_as_root().then_some(0),
        })
    }

    /// Constructs an isolated manager for fixture tests (never touches `/etc/exports.d`,
    /// `/etc/nfs.conf.d`, `/etc/systemd/system`, `/mnt/af-peers`, or host binaries).
    pub fn new_isolated(
        root: PathBuf,
        bin_dir: PathBuf,
        tunnel_cidr: &str,
    ) -> Result<Self, PeerStorageError> {
        let parsed_cidr = StorageTunnelCidr::parse_subnet(tunnel_cidr)?;
        Ok(Self {
            exports_dir: root.join("etc/exports.d"),
            nfs_conf_dir: root.join("etc/nfs.conf.d"),
            systemd_dir: root.join("etc/systemd/system"),
            mounts_root: root.join("mnt/af-peers"),
            state_dir: root.join("etc/aetherflow/peers"),
            bin: Some(bin_dir),
            fs_root: Some(root),
            tunnel_cidr: parsed_cidr,
            command_timeout: COMMAND_TIMEOUT,
            mount_command_timeout: MOUNT_COMMAND_TIMEOUT,
            apt_timeout: APT_STEP_TIMEOUT,
            lock_timeout: STORAGE_LOCK_TIMEOUT,
            package_lock_timeout: PACKAGE_LOCK_TIMEOUT,
            expected_uid: running_as_root().then_some(0),
        })
    }

    #[cfg(test)]
    fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self.mount_command_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_apt_timeout(mut self, timeout: Duration) -> Self {
        self.apt_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self.package_lock_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_expected_uid(mut self, uid: Option<u32>) -> Self {
        self.expected_uid = uid;
        self
    }

    fn program(&self, name: &str) -> PathBuf {
        self.bin
            .as_ref()
            .map_or_else(|| PathBuf::from(name), |bin| bin.join(name))
    }

    fn resolve_host_path(&self, canonical_abs: &str) -> PathBuf {
        match &self.fs_root {
            Some(root) => root.join(canonical_abs.trim_start_matches('/')),
            None => PathBuf::from(canonical_abs),
        }
    }

    fn validate_managed_ancestors(&self, path: &Path) -> Result<(), PeerStorageError> {
        let anchor = self.fs_root.as_deref().unwrap_or_else(|| Path::new("/"));
        let Ok(rel) = path.strip_prefix(anchor) else {
            return Ok(());
        };
        let components: Vec<&OsStr> = rel
            .components()
            .filter_map(|comp| match comp {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        if components.len() <= 1 {
            return Ok(());
        }
        let mut cursor = anchor.to_path_buf();
        for name in &components[..components.len() - 1] {
            cursor.push(name);
            let Some(anc_dir) = ReceiptDirectory::open_existing(&cursor).map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Refusing unsafe or inaccessible ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?
            else {
                return Err(PeerStorageError::Runtime(format!(
                    "Managed ancestor directory {} disappeared",
                    cursor.display()
                )));
            };
            if let Some(uid) = self.expected_uid {
                anc_dir.verify_owners(&[uid]).map_err(|err| {
                    PeerStorageError::Runtime(format!(
                        "Ancestor directory {} is not owned by expected uid {uid}: {err}",
                        cursor.display()
                    ))
                })?;
            }
            let meta = anc_dir.file().metadata().map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Cannot stat ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?;
            let perm = meta.mode() & 0o7777;
            if perm & 0o6022 != 0 {
                return Err(PeerStorageError::Runtime(format!(
                    "Refusing writable or privileged ancestor directory {} (mode {perm:04o})",
                    cursor.display()
                )));
            }
        }
        Ok(())
    }

    fn validate_system_dir(
        &self,
        path: &Path,
        dir: &ReceiptDirectory,
        forbidden_bits: u32,
    ) -> Result<(), PeerStorageError> {
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Directory verification failed for {}: {err}",
                path.display()
            ))
        })?;
        if let Some(uid) = self.expected_uid {
            dir.verify_owners(&[uid]).map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Directory {} is not owned by expected uid {uid}: {err}",
                    path.display()
                ))
            })?;
        }
        self.validate_managed_ancestors(path)?;
        let meta = dir.file().metadata().map_err(|err| {
            PeerStorageError::Runtime(format!("Cannot stat directory {}: {err}", path.display()))
        })?;
        if !meta.is_dir() {
            return Err(PeerStorageError::Runtime(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        let perm = meta.mode() & 0o7777;
        if perm & forbidden_bits != 0 {
            return Err(PeerStorageError::Runtime(format!(
                "Refusing overly permissive directory {} (mode {perm:04o})",
                path.display()
            )));
        }
        Ok(())
    }

    fn open_existing_system_dir(
        &self,
        path: &Path,
        forbidden_bits: u32,
    ) -> Result<Option<ReceiptDirectory>, PeerStorageError> {
        let dir = ReceiptDirectory::open_existing(path).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Refusing unsafe or inaccessible directory {}: {err}",
                path.display()
            ))
        })?;
        if let Some(ref directory) = dir {
            self.validate_system_dir(path, directory, forbidden_bits)?;
        }
        Ok(dir)
    }

    fn ensure_system_dir(
        &self,
        path: &Path,
        create_mode: u32,
        forbidden_bits: u32,
    ) -> Result<ReceiptDirectory, PeerStorageError> {
        if let Some(existing) = self.open_existing_system_dir(path, forbidden_bits)? {
            return Ok(existing);
        }
        let dir = ReceiptDirectory::open_confined(path, true, create_mode).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Refusing unsafe or inaccessible directory {}: {err}",
                path.display()
            ))
        })?;
        enforce_root_ownership_and_mode(dir.file(), create_mode).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Failed to secure directory {}: {err}",
                path.display()
            ))
        })?;
        self.validate_system_dir(path, &dir, forbidden_bits)?;
        Ok(dir)
    }

    fn open_verified_local_directory(
        &self,
        canonical_abs: &str,
    ) -> Result<(ReceiptDirectory, u32, u32), PeerStorageError> {
        let resolved = self.resolve_host_path(canonical_abs);
        let Some(dir) = ReceiptDirectory::open_existing(&resolved)
            .map_err(|err| map_directory_open_error(canonical_abs, err))?
        else {
            return Err(PeerStorageError::NotFound(format!(
                "Directory '{canonical_abs}' does not exist"
            )));
        };
        let meta = dir.file().metadata().map_err(|err| {
            PeerStorageError::Runtime(format!("Cannot stat directory '{canonical_abs}': {err}"))
        })?;
        if !meta.is_dir() {
            return Err(PeerStorageError::InvalidInput(format!(
                "Path '{canonical_abs}' is not a directory"
            )));
        }
        Ok((dir, meta.uid(), meta.gid()))
    }

    fn read_managed_file_checked(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        require_managed_header: bool,
    ) -> Result<Option<Vec<u8>>, PeerStorageError> {
        let name_os = OsStr::new(name);
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let mut file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerStorageError::Conflict(format!(
                    "Refusing unsafe or symlinked managed file '{name}': {err}"
                )));
            }
        };
        let meta = file.metadata().map_err(|err| {
            PeerStorageError::Runtime(format!("Cannot stat managed file '{name}': {err}"))
        })?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(PeerStorageError::Conflict(format!(
                "Refusing non-regular or hard-linked managed file '{name}'"
            )));
        }
        if let Some(uid) = self.expected_uid {
            if meta.uid() != uid {
                return Err(PeerStorageError::Conflict(format!(
                    "Refusing managed file '{name}' not owned by expected uid {uid}"
                )));
            }
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_MANAGED_FILE_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| {
                PeerStorageError::Runtime(format!("Failed reading managed file '{name}': {err}"))
            })?;
        if bytes.len() > MAX_MANAGED_FILE_BYTES {
            return Err(PeerStorageError::Conflict(format!(
                "Managed file '{name}' exceeds size limit"
            )));
        }
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Managed file identity verification failed for '{name}': {err}"
            ))
        })?;
        if require_managed_header && !managed_header_matches(&bytes) {
            return Err(PeerStorageError::Conflict(format!(
                "Refusing to modify unmanaged host file '{name}' (missing AetherFlow managed header)"
            )));
        }
        Ok(Some(bytes))
    }

    fn write_managed_file_atomic(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), PeerStorageError> {
        let name_os = OsStr::new(name);
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let previous = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(mut file) => {
                if let Some(uid) = self.expected_uid {
                    let meta = file.metadata().map_err(|err| {
                        PeerStorageError::Runtime(format!("Cannot stat existing '{name}': {err}"))
                    })?;
                    if meta.uid() != uid {
                        return Err(PeerStorageError::Conflict(format!(
                            "Refusing to overwrite '{name}' not owned by expected uid {uid}"
                        )));
                    }
                }
                let mut existing_prefix = Vec::new();
                Read::by_ref(&mut file)
                    .take((PEER_MANAGED_HEADER.len() as u64).saturating_add(16))
                    .read_to_end(&mut existing_prefix)
                    .map_err(|err| {
                        PeerStorageError::Runtime(format!(
                            "Failed reading existing '{name}' header: {err}"
                        ))
                    })?;
                if !managed_header_matches(&existing_prefix) {
                    return Err(PeerStorageError::Conflict(format!(
                        "Refusing to overwrite unmanaged host file '{name}' (missing AetherFlow managed header)"
                    )));
                }
                Some(file)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PeerStorageError::Conflict(format!(
                    "Refusing to overwrite non-regular or symlinked file '{name}': {err}"
                )));
            }
        };

        let tmp_name = format!(".af-peer-storage.tmp.{}", uuid::Uuid::new_v4().simple());
        let tmp_os = OsStr::new(&tmp_name);
        let mut tmp_file = dir
            .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Failed to create temporary file for '{name}': {err}"
                ))
            })?;
        let parent_fd = dir.file().as_raw_fd();
        let result = (|| -> std::io::Result<()> {
            tmp_file.write_all(bytes)?;
            enforce_root_ownership_and_mode(&tmp_file, mode)?;
            tmp_file.sync_all()?;
            dir.verify()?;
            verify_entry(dir.file(), tmp_os, &tmp_file, false)?;
            if let Some(prev) = previous.as_ref() {
                verify_entry(dir.file(), name_os, prev, false)?;
            } else {
                match entry_at(dir.file(), name_os) {
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    _ => {
                        return Err(std::io::Error::other(
                            "target file appeared concurrently during atomic write",
                        ));
                    }
                }
            }
            if unsafe {
                libc::renameat(
                    parent_fd,
                    c_name(tmp_os)?.as_ptr(),
                    parent_fd,
                    c_name(name_os)?.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            dir.verify()?;
            verify_entry(dir.file(), name_os, &tmp_file, false)?;
            dir.file().sync_all()
        })();
        if let Err(err) = result {
            if let Ok(tmp_c) = c_name(tmp_os) {
                unsafe {
                    libc::unlinkat(parent_fd, tmp_c.as_ptr(), 0);
                }
            }
            return Err(PeerStorageError::Runtime(format!(
                "Atomic write of '{name}' failed: {err}"
            )));
        }
        Ok(())
    }

    fn delete_managed_file_checked(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
    ) -> Result<Option<Vec<u8>>, PeerStorageError> {
        let Some(previous_bytes) = self.read_managed_file_checked(dir, name, true)? else {
            return Ok(None);
        };
        let name_os = OsStr::new(name);
        let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerStorageError::Conflict(format!(
                    "Refusing to remove unsafe or symlinked file '{name}': {err}"
                )));
            }
        };
        if let Some(uid) = self.expected_uid {
            let meta = file.metadata().map_err(|err| {
                PeerStorageError::Runtime(format!("Cannot stat '{name}' before deletion: {err}"))
            })?;
            if meta.uid() != uid {
                return Err(PeerStorageError::Conflict(format!(
                    "Refusing to remove '{name}' not owned by expected uid {uid}"
                )));
            }
        }
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerStorageError::Conflict(format!(
                "Refusing to remove non-regular file '{name}': {err}"
            ))
        })?;
        let name_c = c_name(name_os).map_err(|err| {
            PeerStorageError::Runtime(format!("Invalid filename '{name}': {err}"))
        })?;
        if unsafe { libc::unlinkat(dir.file().as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(PeerStorageError::Runtime(format!(
                "Failed deleting managed file '{name}': {err}"
            )));
        }
        let _ = dir.file().sync_all();
        Ok(Some(previous_bytes))
    }

    fn restore_managed_file_after_failure(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        previous: Option<&[u8]>,
        mode: u32,
    ) -> Result<(), PeerStorageError> {
        match previous {
            Some(bytes) => self.write_managed_file_atomic(dir, name, bytes, mode),
            None => self.delete_managed_file_checked(dir, name).map(|_| ()),
        }
    }

    async fn acquire_storage_write_locks(
        &self,
        create_state_dir: bool,
    ) -> Result<(OwnedRwLockWriteGuard<()>, Option<ConfinedLockGuard>), PeerStorageError> {
        const BUSY: &str = "Another peer storage operation is in progress; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_storage_lock_for(&self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.write_owned())
            .await
            .map_err(|_| PeerStorageError::Busy(BUSY.to_string()))?;

        let dir_opt = if create_state_dir {
            Some(self.ensure_system_dir(&self.state_dir, 0o750, 0o7027)?)
        } else {
            self.open_existing_system_dir(&self.state_dir, 0o7027)?
        };
        let Some(dir) = dir_opt else {
            return Ok((mem_guard, None));
        };
        let file_guard = self
            .open_and_lock_exclusive(dir, PEER_STORAGE_LOCK_FILE_NAME, deadline, BUSY)
            .await?;
        Ok((mem_guard, Some(file_guard)))
    }

    async fn acquire_storage_read_locks(
        &self,
    ) -> Result<(OwnedRwLockReadGuard<()>, Option<ConfinedLockGuard>), PeerStorageError> {
        const BUSY: &str = "Peer storage configuration is busy; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_storage_lock_for(&self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.read_owned())
            .await
            .map_err(|_| PeerStorageError::Busy(BUSY.to_string()))?;

        let Some(dir) = self.open_existing_system_dir(&self.state_dir, 0o7027)? else {
            return Ok((mem_guard, None));
        };
        let name_os = OsStr::new(PEER_STORAGE_LOCK_FILE_NAME);
        let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((mem_guard, None)),
            Err(err) => {
                return Err(PeerStorageError::Runtime(format!(
                    "Refusing unsafe peer storage lock {PEER_STORAGE_LOCK_FILE_NAME}: {err}"
                )));
            }
        };
        validate_lock_file_metadata(&file, PEER_STORAGE_LOCK_FILE_NAME, self.expected_uid)?;
        poll_flock_until(&file, libc::LOCK_SH, deadline, BUSY).await?;
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Peer storage lock directory verification failed: {err}"
            ))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Peer storage lock identity changed during acquisition: {err}"
            ))
        })?;
        Ok((mem_guard, Some(ConfinedLockGuard { _dir: dir, file })))
    }

    async fn open_and_lock_exclusive(
        &self,
        dir: ReceiptDirectory,
        lock_name: &str,
        deadline: Instant,
        busy_message: &str,
    ) -> Result<ConfinedLockGuard, PeerStorageError> {
        let name_os = OsStr::new(lock_name);
        let (file, created) = match dir.open_file(name_os, libc::O_RDWR, 0) {
            Ok(file) => (file, false),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match dir.open_file(name_os, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) {
                    Ok(file) => (file, true),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        let file = dir.open_file(name_os, libc::O_RDWR, 0).map_err(|e| {
                            PeerStorageError::Runtime(format!(
                                "Refusing unsafe peer storage lock {lock_name}: {e}"
                            ))
                        })?;
                        (file, false)
                    }
                    Err(err) => {
                        return Err(PeerStorageError::Runtime(format!(
                            "Failed creating peer storage lock {lock_name}: {err}"
                        )));
                    }
                }
            }
            Err(err) => {
                return Err(PeerStorageError::Runtime(format!(
                    "Refusing unsafe peer storage lock {lock_name}: {err}"
                )));
            }
        };
        if created {
            enforce_root_ownership_and_mode(&file, 0o600).map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Failed securing newly created peer storage lock {lock_name}: {err}"
                ))
            })?;
        }
        validate_lock_file_metadata(&file, lock_name, self.expected_uid)?;
        poll_flock_until(&file, libc::LOCK_EX, deadline, busy_message).await?;
        dir.verify().map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Peer storage lock directory verification failed: {err}"
            ))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Peer storage lock {lock_name} identity changed during acquisition: {err}"
            ))
        })?;
        validate_lock_file_metadata(&file, lock_name, self.expected_uid)?;
        Ok(ConfinedLockGuard { _dir: dir, file })
    }

    async fn output_with_timeout(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<CmdOutput, PeerStorageError> {
        let mut cmd = Command::new(self.program(program));
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let mut child = cmd.spawn().map_err(|err| {
            PeerStorageError::Runtime(format!(
                "{program} is unavailable; run ensure_packages to install NFS tools ({err})"
            ))
        })?;
        let pgid = child.id();
        let mut pg_guard = ProcessGroupKillGuard(pgid);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PeerStorageError::Runtime("Missing command stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PeerStorageError::Runtime("Missing command stderr".to_string()))?;

        let task = async {
            let (out_bytes, err_bytes) = tokio::try_join!(
                read_bounded(stdout, MAX_COMMAND_OUTPUT_BYTES),
                read_bounded(stderr, MAX_COMMAND_OUTPUT_BYTES),
            )?;
            let status = child.wait().await.map_err(|err| {
                PeerStorageError::Runtime(format!("Failed waiting for {program}: {err}"))
            })?;
            Ok::<CmdOutput, PeerStorageError>(CmdOutput {
                status,
                stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
                stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
            })
        };

        let result = match tokio::time::timeout(timeout, task).await {
            Ok(res) => res,
            Err(_) => {
                kill_process_group(pgid);
                let _ = child.start_kill();
                let _ = child.wait().await;
                pg_guard.disarm();
                return Err(PeerStorageError::Runtime(format!(
                    "{program} timed out after {}",
                    format_duration_human(timeout)
                )));
            }
        };

        if result.is_err() {
            kill_process_group(pgid);
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        pg_guard.disarm();
        result
    }

    async fn run_checked_with_timeout(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<String, PeerStorageError> {
        let out = self.output_with_timeout(program, args, timeout).await?;
        if !out.status.success() {
            let detail_raw = if !out.stderr.trim().is_empty() {
                out.stderr.trim()
            } else {
                out.stdout.trim()
            };
            let detail: String = redact_secrets(detail_raw).chars().take(512).collect();
            if detail.is_empty() {
                return Err(PeerStorageError::Runtime(format!(
                    "{program} failed ({})",
                    out.status
                )));
            }
            return Err(PeerStorageError::Runtime(format!(
                "{program} failed ({}): {detail}",
                out.status
            )));
        }
        Ok(out.stdout)
    }

    async fn unit_is_active(&self, unit: &str) -> String {
        match self
            .output_with_timeout(
                "systemctl",
                &strings(&["is-active", unit]),
                self.command_timeout,
            )
            .await
        {
            Ok(out) if !out.stdout.trim().is_empty() => out.stdout.trim().to_string(),
            _ => "unknown".to_string(),
        }
    }

    async fn run_package_command_with_timeout(
        runner: &TokioCommandRunner,
        program: &str,
        args: &[String],
        env_vars: &[(String, String)],
        timeout: Duration,
        label: &str,
    ) -> Result<CommandOutput, PeerStorageError> {
        let step_cancel = CancellationToken::new();
        let mut cmd_fut = runner.run_command(program, args, env_vars, &step_cancel);
        tokio::select! {
            res = &mut cmd_fut => {
                res.map_err(|err| PeerStorageError::Runtime(format!("{label} failed: {err}")))
            }
            _ = tokio::time::sleep(timeout) => {
                step_cancel.cancel();
                let _ = cmd_fut.await;
                Err(PeerStorageError::Runtime(format!(
                    "{label} timed out after {}",
                    format_duration_human(timeout)
                )))
            }
        }
    }

    async fn query_dpkg_installed_version(
        &self,
        runner: &TokioCommandRunner,
        pkg: &str,
    ) -> Result<Option<String>, PeerStorageError> {
        let dpkg_prog = self.program("dpkg-query").to_string_lossy().into_owned();
        let args = vec![
            "-W".to_string(),
            "-f=${db:Status-Status} ${Version}\n".to_string(),
            pkg.to_string(),
        ];
        let out = Self::run_package_command_with_timeout(
            runner,
            &dpkg_prog,
            &args,
            &[],
            self.command_timeout,
            &format!("dpkg-query for {pkg}"),
        )
        .await?;
        if !out.success() {
            return Ok(None);
        }
        Ok(
            af_release::lifecycle::parse_installed_dpkg_status_version(&out.stdout)
                .map(str::to_string),
        )
    }

    async fn query_all_storage_packages(
        &self,
        runner: &TokioCommandRunner,
    ) -> Result<(HashMap<String, String>, Vec<&'static str>), PeerStorageError> {
        let mut versions = HashMap::new();
        let mut missing = Vec::new();
        for pkg in PEER_STORAGE_PACKAGES {
            if let Some(version) = self.query_dpkg_installed_version(runner, pkg).await? {
                versions.insert(pkg.to_string(), version);
            } else {
                missing.push(pkg);
            }
        }
        Ok((versions, missing))
    }

    async fn acquire_package_locks_bounded(
        &self,
        env_cfg: &PackageExecutionEnv,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'static, ()>,
            CrossProcessLockGuard,
            af_release::ReleaseLockGuard,
        ),
        PeerStorageError,
    > {
        const BUSY: &str =
            "Package maintenance or another lifecycle operation is busy; retry shortly";
        let deadline = Instant::now() + self.package_lock_timeout;

        let pkg_mutex = tokio::time::timeout_at(deadline, crate::PACKAGE_MUTEX.lock())
            .await
            .map_err(|_| PeerStorageError::Busy(BUSY.to_string()))?;

        let flock_guard = loop {
            match CrossProcessLockGuard::try_acquire(env_cfg, "nfs-kernel-server") {
                Ok(guard) => break guard,
                Err(PackageExecutorError::LockConflict(_)) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(PeerStorageError::Busy(BUSY.to_string()));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(Duration::from_millis(25).min(remaining)).await;
                }
                Err(err) => {
                    return Err(PeerStorageError::Runtime(format!(
                        "Failed acquiring package cross-process lock: {err}"
                    )));
                }
            }
        };

        let maintenance_guard = loop {
            match crate::acquire_package_maintenance_guard(
                env_cfg.fs_root.as_deref(),
                af_release::lifecycle::ReservationTarget::System,
                "",
                None,
            )
            .await
            {
                Ok(guard) => break guard,
                Err(err)
                    if matches!(
                        err.downcast_ref::<af_release::ReleaseError>(),
                        Some(af_release::ReleaseError::LockBusy { .. })
                    ) =>
                {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(PeerStorageError::Busy(BUSY.to_string()));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(Duration::from_millis(25).min(remaining)).await;
                }
                Err(err) if crate::is_lifecycle_busy(&err) => {
                    return Err(PeerStorageError::Busy(redact_secrets(&err.to_string())));
                }
                Err(err) => {
                    return Err(PeerStorageError::Runtime(redact_secrets(&err.to_string())));
                }
            }
        };

        Ok((pkg_mutex, flock_guard, maintenance_guard))
    }

    /// Safely removes an empty leaf mountpoint directory `/mnt/af-peers/<link>/<export>` only if
    /// it exists as a regular directory on the same device (`st_dev`) as its parent (never while
    /// still mounted, never recursive, never following symlinks).
    fn remove_empty_mount_leaf(
        &self,
        link_seg: &str,
        export_seg: &str,
        also_prune_empty_link_dir: bool,
    ) -> Result<bool, PeerStorageError> {
        let Some(mounts_root_dir) = self.open_existing_system_dir(&self.mounts_root, 0o6022)?
        else {
            return Ok(false);
        };
        let link_dir_path = self.mounts_root.join(link_seg);
        let Some(link_dir) = self.open_existing_system_dir(&link_dir_path, 0o6022)? else {
            return Ok(false);
        };
        let parent_meta = link_dir.file().metadata().map_err(|err| {
            PeerStorageError::Runtime(format!(
                "Cannot stat mount parent {}: {err}",
                link_dir_path.display()
            ))
        })?;
        let leaf_os = OsStr::new(export_seg);
        let removed = match entry_at(link_dir.file(), leaf_os) {
            Ok(stat) => {
                if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    return Err(PeerStorageError::Conflict(format!(
                        "Refusing non-directory entry at peer mountpoint '{DEFAULT_PEER_MOUNTS_ROOT}/{link_seg}/{export_seg}'"
                    )));
                }
                if stat.st_dev != parent_meta.dev() {
                    // Still mounted on a different filesystem; refuse to touch it.
                    false
                } else {
                    let leaf_c = c_name(leaf_os).map_err(|err| {
                        PeerStorageError::Runtime(format!("Invalid mountpoint name: {err}"))
                    })?;
                    if unsafe {
                        libc::unlinkat(
                            link_dir.file().as_raw_fd(),
                            leaf_c.as_ptr(),
                            libc::AT_REMOVEDIR,
                        )
                    } == 0
                    {
                        let _ = link_dir.file().sync_all();
                        true
                    } else {
                        let err = std::io::Error::last_os_error();
                        match err.raw_os_error() {
                            Some(libc::ENOENT | libc::ENOTEMPTY | libc::EEXIST | libc::EBUSY) => {
                                false
                            }
                            _ => {
                                return Err(PeerStorageError::Runtime(format!(
                                    "Failed removing empty mountpoint directory: {err}"
                                )));
                            }
                        }
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(PeerStorageError::Runtime(format!(
                    "Cannot stat mountpoint directory: {err}"
                )));
            }
        };

        drop(link_dir);
        if also_prune_empty_link_dir {
            let link_os = OsStr::new(link_seg);
            if let Ok(link_c) = c_name(link_os) {
                let _ = unsafe {
                    libc::unlinkat(
                        mounts_root_dir.file().as_raw_fd(),
                        link_c.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
            }
        }
        Ok(removed)
    }

    fn verify_mount_leaf_not_symlink(
        &self,
        link_seg: &str,
        export_seg: &str,
    ) -> Result<(), PeerStorageError> {
        let Some(_) = self.open_existing_system_dir(&self.mounts_root, 0o6022)? else {
            return Ok(());
        };
        let link_dir_path = self.mounts_root.join(link_seg);
        let Some(link_dir) = self.open_existing_system_dir(&link_dir_path, 0o6022)? else {
            return Ok(());
        };
        match entry_at(link_dir.file(), OsStr::new(export_seg)) {
            Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFDIR => Ok(()),
            Ok(_) => Err(PeerStorageError::Conflict(format!(
                "Refusing unsafe non-directory or symlink mountpoint '{DEFAULT_PEER_MOUNTS_ROOT}/{link_seg}/{export_seg}'"
            ))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(PeerStorageError::Runtime(format!(
                "Cannot stat peer mountpoint '{DEFAULT_PEER_MOUNTS_ROOT}/{link_seg}/{export_seg}': {err}"
            ))),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Ensures `nfs-kernel-server` and `nfs-common` are installed using the runner's existing
    /// Marketplace apt serialization and `ReservationTarget::System` lease.
    pub async fn ensure_packages(&self) -> Result<PeerStoragePackagesResponse, PeerStorageError> {
        let runner = TokioCommandRunner {
            respect_dry_run_env: self.bin.is_none(),
        };

        let (versions, missing) = self.query_all_storage_packages(&runner).await?;
        if missing.is_empty() {
            return Ok(PeerStoragePackagesResponse {
                installed: true,
                already_installed: true,
                packages: PEER_STORAGE_PACKAGES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
                versions,
            });
        }

        let env_cfg = match &self.fs_root {
            Some(root) => PackageExecutionEnv::isolated(root),
            None => PackageExecutionEnv::default(),
        };

        let (_pkg_mutex, _flock_guard, maintenance_guard) =
            self.acquire_package_locks_bounded(&env_cfg).await?;
        let maintenance_lease = Arc::new(maintenance_guard);

        // Re-check after acquiring package locks.
        let (versions, missing) = self.query_all_storage_packages(&runner).await?;
        if missing.is_empty() {
            return Ok(PeerStoragePackagesResponse {
                installed: true,
                already_installed: true,
                packages: PEER_STORAGE_PACKAGES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
                versions,
            });
        }

        let apt_prog = self.program("apt-get").to_string_lossy().into_owned();
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];

        let update_args = strings(&["-o", "DPkg::Lock::Timeout=120", "update", "-y", "-qq"]);
        let mut install_args = strings(&[
            "-o",
            "DPkg::Lock::Timeout=120",
            "-o",
            "DPkg::Options::=--force-confdef",
            "-o",
            "DPkg::Options::=--force-confold",
            "install",
            "-y",
            "-qq",
        ]);
        for pkg in &missing {
            install_args.push((*pkg).to_string());
        }

        let apt_timeout = self.apt_timeout;
        let missing_label = missing.join(" ");
        let run_apt = async {
            let update_out = Self::run_package_command_with_timeout(
                &runner,
                &apt_prog,
                &update_args,
                &apt_env,
                apt_timeout,
                "apt-get update",
            )
            .await?;
            if !update_out.success() {
                return Err(PeerStorageError::Runtime(format!(
                    "apt-get update exited with {}: {}",
                    update_out.exit_code,
                    redact_secrets(&update_out.combined_output())
                )));
            }

            let install_out = Self::run_package_command_with_timeout(
                &runner,
                &apt_prog,
                &install_args,
                &apt_env,
                apt_timeout,
                "apt-get install",
            )
            .await?;
            if !install_out.success() {
                return Err(PeerStorageError::Runtime(format!(
                    "apt-get install {missing_label} exited with {}: {}",
                    install_out.exit_code,
                    redact_secrets(&install_out.combined_output())
                )));
            }
            Ok(())
        };

        let apt_result = crate::PACKAGE_MAINTENANCE_LEASE
            .scope(Arc::clone(&maintenance_lease), run_apt)
            .await;
        apt_result?;

        let (versions, still_missing) = self.query_all_storage_packages(&runner).await?;
        if !still_missing.is_empty() {
            return Err(PeerStorageError::Runtime(format!(
                "{} did not report as installed after apt-get install",
                still_missing.join(", ")
            )));
        }

        drop(maintenance_lease);

        Ok(PeerStoragePackagesResponse {
            installed: true,
            already_installed: false,
            packages: PEER_STORAGE_PACKAGES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            versions,
        })
    }

    /// Binds `nfsd` exclusively to `tunnel_ip` via `/etc/nfs.conf.d/aetherflow-peers.conf` and
    /// restarts `nfs-server.service`. Never touches `/etc/nfs.conf` or unrelated drop-ins.
    pub async fn configure_nfsd(
        &self,
        tunnel_ip: &str,
    ) -> Result<PeerNfsdConfigResponse, PeerStorageError> {
        let valid_ip = validate_tunnel_ip(tunnel_ip, &self.tunnel_cidr)?;
        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(true).await?;

        let conf_dir = self.ensure_system_dir(&self.nfs_conf_dir, 0o755, 0o6022)?;
        let previous = self.read_managed_file_checked(&conf_dir, PEER_NFSD_CONF_NAME, true)?;
        let rendered = render_nfsd_conf(valid_ip);
        let config_path = format!("{DEFAULT_PEER_NFS_CONF_DIR}/{PEER_NFSD_CONF_NAME}");

        let before_state = self.unit_is_active(PEER_NFSD_SERVICE_UNIT).await;
        let unchanged = previous
            .as_deref()
            .is_some_and(|prev| prev == rendered.as_bytes());
        if unchanged && before_state == "active" {
            return Ok(PeerNfsdConfigResponse {
                config_path,
                tunnel_ip: valid_ip.to_string(),
                service_unit: PEER_NFSD_SERVICE_UNIT.to_string(),
                service_state: before_state,
                changed: false,
            });
        }

        if !unchanged {
            self.write_managed_file_atomic(
                &conf_dir,
                PEER_NFSD_CONF_NAME,
                rendered.as_bytes(),
                0o644,
            )?;
        }

        let apply_res = async {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["enable", PEER_NFSD_SERVICE_UNIT]),
                    self.command_timeout,
                )
                .await?;
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["restart", PEER_NFSD_SERVICE_UNIT]),
                    self.mount_command_timeout,
                )
                .await?;
            Ok::<(), PeerStorageError>(())
        }
        .await;

        if let Err(apply_err) = apply_res {
            if !unchanged {
                let rollback_res = self.restore_managed_file_after_failure(
                    &conf_dir,
                    PEER_NFSD_CONF_NAME,
                    previous.as_deref(),
                    0o644,
                );
                if before_state == "active" && previous.is_some() && rollback_res.is_ok() {
                    let _ = self
                        .output_with_timeout(
                            "systemctl",
                            &strings(&["restart", PEER_NFSD_SERVICE_UNIT]),
                            self.mount_command_timeout,
                        )
                        .await;
                }
                if let Err(rb_err) = rollback_res {
                    return Err(PeerStorageError::Runtime(format!(
                        "Failed restarting {PEER_NFSD_SERVICE_UNIT} and rollback of {config_path} failed ({apply_err}; rollback: {rb_err})"
                    )));
                }
                return Err(PeerStorageError::Runtime(format!(
                    "Failed restarting {PEER_NFSD_SERVICE_UNIT}; previous {config_path} was restored ({apply_err})"
                )));
            }
            return Err(apply_err);
        }

        let service_state = self.unit_is_active(PEER_NFSD_SERVICE_UNIT).await;
        Ok(PeerNfsdConfigResponse {
            config_path,
            tunnel_ip: valid_ip.to_string(),
            service_unit: PEER_NFSD_SERVICE_UNIT.to_string(),
            service_state,
            changed: !unchanged || before_state != "active",
        })
    }

    /// Writes `/etc/exports.d/aetherflow-peer-<link>.exports` restricted to `tunnel_ip` and runs
    /// `exportfs -ra`. When `exports` is empty, removes the managed file (if present) and runs
    /// `exportfs -ra`.
    pub async fn write_exports(
        &self,
        link: &str,
        tunnel_ip: &str,
        exports: &[PeerStorageExportSpec],
    ) -> Result<PeerExportsWriteResponse, PeerStorageError> {
        let valid_link = validate_peer_storage_link_id(link)?;
        let valid_ip = validate_tunnel_ip(tunnel_ip, &self.tunnel_cidr)?;
        let validated_exports = validate_export_specs(exports)?;

        let (_mem_guard, _file_lock) = self
            .acquire_storage_write_locks(!validated_exports.is_empty())
            .await?;

        let file_name = derive_peer_export_file_name(valid_link)?;
        let exports_path = format!("{DEFAULT_PEER_EXPORTS_DIR}/{file_name}");

        if validated_exports.is_empty() {
            return self
                .remove_exports_locked(valid_link, &file_name, &exports_path, Some(valid_ip))
                .await;
        }

        // Verify every exported directory exists locally with zero symlink traversal.
        for spec in &validated_exports {
            let _ = self.open_verified_local_directory(&spec.path)?;
        }

        let exports_dir = self.ensure_system_dir(&self.exports_dir, 0o755, 0o6022)?;
        let previous = self.read_managed_file_checked(&exports_dir, &file_name, true)?;
        let rendered = render_exports_file(valid_ip, &validated_exports);
        let unchanged = previous
            .as_deref()
            .is_some_and(|prev| prev == rendered.as_bytes());

        if !unchanged {
            self.write_managed_file_atomic(&exports_dir, &file_name, rendered.as_bytes(), 0o644)?;
        }

        if let Err(exportfs_err) = self
            .run_checked_with_timeout("exportfs", &strings(&["-ra"]), self.command_timeout)
            .await
        {
            if !unchanged {
                let rollback_res = self.restore_managed_file_after_failure(
                    &exports_dir,
                    &file_name,
                    previous.as_deref(),
                    0o644,
                );
                if rollback_res.is_ok() {
                    let _ = self
                        .output_with_timeout("exportfs", &strings(&["-ra"]), self.command_timeout)
                        .await;
                }
                if let Err(rb_err) = rollback_res {
                    return Err(PeerStorageError::Runtime(format!(
                        "exportfs -ra failed and rollback of {exports_path} failed ({exportfs_err}; rollback: {rb_err})"
                    )));
                }
                return Err(PeerStorageError::Runtime(format!(
                    "exportfs -ra failed; previous {exports_path} was restored ({exportfs_err})"
                )));
            }
            return Err(exportfs_err);
        }

        Ok(PeerExportsWriteResponse {
            link: valid_link.to_string(),
            exports_path,
            tunnel_ip: Some(valid_ip.to_string()),
            export_count: validated_exports.len(),
            changed: !unchanged,
            removed: false,
        })
    }

    /// Removes `/etc/exports.d/aetherflow-peer-<link>.exports` if present and refreshes kernel
    /// exports via `exportfs -ra`. Idempotent when the file does not exist.
    pub async fn remove_exports(
        &self,
        link: &str,
    ) -> Result<PeerExportsWriteResponse, PeerStorageError> {
        let valid_link = validate_peer_storage_link_id(link)?;
        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(false).await?;
        let file_name = derive_peer_export_file_name(valid_link)?;
        let exports_path = format!("{DEFAULT_PEER_EXPORTS_DIR}/{file_name}");
        self.remove_exports_locked(valid_link, &file_name, &exports_path, None)
            .await
    }

    async fn remove_exports_locked(
        &self,
        valid_link: &str,
        file_name: &str,
        exports_path: &str,
        tunnel_ip: Option<IpAddr>,
    ) -> Result<PeerExportsWriteResponse, PeerStorageError> {
        let Some(exports_dir) = self.open_existing_system_dir(&self.exports_dir, 0o6022)? else {
            return Ok(PeerExportsWriteResponse {
                link: valid_link.to_string(),
                exports_path: exports_path.to_string(),
                tunnel_ip: tunnel_ip.map(|ip| ip.to_string()),
                export_count: 0,
                changed: false,
                removed: false,
            });
        };
        let Some(previous) = self.delete_managed_file_checked(&exports_dir, file_name)? else {
            return Ok(PeerExportsWriteResponse {
                link: valid_link.to_string(),
                exports_path: exports_path.to_string(),
                tunnel_ip: tunnel_ip.map(|ip| ip.to_string()),
                export_count: 0,
                changed: false,
                removed: false,
            });
        };

        if let Err(exportfs_err) = self
            .run_checked_with_timeout("exportfs", &strings(&["-ra"]), self.command_timeout)
            .await
        {
            if let Err(rb_err) =
                self.write_managed_file_atomic(&exports_dir, file_name, &previous, 0o644)
            {
                return Err(PeerStorageError::Runtime(format!(
                    "exportfs -ra failed after removing {exports_path} and rollback failed ({exportfs_err}; rollback: {rb_err})"
                )));
            }
            let _ = self
                .output_with_timeout("exportfs", &strings(&["-ra"]), self.command_timeout)
                .await;
            return Err(PeerStorageError::Runtime(format!(
                "exportfs -ra failed after removing {exports_path}; previous exports file was restored ({exportfs_err})"
            )));
        }

        Ok(PeerExportsWriteResponse {
            link: valid_link.to_string(),
            exports_path: exports_path.to_string(),
            tunnel_ip: tunnel_ip.map(|ip| ip.to_string()),
            export_count: 0,
            changed: true,
            removed: true,
        })
    }

    /// Validates that `path` is a real non-symlinked directory, ensures `.af-peer-sentinel`
    /// exists (0644), and returns its authoritative `(owner_uid, owner_gid)`.
    pub async fn ensure_sentinel(
        &self,
        path: &str,
        require_non_root_owner: bool,
    ) -> Result<PeerSentinelResponse, PeerStorageError> {
        let canonical = validate_export_path_syntax(path)?;
        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(true).await?;
        let (dir, owner_uid, owner_gid) = self.open_verified_local_directory(&canonical)?;
        validate_sentinel_owner(&canonical, owner_uid, owner_gid, require_non_root_owner)?;

        let sentinel_os = OsStr::new(PEER_SENTINEL_FILE_NAME);
        let sentinel_path = format!("{canonical}/{PEER_SENTINEL_FILE_NAME}");
        match dir.open_file(sentinel_os, libc::O_RDONLY, 0) {
            Ok(mut existing) => {
                let meta = existing.metadata().map_err(|err| {
                    PeerStorageError::Runtime(format!(
                        "Cannot stat existing sentinel '{sentinel_path}': {err}"
                    ))
                })?;
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(PeerStorageError::Conflict(format!(
                        "Refusing non-regular or hard-linked sentinel '{sentinel_path}'"
                    )));
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut existing)
                    .take((MAX_SENTINEL_BYTES as u64).saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|err| {
                        PeerStorageError::Runtime(format!(
                            "Failed reading existing sentinel '{sentinel_path}': {err}"
                        ))
                    })?;
                if bytes.len() > MAX_SENTINEL_BYTES {
                    return Err(PeerStorageError::Conflict(format!(
                        "Existing sentinel '{sentinel_path}' exceeds size limit"
                    )));
                }
                verify_entry(dir.file(), sentinel_os, &existing, false).map_err(|err| {
                    PeerStorageError::Runtime(format!(
                        "Sentinel identity changed during verification for '{sentinel_path}': {err}"
                    ))
                })?;
                if !bytes.is_empty() && !managed_header_matches(&bytes) {
                    return Err(PeerStorageError::Conflict(format!(
                        "Refusing to adopt unmanaged file at '{sentinel_path}'"
                    )));
                }
                Ok(PeerSentinelResponse {
                    path: canonical,
                    sentinel_path,
                    created: false,
                    owner_uid,
                    owner_gid,
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let payload = format!("{PEER_MANAGED_HEADER}\n");
                let tmp_name = format!(
                    ".{PEER_SENTINEL_FILE_NAME}.tmp.{}",
                    uuid::Uuid::new_v4().simple()
                );
                let tmp_os = OsStr::new(&tmp_name);
                let mut tmp = dir
                    .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o644)
                    .map_err(|e| {
                        PeerStorageError::Runtime(format!(
                            "Failed creating temporary sentinel in '{canonical}': {e}"
                        ))
                    })?;
                let parent_fd = dir.file().as_raw_fd();
                let write_res = (|| -> std::io::Result<()> {
                    tmp.write_all(payload.as_bytes())?;
                    enforce_root_ownership_and_mode(&tmp, 0o644)?;
                    tmp.sync_all()?;
                    dir.verify()?;
                    verify_entry(dir.file(), tmp_os, &tmp, false)?;
                    match entry_at(dir.file(), sentinel_os) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        _ => {
                            return Err(std::io::Error::other(
                                "sentinel appeared concurrently during creation",
                            ));
                        }
                    }
                    if unsafe {
                        libc::renameat(
                            parent_fd,
                            c_name(tmp_os)?.as_ptr(),
                            parent_fd,
                            c_name(sentinel_os)?.as_ptr(),
                        )
                    } != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    dir.verify()?;
                    verify_entry(dir.file(), sentinel_os, &tmp, false)?;
                    dir.file().sync_all()
                })();
                if let Err(e) = write_res {
                    if let Ok(tmp_c) = c_name(tmp_os) {
                        unsafe {
                            libc::unlinkat(parent_fd, tmp_c.as_ptr(), 0);
                        }
                    }
                    return Err(PeerStorageError::Runtime(format!(
                        "Failed writing sentinel '{sentinel_path}': {e}"
                    )));
                }
                Ok(PeerSentinelResponse {
                    path: canonical,
                    sentinel_path,
                    created: true,
                    owner_uid,
                    owner_gid,
                })
            }
            Err(err) => Err(PeerStorageError::InvalidInput(format!(
                "Refusing unsafe sentinel entry '{sentinel_path}': {err}"
            ))),
        }
    }

    /// Probes `<mount_path>/.af-peer-sentinel` without acquiring mutation locks so a hung NFS
    /// mount never blocks `StopMount`.
    pub async fn probe_sentinel(
        &self,
        mount_path: &str,
        timeout_ms: Option<u64>,
    ) -> Result<PeerSentinelProbeResponse, PeerStorageError> {
        let _ = validate_peer_mount_path(mount_path)?;
        let effective_ms = timeout_ms.unwrap_or(DEFAULT_SENTINEL_PROBE_TIMEOUT_MS);
        if !(MIN_SENTINEL_PROBE_TIMEOUT_MS..=MAX_SENTINEL_PROBE_TIMEOUT_MS).contains(&effective_ms)
        {
            return Err(PeerStorageError::InvalidInput(format!(
                "Sentinel probe timeout_ms must be between {MIN_SENTINEL_PROBE_TIMEOUT_MS} and {MAX_SENTINEL_PROBE_TIMEOUT_MS}"
            )));
        }
        let resolved = self.resolve_host_path(mount_path);
        Ok(probe_sentinel_file_for_display(
            &resolved,
            mount_path,
            Duration::from_millis(effective_ms),
        )
        .await)
    }

    /// Writes a constrained systemd NFSv4.2 `.mount` unit for `/mnt/af-peers/<link>/<export>` and
    /// runs `systemctl daemon-reload`.
    pub async fn write_mount(
        &self,
        mount_path: &str,
        tunnel_ip: &str,
        remote_path: &str,
        writable: bool,
    ) -> Result<PeerMountWriteResponse, PeerStorageError> {
        let (link_seg, export_seg) = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;
        let valid_ip = validate_tunnel_ip(tunnel_ip, &self.tunnel_cidr)?;
        let valid_remote_path = validate_export_path_syntax(remote_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(true).await?;
        let systemd_dir = self.ensure_system_dir(&self.systemd_dir, 0o755, 0o6022)?;
        let _ = self.ensure_system_dir(&self.mounts_root, 0o755, 0o6022)?;
        let _ = self.ensure_system_dir(&self.mounts_root.join(&link_seg), 0o755, 0o6022)?;
        self.verify_mount_leaf_not_symlink(&link_seg, &export_seg)?;

        let (what, options, rendered) =
            render_nfs_mount_unit(mount_path, valid_ip, &valid_remote_path, writable);
        let changed = self
            .write_mount_unit_with_reload(&systemd_dir, &unit_name, rendered.as_bytes())
            .await?;

        Ok(PeerMountWriteResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            what,
            fs_type: "nfs4".to_string(),
            options,
            writable,
            changed,
        })
    }

    /// Writes a constrained systemd bind `.mount` unit mapping local `source_path` onto
    /// `/mnt/af-peers/<link>/<export>` (used in P9) and runs `systemctl daemon-reload`.
    pub async fn write_bind_mount(
        &self,
        source_path: &str,
        mount_path: &str,
        writable: bool,
    ) -> Result<PeerMountWriteResponse, PeerStorageError> {
        let valid_source = validate_export_path_syntax(source_path)?;
        let (link_seg, export_seg) = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(true).await?;
        let _ = self.open_verified_local_directory(&valid_source)?;
        let systemd_dir = self.ensure_system_dir(&self.systemd_dir, 0o755, 0o6022)?;
        let _ = self.ensure_system_dir(&self.mounts_root, 0o755, 0o6022)?;
        let _ = self.ensure_system_dir(&self.mounts_root.join(&link_seg), 0o755, 0o6022)?;
        self.verify_mount_leaf_not_symlink(&link_seg, &export_seg)?;

        let (options, rendered) = render_bind_mount_unit(&valid_source, mount_path, writable);
        let changed = self
            .write_mount_unit_with_reload(&systemd_dir, &unit_name, rendered.as_bytes())
            .await?;

        Ok(PeerMountWriteResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            what: valid_source,
            fs_type: "none".to_string(),
            options,
            writable,
            changed,
        })
    }

    async fn write_mount_unit_with_reload(
        &self,
        systemd_dir: &ReceiptDirectory,
        unit_name: &str,
        rendered_bytes: &[u8],
    ) -> Result<bool, PeerStorageError> {
        let previous = self.read_managed_file_checked(systemd_dir, unit_name, true)?;
        let unchanged = previous
            .as_deref()
            .is_some_and(|prev| prev == rendered_bytes);
        if unchanged {
            return Ok(false);
        }

        self.write_managed_file_atomic(systemd_dir, unit_name, rendered_bytes, 0o644)?;
        if let Err(reload_err) = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["daemon-reload"]),
                self.command_timeout,
            )
            .await
        {
            let rollback_res = self.restore_managed_file_after_failure(
                systemd_dir,
                unit_name,
                previous.as_deref(),
                0o644,
            );
            if rollback_res.is_ok() {
                let _ = self
                    .output_with_timeout(
                        "systemctl",
                        &strings(&["daemon-reload"]),
                        self.command_timeout,
                    )
                    .await;
            }
            if let Err(rb_err) = rollback_res {
                return Err(PeerStorageError::Runtime(format!(
                    "systemctl daemon-reload failed for {unit_name} and rollback failed ({reload_err}; rollback: {rb_err})"
                )));
            }
            return Err(PeerStorageError::Runtime(format!(
                "systemctl daemon-reload failed for {unit_name}; previous unit state was restored ({reload_err})"
            )));
        }
        Ok(true)
    }

    /// Starts the managed `.mount` unit derived from `mount_path`.
    pub async fn start_mount(
        &self,
        mount_path: &str,
    ) -> Result<PeerMountStateResponse, PeerStorageError> {
        let (link_seg, export_seg) = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(true).await?;
        let Some(systemd_dir) = self.open_existing_system_dir(&self.systemd_dir, 0o6022)? else {
            return Err(PeerStorageError::NotFound(format!(
                "Managed peer mount unit '{unit_name}' does not exist"
            )));
        };
        if self
            .read_managed_file_checked(&systemd_dir, &unit_name, true)?
            .is_none()
        {
            return Err(PeerStorageError::NotFound(format!(
                "Managed peer mount unit '{unit_name}' does not exist"
            )));
        }
        let _ = self.ensure_system_dir(&self.mounts_root, 0o755, 0o6022)?;
        let _ = self.ensure_system_dir(&self.mounts_root.join(&link_seg), 0o755, 0o6022)?;
        self.verify_mount_leaf_not_symlink(&link_seg, &export_seg)?;

        let _ = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["start", &unit_name]),
                self.mount_command_timeout,
            )
            .await?;

        let unit_state = self.unit_is_active(&unit_name).await;
        Ok(PeerMountStateResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            exists: true,
            active: unit_state == "active",
            unit_state,
        })
    }

    /// Stops the managed `.mount` unit derived from `mount_path` and removes the empty leaf
    /// mountpoint directory when unmounted so media libraries never scan an empty root folder.
    pub async fn stop_mount(
        &self,
        mount_path: &str,
    ) -> Result<PeerMountStateResponse, PeerStorageError> {
        let (link_seg, export_seg) = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(false).await?;
        let exists = match self.open_existing_system_dir(&self.systemd_dir, 0o6022)? {
            Some(systemd_dir) => self
                .read_managed_file_checked(&systemd_dir, &unit_name, true)?
                .is_some(),
            None => false,
        };
        if !exists {
            let _ = self.remove_empty_mount_leaf(&link_seg, &export_seg, false)?;
            return Ok(PeerMountStateResponse {
                unit_name,
                mount_path: mount_path.to_string(),
                exists: false,
                active: false,
                unit_state: "not-found".to_string(),
            });
        }

        let _ = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["stop", &unit_name]),
                self.mount_command_timeout,
            )
            .await?;
        let _ = self.remove_empty_mount_leaf(&link_seg, &export_seg, false)?;
        let unit_state = self.unit_is_active(&unit_name).await;

        Ok(PeerMountStateResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            exists: true,
            active: unit_state == "active",
            unit_state,
        })
    }

    /// Stops, disables, and removes the managed `.mount` unit for `mount_path`, runs
    /// `systemctl daemon-reload`, and removes empty mountpoint directories.
    pub async fn remove_mount(
        &self,
        mount_path: &str,
    ) -> Result<PeerMountRemoveResponse, PeerStorageError> {
        let (link_seg, export_seg) = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_write_locks(false).await?;
        let Some(systemd_dir) = self.open_existing_system_dir(&self.systemd_dir, 0o6022)? else {
            let mount_dir_removed = self.remove_empty_mount_leaf(&link_seg, &export_seg, true)?;
            return Ok(PeerMountRemoveResponse {
                unit_name,
                mount_path: mount_path.to_string(),
                removed: false,
                stopped: false,
                mount_dir_removed,
            });
        };
        if self
            .read_managed_file_checked(&systemd_dir, &unit_name, true)?
            .is_none()
        {
            let mount_dir_removed = self.remove_empty_mount_leaf(&link_seg, &export_seg, true)?;
            return Ok(PeerMountRemoveResponse {
                unit_name,
                mount_path: mount_path.to_string(),
                removed: false,
                stopped: false,
                mount_dir_removed,
            });
        }

        // Stop before unlinking the unit so an active mount is never orphaned.
        let _ = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["stop", &unit_name]),
                self.mount_command_timeout,
            )
            .await?;
        let _ = self
            .output_with_timeout(
                "systemctl",
                &strings(&["disable", &unit_name]),
                self.command_timeout,
            )
            .await;

        let Some(previous) = self.delete_managed_file_checked(&systemd_dir, &unit_name)? else {
            let mount_dir_removed = self.remove_empty_mount_leaf(&link_seg, &export_seg, true)?;
            return Ok(PeerMountRemoveResponse {
                unit_name,
                mount_path: mount_path.to_string(),
                removed: false,
                stopped: true,
                mount_dir_removed,
            });
        };

        if let Err(reload_err) = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["daemon-reload"]),
                self.command_timeout,
            )
            .await
        {
            if let Err(rb_err) =
                self.write_managed_file_atomic(&systemd_dir, &unit_name, &previous, 0o644)
            {
                return Err(PeerStorageError::Runtime(format!(
                    "systemctl daemon-reload failed after removing {unit_name} and rollback failed ({reload_err}; rollback: {rb_err})"
                )));
            }
            let _ = self
                .output_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.command_timeout,
                )
                .await;
            return Err(PeerStorageError::Runtime(format!(
                "systemctl daemon-reload failed after removing {unit_name}; unit file was restored ({reload_err})"
            )));
        }

        let _ = self
            .output_with_timeout(
                "systemctl",
                &strings(&["reset-failed", &unit_name]),
                self.command_timeout,
            )
            .await;
        let mount_dir_removed = self.remove_empty_mount_leaf(&link_seg, &export_seg, true)?;

        Ok(PeerMountRemoveResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            removed: true,
            stopped: true,
            mount_dir_removed,
        })
    }

    /// Queries managed `.mount` unit existence and active state.
    pub async fn mount_status(
        &self,
        mount_path: &str,
    ) -> Result<PeerMountStateResponse, PeerStorageError> {
        let _ = validate_peer_mount_path(mount_path)?;
        let unit_name = systemd_escape_mount_unit(mount_path)?;

        let (_mem_guard, _file_lock) = self.acquire_storage_read_locks().await?;
        let exists = match self.open_existing_system_dir(&self.systemd_dir, 0o6022)? {
            Some(systemd_dir) => self
                .read_managed_file_checked(&systemd_dir, &unit_name, true)?
                .is_some(),
            None => false,
        };
        if !exists {
            return Ok(PeerMountStateResponse {
                unit_name,
                mount_path: mount_path.to_string(),
                exists: false,
                active: false,
                unit_state: "not-found".to_string(),
            });
        }
        let unit_state = self.unit_is_active(&unit_name).await;
        Ok(PeerMountStateResponse {
            unit_name,
            mount_path: mount_path.to_string(),
            exists: true,
            active: unit_state == "active",
            unit_state,
        })
    }

    pub async fn execute(
        &self,
        req: &PeerStorageRequest,
    ) -> Result<PeerStorageResponse, PeerStorageError> {
        match req {
            PeerStorageRequest::EnsurePackages => {
                Ok(PeerStorageResponse::Packages(self.ensure_packages().await?))
            }
            PeerStorageRequest::ConfigureNfsd { tunnel_ip } => Ok(
                PeerStorageResponse::NfsdConfigured(self.configure_nfsd(tunnel_ip).await?),
            ),
            PeerStorageRequest::WriteExports {
                link,
                tunnel_ip,
                exports,
            } => Ok(PeerStorageResponse::ExportsWritten(
                self.write_exports(link, tunnel_ip, exports).await?,
            )),
            PeerStorageRequest::RemoveExports { link } => Ok(PeerStorageResponse::ExportsWritten(
                self.remove_exports(link).await?,
            )),
            PeerStorageRequest::EnsureSentinel {
                path,
                require_non_root_owner,
            } => Ok(PeerStorageResponse::SentinelEnsured(
                self.ensure_sentinel(path, *require_non_root_owner).await?,
            )),
            PeerStorageRequest::ProbeSentinel {
                mount_path,
                timeout_ms,
            } => Ok(PeerStorageResponse::SentinelProbed(
                self.probe_sentinel(mount_path, *timeout_ms).await?,
            )),
            PeerStorageRequest::WriteMount {
                mount_path,
                tunnel_ip,
                remote_path,
                writable,
            } => Ok(PeerStorageResponse::MountWritten(
                self.write_mount(mount_path, tunnel_ip, remote_path, *writable)
                    .await?,
            )),
            PeerStorageRequest::WriteBindMount {
                source_path,
                mount_path,
                writable,
            } => Ok(PeerStorageResponse::MountWritten(
                self.write_bind_mount(source_path, mount_path, *writable)
                    .await?,
            )),
            PeerStorageRequest::RemoveMount { mount_path } => Ok(
                PeerStorageResponse::MountRemoved(self.remove_mount(mount_path).await?),
            ),
            PeerStorageRequest::StartMount { mount_path } => Ok(PeerStorageResponse::MountState(
                self.start_mount(mount_path).await?,
            )),
            PeerStorageRequest::StopMount { mount_path } => Ok(PeerStorageResponse::MountState(
                self.stop_mount(mount_path).await?,
            )),
            PeerStorageRequest::MountStatus { mount_path } => Ok(PeerStorageResponse::MountState(
                self.mount_status(mount_path).await?,
            )),
        }
    }
}

pub async fn execute_peer_storage_local(
    req: &PeerStorageRequest,
) -> Result<PeerStorageResponse, PeerStorageError> {
    let manager = PeerStorageManager::from_env()?;
    manager.execute(req).await
}

pub(crate) async fn handle_peer_storage(
    manager_ext: Option<Extension<Arc<PeerStorageManager>>>,
    payload: Result<Json<PeerStorageRequest>, JsonRejection>,
) -> Response {
    let req = match payload {
        Ok(Json(req)) => req,
        Err(_) => {
            return PeerStorageError::InvalidInput(
                "Invalid peer-storage request payload".to_string(),
            )
            .into_http_response();
        }
    };
    let manager = match manager_ext {
        Some(Extension(mgr)) => mgr,
        None => match PeerStorageManager::from_env() {
            Ok(mgr) => Arc::new(mgr),
            Err(err) => return err.into_http_response(),
        },
    };
    // Run mutating operations in a detached Tokio task so caller disconnect cannot abort an
    // in-flight write, exportfs/systemctl apply, rollback, or lock release.
    let result = if req.is_mutating() {
        let mgr = Arc::clone(&manager);
        match tokio::spawn(async move { mgr.execute(&req).await }).await {
            Ok(res) => res,
            Err(_) => Err(PeerStorageError::Runtime(
                "Peer-storage operation task terminated unexpectedly".to_string(),
            )),
        }
    } else {
        manager.execute(&req).await
    };

    match result {
        Ok(typed_resp) => {
            let output = match typed_resp.serialize_wire_output() {
                Ok(out) => out,
                Err(err) => return err.into_http_response(),
            };
            let runner_resp = RunnerResponse {
                success: true,
                output,
                error: String::new(),
            };
            match serde_json::to_vec(&runner_resp) {
                Ok(body) => Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| Response::new(Body::empty())),
                Err(_) => PeerStorageError::Runtime(
                    "Failed encoding peer-storage runner response".to_string(),
                )
                .into_http_response(),
            }
        }
        Err(err) => err.into_http_response(),
    }
}
