//! Privileged transcode shim, Jellyfin drop-in, worker service, NFS transcode directory export/mount,
//! and media bind-mount management for Peer Clustering (Phase P9).
//!
//! Security and isolation invariants:
//! - Dormant at daemon startup: performs zero host probing, file creation, or unit mutations until
//!   an explicit `/v1/peer-transcode` request arrives.
//! - Uses FD-anchored directory traversal (`ReceiptDirectory` with `O_NOFOLLOW`) and atomic
//!   `renameat` writes, refusing symlinks, `..` traversal, hard links (`nlink != 1`), and
//!   overwrites/deletions of unmanaged host files.
//! - Never adds `jellyfin` to the privileged `aetherflow` group; grants `aetherflow-api` access to
//!   transcode runtime sockets via `SupplementaryGroups=jellyfin` and dedicated runtime directories.
//! - Never touches Jellyfin or API sandbox drop-ins (`10-aetherflow-sandbox.conf` /
//!   `aetherflow-sandbox.conf`) or P7 media exports (`aetherflow-peer-<link>.exports`).

use crate::confined_fs::lookup_group_gid;
use crate::job_receipts::{c_name, entry_at, verify_entry, ReceiptDirectory};
use crate::package_executor::{
    CancellationToken, CommandOutput, CommandRunner, TokioCommandRunner,
};
use crate::peer_network::{
    redact_secrets, DEFAULT_PEER_STATE_DIR, DEFAULT_PEER_TUNNEL_CIDR, PEER_ERROR_CODE_HEADER,
    PEER_WG_SERVICE_UNIT,
};
use crate::peer_storage::{
    systemd_escape_path, validate_peer_mount_segment, validate_peer_storage_link_id,
    DEFAULT_PEER_EXPORTS_DIR, DEFAULT_PEER_MOUNTS_ROOT, DEFAULT_PEER_SYSTEMD_DIR,
    PEER_MANAGED_HEADER,
};
use af_models::RunnerResponse;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{
    Mutex as TokioMutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};
use tokio::time::Instant;

#[cfg(test)]
mod tests;

pub use crate::resolve_af_transcode_binary;

pub const DEFAULT_TRANSCODE_SHIM_DIR: &str = "/usr/lib/aetherflow/transcode";
pub const DEFAULT_TRANSCODE_SHIM_PATH: &str = "/usr/lib/aetherflow/transcode/ffmpeg";
pub const DEFAULT_TRANSCODE_FFPROBE_SYMLINK: &str = "/usr/lib/aetherflow/transcode/ffprobe";
pub const DEFAULT_REAL_FFPROBE_PATH: &str = "/usr/lib/jellyfin-ffmpeg/ffprobe";
pub const DEFAULT_JELLYFIN_ENCODING_XML: &str = "/var/lib/jellyfin/config/encoding.xml";
pub const DEFAULT_JELLYFIN_TRANSCODE_DIR: &str = "/var/cache/jellyfin/transcodes";
pub const DEFAULT_JELLYFIN_TMP_DIR: &str = "/var/cache/jellyfin/af-tmp";
pub const DEFAULT_JELLYFIN_CACHE_DIR: &str = "/var/cache/jellyfin";
pub const DEFAULT_DISPATCHER_RUNTIME_DIR: &str = "/run/aetherflow-transcode";
pub const DEFAULT_WORKER_RUNTIME_DIR: &str = "/run/aetherflow-transcode-worker";
pub const DEFAULT_TRANSCODE_ENV_FILE: &str = "/etc/aetherflow/transcode.env";
pub const PEER_TRANSCODE_WORKER_UNIT: &str = "af-transcode-worker.service";
pub const JELLYFIN_TRANSCODE_DROPIN_NAME: &str = "20-aetherflow-transcode.conf";
pub const API_TRANSCODE_DROPIN_NAME: &str = "20-aetherflow-transcode.conf";
pub const RUNNER_TRANSCODE_DROPIN_NAME: &str = "20-aetherflow-transcode.conf";
pub const WORKER_TRANSCODE_PATHS_DROPIN_NAME: &str = "30-aetherflow-transcode-paths.conf";
pub const TRANSCODE_API_RESTART_UNIT: &str = "aetherflow-transcode-api-restart";

pub const DEFAULT_TMPFILES_DIR: &str = "/etc/tmpfiles.d";
pub const TRANSCODE_TMPFILES_CONF_NAME: &str = "aetherflow-transcode.conf";
pub const JELLYFIN_SERVICE_UNIT: &str = "jellyfin.service";
pub const API_SERVICE_UNIT: &str = "aetherflow-api.service";
pub const RUNNER_SERVICE_UNIT: &str = "aetherflow-runner.service";

const TRANSCODE_MOUNT_PURPOSE_HEADER: &str = "# AetherFlow-Peer-Purpose: transcode";
const TRANSCODE_BIND_PURPOSE_HEADER: &str = "# AetherFlow-Peer-Purpose: transcode-bind";

const DEFAULT_WORKER_SOCKET_PATH: &str = "/run/aetherflow-transcode-worker/worker.sock";
const DEFAULT_WORKER_SOCKET_MODE_STR: &str = "0660";
const PEER_TRANSCODE_LOCK_FILE_NAME: &str = ".aetherflow-peer-transcode.lock";
const TRANSCODE_EXPORT_FILE_PREFIX: &str = "aetherflow-peer-";
const TRANSCODE_EXPORT_FILE_SUFFIX: &str = "-transcode.exports";
const MAX_TRANSCODE_PATHS: usize = 32;
const MAX_PATH_BYTES: usize = 4096;
const MAX_MANAGED_FILE_BYTES: usize = 256 * 1024;
const MAX_ENCODING_XML_BYTES: usize = 512 * 1024;
const MAX_SHIM_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SYSTEMD_UNIT_NAME_BYTES: usize = 255;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(35);
const TRANSCODE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

pub const TRANSCODE_INSPECT_CLIENT_TIMEOUT: Duration = Duration::from_secs(20);
pub const TRANSCODE_DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(90);
pub const TRANSCODE_MOUNT_CLIENT_TIMEOUT: Duration = Duration::from_secs(150);

/// Returns the recommended Unix socket client timeout for a given `PeerTranscodeRequest`.
pub fn client_timeout_for_request(req: &PeerTranscodeRequest) -> Duration {
    match req {
        PeerTranscodeRequest::InspectJellyfinPaths => TRANSCODE_INSPECT_CLIENT_TIMEOUT,
        PeerTranscodeRequest::MountTranscodeDirs { .. }
        | PeerTranscodeRequest::RemoveTranscodeMounts { .. }
        | PeerTranscodeRequest::BindMedia { .. }
        | PeerTranscodeRequest::RemoveBindMedia { .. } => TRANSCODE_MOUNT_CLIENT_TIMEOUT,
        _ => TRANSCODE_DEFAULT_CLIENT_TIMEOUT,
    }
}

type PeerTranscodeLockMap = HashMap<PathBuf, Arc<RwLock<()>>>;
type PeerTranscodeUnitLockMap = HashMap<(PathBuf, String), Arc<TokioMutex<()>>>;

static PEER_TRANSCODE_LOCKS: Lazy<StdMutex<PeerTranscodeLockMap>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

static PEER_TRANSCODE_UNIT_LOCKS: Lazy<StdMutex<PeerTranscodeUnitLockMap>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn peer_transcode_lock_for(state_dir: &Path) -> Arc<RwLock<()>> {
    let mut map = PEER_TRANSCODE_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.entry(state_dir.to_path_buf())
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

fn peer_transcode_unit_lock_for(state_dir: &Path, unit_name: &str) -> Arc<TokioMutex<()>> {
    let mut map = PEER_TRANSCODE_UNIT_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.entry((state_dir.to_path_buf(), unit_name.to_string()))
        .or_insert_with(|| Arc::new(TokioMutex::new(())))
        .clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire Types & Typed Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Request payload dispatched over `/v1/peer-transcode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerTranscodeRequest {
    InspectJellyfinPaths,
    EnsureDispatcherDir,
    InstallShim,
    EnableJellyfin,
    DisableJellyfin,
    InstallWorkerUnit,
    RemoveWorkerUnit,
    ExportTranscodeDirs {
        link_id: String,
        tunnel_ip: String,
        uid: u32,
        gid: u32,
        paths: Vec<String>,
    },
    RemoveTranscodeExports {
        link_id: String,
    },
    MountTranscodeDirs {
        link_id: String,
        tunnel_ip: String,
        paths: Vec<String>,
    },
    RemoveTranscodeMounts {
        link_id: String,
        paths: Vec<String>,
    },
    BindMedia {
        from: String,
        to: String,
        #[serde(default)]
        writable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        calling_link_segment: Option<String>,
    },
    RemoveBindMedia {
        to: String,
    },
    /// Schedules a short deferred `systemctl restart aetherflow-api.service` via `systemd-run`
    /// so a newly installed `20-aetherflow-transcode.conf` drop-in takes effect after the HTTP
    /// response completes.
    ScheduleApiRestart,
    /// Verifies (read + non-symlink regular file) and unlinks a `.af-parity-<32hex>.ts` file
    /// inside an inspected Jellyfin transcode/temp/cache directory so read-only `aetherflow-api`
    /// (`ProtectSystem=strict`) never leaks parity temp files.
    CleanupParityFile {
        dir: String,
        file_name: String,
    },
}

impl PeerTranscodeRequest {
    pub(crate) fn is_mutating(&self) -> bool {
        !matches!(self, Self::InspectJellyfinPaths)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JellyfinTranscodePaths {
    pub transcoding_temp_path: String,
    pub tmp_dir: String,
    pub cache_dir: String,
    pub shim_path: String,
    pub shim_installed: bool,
    pub dropin_enabled: bool,
    pub worker_unit_installed: bool,
    pub worker_unit_active: bool,
    pub jellyfin_uid: Option<u32>,
    pub jellyfin_gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscodeMutationReport {
    pub changed: bool,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub api_restart_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityFileCleanupReport {
    pub existed: bool,
    pub size_bytes: u64,
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerTranscodeResponse {
    JellyfinPaths(JellyfinTranscodePaths),
    Mutation(TranscodeMutationReport),
    ParityFileCleanup(ParityFileCleanupReport),
}

impl PeerTranscodeResponse {
    pub fn into_jellyfin_paths(self) -> Result<JellyfinTranscodePaths, PeerTranscodeError> {
        match self {
            Self::JellyfinPaths(v) => Ok(v),
            _ => Err(PeerTranscodeError::Runtime(
                "Unexpected peer-transcode response variant (expected jellyfin_paths)".to_string(),
            )),
        }
    }

    pub fn into_mutation(self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        match self {
            Self::Mutation(v) => Ok(v),
            _ => Err(PeerTranscodeError::Runtime(
                "Unexpected peer-transcode response variant (expected mutation)".to_string(),
            )),
        }
    }

    pub fn into_parity_file_cleanup(self) -> Result<ParityFileCleanupReport, PeerTranscodeError> {
        match self {
            Self::ParityFileCleanup(v) => Ok(v),
            _ => Err(PeerTranscodeError::Runtime(
                "Unexpected peer-transcode response variant (expected parity_file_cleanup)"
                    .to_string(),
            )),
        }
    }

    fn serialize_wire_output(&self) -> Result<String, PeerTranscodeError> {
        serde_json::to_string(self).map_err(|_| {
            PeerTranscodeError::Runtime("Failed serializing peer-transcode response".to_string())
        })
    }
}

/// Decodes `RunnerResponse.output` for a given `PeerTranscodeRequest`, enforcing variant matching.
pub fn decode_peer_transcode_response(
    req: &PeerTranscodeRequest,
    output: &str,
) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
    let parse_err = || {
        PeerTranscodeError::Runtime(
            "Invalid typed response payload from peer-transcode runner".to_string(),
        )
    };
    let raw_val: serde_json::Value = serde_json::from_str(output).map_err(|_| parse_err())?;
    let has_kind = raw_val
        .as_object()
        .is_some_and(|map| map.contains_key("kind"));

    if has_kind {
        let decoded: PeerTranscodeResponse =
            serde_json::from_value(raw_val).map_err(|_| parse_err())?;
        let matches_req = match (req, &decoded) {
            (
                PeerTranscodeRequest::InspectJellyfinPaths,
                PeerTranscodeResponse::JellyfinPaths(_),
            ) => true,
            (
                PeerTranscodeRequest::CleanupParityFile { .. },
                PeerTranscodeResponse::ParityFileCleanup(_),
            ) => true,
            (
                PeerTranscodeRequest::InspectJellyfinPaths
                | PeerTranscodeRequest::CleanupParityFile { .. },
                _,
            ) => false,
            (_, PeerTranscodeResponse::Mutation(_)) => true,
            (
                _,
                PeerTranscodeResponse::JellyfinPaths(_)
                | PeerTranscodeResponse::ParityFileCleanup(_),
            ) => false,
        };
        if !matches_req {
            return Err(PeerTranscodeError::Runtime(
                "Mismatched peer-transcode response variant for request".to_string(),
            ));
        }
        return Ok(decoded);
    }

    match req {
        PeerTranscodeRequest::InspectJellyfinPaths => Ok(PeerTranscodeResponse::JellyfinPaths(
            serde_json::from_value(raw_val).map_err(|_| parse_err())?,
        )),
        PeerTranscodeRequest::CleanupParityFile { .. } => {
            Ok(PeerTranscodeResponse::ParityFileCleanup(
                serde_json::from_value(raw_val).map_err(|_| parse_err())?,
            ))
        }
        _ => Ok(PeerTranscodeResponse::Mutation(
            serde_json::from_value(raw_val).map_err(|_| parse_err())?,
        )),
    }
}

/// Typed error returned by peer-transcode runner operations and preserved across the Unix socket.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerTranscodeError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Busy(String),
    #[error("{0}")]
    UnmanagedFile(String),
    #[error("{0}")]
    Runtime(String),
}

impl PeerTranscodeError {
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) | Self::UnmanagedFile(_) => StatusCode::CONFLICT,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn status_code(&self) -> StatusCode {
        self.http_status()
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::Conflict(_) => "conflict",
            Self::NotFound(_) => "not_found",
            Self::Busy(_) => "busy",
            Self::UnmanagedFile(_) => "unmanaged_file",
            Self::Runtime(_) => "runtime",
        }
    }

    pub fn is_invalid_input(&self) -> bool {
        matches!(self, Self::InvalidInput(_))
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }

    pub fn is_unmanaged_file(&self) -> bool {
        matches!(self, Self::UnmanagedFile(_))
    }

    pub fn from_http_response(status: StatusCode, code: Option<&str>, error: String) -> Self {
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
                "conflict" => return Self::Conflict(msg),
                "not_found" => return Self::NotFound(msg),
                "busy" => return Self::Busy(msg),
                "unmanaged_file" => return Self::UnmanagedFile(msg),
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
        let status = self.http_status();
        let error_code = self.error_code();
        let error = redact_secrets(&self.to_string());
        let body = serde_json::to_vec(&RunnerResponse {
            success: false,
            output: String::new(),
            error,
        })
        .unwrap_or_else(|_| {
            br#"{"success":false,"error":"Internal peer-transcode serialization error"}"#.to_vec()
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
// Validation, Parsing & Rendering Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TranscodeTunnelCidr {
    ip: IpAddr,
    prefix: u8,
}

impl TranscodeTunnelCidr {
    fn parse_subnet(raw: &str) -> Result<Self, PeerTranscodeError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            return Err(PeerTranscodeError::InvalidInput(
                "Tunnel CIDR must not be empty".to_string(),
            ));
        }
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            PeerTranscodeError::InvalidInput(
                "Tunnel CIDR must use address/prefix format".to_string(),
            )
        })?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| PeerTranscodeError::InvalidInput("Invalid tunnel CIDR IP".to_string()))?;
        let prefix: u8 = prefix_str.parse().map_err(|_| {
            PeerTranscodeError::InvalidInput("Invalid tunnel CIDR prefix".to_string())
        })?;
        let valid = match ip {
            IpAddr::V4(_) => (1..=30).contains(&prefix),
            IpAddr::V6(_) => (1..=126).contains(&prefix),
        };
        if !valid {
            return Err(PeerTranscodeError::InvalidInput(
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

fn validate_tunnel_ip(raw: &str, cidr: &TranscodeTunnelCidr) -> Result<IpAddr, PeerTranscodeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains(',')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PeerTranscodeError::InvalidInput(
            "Tunnel IP must be a single bare IP address without a CIDR prefix".to_string(),
        ));
    }
    let ip: IpAddr = trimmed.parse().map_err(|_| {
        PeerTranscodeError::InvalidInput("Tunnel IP is not a valid IP address".to_string())
    })?;
    if !cidr.contains_ip(ip) {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Tunnel IP {ip} is outside the configured peer tunnel CIDR {}",
            cidr.network_string()
        )));
    }
    if !cidr.is_usable_host(ip) {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Tunnel IP {ip} cannot be a subnet network or broadcast address"
        )));
    }
    Ok(ip)
}

fn validate_link_id(link_id: &str) -> Result<&str, PeerTranscodeError> {
    validate_peer_storage_link_id(link_id)
        .map_err(|err| PeerTranscodeError::InvalidInput(err.to_string()))
}

/// Derives the transcode-specific `/etc/exports.d/` filename for `link_id`:
/// `aetherflow-peer-<link_id>-transcode.exports` (strictly separate from P7 media exports).
pub fn derive_peer_transcode_export_file_name(link_id: &str) -> Result<String, PeerTranscodeError> {
    let valid = validate_link_id(link_id)?;
    Ok(format!(
        "{TRANSCODE_EXPORT_FILE_PREFIX}{valid}{TRANSCODE_EXPORT_FILE_SUFFIX}"
    ))
}

const FORBIDDEN_SYSTEM_PREFIXES: &[&str] = &[
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
    "/var/lib/aetherflow",
    "/var/run",
    "/var/spool",
    "/opt/AetherFlow",
];

const DEFAULT_BIND_MEDIA_ROOTS: &[&str] = &[
    "/mnt",
    "/media",
    "/srv",
    "/downloads",
    "/data",
    "/var/lib/jellyfin",
];

const FORBIDDEN_EXACT_PATHS: &[&str] = &[
    "/",
    "/tmp",
    "/var/tmp",
    "/var",
    "/home",
    "/mnt",
    "/mnt/af-peers",
    "/var/lib",
    "/var/cache",
];

fn is_under_peer_mounts_root(path: &str) -> bool {
    path == DEFAULT_PEER_MOUNTS_ROOT
        || path
            .strip_prefix(DEFAULT_PEER_MOUNTS_ROOT)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn is_strict_descendant_path(child: &str, ancestor: &str) -> bool {
    if child == ancestor {
        return false;
    }
    if ancestor == "/" {
        return child.starts_with('/');
    }
    child
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn has_sensitive_dot_segment(path: &str) -> bool {
    path.split('/').skip(1).any(|seg| seg == ".ssh")
}

/// Extracts and validates `(link_segment, export_segment)` from a canonical path under
/// `/mnt/af-peers/<link>/<export>(/...)`.
fn extract_peer_mount_segments(path: &str) -> Result<(String, String), PeerTranscodeError> {
    let Some(rest) = path.strip_prefix(&format!("{DEFAULT_PEER_MOUNTS_ROOT}/")) else {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Peer mount path '{path}' must lie under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
        )));
    };
    let mut parts = rest.split('/');
    let link_seg = parts.next().unwrap_or("");
    let export_seg = parts.next().unwrap_or("");
    if link_seg.is_empty() || export_seg.is_empty() {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Peer mount path '{path}' must specify <link>/<export>"
        )));
    }
    validate_peer_mount_segment(link_seg)
        .map_err(|err| PeerTranscodeError::InvalidInput(err.to_string()))?;
    validate_peer_mount_segment(export_seg)
        .map_err(|err| PeerTranscodeError::InvalidInput(err.to_string()))?;
    Ok((link_seg.to_string(), export_seg.to_string()))
}

/// Derives the backing NFS `.mount` unit for a bind source under `/mnt/af-peers/<link>/<export>`
/// using the first 4 path components (`/mnt/af-peers/<link>/<export>`). Returns `Ok(None)` for
/// local-directory sources outside `/mnt/af-peers/`.
fn derive_backing_peer_nfs_mount_unit(from: &str) -> Result<Option<String>, PeerTranscodeError> {
    if !is_under_peer_mounts_root(from) {
        return Ok(None);
    }
    let (link_seg, export_seg) = extract_peer_mount_segments(from)?;
    let backing_path = format!("{DEFAULT_PEER_MOUNTS_ROOT}/{link_seg}/{export_seg}");
    Ok(Some(derive_systemd_mount_unit(&backing_path)?))
}

/// Prunes child export paths ONLY when they are a strict descendant of another exported path in
/// the same request AND share the exact same `st_dev` as their nearest kept ancestor.
/// Separate-filesystem children (differing `st_dev`) are always preserved.
fn prune_same_device_descendant_exports(paths_with_dev: &[(String, u64)]) -> Vec<String> {
    let mut kept: Vec<(String, u64)> = Vec::with_capacity(paths_with_dev.len());
    for (path, dev) in paths_with_dev {
        let nearest_ancestor = kept
            .iter()
            .filter(|(ancestor, _)| is_strict_descendant_path(path, ancestor))
            .max_by_key(|(ancestor, _)| ancestor.len());
        let covered_by_same_fs_ancestor =
            nearest_ancestor.is_some_and(|(_, anc_dev)| *anc_dev == *dev);
        if !covered_by_same_fs_ancestor {
            kept.push((path.clone(), *dev));
        }
    }
    kept.into_iter().map(|(p, _)| p).collect()
}

fn normalize_allowed_root_entry(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed.chars().any(char::is_control) {
        return None;
    }
    let normalized = if trimmed.len() > 1 {
        trimmed.trim_end_matches('/')
    } else {
        trimmed
    };
    if normalized == "/" || normalized.contains("//") {
        return None;
    }
    if normalized
        .split('/')
        .skip(1)
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return None;
    }
    Some(normalized.to_string())
}

fn parse_allowed_bind_media_roots_env(raw: Option<&str>) -> Option<Vec<String>> {
    let env_val = raw?.trim();
    if env_val.is_empty() {
        return None;
    }
    let roots: Vec<String> = env_val
        .split(',')
        .filter_map(normalize_allowed_root_entry)
        .collect();
    Some(roots)
}

fn validate_canonical_path_syntax(
    path: &str,
    allow_peer_mounts_subpath: bool,
) -> Result<String, PeerTranscodeError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(PeerTranscodeError::InvalidInput(
            "Path must be a non-empty canonical absolute path".to_string(),
        ));
    }
    if path.trim() != path {
        return Err(PeerTranscodeError::InvalidInput(
            "Path must not have leading or trailing whitespace".to_string(),
        ));
    }
    if !path.starts_with('/') {
        return Err(PeerTranscodeError::InvalidInput(
            "Path must be an absolute path starting with '/'".to_string(),
        ));
    }
    if path == "/" || path.ends_with('/') || path.contains("//") {
        return Err(PeerTranscodeError::InvalidInput(
            "Path must be a canonical non-root path without duplicate or trailing slashes"
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
        return Err(PeerTranscodeError::InvalidInput(
            "Path contains disallowed control or config-syntax characters".to_string(),
        ));
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." || segment.len() > 255 {
            return Err(PeerTranscodeError::InvalidInput(
                "Path must not contain empty, '.', '..', or oversized segments".to_string(),
            ));
        }
    }
    if FORBIDDEN_EXACT_PATHS.contains(&path) {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Refusing sensitive top-level directory '{path}'"
        )));
    }
    for prefix in FORBIDDEN_SYSTEM_PREFIXES {
        if path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Refusing restricted system path '{path}'"
            )));
        }
    }
    if let Some(rest) = path.strip_prefix(DEFAULT_PEER_MOUNTS_ROOT) {
        if rest.is_empty() || rest.starts_with('/') {
            if !allow_peer_mounts_subpath {
                return Err(PeerTranscodeError::InvalidInput(format!(
                    "Refusing peer mount hierarchy path '{path}' for transcode directory"
                )));
            }
            let sub = rest.trim_start_matches('/');
            let segments: Vec<&str> = sub.split('/').collect();
            if segments.len() < 2 || segments.iter().any(|s| s.is_empty()) {
                return Err(PeerTranscodeError::InvalidInput(format!(
                    "Bind target under {DEFAULT_PEER_MOUNTS_ROOT} must specify <link>/<export>"
                )));
            }
        }
    }
    Ok(path.to_string())
}

fn derive_systemd_mount_unit(path: &str) -> Result<String, PeerTranscodeError> {
    let escaped = systemd_escape_path(path)
        .map_err(|err| PeerTranscodeError::InvalidInput(err.to_string()))?;
    let unit = format!("{escaped}.mount");
    if unit.len() > MAX_SYSTEMD_UNIT_NAME_BYTES {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Derived systemd mount unit name exceeds {MAX_SYSTEMD_UNIT_NAME_BYTES} bytes"
        )));
    }
    Ok(unit)
}

fn validate_transcode_paths_list(paths: &[String]) -> Result<Vec<String>, PeerTranscodeError> {
    if paths.is_empty() {
        return Err(PeerTranscodeError::InvalidInput(
            "At least one transcode directory path is required".to_string(),
        ));
    }
    if paths.len() > MAX_TRANSCODE_PATHS {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Too many transcode directory paths (maximum {MAX_TRANSCODE_PATHS})"
        )));
    }
    let mut seen = HashSet::with_capacity(paths.len());
    let mut validated = Vec::with_capacity(paths.len());
    for raw in paths {
        let canonical = validate_canonical_path_syntax(raw, false)?;
        let _ = derive_systemd_mount_unit(&canonical)?;
        if !seen.insert(canonical.clone()) {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Duplicate transcode directory path '{canonical}'"
            )));
        }
        validated.push(canonical);
    }
    // Sort shallower (parent) paths before deeper (child) paths, with lexicographic tie-breaker.
    validated.sort_by(|a, b| {
        let depth_a = a.bytes().filter(|&c| c == b'/').count();
        let depth_b = b.bytes().filter(|&c| c == b'/').count();
        depth_a.cmp(&depth_b).then_with(|| a.cmp(b))
    });
    Ok(validated)
}

fn escape_systemd_specifiers(value: &str) -> String {
    value.replace('%', "%%")
}

fn unescape_systemd_specifiers(value: &str) -> String {
    value.replace("%%", "%")
}

fn format_systemd_rw_path_token(path: &str) -> String {
    let escaped = escape_systemd_specifiers(path);
    if escaped.contains(' ') || escaped.contains('\t') {
        format!("\"-{escaped}\"")
    } else {
        format!("-{escaped}")
    }
}

/// Parses a managed `.mount` unit file (with `PEER_MANAGED_HEADER`) and returns `Some(where_path)`
/// if it contributes a writable path to `af-transcode-worker.service`'s `ReadWritePaths=`:
/// - `# AetherFlow-Peer-Purpose: transcode` (always writable NFS transcode mount), or
/// - `# AetherFlow-Peer-Purpose: transcode-bind` when `Options=` includes `rw`.
fn extract_managed_worker_rw_path(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.starts_with(PEER_MANAGED_HEADER) {
        return None;
    }
    let mut is_transcode_mount = false;
    let mut is_transcode_bind = false;
    let mut where_path: Option<String> = None;
    let mut options_rw = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == TRANSCODE_MOUNT_PURPOSE_HEADER {
            is_transcode_mount = true;
        } else if trimmed == TRANSCODE_BIND_PURPOSE_HEADER {
            is_transcode_bind = true;
        } else if let Some(val) = trimmed.strip_prefix("Where=") {
            let unescaped = unescape_systemd_specifiers(val.trim());
            if !unescaped.is_empty() && !unescaped.chars().any(char::is_control) {
                where_path = Some(unescaped);
            }
        } else if let Some(val) = trimmed.strip_prefix("Options=") {
            options_rw = val.split(',').any(|opt| opt.trim() == "rw");
        }
    }

    if is_transcode_mount || (is_transcode_bind && options_rw) {
        where_path
    } else {
        None
    }
}

fn is_managed_bind_unit_for_path(bytes: &[u8], expected_where: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if !text.starts_with(PEER_MANAGED_HEADER) {
        return false;
    }
    let mut has_bind_purpose = false;
    let mut where_matches = false;
    let escaped_expected = escape_systemd_specifiers(expected_where);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == TRANSCODE_BIND_PURPOSE_HEADER {
            has_bind_purpose = true;
        } else if let Some(val) = trimmed.strip_prefix("Where=") {
            if val.trim() == escaped_expected {
                where_matches = true;
            }
        }
    }
    has_bind_purpose && where_matches
}

fn has_managed_purpose(bytes: &[u8], expected_purpose_header: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.starts_with(PEER_MANAGED_HEADER)
        && text.lines().any(|l| l.trim() == expected_purpose_header)
}

/// Validates a parity test output filename strictly matching `^\.af-parity-[0-9a-f]{32}\.ts$`.
fn validate_parity_file_name(file_name: &str) -> Result<(), PeerTranscodeError> {
    const PREFIX: &str = ".af-parity-";
    const SUFFIX: &str = ".ts";
    let Some(rest) = file_name.strip_prefix(PREFIX) else {
        return Err(PeerTranscodeError::InvalidInput(
            "Parity file name must start with '.af-parity-'".to_string(),
        ));
    };
    let Some(hex) = rest.strip_suffix(SUFFIX) else {
        return Err(PeerTranscodeError::InvalidInput(
            "Parity file name must end with '.ts'".to_string(),
        ));
    };
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PeerTranscodeError::InvalidInput(
            "Parity file name must contain a 32-character lowercase hex identifier".to_string(),
        ));
    }
    Ok(())
}

/// Extracts and validates `<TranscodingTempPath>` from Jellyfin's `encoding.xml`.
///
/// Returns `Ok(None)` when the element is absent, self-closing, or empty so the caller falls
/// back to [`DEFAULT_JELLYFIN_TRANSCODE_DIR`]. Rejects path traversal, relative paths, and
/// restricted system directories.
pub fn parse_jellyfin_transcoding_temp_path(
    xml: &str,
) -> Result<Option<String>, PeerTranscodeError> {
    // Strip XML comments (`<!-- ... -->`) so commented-out tags are ignored.
    let mut stripped = String::with_capacity(xml.len());
    let mut cursor = xml;
    while let Some(start) = cursor.find("<!--") {
        stripped.push_str(&cursor[..start]);
        let rest = &cursor[start + 4..];
        let Some(end) = rest.find("-->") else {
            return Err(PeerTranscodeError::InvalidInput(
                "Malformed Jellyfin encoding.xml (unterminated XML comment)".to_string(),
            ));
        };
        cursor = &rest[end + 3..];
    }
    stripped.push_str(cursor);

    let open_marker = "<TranscodingTempPath";
    let mut search_from = 0usize;
    let after_name = loop {
        let Some(rel_start) = stripped[search_from..].find(open_marker) else {
            return Ok(None);
        };
        let after_pos = search_from + rel_start + open_marker.len();
        let candidate = &stripped[after_pos..];
        // Next character must end the tag name (`>`, `/`, or XML whitespace).
        let Some(first_ch) = candidate.chars().next() else {
            return Err(PeerTranscodeError::InvalidInput(
                "Malformed <TranscodingTempPath> tag in encoding.xml".to_string(),
            ));
        };
        if matches!(first_ch, '>' | '/' | ' ' | '\t' | '\r' | '\n') {
            break candidate;
        }
        // Prefix match on a longer tag name such as `<TranscodingTempPathFoo>`; keep scanning.
        search_from = after_pos;
    };
    let Some(gt_pos) = after_name.find('>') else {
        return Err(PeerTranscodeError::InvalidInput(
            "Malformed <TranscodingTempPath> tag in encoding.xml".to_string(),
        ));
    };
    let tag_head = &after_name[..gt_pos];
    if tag_head.trim_end().ends_with('/') {
        // Self-closing tag such as `<TranscodingTempPath />`
        return Ok(None);
    }
    let body_start = &after_name[gt_pos + 1..];
    let Some(close_pos) = body_start.find("</TranscodingTempPath>") else {
        return Err(PeerTranscodeError::InvalidInput(
            "Unterminated <TranscodingTempPath> element in encoding.xml".to_string(),
        ));
    };
    let raw_inner = &body_start[..close_pos];
    if raw_inner.contains('<') {
        return Err(PeerTranscodeError::InvalidInput(
            "Unexpected nested markup inside <TranscodingTempPath> in encoding.xml".to_string(),
        ));
    }
    let decoded = raw_inner
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    let trimmed = decoded.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = if trimmed.len() > 1 {
        trimmed.trim_end_matches('/')
    } else {
        trimmed
    };
    let valid = validate_canonical_path_syntax(normalized, false)?;
    Ok(Some(valid))
}

fn render_tmpfiles_conf() -> String {
    format!(
        "{PEER_MANAGED_HEADER}\nd {DEFAULT_DISPATCHER_RUNTIME_DIR} 0750 aetherflow jellyfin -\n"
    )
}

fn render_default_transcode_env_file() -> &'static str {
    "# AetherFlow distributed transcoding configuration (secret-free).\n\
     # Loaded by af-transcode-worker.service, jellyfin.service, aetherflow-api.service,\n\
     # and aetherflow-runner.service. Never place API keys, tokens, or secrets in this file.\n\
     #\n\
     # Override the real ffmpeg binary executed by the shim and worker:\n\
     # AF_TRANSCODE_REAL_FFMPEG=/usr/lib/jellyfin-ffmpeg/ffmpeg\n\
     #\n\
     # Override the maximum concurrent transcode jobs allowed on this worker (1..=64):\n\
     # AF_TRANSCODE_WORKER_MAX_JOBS=8\n"
}

fn render_api_transcode_dropin(transcode_env_path: &str) -> String {
    let escaped_env = escape_systemd_specifiers(transcode_env_path);
    format!(
        "{PEER_MANAGED_HEADER}\n\
         [Service]\n\
         EnvironmentFile=-{escaped_env}\n\
         SupplementaryGroups=jellyfin\n\
         ReadWritePaths=-{DEFAULT_DISPATCHER_RUNTIME_DIR} -{DEFAULT_WORKER_RUNTIME_DIR}\n"
    )
}

fn render_runner_transcode_dropin(transcode_env_path: &str) -> String {
    let escaped_env = escape_systemd_specifiers(transcode_env_path);
    format!(
        "{PEER_MANAGED_HEADER}\n\
         [Service]\n\
         EnvironmentFile=-{escaped_env}\n"
    )
}

fn render_jellyfin_transcode_dropin(transcode_env_path: &str) -> String {
    let escaped_env = escape_systemd_specifiers(transcode_env_path);
    format!(
        "{PEER_MANAGED_HEADER}\n\
         [Service]\n\
         EnvironmentFile=-{escaped_env}\n\
         Environment=JELLYFIN_FFMPEG={DEFAULT_TRANSCODE_SHIM_PATH}\n\
         Environment=TMPDIR={DEFAULT_JELLYFIN_TMP_DIR}\n"
    )
}

fn render_worker_service_unit(
    binary_path: &Path,
    transcode_env_path: &str,
) -> Result<String, PeerTranscodeError> {
    let bin_str = binary_path.to_string_lossy();
    if bin_str.is_empty() || bin_str.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(PeerTranscodeError::InvalidInput(
            "Transcode binary path must not be empty or contain whitespace or control characters"
                .to_string(),
        ));
    }
    if transcode_env_path.is_empty()
        || transcode_env_path
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PeerTranscodeError::InvalidInput(
            "Transcode environment file path must not be empty or contain whitespace or control characters"
                .to_string(),
        ));
    }
    let escaped_bin = escape_systemd_specifiers(&bin_str);
    let escaped_env = escape_systemd_specifiers(transcode_env_path);
    Ok(format!(
        "{PEER_MANAGED_HEADER}\n\
         [Unit]\n\
         Description=AetherFlow Peer Transcode Worker\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=jellyfin\n\
         Group=jellyfin\n\
         SupplementaryGroups=render video\n\
         RuntimeDirectory=aetherflow-transcode-worker\n\
         RuntimeDirectoryMode=0750\n\
         WorkingDirectory={DEFAULT_WORKER_RUNTIME_DIR}\n\
         EnvironmentFile=-{escaped_env}\n\
         Environment=AF_TRANSCODE_WORKER_SOCK={DEFAULT_WORKER_SOCKET_PATH}\n\
         Environment=AF_TRANSCODE_WORKER_SOCKET_MODE={DEFAULT_WORKER_SOCKET_MODE_STR}\n\
         ExecStart={escaped_bin} worker\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         NoNewPrivileges=yes\n\
         PrivateNetwork=yes\n\
         RestrictAddressFamilies=AF_UNIX\n\
         ProtectSystem=strict\n\
         ProtectHome=read-only\n\
         DevicePolicy=closed\n\
         DeviceAllow=char-drm rw\n\
         DeviceAllow=/dev/dri rw\n\
         DeviceAllow=char-nvidia-frontend rw\n\
         DeviceAllow=char-nvidia-uvm rw\n\
         DeviceAllow=char-nvidia-caps rw\n\
         DeviceAllow=/dev/nvidiactl rw\n\
         DeviceAllow=/dev/nvidia-modeset rw\n\
         DeviceAllow=/dev/nvidia-uvm rw\n\
         DeviceAllow=/dev/nvidia-uvm-tools rw\n\
         ReadWritePaths=-{DEFAULT_WORKER_RUNTIME_DIR} -{DEFAULT_JELLYFIN_CACHE_DIR}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    ))
}

fn render_worker_transcode_paths_dropin(paths: &BTreeSet<String>) -> String {
    let tokens: Vec<String> = paths
        .iter()
        .map(|p| format_systemd_rw_path_token(p))
        .collect();
    format!(
        "{PEER_MANAGED_HEADER}\n\
         [Service]\n\
         ReadWritePaths={}\n",
        tokens.join(" ")
    )
}

fn render_transcode_exports_file(
    tunnel_ip: IpAddr,
    uid: u32,
    gid: u32,
    paths: &[String],
) -> String {
    let mut out = format!("{PEER_MANAGED_HEADER}\n");
    for path in paths {
        let path_token = if path.contains(' ') {
            format!("\"{path}\"")
        } else {
            path.clone()
        };
        out.push_str(&format!(
            "{path_token} {tunnel_ip}(rw,all_squash,anonuid={uid},anongid={gid},secure,no_subtree_check)\n"
        ));
    }
    out
}

fn render_transcode_nfs_mount_unit(link_id: &str, tunnel_ip: IpAddr, path: &str) -> String {
    let what = match tunnel_ip {
        IpAddr::V4(v4) => format!("{v4}:{path}"),
        IpAddr::V6(v6) => format!("[{v6}]:{path}"),
    };
    let options = format!(
        "vers=4.2,soft,timeo=100,retrans=2,rw,_netdev,nosuid,nodev,x-systemd.requires={PEER_WG_SERVICE_UNIT}"
    );
    let desc_path = escape_systemd_specifiers(path);
    let what_escaped = escape_systemd_specifiers(&what);
    let where_escaped = escape_systemd_specifiers(path);
    format!(
        "{PEER_MANAGED_HEADER}\n\
         # AetherFlow-Peer-Link: {link_id}\n\
         {TRANSCODE_MOUNT_PURPOSE_HEADER}\n\
         [Unit]\n\
         Description=AetherFlow Peer Transcode NFS Mount ({desc_path})\n\
         Requires={PEER_WG_SERVICE_UNIT}\n\
         After={PEER_WG_SERVICE_UNIT}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
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
    )
}

fn render_bind_media_mount_unit(
    from: &str,
    to: &str,
    writable: bool,
    backing_mount_unit: Option<&str>,
) -> String {
    let rw_mode = if writable { "rw" } else { "ro" };
    let options = format!("bind,{rw_mode},nosuid,nodev");
    let desc_path = escape_systemd_specifiers(to);
    let what_escaped = escape_systemd_specifiers(from);
    let where_escaped = escape_systemd_specifiers(to);
    let backing_deps = match backing_mount_unit {
        Some(unit) => format!("BindsTo={unit}\nAfter={unit}\n"),
        None => String::new(),
    };
    format!(
        "{PEER_MANAGED_HEADER}\n\
         {TRANSCODE_BIND_PURPOSE_HEADER}\n\
         [Unit]\n\
         Description=AetherFlow Peer Transcode Bind Mount ({desc_path})\n\
         After=local-fs.target\n\
         {backing_deps}\
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
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary Validation & Low-Level Unix Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Validates that `path` is a clean absolute path to a regular, non-symlink executable binary
/// that is NOT world-writable.
pub(crate) fn validate_transcode_binary_file(path: &Path) -> Result<(), PeerTranscodeError> {
    let raw = path.to_string_lossy();
    if raw.is_empty()
        || !path.is_absolute()
        || raw.chars().any(char::is_control)
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Invalid af-transcode binary path '{}'",
            path.display()
        )));
    }
    let meta = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PeerTranscodeError::NotFound(format!(
                "af-transcode binary not found at '{}'",
                path.display()
            ))
        } else {
            PeerTranscodeError::InvalidInput(format!(
                "Cannot inspect af-transcode binary '{}': {err}",
                path.display()
            ))
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Refusing symlinked af-transcode binary '{}'",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "af-transcode binary '{}' is not a regular file",
            path.display()
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "af-transcode binary '{}' is not executable (mode {:04o})",
            path.display(),
            mode & 0o7777
        )));
    }
    if mode & 0o002 != 0 {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Refusing world-writable af-transcode binary '{}' (mode {:04o})",
            path.display(),
            mode & 0o7777
        )));
    }
    Ok(())
}

pub(crate) fn is_valid_transcode_binary(path: &Path) -> bool {
    validate_transcode_binary_file(path).is_ok()
}

fn validate_real_ffprobe_file(disk_path: &Path, shim_dir: &Path) -> Result<(), PeerTranscodeError> {
    let raw = disk_path.to_string_lossy();
    if raw.is_empty()
        || !disk_path.is_absolute()
        || raw.chars().any(char::is_control)
        || disk_path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Invalid real ffprobe path '{}'",
            disk_path.display()
        )));
    }
    let meta = fs::metadata(disk_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PeerTranscodeError::NotFound(format!(
                "Real ffprobe binary not found at '{}'",
                disk_path.display()
            ))
        } else {
            PeerTranscodeError::InvalidInput(format!(
                "Cannot inspect real ffprobe binary '{}': {err}",
                disk_path.display()
            ))
        }
    })?;
    if !meta.is_file() {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Real ffprobe path '{}' is not a regular file",
            disk_path.display()
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Real ffprobe '{}' is not executable",
            disk_path.display()
        )));
    }
    if mode & 0o002 != 0 {
        return Err(PeerTranscodeError::InvalidInput(format!(
            "Refusing world-writable real ffprobe '{}'",
            disk_path.display()
        )));
    }
    if let (Ok(canon_probe), Ok(canon_shim)) =
        (fs::canonicalize(disk_path), fs::canonicalize(shim_dir))
    {
        if canon_probe.starts_with(&canon_shim) {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Refusing recursive ffprobe symlink target '{}' inside shim directory",
                disk_path.display()
            )));
        }
    }
    Ok(())
}

fn lookup_passwd_uid_gid_reentrant(username: &str) -> Option<(u32, u32)> {
    let c_user = CString::new(username).ok()?;
    let mut buf_len = 1024usize;
    const MAX_BUF_LEN: usize = 16 * 1024;
    while buf_len <= MAX_BUF_LEN {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; buf_len];
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() {
                return None;
            }
            return Some((pwd.pw_uid as u32, pwd.pw_gid as u32));
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
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

fn managed_header_matches(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .is_some_and(|text| text.starts_with(PEER_MANAGED_HEADER))
}

fn sha256_of_file(file: &mut File, max_bytes: u64) -> std::io::Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "binary exceeds maximum permitted size",
            ));
        }
        hasher.update(&buf[..n]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((digest, total))
}

fn readlink_at(dir: &File, name: &OsStr) -> std::io::Result<OsString> {
    let name_c = c_name(name)?;
    let mut buf = vec![0u8; MAX_PATH_BYTES + 1];
    let len = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = len as usize;
    if len >= buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "symlink target exceeds maximum length",
        ));
    }
    buf.truncate(len);
    Ok(OsStr::from_bytes(&buf).to_os_string())
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_string()).collect()
}

fn map_directory_open_error(display_path: &str, err: std::io::Error) -> PeerTranscodeError {
    if err.kind() == std::io::ErrorKind::NotFound {
        return PeerTranscodeError::NotFound(format!("Directory '{display_path}' does not exist"));
    }
    if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
        || err.kind() == std::io::ErrorKind::InvalidInput
    {
        return PeerTranscodeError::InvalidInput(format!(
            "Refusing symlink or non-directory path '{display_path}': {err}"
        ));
    }
    PeerTranscodeError::Runtime(format!(
        "Cannot safely open directory '{display_path}': {err}"
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Confined Advisory Locking
// ─────────────────────────────────────────────────────────────────────────────

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
) -> Result<(), PeerTranscodeError> {
    let meta = file.metadata().map_err(|err| {
        PeerTranscodeError::Runtime(format!(
            "Cannot stat peer transcode lock {lock_name}: {err}"
        ))
    })?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(PeerTranscodeError::Runtime(format!(
            "Refusing non-regular or hard-linked peer transcode lock {lock_name}"
        )));
    }
    if let Some(uid) = expected_uid {
        if meta.uid() != uid || meta.gid() != 0 {
            return Err(PeerTranscodeError::Runtime(format!(
                "Refusing peer transcode lock {lock_name} not owned by expected uid {uid}:0"
            )));
        }
    }
    let perm = meta.mode() & 0o7777;
    if perm != 0o600 {
        return Err(PeerTranscodeError::Runtime(format!(
            "Refusing peer transcode lock {lock_name} with non-strict mode {perm:04o} (expected 0600)"
        )));
    }
    Ok(())
}

async fn poll_flock_until(
    file: &File,
    lock_op: libc::c_int,
    deadline: Instant,
    busy_message: &str,
) -> Result<(), PeerTranscodeError> {
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
                return Err(PeerTranscodeError::Busy(busy_message.to_string()));
            }
            let remaining = deadline.saturating_duration_since(now);
            tokio::time::sleep(Duration::from_millis(15).min(remaining)).await;
            continue;
        }
        return Err(PeerTranscodeError::Runtime(format!(
            "Failed acquiring peer transcode advisory lock: {err}"
        )));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerTranscodePathsConfig & PeerTranscodeManager
// ─────────────────────────────────────────────────────────────────────────────

/// Injectable filesystem & identity configuration for [`PeerTranscodeManager`].
#[derive(Debug, Clone)]
pub struct PeerTranscodePathsConfig {
    pub fs_root: Option<PathBuf>,
    pub shim_dir: PathBuf,
    pub jellyfin_encoding_xml: PathBuf,
    pub jellyfin_tmp_dir: PathBuf,
    pub jellyfin_cache_dir: PathBuf,
    pub dispatcher_runtime_dir: PathBuf,
    pub worker_runtime_dir: PathBuf,
    pub tmpfiles_dir: PathBuf,
    pub systemd_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub state_dir: PathBuf,
    pub transcode_env_file: PathBuf,
    pub extra_bind_media_roots: Vec<PathBuf>,
    pub transcode_bin_override: Option<PathBuf>,
    pub real_ffprobe_override: Option<PathBuf>,
    pub tunnel_cidr: String,
    pub jellyfin_identity_override: Option<(u32, u32)>,
    pub aetherflow_identity_override: Option<(u32, u32)>,
    pub expected_uid: Option<u32>,
    pub command_timeout: Duration,
    pub mount_command_timeout: Duration,
    pub lock_timeout: Duration,
}

impl Default for PeerTranscodePathsConfig {
    fn default() -> Self {
        Self {
            fs_root: None,
            shim_dir: PathBuf::from(DEFAULT_TRANSCODE_SHIM_DIR),
            jellyfin_encoding_xml: PathBuf::from(DEFAULT_JELLYFIN_ENCODING_XML),
            jellyfin_tmp_dir: PathBuf::from(DEFAULT_JELLYFIN_TMP_DIR),
            jellyfin_cache_dir: PathBuf::from(DEFAULT_JELLYFIN_CACHE_DIR),
            dispatcher_runtime_dir: PathBuf::from(DEFAULT_DISPATCHER_RUNTIME_DIR),
            worker_runtime_dir: PathBuf::from(DEFAULT_WORKER_RUNTIME_DIR),
            tmpfiles_dir: PathBuf::from(DEFAULT_TMPFILES_DIR),
            systemd_dir: PathBuf::from(DEFAULT_PEER_SYSTEMD_DIR),
            exports_dir: PathBuf::from(DEFAULT_PEER_EXPORTS_DIR),
            state_dir: PathBuf::from(DEFAULT_PEER_STATE_DIR),
            transcode_env_file: PathBuf::from(DEFAULT_TRANSCODE_ENV_FILE),
            extra_bind_media_roots: Vec::new(),
            transcode_bin_override: None,
            real_ffprobe_override: None,
            tunnel_cidr: DEFAULT_PEER_TUNNEL_CIDR.to_string(),
            jellyfin_identity_override: None,
            aetherflow_identity_override: None,
            expected_uid: running_as_root().then_some(0),
            command_timeout: COMMAND_TIMEOUT,
            mount_command_timeout: MOUNT_COMMAND_TIMEOUT,
            lock_timeout: TRANSCODE_LOCK_TIMEOUT,
        }
    }
}

impl PeerTranscodePathsConfig {
    /// Builds production configuration reading `AF_PEER_TUNNEL_CIDR` with zero host I/O.
    pub fn from_env() -> Result<Self, PeerTranscodeError> {
        let cidr_raw = env::var("AF_PEER_TUNNEL_CIDR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PEER_TUNNEL_CIDR.to_string());
        let _ = TranscodeTunnelCidr::parse_subnet(&cidr_raw)?;
        Ok(Self {
            tunnel_cidr: cidr_raw,
            ..Self::default()
        })
    }

    /// Builds an isolated configuration rooted at `root` for offline unit/integration tests.
    pub fn isolated(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            fs_root: Some(root.clone()),
            shim_dir: root.join(DEFAULT_TRANSCODE_SHIM_DIR.trim_start_matches('/')),
            jellyfin_encoding_xml: root.join(DEFAULT_JELLYFIN_ENCODING_XML.trim_start_matches('/')),
            jellyfin_tmp_dir: root.join(DEFAULT_JELLYFIN_TMP_DIR.trim_start_matches('/')),
            jellyfin_cache_dir: root.join(DEFAULT_JELLYFIN_CACHE_DIR.trim_start_matches('/')),
            dispatcher_runtime_dir: root
                .join(DEFAULT_DISPATCHER_RUNTIME_DIR.trim_start_matches('/')),
            worker_runtime_dir: root.join(DEFAULT_WORKER_RUNTIME_DIR.trim_start_matches('/')),
            tmpfiles_dir: root.join(DEFAULT_TMPFILES_DIR.trim_start_matches('/')),
            systemd_dir: root.join(DEFAULT_PEER_SYSTEMD_DIR.trim_start_matches('/')),
            exports_dir: root.join(DEFAULT_PEER_EXPORTS_DIR.trim_start_matches('/')),
            state_dir: root.join(DEFAULT_PEER_STATE_DIR.trim_start_matches('/')),
            transcode_env_file: root.join(DEFAULT_TRANSCODE_ENV_FILE.trim_start_matches('/')),
            extra_bind_media_roots: Vec::new(),
            transcode_bin_override: None,
            real_ffprobe_override: None,
            tunnel_cidr: DEFAULT_PEER_TUNNEL_CIDR.to_string(),
            jellyfin_identity_override: None,
            aetherflow_identity_override: None,
            expected_uid: running_as_root().then_some(0),
            command_timeout: COMMAND_TIMEOUT,
            mount_command_timeout: MOUNT_COMMAND_TIMEOUT,
            lock_timeout: TRANSCODE_LOCK_TIMEOUT,
        }
    }
}

/// Manages privileged Peer Clustering transcode operations.
#[derive(Clone)]
pub struct PeerTranscodeManager {
    config: PeerTranscodePathsConfig,
    tunnel_cidr: TranscodeTunnelCidr,
    runner: Arc<dyn CommandRunner>,
    #[cfg(test)]
    st_dev_overrides: HashMap<String, u64>,
}

impl fmt::Debug for PeerTranscodeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerTranscodeManager")
            .field("config", &self.config)
            .field("tunnel_cidr", &self.tunnel_cidr)
            .finish_non_exhaustive()
    }
}

impl PeerTranscodeManager {
    /// Builds the production manager from operator configuration with zero host probes or mutations.
    pub fn from_env() -> Result<Self, PeerTranscodeError> {
        let config = PeerTranscodePathsConfig::from_env()?;
        Self::with_default_runner(config)
    }

    /// Constructs a manager with custom paths and the default `TokioCommandRunner`.
    pub fn with_default_runner(
        config: PeerTranscodePathsConfig,
    ) -> Result<Self, PeerTranscodeError> {
        Self::new(
            config,
            Arc::new(TokioCommandRunner {
                respect_dry_run_env: false,
            }),
        )
    }

    /// Constructs a manager with injected path config and `CommandRunner` for isolated testing.
    pub fn new(
        config: PeerTranscodePathsConfig,
        runner: Arc<dyn CommandRunner>,
    ) -> Result<Self, PeerTranscodeError> {
        let tunnel_cidr = TranscodeTunnelCidr::parse_subnet(&config.tunnel_cidr)?;
        Ok(Self {
            config,
            tunnel_cidr,
            runner,
            #[cfg(test)]
            st_dev_overrides: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_st_dev_overrides(mut self, overrides: HashMap<String, u64>) -> Self {
        self.st_dev_overrides = overrides;
        self
    }

    pub fn config(&self) -> &PeerTranscodePathsConfig {
        &self.config
    }

    fn resolve_host_path(&self, canonical_abs: &str) -> PathBuf {
        match &self.config.fs_root {
            Some(root) => root.join(canonical_abs.trim_start_matches('/')),
            None => PathBuf::from(canonical_abs),
        }
    }

    fn logical_path(&self, disk_path: &Path) -> String {
        if let Some(root) = &self.config.fs_root {
            if let Ok(rel) = disk_path.strip_prefix(root) {
                return format!("/{}", rel.to_string_lossy());
            }
        }
        disk_path.to_string_lossy().into_owned()
    }

    fn ancestor_forbidden_bits(&self) -> u32 {
        if self.config.expected_uid.is_some() || self.config.fs_root.is_none() {
            0o6022
        } else {
            // In non-root isolated fixtures, avoid spurious failures when callers use `create_dir_all`
            // under a `0002` umask, while still rejecting SUID/SGID and world-writable directories.
            0o6002
        }
    }

    fn validate_managed_ancestors(&self, path: &Path) -> Result<(), PeerTranscodeError> {
        let anchor = self
            .config
            .fs_root
            .as_deref()
            .unwrap_or_else(|| Path::new("/"));
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
        let forbidden = self.ancestor_forbidden_bits();
        let mut cursor = anchor.to_path_buf();
        for name in &components[..components.len() - 1] {
            cursor.push(name);
            let Some(anc_dir) = ReceiptDirectory::open_existing(&cursor).map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Refusing unsafe or inaccessible ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?
            else {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Managed ancestor directory {} disappeared",
                    cursor.display()
                )));
            };
            if let Some(uid) = self.config.expected_uid {
                anc_dir.verify_owners(&[uid]).map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "Ancestor directory {} is not owned by expected uid {uid}: {err}",
                        cursor.display()
                    ))
                })?;
            }
            let meta = anc_dir.file().metadata().map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Cannot stat ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?;
            let perm = meta.mode() & 0o7777;
            if perm & forbidden != 0 {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Refusing overly permissive ancestor directory {} (mode {perm:04o})",
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
    ) -> Result<(), PeerTranscodeError> {
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Directory verification failed for {}: {err}",
                path.display()
            ))
        })?;
        if let Some(uid) = self.config.expected_uid {
            dir.verify_owners(&[uid]).map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Directory {} is not owned by expected uid {uid}: {err}",
                    path.display()
                ))
            })?;
        }
        self.validate_managed_ancestors(path)?;
        let meta = dir.file().metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Cannot stat directory {}: {err}", path.display()))
        })?;
        if !meta.is_dir() {
            return Err(PeerTranscodeError::Runtime(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        let effective_forbidden =
            if self.config.expected_uid.is_none() && self.config.fs_root.is_some() {
                forbidden_bits & !0o0020
            } else {
                forbidden_bits
            };
        let perm = meta.mode() & 0o7777;
        if perm & effective_forbidden != 0 {
            return Err(PeerTranscodeError::Runtime(format!(
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
    ) -> Result<Option<ReceiptDirectory>, PeerTranscodeError> {
        let dir = ReceiptDirectory::open_existing(path).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
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
    ) -> Result<ReceiptDirectory, PeerTranscodeError> {
        if let Some(existing) = self.open_existing_system_dir(path, forbidden_bits)? {
            return Ok(existing);
        }
        let dir = ReceiptDirectory::open_confined(path, true, create_mode).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Refusing unsafe or inaccessible directory {}: {err}",
                path.display()
            ))
        })?;
        enforce_root_ownership_and_mode(dir.file(), create_mode).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
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
    ) -> Result<ReceiptDirectory, PeerTranscodeError> {
        let resolved = self.resolve_host_path(canonical_abs);
        let Some(dir) = ReceiptDirectory::open_existing(&resolved)
            .map_err(|err| map_directory_open_error(canonical_abs, err))?
        else {
            return Err(PeerTranscodeError::NotFound(format!(
                "Directory '{canonical_abs}' does not exist"
            )));
        };
        let meta = dir.file().metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Cannot stat directory '{canonical_abs}': {err}"))
        })?;
        if !meta.is_dir() {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Path '{canonical_abs}' is not a directory"
            )));
        }
        Ok(dir)
    }

    /// Verifies that no existing component along `canonical_abs` is a symlink and that if the
    /// target path already exists, it is a real directory.
    fn verify_mountpoint_no_symlinks(&self, canonical_abs: &str) -> Result<(), PeerTranscodeError> {
        let anchor = self
            .config
            .fs_root
            .as_deref()
            .unwrap_or_else(|| Path::new("/"));
        let mut cursor = anchor.to_path_buf();
        for seg in canonical_abs.trim_start_matches('/').split('/') {
            if seg.is_empty() {
                continue;
            }
            cursor.push(seg);
            match fs::symlink_metadata(&cursor) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(PeerTranscodeError::InvalidInput(format!(
                            "Refusing symlink along mountpoint path '{canonical_abs}'"
                        )));
                    }
                    if !meta.file_type().is_dir() {
                        return Err(PeerTranscodeError::Conflict(format!(
                            "Refusing non-directory entry along mountpoint path '{canonical_abs}'"
                        )));
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Remaining components do not exist yet; systemd creates them safely.
                    break;
                }
                Err(err) => {
                    return Err(PeerTranscodeError::Runtime(format!(
                        "Cannot inspect mountpoint path '{canonical_abs}': {err}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn read_managed_file_checked(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        require_managed_header: bool,
    ) -> Result<Option<Vec<u8>>, PeerTranscodeError> {
        let name_os = OsStr::new(name);
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let mut file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing unsafe or symlinked file '{name}': {err}"
                )));
            }
        };
        let meta = file.metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Cannot stat managed file '{name}': {err}"))
        })?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(PeerTranscodeError::Conflict(format!(
                "Refusing non-regular or hard-linked file '{name}'"
            )));
        }
        if let Some(uid) = self.config.expected_uid {
            if meta.uid() != uid {
                return Err(PeerTranscodeError::UnmanagedFile(format!(
                    "Refusing file '{name}' not owned by expected uid {uid}"
                )));
            }
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_MANAGED_FILE_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!("Failed reading managed file '{name}': {err}"))
            })?;
        if bytes.len() > MAX_MANAGED_FILE_BYTES {
            return Err(PeerTranscodeError::UnmanagedFile(format!(
                "File '{name}' exceeds managed file size limit"
            )));
        }
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Managed file identity verification failed for '{name}': {err}"
            ))
        })?;
        if require_managed_header && !managed_header_matches(&bytes) {
            return Err(PeerTranscodeError::UnmanagedFile(format!(
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
    ) -> Result<(), PeerTranscodeError> {
        let name_os = OsStr::new(name);
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let previous = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(mut file) => {
                if let Some(uid) = self.config.expected_uid {
                    let meta = file.metadata().map_err(|err| {
                        PeerTranscodeError::Runtime(format!("Cannot stat existing '{name}': {err}"))
                    })?;
                    if meta.uid() != uid {
                        return Err(PeerTranscodeError::UnmanagedFile(format!(
                            "Refusing to overwrite '{name}' not owned by expected uid {uid}"
                        )));
                    }
                }
                let mut existing_prefix = Vec::new();
                Read::by_ref(&mut file)
                    .take((PEER_MANAGED_HEADER.len() as u64).saturating_add(16))
                    .read_to_end(&mut existing_prefix)
                    .map_err(|err| {
                        PeerTranscodeError::Runtime(format!(
                            "Failed reading existing '{name}' header: {err}"
                        ))
                    })?;
                if !managed_header_matches(&existing_prefix) {
                    return Err(PeerTranscodeError::UnmanagedFile(format!(
                        "Refusing to overwrite unmanaged host file '{name}' (missing AetherFlow managed header)"
                    )));
                }
                Some(file)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing to overwrite non-regular or symlinked file '{name}': {err}"
                )));
            }
        };

        let tmp_name = format!(".af-peer-transcode.tmp.{}", uuid::Uuid::new_v4().simple());
        let tmp_os = OsStr::new(&tmp_name);
        let mut tmp_file = dir
            .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!(
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
            return Err(PeerTranscodeError::Runtime(format!(
                "Atomic write of '{name}' failed: {err}"
            )));
        }
        Ok(())
    }

    fn delete_managed_file_checked(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
    ) -> Result<Option<Vec<u8>>, PeerTranscodeError> {
        let Some(previous_bytes) = self.read_managed_file_checked(dir, name, true)? else {
            return Ok(None);
        };
        let name_os = OsStr::new(name);
        let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing to remove unsafe or symlinked file '{name}': {err}"
                )));
            }
        };
        if let Some(uid) = self.config.expected_uid {
            let meta = file.metadata().map_err(|err| {
                PeerTranscodeError::Runtime(format!("Cannot stat '{name}' before deletion: {err}"))
            })?;
            if meta.uid() != uid {
                return Err(PeerTranscodeError::UnmanagedFile(format!(
                    "Refusing to remove '{name}' not owned by expected uid {uid}"
                )));
            }
        }
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerTranscodeError::Conflict(format!(
                "Refusing to remove non-regular file '{name}': {err}"
            ))
        })?;
        let name_c = c_name(name_os).map_err(|err| {
            PeerTranscodeError::Runtime(format!("Invalid filename '{name}': {err}"))
        })?;
        if unsafe { libc::unlinkat(dir.file().as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(PeerTranscodeError::Runtime(format!(
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
    ) -> Result<(), PeerTranscodeError> {
        match previous {
            Some(bytes) => self.write_managed_file_atomic(dir, name, bytes, mode),
            None => self.delete_managed_file_checked(dir, name).map(|_| ()),
        }
    }

    async fn acquire_transcode_write_locks(
        &self,
        create_state_dir: bool,
    ) -> Result<(OwnedRwLockWriteGuard<()>, Option<ConfinedLockGuard>), PeerTranscodeError> {
        const BUSY: &str = "Another peer transcode operation is in progress; retry shortly";
        let deadline = Instant::now() + self.config.lock_timeout;
        let lock = peer_transcode_lock_for(&self.config.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.write_owned())
            .await
            .map_err(|_| PeerTranscodeError::Busy(BUSY.to_string()))?;

        let dir_opt = if create_state_dir {
            Some(self.ensure_system_dir(&self.config.state_dir, 0o750, 0o7027)?)
        } else {
            self.open_existing_system_dir(&self.config.state_dir, 0o7027)?
        };
        let Some(dir) = dir_opt else {
            return Ok((mem_guard, None));
        };
        let file_guard = self
            .open_and_lock_exclusive(dir, PEER_TRANSCODE_LOCK_FILE_NAME, deadline, BUSY)
            .await?;
        Ok((mem_guard, Some(file_guard)))
    }

    async fn acquire_transcode_read_locks(
        &self,
    ) -> Result<(OwnedRwLockReadGuard<()>, Option<ConfinedLockGuard>), PeerTranscodeError> {
        const BUSY: &str = "Peer transcode configuration is busy; retry shortly";
        let deadline = Instant::now() + self.config.lock_timeout;
        let lock = peer_transcode_lock_for(&self.config.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.read_owned())
            .await
            .map_err(|_| PeerTranscodeError::Busy(BUSY.to_string()))?;

        let Some(dir) = self.open_existing_system_dir(&self.config.state_dir, 0o7027)? else {
            return Ok((mem_guard, None));
        };
        let name_os = OsStr::new(PEER_TRANSCODE_LOCK_FILE_NAME);
        let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((mem_guard, None)),
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Refusing unsafe peer transcode lock {PEER_TRANSCODE_LOCK_FILE_NAME}: {err}"
                )));
            }
        };
        validate_lock_file_metadata(
            &file,
            PEER_TRANSCODE_LOCK_FILE_NAME,
            self.config.expected_uid,
        )?;
        poll_flock_until(&file, libc::LOCK_SH, deadline, BUSY).await?;
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Peer transcode lock directory verification failed: {err}"
            ))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Peer transcode lock identity changed during acquisition: {err}"
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
    ) -> Result<ConfinedLockGuard, PeerTranscodeError> {
        let name_os = OsStr::new(lock_name);
        let (file, created) = match dir.open_file(name_os, libc::O_RDWR, 0) {
            Ok(file) => (file, false),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match dir.open_file(name_os, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) {
                    Ok(file) => (file, true),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        let file = dir.open_file(name_os, libc::O_RDWR, 0).map_err(|e| {
                            PeerTranscodeError::Runtime(format!(
                                "Refusing unsafe peer transcode lock {lock_name}: {e}"
                            ))
                        })?;
                        (file, false)
                    }
                    Err(err) => {
                        return Err(PeerTranscodeError::Runtime(format!(
                            "Failed creating peer transcode lock {lock_name}: {err}"
                        )));
                    }
                }
            }
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Refusing unsafe peer transcode lock {lock_name}: {err}"
                )));
            }
        };
        if created {
            enforce_root_ownership_and_mode(&file, 0o600).map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Failed securing newly created peer transcode lock {lock_name}: {err}"
                ))
            })?;
        }
        validate_lock_file_metadata(&file, lock_name, self.config.expected_uid)?;
        poll_flock_until(&file, libc::LOCK_EX, deadline, busy_message).await?;
        dir.verify().map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Peer transcode lock directory verification failed: {err}"
            ))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Peer transcode lock {lock_name} identity changed during acquisition: {err}"
            ))
        })?;
        validate_lock_file_metadata(&file, lock_name, self.config.expected_uid)?;
        Ok(ConfinedLockGuard { _dir: dir, file })
    }

    async fn run_command_with_timeout(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<CommandOutput, PeerTranscodeError> {
        let cancel = CancellationToken::new();
        let mut fut = self.runner.run_command(program, args, &[], &cancel);
        tokio::select! {
            res = &mut fut => {
                res.map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "{program} execution failed: {}",
                        redact_secrets(&err.to_string())
                    ))
                })
            }
            _ = tokio::time::sleep(timeout) => {
                cancel.cancel();
                let _ = fut.await;
                Err(PeerTranscodeError::Runtime(format!(
                    "{program} timed out after {}s",
                    timeout.as_secs()
                )))
            }
        }
    }

    async fn run_checked_with_timeout(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<CommandOutput, PeerTranscodeError> {
        let out = self
            .run_command_with_timeout(program, args, timeout)
            .await?;
        if !out.success() {
            let detail_raw = if !out.stderr.trim().is_empty() {
                out.stderr.trim()
            } else {
                out.stdout.trim()
            };
            let detail: String = redact_secrets(detail_raw).chars().take(512).collect();
            if detail.is_empty() {
                return Err(PeerTranscodeError::Runtime(format!(
                    "{program} failed with exit code {}",
                    out.exit_code
                )));
            }
            return Err(PeerTranscodeError::Runtime(format!(
                "{program} failed (exit {}): {detail}",
                out.exit_code
            )));
        }
        Ok(out)
    }

    fn resolve_jellyfin_identity(&self) -> Option<(u32, u32)> {
        if let Some(id) = self.config.jellyfin_identity_override {
            return Some(id);
        }
        lookup_passwd_uid_gid_reentrant("jellyfin")
    }

    fn resolve_aetherflow_uid(&self) -> Option<u32> {
        if let Some((uid, _)) = self.config.aetherflow_identity_override {
            return Some(uid);
        }
        lookup_passwd_uid_gid_reentrant("aetherflow").map(|(uid, _)| uid)
    }

    fn resolve_jellyfin_gid(&self) -> Option<u32> {
        if let Some((_, gid)) = self.config.jellyfin_identity_override {
            return Some(gid);
        }
        lookup_group_gid("jellyfin")
            .or_else(|| lookup_passwd_uid_gid_reentrant("jellyfin").map(|(_, gid)| gid))
    }

    fn resolve_verified_transcode_binary(&self) -> Result<PathBuf, PeerTranscodeError> {
        if let Some(ref explicit) = self.config.transcode_bin_override {
            validate_transcode_binary_file(explicit)?;
            return Ok(explicit.clone());
        }
        let Some(candidate) = crate::resolve_af_transcode_binary() else {
            return Err(PeerTranscodeError::NotFound(
                "Verified af-transcode binary not found in release bundle or AETHERFLOW_TRANSCODE_BIN"
                    .to_string(),
            ));
        };
        validate_transcode_binary_file(&candidate)?;
        Ok(candidate)
    }

    fn resolve_validated_real_ffprobe(&self) -> Result<(PathBuf, PathBuf), PeerTranscodeError> {
        if let Some(ref explicit) = self.config.real_ffprobe_override {
            validate_real_ffprobe_file(explicit, &self.config.shim_dir)?;
            return Ok((explicit.clone(), explicit.clone()));
        }
        if let Ok(real_ffmpeg) = env::var("AF_TRANSCODE_REAL_FFMPEG") {
            let trimmed = real_ffmpeg.trim();
            if !trimmed.is_empty() {
                let ffmpeg_path = Path::new(trimmed);
                if let Some(parent) = ffmpeg_path.parent() {
                    let logical = parent.join("ffprobe");
                    let disk = if self.config.fs_root.is_some() && !logical.exists() {
                        self.resolve_host_path(&logical.to_string_lossy())
                    } else {
                        logical.clone()
                    };
                    validate_real_ffprobe_file(&disk, &self.config.shim_dir)?;
                    return Ok((disk, logical));
                }
            }
        }
        let logical = PathBuf::from(DEFAULT_REAL_FFPROBE_PATH);
        let disk = self.resolve_host_path(DEFAULT_REAL_FFPROBE_PATH);
        validate_real_ffprobe_file(&disk, &self.config.shim_dir)?;
        Ok((disk, logical))
    }

    fn read_jellyfin_transcoding_temp_path(&self) -> Result<String, PeerTranscodeError> {
        let xml_path = &self.config.jellyfin_encoding_xml;
        let Some(parent) = xml_path.parent() else {
            return Ok(DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string());
        };
        let Some(file_name) = xml_path.file_name() else {
            return Ok(DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string());
        };
        let Some(dir) = ReceiptDirectory::open_existing(parent).map_err(|err| {
            PeerTranscodeError::InvalidInput(format!(
                "Refusing unsafe Jellyfin config directory {}: {err}",
                parent.display()
            ))
        })?
        else {
            return Ok(DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string());
        };
        let mut file = match dir.open_file(file_name, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string());
            }
            Err(err) => {
                return Err(PeerTranscodeError::InvalidInput(format!(
                    "Refusing unsafe or symlinked encoding.xml: {err}"
                )));
            }
        };
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_ENCODING_XML_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!("Failed reading Jellyfin encoding.xml: {err}"))
            })?;
        if bytes.len() > MAX_ENCODING_XML_BYTES {
            return Err(PeerTranscodeError::InvalidInput(
                "Jellyfin encoding.xml exceeds maximum permitted size".to_string(),
            ));
        }
        let xml = String::from_utf8(bytes).map_err(|_| {
            PeerTranscodeError::InvalidInput("Jellyfin encoding.xml is not valid UTF-8".to_string())
        })?;
        Ok(parse_jellyfin_transcoding_temp_path(&xml)?
            .unwrap_or_else(|| DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string()))
    }

    async fn acquire_unit_locks(
        &self,
        unit_names: &[&str],
    ) -> Result<Vec<OwnedMutexGuard<()>>, PeerTranscodeError> {
        const BUSY: &str =
            "Another operation on the same peer transcode unit is in progress; retry shortly";
        let sorted: BTreeSet<&str> = unit_names.iter().copied().collect();
        let deadline = Instant::now() + self.config.lock_timeout;
        let mut guards = Vec::with_capacity(sorted.len());
        for unit in sorted {
            let lock = peer_transcode_unit_lock_for(&self.config.state_dir, unit);
            let guard = tokio::time::timeout_at(deadline, lock.lock_owned())
                .await
                .map_err(|_| PeerTranscodeError::Busy(BUSY.to_string()))?;
            guards.push(guard);
        }
        Ok(guards)
    }

    async fn acquire_unit_lock(
        &self,
        unit_name: &str,
    ) -> Result<OwnedMutexGuard<()>, PeerTranscodeError> {
        let mut guards = self.acquire_unit_locks(&[unit_name]).await?;
        guards.pop().ok_or_else(|| {
            PeerTranscodeError::Runtime("Failed acquiring peer transcode unit lock".to_string())
        })
    }

    fn transcode_env_logical_path(&self) -> Result<String, PeerTranscodeError> {
        let logical = self.logical_path(&self.config.transcode_env_file);
        if logical.is_empty()
            || !logical.starts_with('/')
            || logical.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Invalid transcode environment file path '{logical}'"
            )));
        }
        Ok(logical)
    }

    /// Idempotently creates the secret-free transcode environment file (default
    /// `/etc/aetherflow/transcode.env`, `0640 root:jellyfin` when root and `jellyfin` group
    /// exists, else `0640`) if it does not already exist. Never overwrites operator edits and
    /// refuses symlinks or hard-linked targets.
    pub fn ensure_transcode_env_file(&self) -> Result<bool, PeerTranscodeError> {
        let env_path = &self.config.transcode_env_file;
        let _ = self.transcode_env_logical_path()?;
        let Some(parent) = env_path.parent() else {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Transcode environment file '{}' has no parent directory",
                env_path.display()
            )));
        };
        let Some(file_name) = env_path.file_name() else {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Transcode environment file '{}' has no filename",
                env_path.display()
            )));
        };

        let parent_dir = self.ensure_system_dir(parent, 0o755, 0o6022)?;
        match entry_at(parent_dir.file(), file_name) {
            Ok(st) => {
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 1 {
                    return Err(PeerTranscodeError::Conflict(format!(
                        "Refusing symlink, non-regular, or hard-linked transcode env file '{}'",
                        env_path.display()
                    )));
                }
                return Ok(false);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Cannot stat transcode env file '{}': {err}",
                    env_path.display()
                )));
            }
        }

        let tmp_name = format!(".af-transcode-env.tmp.{}", uuid::Uuid::new_v4().simple());
        let tmp_os = OsStr::new(&tmp_name);
        let mut tmp_file = parent_dir
            .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Failed creating temporary transcode env file '{}': {err}",
                    env_path.display()
                ))
            })?;

        let parent_fd = parent_dir.file().as_raw_fd();
        let jellyfin_gid = self.resolve_jellyfin_gid();
        let mut appeared_concurrently = false;
        let write_res = (|| -> std::io::Result<()> {
            tmp_file.write_all(render_default_transcode_env_file().as_bytes())?;
            if running_as_root() {
                let target_gid = jellyfin_gid.unwrap_or(0);
                if unsafe { libc::fchown(tmp_file.as_raw_fd(), 0, target_gid) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if unsafe { libc::fchmod(tmp_file.as_raw_fd(), 0o640) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            tmp_file.sync_all()?;
            parent_dir.verify()?;
            verify_entry(parent_dir.file(), tmp_os, &tmp_file, false)?;
            match entry_at(parent_dir.file(), file_name) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Ok(st) if (st.st_mode & libc::S_IFMT) == libc::S_IFREG && st.st_nlink == 1 => {
                    appeared_concurrently = true;
                    return Ok(());
                }
                _ => {
                    return Err(std::io::Error::other(
                        "non-regular transcode env file appeared concurrently",
                    ));
                }
            }
            if unsafe {
                libc::renameat(
                    parent_fd,
                    c_name(tmp_os)?.as_ptr(),
                    parent_fd,
                    c_name(file_name)?.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            parent_dir.verify()?;
            verify_entry(parent_dir.file(), file_name, &tmp_file, false)?;
            parent_dir.file().sync_all()
        })();

        if appeared_concurrently || write_res.is_err() {
            if let Ok(tmp_c) = c_name(tmp_os) {
                unsafe {
                    libc::unlinkat(parent_fd, tmp_c.as_ptr(), 0);
                }
            }
        }
        write_res.map_err(|err| {
            PeerTranscodeError::Runtime(format!(
                "Failed writing transcode env file '{}': {err}",
                env_path.display()
            ))
        })?;
        Ok(!appeared_concurrently)
    }

    fn ensure_api_transcode_dropin_locked(
        &self,
        transcode_env_path: &str,
    ) -> Result<(ReceiptDirectory, Option<Vec<u8>>, bool), PeerTranscodeError> {
        let dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{API_SERVICE_UNIT}.d"));
        let dropin_dir = self.ensure_system_dir(&dropin_dir_path, 0o755, 0o6022)?;
        let previous =
            self.read_managed_file_checked(&dropin_dir, API_TRANSCODE_DROPIN_NAME, true)?;
        let rendered = render_api_transcode_dropin(transcode_env_path);
        let unchanged = previous
            .as_deref()
            .is_some_and(|prev| prev == rendered.as_bytes());
        if !unchanged {
            self.write_managed_file_atomic(
                &dropin_dir,
                API_TRANSCODE_DROPIN_NAME,
                rendered.as_bytes(),
                0o644,
            )?;
        }
        Ok((dropin_dir, previous, !unchanged))
    }

    fn ensure_runner_transcode_dropin_locked(
        &self,
        transcode_env_path: &str,
    ) -> Result<(ReceiptDirectory, Option<Vec<u8>>, bool), PeerTranscodeError> {
        let dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{RUNNER_SERVICE_UNIT}.d"));
        let dropin_dir = self.ensure_system_dir(&dropin_dir_path, 0o755, 0o6022)?;
        let previous =
            self.read_managed_file_checked(&dropin_dir, RUNNER_TRANSCODE_DROPIN_NAME, true)?;
        let rendered = render_runner_transcode_dropin(transcode_env_path);
        let unchanged = previous
            .as_deref()
            .is_some_and(|prev| prev == rendered.as_bytes());
        if !unchanged {
            self.write_managed_file_atomic(
                &dropin_dir,
                RUNNER_TRANSCODE_DROPIN_NAME,
                rendered.as_bytes(),
                0o644,
            )?;
        }
        Ok((dropin_dir, previous, !unchanged))
    }

    fn is_dispatcher_installed_locked(&self) -> Result<bool, PeerTranscodeError> {
        if let Some(tmpfiles_dir) =
            self.open_existing_system_dir(&self.config.tmpfiles_dir, 0o6022)?
        {
            if entry_at(
                tmpfiles_dir.file(),
                OsStr::new(TRANSCODE_TMPFILES_CONF_NAME),
            )
            .is_ok()
            {
                return Ok(true);
            }
        }
        match ReceiptDirectory::open_existing(&self.config.dispatcher_runtime_dir) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(err) => Err(PeerTranscodeError::Conflict(format!(
                "Refusing unsafe dispatcher runtime directory {}: {err}",
                self.config.dispatcher_runtime_dir.display()
            ))),
        }
    }

    fn is_worker_unit_installed_locked(&self) -> bool {
        match ReceiptDirectory::open_existing(&self.config.systemd_dir) {
            Ok(Some(dir)) => self
                .read_managed_file_checked(&dir, PEER_TRANSCODE_WORKER_UNIT, true)
                .ok()
                .flatten()
                .is_some(),
            _ => false,
        }
    }

    fn collect_managed_worker_rw_paths_locked(
        &self,
        systemd_dir: &ReceiptDirectory,
    ) -> Result<BTreeSet<String>, PeerTranscodeError> {
        let mut rw_paths = BTreeSet::new();
        let entries = match fs::read_dir(&self.config.systemd_dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(rw_paths),
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Cannot scan systemd directory {}: {err}",
                    self.config.systemd_dir.display()
                )));
            }
        };
        for entry_res in entries {
            let Ok(entry) = entry_res else {
                continue;
            };
            let file_name_os = entry.file_name();
            let Some(file_name) = file_name_os.to_str() else {
                continue;
            };
            if !file_name.ends_with(".mount") {
                continue;
            }
            if let Ok(Some(bytes)) = self.read_managed_file_checked(systemd_dir, file_name, false) {
                if let Some(where_path) = extract_managed_worker_rw_path(&bytes) {
                    rw_paths.insert(where_path);
                }
            }
        }
        Ok(rw_paths)
    }

    /// Synchronizes `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf` from all
    /// currently managed transcode NFS `.mount` units and writable bind `.mount` units.
    /// Returns `Ok(true)` if the drop-in was created, updated, or removed.
    fn sync_worker_transcode_paths_dropin_locked(
        &self,
        systemd_dir: &ReceiptDirectory,
    ) -> Result<bool, PeerTranscodeError> {
        let rw_paths = self.collect_managed_worker_rw_paths_locked(systemd_dir)?;
        let dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{PEER_TRANSCODE_WORKER_UNIT}.d"));
        if rw_paths.is_empty() {
            let Some(dropin_dir) = self.open_existing_system_dir(&dropin_dir_path, 0o6022)? else {
                return Ok(false);
            };
            let removed = self
                .delete_managed_file_checked(&dropin_dir, WORKER_TRANSCODE_PATHS_DROPIN_NAME)?
                .is_some();
            return Ok(removed);
        }
        let dropin_dir = self.ensure_system_dir(&dropin_dir_path, 0o755, 0o6022)?;
        let prev =
            self.read_managed_file_checked(&dropin_dir, WORKER_TRANSCODE_PATHS_DROPIN_NAME, true)?;
        let rendered = render_worker_transcode_paths_dropin(&rw_paths);
        if prev.as_deref() == Some(rendered.as_bytes()) {
            return Ok(false);
        }
        self.write_managed_file_atomic(
            &dropin_dir,
            WORKER_TRANSCODE_PATHS_DROPIN_NAME,
            rendered.as_bytes(),
            0o644,
        )?;
        Ok(true)
    }

    /// Restarts `af-transcode-worker.service` ONLY if its managed unit is installed AND currently
    /// active. Callers must NOT hold any mount unit lock when calling this method.
    async fn maybe_restart_active_worker(&self) -> Result<(), PeerTranscodeError> {
        let _worker_guard = self.acquire_unit_lock(PEER_TRANSCODE_WORKER_UNIT).await?;
        let installed = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_read_locks().await?;
            self.is_worker_unit_installed_locked()
        };
        if !installed {
            return Ok(());
        }
        let is_active = match self
            .run_command_with_timeout(
                "systemctl",
                &strings(&["is-active", PEER_TRANSCODE_WORKER_UNIT]),
                self.config.command_timeout,
            )
            .await
        {
            Ok(out) => out.success() && out.stdout.trim() == "active",
            Err(_) => false,
        };
        if is_active {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["restart", PEER_TRANSCODE_WORKER_UNIT]),
                    self.config.mount_command_timeout,
                )
                .await?;
        }
        Ok(())
    }

    /// Enforces the worker-side allowlist for `MountTranscodeDirs` and `RemoveTranscodeMounts`:
    /// every path must match one of the worker's own inspected Jellyfin cache/transcode/tmp
    /// directories OR be a direct subdirectory inside `/var/cache/jellyfin/`.
    fn validate_worker_transcode_mount_path(
        &self,
        canonical_path: &str,
    ) -> Result<(), PeerTranscodeError> {
        let configured_temp = self.read_jellyfin_transcoding_temp_path()?;
        let tmp_dir = self.logical_path(&self.config.jellyfin_tmp_dir);
        let cache_dir = self.logical_path(&self.config.jellyfin_cache_dir);
        let exact_allowed = [
            configured_temp.as_str(),
            tmp_dir.as_str(),
            cache_dir.as_str(),
            DEFAULT_JELLYFIN_CACHE_DIR,
            DEFAULT_JELLYFIN_TRANSCODE_DIR,
            DEFAULT_JELLYFIN_TMP_DIR,
        ];
        if exact_allowed.contains(&canonical_path) {
            return Ok(());
        }
        if let Some(sub) = canonical_path.strip_prefix(&format!("{DEFAULT_JELLYFIN_CACHE_DIR}/")) {
            if !sub.is_empty() && !sub.contains('/') && sub != "." && sub != ".." {
                return Ok(());
            }
        }
        Err(PeerTranscodeError::InvalidInput(format!(
            "Transcode mount path '{canonical_path}' is outside the worker Jellyfin cache/transcode allowlist"
        )))
    }

    /// Enforces the explicit allowlist on controller-holds-media `BindMedia` target paths (`to`
    /// outside `/mnt/af-peers/`).
    fn validate_bind_media_target_allowlist(
        &self,
        canonical_to: &str,
    ) -> Result<(), PeerTranscodeError> {
        if has_sensitive_dot_segment(canonical_to) {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Refusing sensitive bind target path '{canonical_to}'"
            )));
        }
        for extra in &self.config.extra_bind_media_roots {
            if let Some(norm) = normalize_allowed_root_entry(&extra.to_string_lossy()) {
                if canonical_to == norm || is_strict_descendant_path(canonical_to, &norm) {
                    return Ok(());
                }
            }
        }
        let env_raw = env::var("AF_ALLOWED_FS_ROOTS").ok();
        if let Some(env_roots) = parse_allowed_bind_media_roots_env(env_raw.as_deref()) {
            if env_roots
                .iter()
                .any(|root| canonical_to == root || is_strict_descendant_path(canonical_to, root))
            {
                return Ok(());
            }
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Bind target '{canonical_to}' is outside allowed AF_ALLOWED_FS_ROOTS media roots"
            )));
        }
        if DEFAULT_BIND_MEDIA_ROOTS
            .iter()
            .any(|root| is_strict_descendant_path(canonical_to, root))
        {
            return Ok(());
        }
        Err(PeerTranscodeError::InvalidInput(format!(
            "Bind target '{canonical_to}' is outside allowed media roots"
        )))
    }

    fn dir_has_entries(&self, canonical_abs: &str) -> Result<bool, PeerTranscodeError> {
        let resolved = self.resolve_host_path(canonical_abs);
        match fs::read_dir(&resolved) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(PeerTranscodeError::Runtime(format!(
                "Cannot inspect directory '{canonical_abs}': {err}"
            ))),
            Ok(mut iter) => match iter.next() {
                None => Ok(false),
                Some(Ok(_)) => Ok(true),
                Some(Err(err)) => Err(PeerTranscodeError::Runtime(format!(
                    "Cannot read entries of directory '{canonical_abs}': {err}"
                ))),
            },
        }
    }

    fn resolve_dir_st_dev(
        &self,
        canonical_abs: &str,
        dir: &ReceiptDirectory,
    ) -> Result<u64, PeerTranscodeError> {
        #[cfg(test)]
        if let Some(&dev) = self.st_dev_overrides.get(canonical_abs) {
            return Ok(dev);
        }
        let meta = dir.file().metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Cannot stat directory '{canonical_abs}': {err}"))
        })?;
        Ok(meta.dev())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Read-only inspection of Jellyfin transcode paths, shim/drop-in/worker state, and UID/GID.
    pub async fn inspect_jellyfin_paths(
        &self,
    ) -> Result<JellyfinTranscodePaths, PeerTranscodeError> {
        let (
            transcoding_temp_path,
            tmp_dir,
            cache_dir,
            shim_path,
            shim_installed,
            dropin_enabled,
            worker_unit_installed,
            jellyfin_uid,
            jellyfin_gid,
        ) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_read_locks().await?;

            let transcoding_temp_path = self.read_jellyfin_transcoding_temp_path()?;
            let tmp_dir = self.logical_path(&self.config.jellyfin_tmp_dir);
            let cache_dir = self.logical_path(&self.config.jellyfin_cache_dir);
            let shim_disk = self.config.shim_dir.join("ffmpeg");
            let shim_path = self.logical_path(&shim_disk);

            let shim_installed = match ReceiptDirectory::open_existing(&self.config.shim_dir) {
                Ok(Some(dir)) => {
                    let ffmpeg_ok = match entry_at(dir.file(), OsStr::new("ffmpeg")) {
                        Ok(st) => {
                            (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                                && (st.st_mode & 0o111) != 0
                                && (st.st_mode & 0o002) == 0
                        }
                        Err(_) => false,
                    };
                    let ffprobe_ok = match entry_at(dir.file(), OsStr::new("ffprobe")) {
                        Ok(st) => (st.st_mode & libc::S_IFMT) == libc::S_IFLNK,
                        Err(_) => false,
                    };
                    ffmpeg_ok && ffprobe_ok
                }
                _ => false,
            };

            let dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{JELLYFIN_SERVICE_UNIT}.d"));
            let dropin_enabled = match ReceiptDirectory::open_existing(&dropin_dir_path) {
                Ok(Some(dir)) => {
                    match self.read_managed_file_checked(&dir, JELLYFIN_TRANSCODE_DROPIN_NAME, true)
                    {
                        Ok(Some(bytes)) => std::str::from_utf8(&bytes)
                            .ok()
                            .is_some_and(|text| text.contains("Environment=JELLYFIN_FFMPEG=")),
                        _ => false,
                    }
                }
                _ => false,
            };

            let worker_unit_installed = self.is_worker_unit_installed_locked();
            let (jellyfin_uid, jellyfin_gid) = match self.resolve_jellyfin_identity() {
                Some((u, g)) => (Some(u), Some(g)),
                None => (None, None),
            };

            (
                transcoding_temp_path,
                tmp_dir,
                cache_dir,
                shim_path,
                shim_installed,
                dropin_enabled,
                worker_unit_installed,
                jellyfin_uid,
                jellyfin_gid,
            )
        };

        let worker_unit_active = if worker_unit_installed {
            match self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["is-active", PEER_TRANSCODE_WORKER_UNIT]),
                    self.config.command_timeout,
                )
                .await
            {
                Ok(out) => out.success() && out.stdout.trim() == "active",
                Err(_) => false,
            }
        } else {
            false
        };

        Ok(JellyfinTranscodePaths {
            transcoding_temp_path,
            tmp_dir,
            cache_dir,
            shim_path,
            shim_installed,
            dropin_enabled,
            worker_unit_installed,
            worker_unit_active,
            jellyfin_uid,
            jellyfin_gid,
        })
    }

    /// Ensures `/run/aetherflow-transcode` (`0750`, `aetherflow:jellyfin` when root),
    /// `/etc/aetherflow/transcode.env`, `/etc/tmpfiles.d/aetherflow-transcode.conf`,
    /// `aetherflow-api.service.d/20-aetherflow-transcode.conf`, and
    /// `aetherflow-runner.service.d/20-aetherflow-transcode.conf`.
    pub async fn ensure_dispatcher_dir(
        &self,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let transcode_env_logical = self.transcode_env_logical_path()?;
        let _unit_guard = self.acquire_unit_lock(API_SERVICE_UNIT).await?;

        let (
            changed,
            api_dropin_changed,
            tmpfiles_changed,
            runner_dropin_changed,
            prev_tmpfiles,
            prev_api_dropin,
            prev_runner_dropin,
        ) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;

            // Pre-validate existing managed files before mutating anything.
            let tmpfiles_dir = self.ensure_system_dir(&self.config.tmpfiles_dir, 0o755, 0o6022)?;
            let prev_tmpfiles =
                self.read_managed_file_checked(&tmpfiles_dir, TRANSCODE_TMPFILES_CONF_NAME, true)?;
            let api_dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{API_SERVICE_UNIT}.d"));
            let api_dropin_dir = self.ensure_system_dir(&api_dropin_dir_path, 0o755, 0o6022)?;
            let prev_api_dropin =
                self.read_managed_file_checked(&api_dropin_dir, API_TRANSCODE_DROPIN_NAME, true)?;
            let runner_dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{RUNNER_SERVICE_UNIT}.d"));
            let runner_dropin_dir =
                self.ensure_system_dir(&runner_dropin_dir_path, 0o755, 0o6022)?;
            let prev_runner_dropin = self.read_managed_file_checked(
                &runner_dropin_dir,
                RUNNER_TRANSCODE_DROPIN_NAME,
                true,
            )?;

            let env_created = self.ensure_transcode_env_file()?;

            // Ensure dispatcher runtime directory safely without following symlinks.
            let existed = ReceiptDirectory::open_existing(&self.config.dispatcher_runtime_dir)
                .map_err(|err| {
                    PeerTranscodeError::Conflict(format!(
                        "Refusing unsafe dispatcher runtime directory {}: {err}",
                        self.config.dispatcher_runtime_dir.display()
                    ))
                })?
                .is_some();
            let runtime_dir =
                ReceiptDirectory::open_confined(&self.config.dispatcher_runtime_dir, true, 0o750)
                    .map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "Failed ensuring dispatcher runtime directory {}: {err}",
                        self.config.dispatcher_runtime_dir.display()
                    ))
                })?;
            let mut dir_changed = !existed;
            let before_meta = runtime_dir.file().metadata().map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Cannot stat dispatcher runtime directory: {err}"
                ))
            })?;
            if running_as_root() {
                let af_uid = self.resolve_aetherflow_uid().ok_or_else(|| {
                    PeerTranscodeError::NotFound(
                        "System user 'aetherflow' is required for dispatcher runtime directory"
                            .to_string(),
                    )
                })?;
                let jf_gid = self.resolve_jellyfin_gid().ok_or_else(|| {
                    PeerTranscodeError::NotFound(
                        "System group 'jellyfin' is required for dispatcher runtime directory"
                            .to_string(),
                    )
                })?;
                if before_meta.uid() != af_uid || before_meta.gid() != jf_gid {
                    if unsafe { libc::fchown(runtime_dir.file().as_raw_fd(), af_uid, jf_gid) } != 0
                    {
                        return Err(PeerTranscodeError::Runtime(format!(
                            "Failed setting aetherflow:jellyfin ownership on dispatcher runtime dir: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                    dir_changed = true;
                }
            }
            if (before_meta.mode() & 0o7777) != 0o750 {
                if unsafe { libc::fchmod(runtime_dir.file().as_raw_fd(), 0o750) } != 0 {
                    return Err(PeerTranscodeError::Runtime(format!(
                        "Failed setting 0750 mode on dispatcher runtime dir: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                dir_changed = true;
            }

            let tmpfiles_rendered = render_tmpfiles_conf();
            let tmpfiles_changed = prev_tmpfiles.as_deref() != Some(tmpfiles_rendered.as_bytes());
            if tmpfiles_changed {
                self.write_managed_file_atomic(
                    &tmpfiles_dir,
                    TRANSCODE_TMPFILES_CONF_NAME,
                    tmpfiles_rendered.as_bytes(),
                    0o644,
                )?;
            }

            let api_dropin_rendered = render_api_transcode_dropin(&transcode_env_logical);
            let api_dropin_changed =
                prev_api_dropin.as_deref() != Some(api_dropin_rendered.as_bytes());
            if api_dropin_changed {
                if let Err(err) = self.write_managed_file_atomic(
                    &api_dropin_dir,
                    API_TRANSCODE_DROPIN_NAME,
                    api_dropin_rendered.as_bytes(),
                    0o644,
                ) {
                    if tmpfiles_changed {
                        let _ = self.restore_managed_file_after_failure(
                            &tmpfiles_dir,
                            TRANSCODE_TMPFILES_CONF_NAME,
                            prev_tmpfiles.as_deref(),
                            0o644,
                        );
                    }
                    return Err(err);
                }
            }

            let runner_dropin_rendered = render_runner_transcode_dropin(&transcode_env_logical);
            let runner_dropin_changed =
                prev_runner_dropin.as_deref() != Some(runner_dropin_rendered.as_bytes());
            if runner_dropin_changed {
                if let Err(err) = self.write_managed_file_atomic(
                    &runner_dropin_dir,
                    RUNNER_TRANSCODE_DROPIN_NAME,
                    runner_dropin_rendered.as_bytes(),
                    0o644,
                ) {
                    if api_dropin_changed {
                        let _ = self.restore_managed_file_after_failure(
                            &api_dropin_dir,
                            API_TRANSCODE_DROPIN_NAME,
                            prev_api_dropin.as_deref(),
                            0o644,
                        );
                    }
                    if tmpfiles_changed {
                        let _ = self.restore_managed_file_after_failure(
                            &tmpfiles_dir,
                            TRANSCODE_TMPFILES_CONF_NAME,
                            prev_tmpfiles.as_deref(),
                            0o644,
                        );
                    }
                    return Err(err);
                }
            }

            let changed = dir_changed
                || tmpfiles_changed
                || api_dropin_changed
                || runner_dropin_changed
                || env_created;
            (
                changed,
                api_dropin_changed,
                tmpfiles_changed,
                runner_dropin_changed,
                prev_tmpfiles,
                prev_api_dropin,
                prev_runner_dropin,
            )
        };

        if api_dropin_changed || runner_dropin_changed || changed {
            if let Err(reload_err) = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await
            {
                if let Ok((_mem_guard, _file_lock)) =
                    self.acquire_transcode_write_locks(false).await
                {
                    if runner_dropin_changed {
                        if let Ok(Some(dir)) = self.open_existing_system_dir(
                            &self
                                .config
                                .systemd_dir
                                .join(format!("{RUNNER_SERVICE_UNIT}.d")),
                            0o6022,
                        ) {
                            let _ = self.restore_managed_file_after_failure(
                                &dir,
                                RUNNER_TRANSCODE_DROPIN_NAME,
                                prev_runner_dropin.as_deref(),
                                0o644,
                            );
                        }
                    }
                    if api_dropin_changed {
                        if let Ok(Some(dir)) = self.open_existing_system_dir(
                            &self
                                .config
                                .systemd_dir
                                .join(format!("{API_SERVICE_UNIT}.d")),
                            0o6022,
                        ) {
                            let _ = self.restore_managed_file_after_failure(
                                &dir,
                                API_TRANSCODE_DROPIN_NAME,
                                prev_api_dropin.as_deref(),
                                0o644,
                            );
                        }
                    }
                    if tmpfiles_changed {
                        if let Ok(Some(dir)) =
                            self.open_existing_system_dir(&self.config.tmpfiles_dir, 0o6022)
                        {
                            let _ = self.restore_managed_file_after_failure(
                                &dir,
                                TRANSCODE_TMPFILES_CONF_NAME,
                                prev_tmpfiles.as_deref(),
                                0o644,
                            );
                        }
                    }
                }
                return Err(PeerTranscodeError::Runtime(format!(
                    "systemctl daemon-reload failed after configuring dispatcher directory; previous config restored ({reload_err})"
                )));
            }
        }

        Ok(TranscodeMutationReport {
            changed,
            detail: if changed {
                "Configured dispatcher runtime directory, transcode.env, tmpfiles.d rule, and API/runner drop-ins"
                    .to_string()
            } else {
                "Dispatcher runtime directory and drop-ins are already configured".to_string()
            },
            units: vec![
                API_SERVICE_UNIT.to_string(),
                RUNNER_SERVICE_UNIT.to_string(),
            ],
            paths: vec![
                self.logical_path(&self.config.dispatcher_runtime_dir),
                transcode_env_logical,
                format!(
                    "{}/{TRANSCODE_TMPFILES_CONF_NAME}",
                    self.logical_path(&self.config.tmpfiles_dir)
                ),
                format!(
                    "{}/{API_SERVICE_UNIT}.d/{API_TRANSCODE_DROPIN_NAME}",
                    self.logical_path(&self.config.systemd_dir)
                ),
                format!(
                    "{}/{RUNNER_SERVICE_UNIT}.d/{RUNNER_TRANSCODE_DROPIN_NAME}",
                    self.logical_path(&self.config.systemd_dir)
                ),
            ],
            api_restart_required: api_dropin_changed,
        })
    }

    /// Atomically installs the verified `af-transcode` binary as `<shim_dir>/ffmpeg` (`0755`)
    /// and symlinks `<shim_dir>/ffprobe` to the validated real `ffprobe`.
    pub async fn install_shim(&self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let src_bin = self.resolve_verified_transcode_binary()?;
        let (_real_ffprobe_disk, real_ffprobe_target) = self.resolve_validated_real_ffprobe()?;

        let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;
        let shim_dir = self.ensure_system_dir(&self.config.shim_dir, 0o755, 0o6022)?;

        // Open source binary without following a final symlink and re-validate on the open FD.
        let mut src_file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&src_bin)
            .map_err(|err| {
                PeerTranscodeError::InvalidInput(format!(
                    "Cannot safely open af-transcode binary '{}': {err}",
                    src_bin.display()
                ))
            })?;
        let src_meta = src_file.metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Cannot stat af-transcode binary: {err}"))
        })?;
        let src_mode = src_meta.permissions().mode();
        if !src_meta.is_file() || src_mode & 0o111 == 0 || src_mode & 0o002 != 0 {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "af-transcode binary '{}' failed executable/permission safety verification",
                src_bin.display()
            )));
        }
        if src_meta.len() == 0 || src_meta.len() > MAX_SHIM_BINARY_BYTES {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "af-transcode binary '{}' has invalid size ({} bytes)",
                src_bin.display(),
                src_meta.len()
            )));
        }

        // Pre-validate existing target entries so we never replace a symlink at `ffmpeg` or an
        // unmanaged non-symlink file at `ffprobe`.
        let ffmpeg_os = OsStr::new("ffmpeg");
        let ffprobe_os = OsStr::new("ffprobe");

        let existing_ffmpeg = match entry_at(shim_dir.file(), ffmpeg_os) {
            Ok(st) => {
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 1 {
                    return Err(PeerTranscodeError::Conflict(
                        "Refusing to replace symlink, non-regular, or hard-linked file at shim ffmpeg path"
                            .to_string(),
                    ));
                }
                let f = shim_dir
                    .open_file(ffmpeg_os, libc::O_RDONLY, 0)
                    .map_err(|err| {
                        PeerTranscodeError::Conflict(format!(
                            "Refusing unsafe existing shim binary: {err}"
                        ))
                    })?;
                Some(f)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Cannot stat shim ffmpeg entry: {err}"
                )));
            }
        };

        let existing_ffprobe_target = match entry_at(shim_dir.file(), ffprobe_os) {
            Ok(st) => {
                if (st.st_mode & libc::S_IFMT) != libc::S_IFLNK {
                    return Err(PeerTranscodeError::UnmanagedFile(
                        "Refusing to overwrite non-symlink file at shim ffprobe path".to_string(),
                    ));
                }
                Some(readlink_at(shim_dir.file(), ffprobe_os).map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "Cannot read existing shim ffprobe symlink: {err}"
                    ))
                })?)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Cannot stat shim ffprobe entry: {err}"
                )));
            }
        };

        // Read source binary and compute digest.
        let mut src_bytes = Vec::with_capacity(src_meta.len() as usize);
        Read::by_ref(&mut src_file)
            .take(MAX_SHIM_BINARY_BYTES.saturating_add(1))
            .read_to_end(&mut src_bytes)
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!("Failed reading af-transcode binary: {err}"))
            })?;
        if src_bytes.is_empty() || src_bytes.len() as u64 > MAX_SHIM_BINARY_BYTES {
            return Err(PeerTranscodeError::InvalidInput(
                "af-transcode binary size is out of bounds".to_string(),
            ));
        }
        let src_digest: [u8; 32] = Sha256::digest(&src_bytes).into();

        let shim_needs_write = match existing_ffmpeg {
            Some(mut prev_file) => {
                let prev_meta = prev_file.metadata().map_err(|err| {
                    PeerTranscodeError::Runtime(format!("Cannot stat existing shim binary: {err}"))
                })?;
                let mode_ok = (prev_meta.mode() & 0o7777) == 0o755;
                let owner_ok = !running_as_root() || (prev_meta.uid() == 0 && prev_meta.gid() == 0);
                let digest_ok = prev_meta.len() == src_bytes.len() as u64
                    && sha256_of_file(&mut prev_file, MAX_SHIM_BINARY_BYTES)
                        .ok()
                        .is_some_and(|(d, _)| d == src_digest);
                !(mode_ok && owner_ok && digest_ok)
            }
            None => true,
        };

        if shim_needs_write {
            // Re-open existing regular file (if any) to bind inode identity across renameat.
            let prev_bound = match shim_dir.open_file(ffmpeg_os, libc::O_RDONLY, 0) {
                Ok(f) => Some(f),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(PeerTranscodeError::Conflict(format!(
                        "Refusing unsafe existing shim binary: {err}"
                    )));
                }
            };
            let tmp_name = format!(".ffmpeg.tmp.{}", uuid::Uuid::new_v4().simple());
            let tmp_os = OsStr::new(&tmp_name);
            let mut tmp_file = shim_dir
                .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o700)
                .map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "Failed creating temporary shim binary: {err}"
                    ))
                })?;
            let parent_fd = shim_dir.file().as_raw_fd();
            let write_res = (|| -> std::io::Result<()> {
                tmp_file.write_all(&src_bytes)?;
                enforce_root_ownership_and_mode(&tmp_file, 0o755)?;
                tmp_file.sync_all()?;
                shim_dir.verify()?;
                verify_entry(shim_dir.file(), tmp_os, &tmp_file, false)?;
                if let Some(prev) = prev_bound.as_ref() {
                    verify_entry(shim_dir.file(), ffmpeg_os, prev, false)?;
                } else {
                    match entry_at(shim_dir.file(), ffmpeg_os) {
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        _ => {
                            return Err(std::io::Error::other(
                                "shim binary appeared concurrently during installation",
                            ));
                        }
                    }
                }
                if unsafe {
                    libc::renameat(
                        parent_fd,
                        c_name(tmp_os)?.as_ptr(),
                        parent_fd,
                        c_name(ffmpeg_os)?.as_ptr(),
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                shim_dir.verify()?;
                verify_entry(shim_dir.file(), ffmpeg_os, &tmp_file, false)?;
                shim_dir.file().sync_all()
            })();
            if let Err(err) = write_res {
                if let Ok(tmp_c) = c_name(tmp_os) {
                    unsafe {
                        libc::unlinkat(parent_fd, tmp_c.as_ptr(), 0);
                    }
                }
                return Err(PeerTranscodeError::Runtime(format!(
                    "Failed installing transcode shim binary: {err}"
                )));
            }
        }

        let desired_target = real_ffprobe_target.as_os_str();
        let ffprobe_needs_write = existing_ffprobe_target.as_deref() != Some(desired_target);
        if ffprobe_needs_write {
            let tmp_name = format!(".ffprobe.tmp.{}", uuid::Uuid::new_v4().simple());
            let tmp_os = OsStr::new(&tmp_name);
            let parent_fd = shim_dir.file().as_raw_fd();
            let link_res = (|| -> std::io::Result<()> {
                shim_dir.verify()?;
                let target_c = c_name(desired_target)?;
                let tmp_c = c_name(tmp_os)?;
                let dst_c = c_name(ffprobe_os)?;
                if unsafe { libc::symlinkat(target_c.as_ptr(), parent_fd, tmp_c.as_ptr()) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if unsafe { libc::renameat(parent_fd, tmp_c.as_ptr(), parent_fd, dst_c.as_ptr()) }
                    != 0
                {
                    let err = std::io::Error::last_os_error();
                    unsafe {
                        libc::unlinkat(parent_fd, tmp_c.as_ptr(), 0);
                    }
                    return Err(err);
                }
                shim_dir.file().sync_all()
            })();
            if let Err(err) = link_res {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Failed updating shim ffprobe symlink: {err}"
                )));
            }
        }

        let changed = shim_needs_write || ffprobe_needs_write;
        Ok(TranscodeMutationReport {
            changed,
            detail: if changed {
                "Installed af-transcode ffmpeg shim and ffprobe symlink".to_string()
            } else {
                "Transcode ffmpeg shim and ffprobe symlink are already up to date".to_string()
            },
            units: Vec::new(),
            paths: vec![
                self.logical_path(&self.config.shim_dir.join("ffmpeg")),
                self.logical_path(&self.config.shim_dir.join("ffprobe")),
            ],
            api_restart_required: false,
        })
    }

    /// Parses Jellyfin's `encoding.xml`, creates `/var/cache/jellyfin/af-tmp` (`0750`, `jellyfin:jellyfin`),
    /// ensures `/etc/aetherflow/transcode.env`, writes managed `jellyfin.service.d/20-aetherflow-transcode.conf`,
    /// and reloads/restarts Jellyfin.
    pub async fn enable_jellyfin(&self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let transcode_env_logical = self.transcode_env_logical_path()?;
        let _unit_guard = self.acquire_unit_lock(JELLYFIN_SERVICE_UNIT).await?;

        let dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{JELLYFIN_SERVICE_UNIT}.d"));

        let (transcoding_temp_path, previous, dropin_changed, changed) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;

            let transcoding_temp_path = self.read_jellyfin_transcoding_temp_path()?;

            // Check existing drop-in before creating directories or mutating state.
            let dropin_dir = self.ensure_system_dir(&dropin_dir_path, 0o755, 0o6022)?;
            let previous =
                self.read_managed_file_checked(&dropin_dir, JELLYFIN_TRANSCODE_DROPIN_NAME, true)?;

            let env_created = self.ensure_transcode_env_file()?;

            // Create `/var/cache/jellyfin/af-tmp` safely (`0750`, owned by `jellyfin:jellyfin` when root).
            let tmp_existed = ReceiptDirectory::open_existing(&self.config.jellyfin_tmp_dir)
                .map_err(|err| {
                    PeerTranscodeError::Conflict(format!(
                        "Refusing unsafe Jellyfin tmp directory {}: {err}",
                        self.config.jellyfin_tmp_dir.display()
                    ))
                })?
                .is_some();
            let tmp_dir =
                ReceiptDirectory::open_confined(&self.config.jellyfin_tmp_dir, true, 0o750)
                    .map_err(|err| {
                        PeerTranscodeError::Runtime(format!(
                            "Failed ensuring Jellyfin tmp directory {}: {err}",
                            self.config.jellyfin_tmp_dir.display()
                        ))
                    })?;
            let mut tmp_changed = !tmp_existed;
            let tmp_meta = tmp_dir.file().metadata().map_err(|err| {
                PeerTranscodeError::Runtime(format!("Cannot stat Jellyfin tmp directory: {err}"))
            })?;
            if running_as_root() {
                let (jf_uid, jf_gid) = self.resolve_jellyfin_identity().ok_or_else(|| {
                    PeerTranscodeError::NotFound(
                        "System user 'jellyfin' is required to configure Jellyfin transcode temp dir"
                            .to_string(),
                    )
                })?;
                if tmp_meta.uid() != jf_uid || tmp_meta.gid() != jf_gid {
                    if unsafe { libc::fchown(tmp_dir.file().as_raw_fd(), jf_uid, jf_gid) } != 0 {
                        return Err(PeerTranscodeError::Runtime(format!(
                            "Failed setting jellyfin ownership on tmp dir: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                    tmp_changed = true;
                }
            }
            if (tmp_meta.mode() & 0o7777) != 0o750 {
                if unsafe { libc::fchmod(tmp_dir.file().as_raw_fd(), 0o750) } != 0 {
                    return Err(PeerTranscodeError::Runtime(format!(
                        "Failed setting 0750 mode on Jellyfin tmp dir: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                tmp_changed = true;
            }

            let rendered = render_jellyfin_transcode_dropin(&transcode_env_logical);
            let dropin_changed = previous.as_deref() != Some(rendered.as_bytes());
            if dropin_changed {
                self.write_managed_file_atomic(
                    &dropin_dir,
                    JELLYFIN_TRANSCODE_DROPIN_NAME,
                    rendered.as_bytes(),
                    0o644,
                )?;
            }

            let changed = dropin_changed || tmp_changed || env_created;
            (transcoding_temp_path, previous, dropin_changed, changed)
        };

        if changed {
            let apply_res = async {
                let _ = self
                    .run_checked_with_timeout(
                        "systemctl",
                        &strings(&["daemon-reload"]),
                        self.config.command_timeout,
                    )
                    .await?;
                let _ = self
                    .run_checked_with_timeout(
                        "systemctl",
                        &strings(&["restart", JELLYFIN_SERVICE_UNIT]),
                        self.config.mount_command_timeout,
                    )
                    .await?;
                Ok::<(), PeerTranscodeError>(())
            }
            .await;

            if let Err(apply_err) = apply_res {
                if dropin_changed {
                    let rb_res = match self.acquire_transcode_write_locks(false).await {
                        Ok((_mem_guard, _file_lock)) => {
                            match self.open_existing_system_dir(&dropin_dir_path, 0o6022) {
                                Ok(Some(dropin_dir)) => self.restore_managed_file_after_failure(
                                    &dropin_dir,
                                    JELLYFIN_TRANSCODE_DROPIN_NAME,
                                    previous.as_deref(),
                                    0o644,
                                ),
                                Ok(None) => Ok(()),
                                Err(err) => Err(err),
                            }
                        }
                        Err(err) => Err(err),
                    };
                    if rb_res.is_ok() {
                        let _ = self
                            .run_command_with_timeout(
                                "systemctl",
                                &strings(&["daemon-reload"]),
                                self.config.command_timeout,
                            )
                            .await;
                    }
                    if let Err(rb_err) = rb_res {
                        return Err(PeerTranscodeError::Runtime(format!(
                            "Failed reloading/restarting {JELLYFIN_SERVICE_UNIT} and rollback failed ({apply_err}; rollback: {rb_err})"
                        )));
                    }
                    return Err(PeerTranscodeError::Runtime(format!(
                        "Failed reloading/restarting {JELLYFIN_SERVICE_UNIT}; previous drop-in restored ({apply_err})"
                    )));
                }
                return Err(apply_err);
            }
        }

        Ok(TranscodeMutationReport {
            changed,
            detail: if changed {
                format!(
                    "Enabled Jellyfin transcode drop-in (TranscodingTempPath={transcoding_temp_path})"
                )
            } else {
                format!(
                    "Jellyfin transcode drop-in is already enabled (TranscodingTempPath={transcoding_temp_path})"
                )
            },
            units: vec![JELLYFIN_SERVICE_UNIT.to_string()],
            paths: vec![
                transcoding_temp_path,
                self.logical_path(&self.config.jellyfin_tmp_dir),
                transcode_env_logical,
                format!(
                    "{}/{JELLYFIN_SERVICE_UNIT}.d/{JELLYFIN_TRANSCODE_DROPIN_NAME}",
                    self.logical_path(&self.config.systemd_dir)
                ),
            ],
            api_restart_required: false,
        })
    }

    /// Removes managed `jellyfin.service.d/20-aetherflow-transcode.conf` (refusing unmanaged files),
    /// runs `systemctl daemon-reload`, and restarts `jellyfin.service`.
    pub async fn disable_jellyfin(&self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let _unit_guard = self.acquire_unit_lock(JELLYFIN_SERVICE_UNIT).await?;
        let dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{JELLYFIN_SERVICE_UNIT}.d"));
        let dropin_logical = format!(
            "{}/{JELLYFIN_SERVICE_UNIT}.d/{JELLYFIN_TRANSCODE_DROPIN_NAME}",
            self.logical_path(&self.config.systemd_dir)
        );

        let previous = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let Some(dropin_dir) = self.open_existing_system_dir(&dropin_dir_path, 0o6022)? else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: "Jellyfin transcode drop-in is already absent".to_string(),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            let Some(previous) =
                self.delete_managed_file_checked(&dropin_dir, JELLYFIN_TRANSCODE_DROPIN_NAME)?
            else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: "Jellyfin transcode drop-in is already absent".to_string(),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            previous
        };

        let apply_res = async {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await?;
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["restart", JELLYFIN_SERVICE_UNIT]),
                    self.config.mount_command_timeout,
                )
                .await?;
            Ok::<(), PeerTranscodeError>(())
        }
        .await;

        if let Err(apply_err) = apply_res {
            let rb_res = match self.acquire_transcode_write_locks(false).await {
                Ok((_mem_guard, _file_lock)) => {
                    match self.ensure_system_dir(&dropin_dir_path, 0o755, 0o6022) {
                        Ok(dropin_dir) => self.write_managed_file_atomic(
                            &dropin_dir,
                            JELLYFIN_TRANSCODE_DROPIN_NAME,
                            &previous,
                            0o644,
                        ),
                        Err(err) => Err(err),
                    }
                }
                Err(err) => Err(err),
            };
            if let Err(rb_err) = rb_res {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Failed reloading/restarting {JELLYFIN_SERVICE_UNIT} after removing drop-in and rollback failed ({apply_err}; rollback: {rb_err})"
                )));
            }
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "Failed reloading/restarting {JELLYFIN_SERVICE_UNIT}; drop-in was restored ({apply_err})"
            )));
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: "Removed Jellyfin transcode drop-in and restarted jellyfin.service".to_string(),
            units: vec![JELLYFIN_SERVICE_UNIT.to_string()],
            paths: vec![dropin_logical],
            api_restart_required: false,
        })
    }

    /// Writes hardened managed `/etc/systemd/system/af-transcode-worker.service`, ensures
    /// `/etc/aetherflow/transcode.env`, and installs API + runner drop-ins, then runs
    /// `daemon-reload` and `enable --now af-transcode-worker.service`.
    pub async fn install_worker_unit(&self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let bin_path = self.resolve_verified_transcode_binary()?;
        let transcode_env_logical = self.transcode_env_logical_path()?;
        let rendered_unit = render_worker_service_unit(&bin_path, &transcode_env_logical)?;

        let _unit_guard = self.acquire_unit_lock(PEER_TRANSCODE_WORKER_UNIT).await?;

        let (
            prev_unit,
            unit_changed,
            prev_api_dropin,
            api_dropin_changed,
            prev_runner_dropin,
            runner_dropin_changed,
            paths_dropin_changed,
            env_created,
        ) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;
            let systemd_dir = self.ensure_system_dir(&self.config.systemd_dir, 0o755, 0o6022)?;
            let prev_unit =
                self.read_managed_file_checked(&systemd_dir, PEER_TRANSCODE_WORKER_UNIT, true)?;

            // Pre-validate API, runner, and worker paths drop-ins before writing any file.
            let api_dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{API_SERVICE_UNIT}.d"));
            let api_dropin_dir = self.ensure_system_dir(&api_dropin_dir_path, 0o755, 0o6022)?;
            let _ =
                self.read_managed_file_checked(&api_dropin_dir, API_TRANSCODE_DROPIN_NAME, true)?;
            let runner_dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{RUNNER_SERVICE_UNIT}.d"));
            let runner_dropin_dir =
                self.ensure_system_dir(&runner_dropin_dir_path, 0o755, 0o6022)?;
            let _ = self.read_managed_file_checked(
                &runner_dropin_dir,
                RUNNER_TRANSCODE_DROPIN_NAME,
                true,
            )?;
            let worker_dropin_dir_path = self
                .config
                .systemd_dir
                .join(format!("{PEER_TRANSCODE_WORKER_UNIT}.d"));
            if let Some(worker_dropin_dir) =
                self.open_existing_system_dir(&worker_dropin_dir_path, 0o6022)?
            {
                let _ = self.read_managed_file_checked(
                    &worker_dropin_dir,
                    WORKER_TRANSCODE_PATHS_DROPIN_NAME,
                    true,
                )?;
            }

            let env_created = self.ensure_transcode_env_file()?;

            let unit_changed = prev_unit.as_deref() != Some(rendered_unit.as_bytes());
            if unit_changed {
                self.write_managed_file_atomic(
                    &systemd_dir,
                    PEER_TRANSCODE_WORKER_UNIT,
                    rendered_unit.as_bytes(),
                    0o644,
                )?;
            }

            let (api_dropin_dir, prev_api_dropin, api_dropin_changed) =
                match self.ensure_api_transcode_dropin_locked(&transcode_env_logical) {
                    Ok(res) => res,
                    Err(err) => {
                        if unit_changed {
                            let _ = self.restore_managed_file_after_failure(
                                &systemd_dir,
                                PEER_TRANSCODE_WORKER_UNIT,
                                prev_unit.as_deref(),
                                0o644,
                            );
                        }
                        return Err(err);
                    }
                };

            let (_runner_dropin_dir, prev_runner_dropin, runner_dropin_changed) =
                match self.ensure_runner_transcode_dropin_locked(&transcode_env_logical) {
                    Ok(res) => res,
                    Err(err) => {
                        if api_dropin_changed {
                            let _ = self.restore_managed_file_after_failure(
                                &api_dropin_dir,
                                API_TRANSCODE_DROPIN_NAME,
                                prev_api_dropin.as_deref(),
                                0o644,
                            );
                        }
                        if unit_changed {
                            let _ = self.restore_managed_file_after_failure(
                                &systemd_dir,
                                PEER_TRANSCODE_WORKER_UNIT,
                                prev_unit.as_deref(),
                                0o644,
                            );
                        }
                        return Err(err);
                    }
                };

            let paths_dropin_changed =
                self.sync_worker_transcode_paths_dropin_locked(&systemd_dir)?;

            (
                prev_unit,
                unit_changed,
                prev_api_dropin,
                api_dropin_changed,
                prev_runner_dropin,
                runner_dropin_changed,
                paths_dropin_changed,
                env_created,
            )
        };

        let apply_res = async {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await?;
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["enable", "--now", PEER_TRANSCODE_WORKER_UNIT]),
                    self.config.mount_command_timeout,
                )
                .await?;
            if unit_changed && prev_unit.is_some() {
                let _ = self
                    .run_checked_with_timeout(
                        "systemctl",
                        &strings(&["restart", PEER_TRANSCODE_WORKER_UNIT]),
                        self.config.mount_command_timeout,
                    )
                    .await?;
            }
            Ok::<(), PeerTranscodeError>(())
        }
        .await;

        if let Err(apply_err) = apply_res {
            if let Ok((_mem_guard, _file_lock)) = self.acquire_transcode_write_locks(false).await {
                if unit_changed {
                    if let Ok(Some(systemd_dir)) =
                        self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                    {
                        let _ = self.restore_managed_file_after_failure(
                            &systemd_dir,
                            PEER_TRANSCODE_WORKER_UNIT,
                            prev_unit.as_deref(),
                            0o644,
                        );
                    }
                }
                if api_dropin_changed {
                    if let Ok(Some(dir)) = self.open_existing_system_dir(
                        &self
                            .config
                            .systemd_dir
                            .join(format!("{API_SERVICE_UNIT}.d")),
                        0o6022,
                    ) {
                        let _ = self.restore_managed_file_after_failure(
                            &dir,
                            API_TRANSCODE_DROPIN_NAME,
                            prev_api_dropin.as_deref(),
                            0o644,
                        );
                    }
                }
                if runner_dropin_changed {
                    if let Ok(Some(dir)) = self.open_existing_system_dir(
                        &self
                            .config
                            .systemd_dir
                            .join(format!("{RUNNER_SERVICE_UNIT}.d")),
                        0o6022,
                    ) {
                        let _ = self.restore_managed_file_after_failure(
                            &dir,
                            RUNNER_TRANSCODE_DROPIN_NAME,
                            prev_runner_dropin.as_deref(),
                            0o644,
                        );
                    }
                }
            }
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "Failed enabling {PEER_TRANSCODE_WORKER_UNIT}; previous unit state restored ({apply_err})"
            )));
        }

        let changed = unit_changed
            || api_dropin_changed
            || runner_dropin_changed
            || paths_dropin_changed
            || env_created;
        Ok(TranscodeMutationReport {
            changed,
            detail: if changed {
                format!(
                    "Installed and enabled {PEER_TRANSCODE_WORKER_UNIT} and API/runner drop-ins"
                )
            } else {
                format!(
                    "{PEER_TRANSCODE_WORKER_UNIT} and API/runner drop-ins are already up to date"
                )
            },
            units: vec![
                PEER_TRANSCODE_WORKER_UNIT.to_string(),
                API_SERVICE_UNIT.to_string(),
                RUNNER_SERVICE_UNIT.to_string(),
            ],
            paths: vec![
                format!(
                    "{}/{PEER_TRANSCODE_WORKER_UNIT}",
                    self.logical_path(&self.config.systemd_dir)
                ),
                transcode_env_logical,
                format!(
                    "{}/{API_SERVICE_UNIT}.d/{API_TRANSCODE_DROPIN_NAME}",
                    self.logical_path(&self.config.systemd_dir)
                ),
                format!(
                    "{}/{RUNNER_SERVICE_UNIT}.d/{RUNNER_TRANSCODE_DROPIN_NAME}",
                    self.logical_path(&self.config.systemd_dir)
                ),
            ],
            api_restart_required: api_dropin_changed,
        })
    }

    /// Disables and stops `af-transcode-worker.service`, removes the managed unit file and
    /// `30-aetherflow-transcode-paths.conf`, cleans up `aetherflow-runner.service.d/20-aetherflow-transcode.conf`
    /// when neither dispatcher nor worker remains installed, and reloads systemd.
    pub async fn remove_worker_unit(&self) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let _unit_guard = self.acquire_unit_lock(PEER_TRANSCODE_WORKER_UNIT).await?;
        let unit_logical = format!(
            "{}/{PEER_TRANSCODE_WORKER_UNIT}",
            self.logical_path(&self.config.systemd_dir)
        );
        let worker_dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{PEER_TRANSCODE_WORKER_UNIT}.d"));
        let runner_dropin_dir_path = self
            .config
            .systemd_dir
            .join(format!("{RUNNER_SERVICE_UNIT}.d"));

        let (worker_present, paths_dropin_present, runner_dropin_removable) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let Some(systemd_dir) =
                self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)?
            else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: format!("{PEER_TRANSCODE_WORKER_UNIT} is already absent"),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            let worker_present = self
                .read_managed_file_checked(&systemd_dir, PEER_TRANSCODE_WORKER_UNIT, true)?
                .is_some();
            let paths_dropin_present =
                match self.open_existing_system_dir(&worker_dropin_dir_path, 0o6022)? {
                    Some(dir) => self
                        .read_managed_file_checked(&dir, WORKER_TRANSCODE_PATHS_DROPIN_NAME, true)?
                        .is_some(),
                    None => false,
                };
            let dispatcher_installed = self.is_dispatcher_installed_locked()?;
            let runner_dropin_removable = if !dispatcher_installed {
                match self.open_existing_system_dir(&runner_dropin_dir_path, 0o6022)? {
                    Some(dir) => self
                        .read_managed_file_checked(&dir, RUNNER_TRANSCODE_DROPIN_NAME, true)?
                        .is_some(),
                    None => false,
                }
            } else {
                false
            };
            (
                worker_present,
                paths_dropin_present,
                runner_dropin_removable,
            )
        };

        if !worker_present && !paths_dropin_present && !runner_dropin_removable {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("{PEER_TRANSCODE_WORKER_UNIT} is already absent"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        }

        if worker_present {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["disable", "--now", PEER_TRANSCODE_WORKER_UNIT]),
                    self.config.mount_command_timeout,
                )
                .await?;
        }

        let (prev_unit, prev_paths_dropin, prev_runner_dropin) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let prev_unit = match self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)? {
                Some(systemd_dir) => {
                    self.delete_managed_file_checked(&systemd_dir, PEER_TRANSCODE_WORKER_UNIT)?
                }
                None => None,
            };
            let prev_paths_dropin =
                match self.open_existing_system_dir(&worker_dropin_dir_path, 0o6022)? {
                    Some(dir) => {
                        self.delete_managed_file_checked(&dir, WORKER_TRANSCODE_PATHS_DROPIN_NAME)?
                    }
                    None => None,
                };
            let prev_runner_dropin = if !self.is_dispatcher_installed_locked()? {
                match self.open_existing_system_dir(&runner_dropin_dir_path, 0o6022)? {
                    Some(dir) => {
                        self.delete_managed_file_checked(&dir, RUNNER_TRANSCODE_DROPIN_NAME)?
                    }
                    None => None,
                }
            } else {
                None
            };
            (prev_unit, prev_paths_dropin, prev_runner_dropin)
        };

        if prev_unit.is_none() && prev_paths_dropin.is_none() && prev_runner_dropin.is_none() {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("{PEER_TRANSCODE_WORKER_UNIT} is already absent"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        }

        if let Err(reload_err) = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["daemon-reload"]),
                self.config.command_timeout,
            )
            .await
        {
            if let Ok((_mem_guard, _file_lock)) = self.acquire_transcode_write_locks(false).await {
                if let Some(ref prev) = prev_unit {
                    if let Ok(Some(systemd_dir)) =
                        self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                    {
                        let _ = self.write_managed_file_atomic(
                            &systemd_dir,
                            PEER_TRANSCODE_WORKER_UNIT,
                            prev,
                            0o644,
                        );
                    }
                }
                if let Some(ref prev) = prev_paths_dropin {
                    if let Ok(dir) = self.ensure_system_dir(&worker_dropin_dir_path, 0o755, 0o6022)
                    {
                        let _ = self.write_managed_file_atomic(
                            &dir,
                            WORKER_TRANSCODE_PATHS_DROPIN_NAME,
                            prev,
                            0o644,
                        );
                    }
                }
                if let Some(ref prev) = prev_runner_dropin {
                    if let Ok(dir) = self.ensure_system_dir(&runner_dropin_dir_path, 0o755, 0o6022)
                    {
                        let _ = self.write_managed_file_atomic(
                            &dir,
                            RUNNER_TRANSCODE_DROPIN_NAME,
                            prev,
                            0o644,
                        );
                    }
                }
            }
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "systemctl daemon-reload failed after removing {PEER_TRANSCODE_WORKER_UNIT}; unit restored ({reload_err})"
            )));
        }

        let mut removed_paths = Vec::new();
        if prev_unit.is_some() {
            removed_paths.push(unit_logical);
        }
        if prev_paths_dropin.is_some() {
            removed_paths.push(format!(
                "{}/{PEER_TRANSCODE_WORKER_UNIT}.d/{WORKER_TRANSCODE_PATHS_DROPIN_NAME}",
                self.logical_path(&self.config.systemd_dir)
            ));
        }
        if prev_runner_dropin.is_some() {
            removed_paths.push(format!(
                "{}/{RUNNER_SERVICE_UNIT}.d/{RUNNER_TRANSCODE_DROPIN_NAME}",
                self.logical_path(&self.config.systemd_dir)
            ));
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: format!("Disabled and removed {PEER_TRANSCODE_WORKER_UNIT}"),
            units: vec![PEER_TRANSCODE_WORKER_UNIT.to_string()],
            paths: removed_paths,
            api_restart_required: false,
        })
    }

    /// Writes `/etc/exports.d/aetherflow-peer-<link_id>-transcode.exports` with `rw,all_squash`
    /// mapped to non-root `(uid, gid)` (pruning strict descendants that share the exact same
    /// `st_dev` as their nearest kept ancestor while preserving separate-filesystem children)
    /// and runs `exportfs -ra`.
    pub async fn export_transcode_dirs(
        &self,
        link_id: &str,
        tunnel_ip: &str,
        uid: u32,
        gid: u32,
        paths: &[String],
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_link = validate_link_id(link_id)?;
        let valid_ip = validate_tunnel_ip(tunnel_ip, &self.tunnel_cidr)?;
        if uid == 0 || gid == 0 {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Transcode NFS exports require non-root uid and gid (got uid={uid}, gid={gid})"
            )));
        }
        let validated_paths = validate_transcode_paths_list(paths)?;

        let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;

        // Verify every exported directory exists locally without symlink traversal and inspect st_dev.
        let mut paths_with_dev: Vec<(String, u64)> = Vec::with_capacity(validated_paths.len());
        for path in &validated_paths {
            let dir = self.open_verified_local_directory(path)?;
            let dev = self.resolve_dir_st_dev(path, &dir)?;
            paths_with_dev.push((path.clone(), dev));
        }
        let exported_paths = prune_same_device_descendant_exports(&paths_with_dev);

        let file_name = derive_peer_transcode_export_file_name(valid_link)?;
        let exports_logical = format!(
            "{}/{file_name}",
            self.logical_path(&self.config.exports_dir)
        );
        let exports_dir = self.ensure_system_dir(&self.config.exports_dir, 0o755, 0o6022)?;
        let previous = self.read_managed_file_checked(&exports_dir, &file_name, true)?;
        let rendered = render_transcode_exports_file(valid_ip, uid, gid, &exported_paths);
        let unchanged = previous.as_deref() == Some(rendered.as_bytes());

        if !unchanged {
            self.write_managed_file_atomic(&exports_dir, &file_name, rendered.as_bytes(), 0o644)?;
        }

        if let Err(exportfs_err) = self
            .run_checked_with_timeout("exportfs", &strings(&["-ra"]), self.config.command_timeout)
            .await
        {
            if !unchanged {
                let rb_res = self.restore_managed_file_after_failure(
                    &exports_dir,
                    &file_name,
                    previous.as_deref(),
                    0o644,
                );
                if rb_res.is_ok() {
                    let _ = self
                        .run_command_with_timeout(
                            "exportfs",
                            &strings(&["-ra"]),
                            self.config.command_timeout,
                        )
                        .await;
                }
                if let Err(rb_err) = rb_res {
                    return Err(PeerTranscodeError::Runtime(format!(
                        "exportfs -ra failed and rollback of {exports_logical} failed ({exportfs_err}; rollback: {rb_err})"
                    )));
                }
                return Err(PeerTranscodeError::Runtime(format!(
                    "exportfs -ra failed; previous {exports_logical} restored ({exportfs_err})"
                )));
            }
            return Err(exportfs_err);
        }

        let mut report_paths = vec![exports_logical];
        report_paths.extend(exported_paths);
        Ok(TranscodeMutationReport {
            changed: !unchanged,
            detail: if unchanged {
                format!("Transcode exports for link '{valid_link}' are already up to date")
            } else {
                format!("Wrote transcode exports for link '{valid_link}' and refreshed exportfs")
            },
            units: Vec::new(),
            paths: report_paths,
            api_restart_required: false,
        })
    }

    /// Removes `/etc/exports.d/aetherflow-peer-<link_id>-transcode.exports` (without touching P7
    /// media exports) and runs `exportfs -ra`.
    pub async fn remove_transcode_exports(
        &self,
        link_id: &str,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_link = validate_link_id(link_id)?;
        let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;

        let file_name = derive_peer_transcode_export_file_name(valid_link)?;
        let exports_logical = format!(
            "{}/{file_name}",
            self.logical_path(&self.config.exports_dir)
        );
        let Some(exports_dir) = self.open_existing_system_dir(&self.config.exports_dir, 0o6022)?
        else {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("Transcode exports for link '{valid_link}' are already absent"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        };
        let Some(previous) = self.delete_managed_file_checked(&exports_dir, &file_name)? else {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("Transcode exports for link '{valid_link}' are already absent"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        };

        if let Err(exportfs_err) = self
            .run_checked_with_timeout("exportfs", &strings(&["-ra"]), self.config.command_timeout)
            .await
        {
            if let Err(rb_err) =
                self.write_managed_file_atomic(&exports_dir, &file_name, &previous, 0o644)
            {
                return Err(PeerTranscodeError::Runtime(format!(
                    "exportfs -ra failed after removing {exports_logical} and rollback failed ({exportfs_err}; rollback: {rb_err})"
                )));
            }
            let _ = self
                .run_command_with_timeout(
                    "exportfs",
                    &strings(&["-ra"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "exportfs -ra failed after removing {exports_logical}; exports restored ({exportfs_err})"
            )));
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: format!("Removed transcode exports for link '{valid_link}'"),
            units: Vec::new(),
            paths: vec![exports_logical],
            api_restart_required: false,
        })
    }

    /// Writes managed NFSv4.2 `.mount` units for each allowlisted transcode directory, syncs
    /// `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf`, runs
    /// `systemctl daemon-reload`, and starts each unit in parent-before-child order under
    /// per-unit locks (releasing the host-wide config lock before slow `systemctl start` calls).
    /// Rolls back started mounts, newly written units, and empty newly created mount directories
    /// on any failure.
    pub async fn mount_transcode_dirs(
        &self,
        link_id: &str,
        tunnel_ip: &str,
        paths: &[String],
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_link = validate_link_id(link_id)?;
        let valid_ip = validate_tunnel_ip(tunnel_ip, &self.tunnel_cidr)?;
        let validated_paths = validate_transcode_paths_list(paths)?;
        for path in &validated_paths {
            self.validate_worker_transcode_mount_path(path)?;
        }

        let mut specs: Vec<(String, String, String)> = Vec::with_capacity(validated_paths.len());
        for path in &validated_paths {
            let unit_name = derive_systemd_mount_unit(path)?;
            let rendered = render_transcode_nfs_mount_unit(valid_link, valid_ip, path);
            specs.push((path.clone(), unit_name, rendered));
        }

        let unit_refs: Vec<&str> = specs.iter().map(|(_, u, _)| u.as_str()).collect();
        let unit_guards = self.acquire_unit_locks(&unit_refs).await?;

        let (previous_states, written_indices, preexisting_dirs, paths_dropin_changed) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;
            let systemd_dir = self.ensure_system_dir(&self.config.systemd_dir, 0o755, 0o6022)?;

            // Pre-validate every unit and mountpoint before writing anything.
            let mut previous_states: Vec<(String, Option<Vec<u8>>, bool)> =
                Vec::with_capacity(specs.len());
            let mut preexisting_dirs: Vec<bool> = Vec::with_capacity(specs.len());
            for (path, unit_name, rendered) in &specs {
                self.verify_mountpoint_no_symlinks(path)?;
                let resolved = self.resolve_host_path(path);
                preexisting_dirs.push(fs::symlink_metadata(&resolved).is_ok());
                let prev = self.read_managed_file_checked(&systemd_dir, unit_name, true)?;
                let unit_changed = prev.as_deref() != Some(rendered.as_bytes());
                previous_states.push((unit_name.clone(), prev, unit_changed));
            }

            let mut written_indices: Vec<usize> = Vec::new();
            for (idx, (_, unit_name, rendered)) in specs.iter().enumerate() {
                if previous_states[idx].2 {
                    if let Err(err) = self.write_managed_file_atomic(
                        &systemd_dir,
                        unit_name,
                        rendered.as_bytes(),
                        0o644,
                    ) {
                        for &w_idx in written_indices.iter().rev() {
                            let (ref name, ref prev, _) = previous_states[w_idx];
                            let _ = self.restore_managed_file_after_failure(
                                &systemd_dir,
                                name,
                                prev.as_deref(),
                                0o644,
                            );
                        }
                        return Err(err);
                    }
                    written_indices.push(idx);
                }
            }

            let paths_dropin_changed =
                match self.sync_worker_transcode_paths_dropin_locked(&systemd_dir) {
                    Ok(changed) => changed,
                    Err(err) => {
                        for &w_idx in written_indices.iter().rev() {
                            let (ref name, ref prev, _) = previous_states[w_idx];
                            let _ = self.restore_managed_file_after_failure(
                                &systemd_dir,
                                name,
                                prev.as_deref(),
                                0o644,
                            );
                        }
                        let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                        return Err(err);
                    }
                };

            (
                previous_states,
                written_indices,
                preexisting_dirs,
                paths_dropin_changed,
            )
        };

        let mut started_units: Vec<String> = Vec::new();
        let apply_res = async {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await?;
            for (_, unit_name, _) in &specs {
                let _ = self
                    .run_checked_with_timeout(
                        "systemctl",
                        &strings(&["start", unit_name]),
                        self.config.mount_command_timeout,
                    )
                    .await?;
                started_units.push(unit_name.clone());
            }
            Ok::<(), PeerTranscodeError>(())
        }
        .await;

        if let Err(apply_err) = apply_res {
            for unit_name in started_units.iter().rev() {
                let _ = self
                    .run_command_with_timeout(
                        "systemctl",
                        &strings(&["stop", unit_name]),
                        self.config.mount_command_timeout,
                    )
                    .await;
            }
            if let Ok((_mem_guard, _file_lock)) = self.acquire_transcode_write_locks(false).await {
                if let Ok(Some(systemd_dir)) =
                    self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                {
                    for &w_idx in written_indices.iter().rev() {
                        let (ref name, ref prev, _) = previous_states[w_idx];
                        let _ = self.restore_managed_file_after_failure(
                            &systemd_dir,
                            name,
                            prev.as_deref(),
                            0o644,
                        );
                    }
                    let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                }
                // Remove empty newly created mount directories in child-before-parent order.
                for (idx, (path, _, _)) in specs.iter().enumerate().rev() {
                    if !preexisting_dirs[idx] {
                        let resolved = self.resolve_host_path(path);
                        if fs::symlink_metadata(&resolved)
                            .is_ok_and(|meta| meta.file_type().is_dir())
                        {
                            let _ = fs::remove_dir(&resolved);
                        }
                    }
                }
            }
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "Failed mounting transcode directories for link '{valid_link}'; rolled back unit files ({apply_err})"
            )));
        }

        drop(unit_guards);
        if paths_dropin_changed {
            self.maybe_restart_active_worker().await?;
        }

        let units: Vec<String> = specs.iter().map(|(_, u, _)| u.clone()).collect();
        let changed = !written_indices.is_empty() || !started_units.is_empty();
        Ok(TranscodeMutationReport {
            changed,
            detail: format!(
                "Mounted {} transcode directory unit(s) for link '{valid_link}'",
                units.len()
            ),
            units,
            paths: validated_paths,
            api_restart_required: false,
        })
    }

    /// Stops and removes managed transcode NFS `.mount` units in child-before-parent order,
    /// updates `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf`, and runs
    /// `systemctl daemon-reload`.
    pub async fn remove_transcode_mounts(
        &self,
        link_id: &str,
        paths: &[String],
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_link = validate_link_id(link_id)?;
        let mut validated_paths = validate_transcode_paths_list(paths)?;
        for path in &validated_paths {
            self.validate_worker_transcode_mount_path(path)?;
        }
        // Unmount deeper/child mounts before shallower/parent mounts.
        validated_paths.reverse();

        let mut targets: Vec<(String, String)> = Vec::with_capacity(validated_paths.len());
        for path in &validated_paths {
            let unit_name = derive_systemd_mount_unit(path)?;
            targets.push((path.clone(), unit_name));
        }

        let unit_refs: Vec<&str> = targets.iter().map(|(_, u)| u.as_str()).collect();
        let unit_guards = self.acquire_unit_locks(&unit_refs).await?;

        let existing_targets = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let Some(systemd_dir) =
                self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)?
            else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: format!("No transcode mount units present for link '{valid_link}'"),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };

            // Pre-validate every unit file before stopping or deleting any.
            let mut existing_targets: Vec<(String, String)> = Vec::new();
            for (path, unit_name) in &targets {
                if let Some(bytes) =
                    self.read_managed_file_checked(&systemd_dir, unit_name, true)?
                {
                    if !has_managed_purpose(&bytes, TRANSCODE_MOUNT_PURPOSE_HEADER) {
                        return Err(PeerTranscodeError::Conflict(format!(
                            "Refusing to remove non-transcode mount unit '{unit_name}'"
                        )));
                    }
                    existing_targets.push((path.clone(), unit_name.clone()));
                }
            }
            existing_targets
        };

        if existing_targets.is_empty() {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("No transcode mount units present for link '{valid_link}'"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        }

        let mut deleted: Vec<(String, String, Vec<u8>)> = Vec::new();
        for (path, unit_name) in &existing_targets {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["stop", unit_name]),
                    self.config.mount_command_timeout,
                )
                .await?;
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            if let Some(systemd_dir) =
                self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)?
            {
                if let Some(prev) = self.delete_managed_file_checked(&systemd_dir, unit_name)? {
                    deleted.push((path.clone(), unit_name.clone(), prev));
                }
            }
        }

        let paths_dropin_changed = if !deleted.is_empty() {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            match self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)? {
                Some(systemd_dir) => {
                    self.sync_worker_transcode_paths_dropin_locked(&systemd_dir)?
                }
                None => false,
            }
        } else {
            false
        };

        if !deleted.is_empty() {
            if let Err(reload_err) = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await
            {
                if let Ok((_mem_guard, _file_lock)) =
                    self.acquire_transcode_write_locks(false).await
                {
                    if let Ok(Some(systemd_dir)) =
                        self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                    {
                        for (_, unit_name, prev) in deleted.iter().rev() {
                            let _ = self.write_managed_file_atomic(
                                &systemd_dir,
                                unit_name,
                                prev,
                                0o644,
                            );
                        }
                        let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                    }
                }
                let _ = self
                    .run_command_with_timeout(
                        "systemctl",
                        &strings(&["daemon-reload"]),
                        self.config.command_timeout,
                    )
                    .await;
                return Err(PeerTranscodeError::Runtime(format!(
                    "systemctl daemon-reload failed after removing transcode mount units; units restored ({reload_err})"
                )));
            }
        }

        drop(unit_guards);
        if paths_dropin_changed {
            self.maybe_restart_active_worker().await?;
        }

        let removed_units: Vec<String> = deleted.iter().map(|(_, u, _)| u.clone()).collect();
        let removed_paths: Vec<String> = deleted.iter().map(|(p, _, _)| p.clone()).collect();
        Ok(TranscodeMutationReport {
            changed: !removed_units.is_empty(),
            detail: format!(
                "Stopped and removed {} transcode mount unit(s) for link '{valid_link}'",
                removed_units.len()
            ),
            units: removed_units,
            paths: removed_paths,
            api_restart_required: false,
        })
    }

    /// Writes a managed systemd bind `.mount` unit (`Type=none`, `Options=bind,ro|rw,nosuid,nodev`)
    /// without calling-link confinement. Prefer [`Self::bind_media_with_link`] when the calling
    /// peer's mount segment is known.
    pub async fn bind_media(
        &self,
        from: &str,
        to: &str,
        writable: bool,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        self.bind_media_with_link(from, to, writable, None).await
    }

    /// Writes a managed systemd bind `.mount` unit (`Type=none`, `Options=bind,ro|rw,nosuid,nodev`),
    /// enforcing bidirectional allowlists, optional calling-link segment confinement, empty-dir
    /// protection on `to`, conditional `BindsTo=`/`After=` on backing `/mnt/af-peers/<link>/<export>`
    /// NFS mounts, and dynamic `30-aetherflow-transcode-paths.conf` syncing.
    pub async fn bind_media_with_link(
        &self,
        from: &str,
        to: &str,
        writable: bool,
        calling_link_segment: Option<&str>,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_from = validate_canonical_path_syntax(from, true)?;
        let valid_to = validate_canonical_path_syntax(to, true)?;
        if valid_from == valid_to {
            return Err(PeerTranscodeError::InvalidInput(
                "Bind media source and destination paths must differ".to_string(),
            ));
        }

        let confined_seg = match calling_link_segment {
            Some(seg) => Some(
                validate_peer_mount_segment(seg)
                    .map_err(|err| PeerTranscodeError::InvalidInput(err.to_string()))?,
            ),
            None => None,
        };

        let from_is_peer = is_under_peer_mounts_root(&valid_from);
        let to_is_peer = is_under_peer_mounts_root(&valid_to);
        let backing_mount_unit = match (from_is_peer, to_is_peer) {
            // Worker-holds-media: local source -> `/mnt/af-peers/<link>/<export>(/...)`
            (false, true) => {
                if has_sensitive_dot_segment(&valid_from) {
                    return Err(PeerTranscodeError::InvalidInput(format!(
                        "Refusing sensitive bind source path '{valid_from}'"
                    )));
                }
                let (to_link_seg, _) = extract_peer_mount_segments(&valid_to)?;
                if let Some(expected_seg) = confined_seg {
                    if to_link_seg != expected_seg {
                        return Err(PeerTranscodeError::InvalidInput(format!(
                            "Bind destination '{valid_to}' lies outside calling link segment '{expected_seg}'"
                        )));
                    }
                }
                None
            }
            // Controller-holds-media: `/mnt/af-peers/<link>/<export>(/...)` -> allowed local media root
            (true, false) => {
                let (from_link_seg, _) = extract_peer_mount_segments(&valid_from)?;
                if let Some(expected_seg) = confined_seg {
                    if from_link_seg != expected_seg {
                        return Err(PeerTranscodeError::InvalidInput(format!(
                            "Bind source '{valid_from}' lies outside calling link segment '{expected_seg}'"
                        )));
                    }
                }
                self.validate_bind_media_target_allowlist(&valid_to)?;
                derive_backing_peer_nfs_mount_unit(&valid_from)?
            }
            (true, true) => {
                return Err(PeerTranscodeError::InvalidInput(format!(
                    "Refusing bind mount with both source and destination under {DEFAULT_PEER_MOUNTS_ROOT}"
                )));
            }
            (false, false) => {
                return Err(PeerTranscodeError::InvalidInput(format!(
                    "BindMedia requires exactly one of 'from' or 'to' to lie under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
                )));
            }
        };

        let unit_name = derive_systemd_mount_unit(&valid_to)?;
        let unit_guard = self.acquire_unit_lock(&unit_name).await?;

        // Phase 1: pre-validate source/target and check non-empty target directory under short lock.
        let need_active_bind_check = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;
            let _ = self.open_verified_local_directory(&valid_from)?;
            self.verify_mountpoint_no_symlinks(&valid_to)?;
            let systemd_dir = self.ensure_system_dir(&self.config.systemd_dir, 0o755, 0o6022)?;
            let previous = self.read_managed_file_checked(&systemd_dir, &unit_name, true)?;
            if self.dir_has_entries(&valid_to)? {
                let is_managed_bind = previous
                    .as_deref()
                    .is_some_and(|prev| is_managed_bind_unit_for_path(prev, &valid_to));
                if !is_managed_bind {
                    return Err(PeerTranscodeError::Conflict(format!(
                        "Refusing to bind over non-empty directory '{valid_to}'"
                    )));
                }
                true
            } else {
                false
            }
        };

        if need_active_bind_check {
            let active = match self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["is-active", &unit_name]),
                    self.config.command_timeout,
                )
                .await
            {
                Ok(out) => out.success() && out.stdout.trim() == "active",
                Err(_) => false,
            };
            if !active {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing to bind over non-empty directory '{valid_to}' (unit {unit_name} is not active)"
                )));
            }
        }

        // Phase 2: write unit file and sync worker ReadWritePaths drop-in under short lock.
        let rendered = render_bind_media_mount_unit(
            &valid_from,
            &valid_to,
            writable,
            backing_mount_unit.as_deref(),
        );
        let (previous, unit_changed, paths_dropin_changed) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(true).await?;
            let _ = self.open_verified_local_directory(&valid_from)?;
            self.verify_mountpoint_no_symlinks(&valid_to)?;
            let systemd_dir = self.ensure_system_dir(&self.config.systemd_dir, 0o755, 0o6022)?;
            let previous = self.read_managed_file_checked(&systemd_dir, &unit_name, true)?;
            if !need_active_bind_check && self.dir_has_entries(&valid_to)? {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing to bind over non-empty directory '{valid_to}'"
                )));
            }
            let unit_changed = previous.as_deref() != Some(rendered.as_bytes());
            if unit_changed {
                self.write_managed_file_atomic(
                    &systemd_dir,
                    &unit_name,
                    rendered.as_bytes(),
                    0o644,
                )?;
            }
            let paths_dropin_changed =
                match self.sync_worker_transcode_paths_dropin_locked(&systemd_dir) {
                    Ok(changed) => changed,
                    Err(err) => {
                        if unit_changed {
                            let _ = self.restore_managed_file_after_failure(
                                &systemd_dir,
                                &unit_name,
                                previous.as_deref(),
                                0o644,
                            );
                            let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                        }
                        return Err(err);
                    }
                };
            (previous, unit_changed, paths_dropin_changed)
        };

        let apply_res = async {
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await?;
            let _ = self
                .run_checked_with_timeout(
                    "systemctl",
                    &strings(&["start", &unit_name]),
                    self.config.mount_command_timeout,
                )
                .await?;
            Ok::<(), PeerTranscodeError>(())
        }
        .await;

        if let Err(apply_err) = apply_res {
            if unit_changed {
                if let Ok((_mem_guard, _file_lock)) =
                    self.acquire_transcode_write_locks(false).await
                {
                    if let Ok(Some(systemd_dir)) =
                        self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                    {
                        let _ = self.restore_managed_file_after_failure(
                            &systemd_dir,
                            &unit_name,
                            previous.as_deref(),
                            0o644,
                        );
                        let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                    }
                }
                let _ = self
                    .run_command_with_timeout(
                        "systemctl",
                        &strings(&["daemon-reload"]),
                        self.config.command_timeout,
                    )
                    .await;
            }
            return Err(PeerTranscodeError::Runtime(format!(
                "Failed starting bind mount unit {unit_name}; rolled back unit file ({apply_err})"
            )));
        }

        drop(unit_guard);
        if paths_dropin_changed {
            self.maybe_restart_active_worker().await?;
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: format!("Bound media directory '{valid_from}' to '{valid_to}' via {unit_name}"),
            units: vec![unit_name],
            paths: vec![valid_from, valid_to],
            api_restart_required: false,
        })
    }

    /// Stops and removes a managed media bind `.mount` unit for `to`, updates
    /// `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf`, and runs `daemon-reload`.
    pub async fn remove_bind_media(
        &self,
        to: &str,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let valid_to = validate_canonical_path_syntax(to, true)?;
        let unit_name = derive_systemd_mount_unit(&valid_to)?;

        let unit_guard = self.acquire_unit_lock(&unit_name).await?;

        let present = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let Some(systemd_dir) =
                self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)?
            else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: format!("Bind mount unit {unit_name} is already absent"),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            match self.read_managed_file_checked(&systemd_dir, &unit_name, true)? {
                Some(bytes) => {
                    if !has_managed_purpose(&bytes, TRANSCODE_BIND_PURPOSE_HEADER) {
                        return Err(PeerTranscodeError::Conflict(format!(
                            "Refusing to remove non-bind mount unit '{unit_name}'"
                        )));
                    }
                    true
                }
                None => false,
            }
        };

        if !present {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!("Bind mount unit {unit_name} is already absent"),
                units: Vec::new(),
                paths: Vec::new(),
                api_restart_required: false,
            });
        }

        let _ = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["stop", &unit_name]),
                self.config.mount_command_timeout,
            )
            .await?;

        let (previous, paths_dropin_changed) = {
            let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
            let Some(systemd_dir) =
                self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)?
            else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: format!("Bind mount unit {unit_name} is already absent"),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            let Some(previous) = self.delete_managed_file_checked(&systemd_dir, &unit_name)? else {
                return Ok(TranscodeMutationReport {
                    changed: false,
                    detail: format!("Bind mount unit {unit_name} is already absent"),
                    units: Vec::new(),
                    paths: Vec::new(),
                    api_restart_required: false,
                });
            };
            let paths_dropin_changed =
                self.sync_worker_transcode_paths_dropin_locked(&systemd_dir)?;
            (previous, paths_dropin_changed)
        };

        if let Err(reload_err) = self
            .run_checked_with_timeout(
                "systemctl",
                &strings(&["daemon-reload"]),
                self.config.command_timeout,
            )
            .await
        {
            if let Ok((_mem_guard, _file_lock)) = self.acquire_transcode_write_locks(false).await {
                if let Ok(Some(systemd_dir)) =
                    self.open_existing_system_dir(&self.config.systemd_dir, 0o6022)
                {
                    let _ =
                        self.write_managed_file_atomic(&systemd_dir, &unit_name, &previous, 0o644);
                    let _ = self.sync_worker_transcode_paths_dropin_locked(&systemd_dir);
                }
            }
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["daemon-reload"]),
                    self.config.command_timeout,
                )
                .await;
            return Err(PeerTranscodeError::Runtime(format!(
                "systemctl daemon-reload failed after removing {unit_name}; unit restored ({reload_err})"
            )));
        }

        drop(unit_guard);
        if paths_dropin_changed {
            self.maybe_restart_active_worker().await?;
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: format!("Stopped and removed bind mount unit {unit_name}"),
            units: vec![unit_name],
            paths: vec![valid_to],
            api_restart_required: false,
        })
    }

    /// Deterministically schedules a debounced deferred `systemctl restart aetherflow-api.service`
    /// (~1s after response) via `systemd-run --unit=aetherflow-transcode-api-restart`. Concurrent
    /// or repeated calls while the timer/service is already active or queued coalesce cleanly
    /// without spawning duplicate transient units.
    pub async fn schedule_api_restart(
        &self,
    ) -> Result<TranscodeMutationReport, PeerTranscodeError> {
        let _unit_guard = self.acquire_unit_lock(TRANSCODE_API_RESTART_UNIT).await?;
        let timer_unit = format!("{TRANSCODE_API_RESTART_UNIT}.timer");
        let service_unit = format!("{TRANSCODE_API_RESTART_UNIT}.service");

        let check_states = |stdout: &str| -> (bool, bool) {
            let mut active_or_queued = false;
            let mut failed = false;
            for line in stdout.lines() {
                match line.trim() {
                    "active" | "activating" | "reloading" => active_or_queued = true,
                    "failed" => failed = true,
                    _ => {}
                }
            }
            (active_or_queued, failed)
        };

        let probe = self
            .run_command_with_timeout(
                "systemctl",
                &strings(&["is-active", &timer_unit, &service_unit]),
                self.config.command_timeout,
            )
            .await?;
        let (already_active, had_failed) = check_states(&probe.stdout);
        if already_active {
            return Ok(TranscodeMutationReport {
                changed: false,
                detail: format!(
                    "Deferred restart of {API_SERVICE_UNIT} is already scheduled via transient unit {TRANSCODE_API_RESTART_UNIT}"
                ),
                units: vec![
                    API_SERVICE_UNIT.to_string(),
                    TRANSCODE_API_RESTART_UNIT.to_string(),
                ],
                paths: Vec::new(),
                api_restart_required: false,
            });
        }
        if had_failed {
            let _ = self
                .run_command_with_timeout(
                    "systemctl",
                    &strings(&["reset-failed", &timer_unit, &service_unit]),
                    self.config.command_timeout,
                )
                .await;
        }

        let args = vec![
            format!("--unit={TRANSCODE_API_RESTART_UNIT}"),
            "--on-active=1s".to_string(),
            "--timer-property=AccuracySec=100ms".to_string(),
            "--timer-property=RemainAfterElapse=no".to_string(),
            "--collect".to_string(),
            "--quiet".to_string(),
            "--".to_string(),
            "systemctl".to_string(),
            "restart".to_string(),
            API_SERVICE_UNIT.to_string(),
        ];

        match self
            .run_checked_with_timeout("systemd-run", &args, self.config.command_timeout)
            .await
        {
            Ok(_) => {}
            Err(err) => {
                let err_lower = err.to_string().to_lowercase();
                if err_lower.contains("already exists") {
                    let recheck = self
                        .run_command_with_timeout(
                            "systemctl",
                            &strings(&["is-active", &timer_unit, &service_unit]),
                            self.config.command_timeout,
                        )
                        .await?;
                    let (now_active, now_failed) = check_states(&recheck.stdout);
                    if now_active {
                        return Ok(TranscodeMutationReport {
                            changed: false,
                            detail: format!(
                                "Deferred restart of {API_SERVICE_UNIT} is already scheduled via transient unit {TRANSCODE_API_RESTART_UNIT}"
                            ),
                            units: vec![
                                API_SERVICE_UNIT.to_string(),
                                TRANSCODE_API_RESTART_UNIT.to_string(),
                            ],
                            paths: Vec::new(),
                            api_restart_required: false,
                        });
                    }
                    if now_failed {
                        let _ = self
                            .run_command_with_timeout(
                                "systemctl",
                                &strings(&["reset-failed", &timer_unit, &service_unit]),
                                self.config.command_timeout,
                            )
                            .await;
                        let _ = self
                            .run_checked_with_timeout(
                                "systemd-run",
                                &args,
                                self.config.command_timeout,
                            )
                            .await?;
                    } else {
                        return Err(err);
                    }
                } else {
                    return Err(err);
                }
            }
        }

        Ok(TranscodeMutationReport {
            changed: true,
            detail: format!(
                "Scheduled deferred restart of {API_SERVICE_UNIT} via transient unit {TRANSCODE_API_RESTART_UNIT}"
            ),
            units: vec![
                API_SERVICE_UNIT.to_string(),
                TRANSCODE_API_RESTART_UNIT.to_string(),
            ],
            paths: Vec::new(),
            api_restart_required: false,
        })
    }

    /// Verifies and unlinks a `.af-parity-<32hex>.ts` file inside an inspected Jellyfin
    /// transcode/temp/cache directory using FD-anchored `O_NOFOLLOW` + `unlinkat`.
    pub async fn cleanup_parity_file(
        &self,
        dir: &str,
        file_name: &str,
    ) -> Result<ParityFileCleanupReport, PeerTranscodeError> {
        validate_parity_file_name(file_name)?;
        let valid_dir = validate_canonical_path_syntax(dir, false)?;

        let configured_temp = self.read_jellyfin_transcoding_temp_path()?;
        let allowed_dirs = [
            configured_temp.as_str(),
            DEFAULT_JELLYFIN_TRANSCODE_DIR,
            DEFAULT_JELLYFIN_TMP_DIR,
            DEFAULT_JELLYFIN_CACHE_DIR,
        ];
        if !allowed_dirs.contains(&valid_dir.as_str()) {
            return Err(PeerTranscodeError::InvalidInput(format!(
                "Directory '{valid_dir}' is not a configured Jellyfin transcode directory"
            )));
        }

        let (_mem_guard, _file_lock) = self.acquire_transcode_write_locks(false).await?;
        let dir_handle = self.open_verified_local_directory(&valid_dir)?;

        let mut file = match dir_handle.open_file(OsStr::new(file_name), libc::O_RDONLY, 0) {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ParityFileCleanupReport {
                    existed: false,
                    size_bytes: 0,
                    removed: false,
                });
            }
            Err(err) => {
                return Err(PeerTranscodeError::Conflict(format!(
                    "Refusing unsafe parity file '{file_name}' in '{valid_dir}': {err}"
                )));
            }
        };

        let meta = file.metadata().map_err(|err| {
            PeerTranscodeError::Runtime(format!("Failed stating parity file '{file_name}': {err}"))
        })?;
        let size_bytes = meta.len();
        if size_bytes > 0 {
            let mut probe_buf = [0u8; 64];
            let n = file.read(&mut probe_buf).map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Failed reading parity file '{file_name}' in '{valid_dir}': {err}"
                ))
            })?;
            if n == 0 {
                return Err(PeerTranscodeError::Runtime(format!(
                    "Parity file '{file_name}' read back 0 bytes despite size {size_bytes}"
                )));
            }
        }
        drop(file);

        let c_file = c_name(OsStr::new(file_name)).map_err(|err| {
            PeerTranscodeError::InvalidInput(format!("Invalid parity file name: {err}"))
        })?;
        let unlink_rc =
            unsafe { libc::unlinkat(dir_handle.file().as_raw_fd(), c_file.as_ptr(), 0) };
        if unlink_rc != 0 {
            let os_err = std::io::Error::last_os_error();
            if os_err.kind() == std::io::ErrorKind::NotFound {
                return Ok(ParityFileCleanupReport {
                    existed: true,
                    size_bytes,
                    removed: false,
                });
            }
            return Err(PeerTranscodeError::Runtime(format!(
                "Failed removing parity file '{file_name}' in '{valid_dir}': {os_err}"
            )));
        }

        Ok(ParityFileCleanupReport {
            existed: true,
            size_bytes,
            removed: true,
        })
    }

    /// Executes any `PeerTranscodeRequest` against this manager.
    pub async fn execute(
        &self,
        req: &PeerTranscodeRequest,
    ) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
        match req {
            PeerTranscodeRequest::InspectJellyfinPaths => Ok(PeerTranscodeResponse::JellyfinPaths(
                self.inspect_jellyfin_paths().await?,
            )),
            PeerTranscodeRequest::EnsureDispatcherDir => Ok(PeerTranscodeResponse::Mutation(
                self.ensure_dispatcher_dir().await?,
            )),
            PeerTranscodeRequest::InstallShim => {
                Ok(PeerTranscodeResponse::Mutation(self.install_shim().await?))
            }
            PeerTranscodeRequest::EnableJellyfin => Ok(PeerTranscodeResponse::Mutation(
                self.enable_jellyfin().await?,
            )),
            PeerTranscodeRequest::DisableJellyfin => Ok(PeerTranscodeResponse::Mutation(
                self.disable_jellyfin().await?,
            )),
            PeerTranscodeRequest::InstallWorkerUnit => Ok(PeerTranscodeResponse::Mutation(
                self.install_worker_unit().await?,
            )),
            PeerTranscodeRequest::RemoveWorkerUnit => Ok(PeerTranscodeResponse::Mutation(
                self.remove_worker_unit().await?,
            )),
            PeerTranscodeRequest::ExportTranscodeDirs {
                link_id,
                tunnel_ip,
                uid,
                gid,
                paths,
            } => Ok(PeerTranscodeResponse::Mutation(
                self.export_transcode_dirs(link_id, tunnel_ip, *uid, *gid, paths)
                    .await?,
            )),
            PeerTranscodeRequest::RemoveTranscodeExports { link_id } => Ok(
                PeerTranscodeResponse::Mutation(self.remove_transcode_exports(link_id).await?),
            ),
            PeerTranscodeRequest::MountTranscodeDirs {
                link_id,
                tunnel_ip,
                paths,
            } => Ok(PeerTranscodeResponse::Mutation(
                self.mount_transcode_dirs(link_id, tunnel_ip, paths).await?,
            )),
            PeerTranscodeRequest::RemoveTranscodeMounts { link_id, paths } => {
                Ok(PeerTranscodeResponse::Mutation(
                    self.remove_transcode_mounts(link_id, paths).await?,
                ))
            }
            PeerTranscodeRequest::BindMedia {
                from,
                to,
                writable,
                calling_link_segment,
            } => Ok(PeerTranscodeResponse::Mutation(
                self.bind_media_with_link(from, to, *writable, calling_link_segment.as_deref())
                    .await?,
            )),
            PeerTranscodeRequest::RemoveBindMedia { to } => Ok(PeerTranscodeResponse::Mutation(
                self.remove_bind_media(to).await?,
            )),
            PeerTranscodeRequest::ScheduleApiRestart => Ok(PeerTranscodeResponse::Mutation(
                self.schedule_api_restart().await?,
            )),
            PeerTranscodeRequest::CleanupParityFile { dir, file_name } => {
                Ok(PeerTranscodeResponse::ParityFileCleanup(
                    self.cleanup_parity_file(dir, file_name).await?,
                ))
            }
        }
    }
}

pub async fn execute_peer_transcode_local(
    req: &PeerTranscodeRequest,
) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
    let manager = PeerTranscodeManager::from_env()?;
    manager.execute(req).await
}

/// Axum HTTP handler for `POST /v1/peer-transcode`.
pub async fn handle_peer_transcode(
    manager_ext: Option<Extension<Arc<PeerTranscodeManager>>>,
    payload: Result<Json<PeerTranscodeRequest>, JsonRejection>,
) -> Response {
    let req = match payload {
        Ok(Json(req)) => req,
        Err(_) => {
            return PeerTranscodeError::InvalidInput(
                "Invalid peer-transcode request payload".to_string(),
            )
            .into_http_response();
        }
    };
    let manager = match manager_ext {
        Some(Extension(mgr)) => mgr,
        None => match PeerTranscodeManager::from_env() {
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
            Err(_) => Err(PeerTranscodeError::Runtime(
                "Peer-transcode operation task terminated unexpectedly".to_string(),
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
                Err(_) => PeerTranscodeError::Runtime(
                    "Failed encoding peer-transcode runner response".to_string(),
                )
                .into_http_response(),
            }
        }
        Err(err) => err.into_http_response(),
    }
}
