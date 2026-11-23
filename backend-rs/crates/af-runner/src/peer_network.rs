//! Privileged WireGuard (`afpeer0`) and peer credential management for Peer Clustering.
//!
//! Strictly isolated from the legacy `wg0` manager in `network.rs`:
//! - Interface is fixed to `afpeer0` (`/etc/wireguard/afpeer0.conf`, `wg-quick@afpeer0.service`).
//! - Never reads, writes, or queries `wg0` or `/etc/wireguard/wg0.conf`.
//! - Dormant at daemon startup: performs no host probing, file creation, or unit changes until an
//!   explicit `/v1/peer-network` request arrives.
//! - Uses strict argument-vector process execution with bounded capture and process-group cleanup.
//! - Keeps raw secrets out of argv, environment variables, debug formatting, and error strings.

use crate::confined_fs::lookup_group_gid;
use crate::job_receipts::{c_name, entry_at, verify_entry, ReceiptDirectory};
use crate::network::parse_wg_dump;
use crate::package_executor::{
    CancellationToken, CommandOutput, CommandRunner, CrossProcessLockGuard, PackageExecutionEnv,
    PackageExecutorError, TokioCommandRunner,
};
use af_models::RunnerResponse;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tokio::time::Instant;

#[cfg(test)]
mod tests;

pub const PEER_WG_INTERFACE: &str = "afpeer0";
pub const PEER_WG_SERVICE_UNIT: &str = "wg-quick@afpeer0.service";
pub const DEFAULT_PEER_TUNNEL_CIDR: &str = "10.231.0.0/16";
pub const DEFAULT_PEER_WG_PORT: u16 = 51821;
pub const DEFAULT_PEER_WG_DIR: &str = "/etc/wireguard";
pub const DEFAULT_PEER_STATE_DIR: &str = "/etc/aetherflow/peers";
pub const PEER_WG_CONF_NAME: &str = "afpeer0.conf";
pub const PEER_WG_KEY_NAME: &str = "afpeer0.key";
pub const PEER_TOKENS_SUBDIR: &str = "tokens";
pub const PEER_PENDING_SUBDIR: &str = "pending";
pub const PEER_PERSISTENT_KEEPALIVE: u16 = 25;

pub(crate) const PEER_ERROR_CODE_HEADER: &str = "x-af-peer-error-code";

const PEER_LOCK_FILE_NAME: &str = ".aetherflow-peer-network.lock";
const PEER_CRED_LOCK_FILE_NAME: &str = ".aetherflow-peer-credentials.lock";
const PEER_WG_PACKAGE: &str = "wireguard-tools";
const REQUIRED_CREDENTIAL_GROUP: &str = "aetherflow";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_PEERS: usize = 256;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CONFIG_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const PACKAGE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const MAINTENANCE_ADMISSION_BUDGET_SECS: u64 = 15;
const APT_STEP_TIMEOUT: Duration = Duration::from_secs(180);
const COMMAND_TEARDOWN_GRACE_SECS: u64 = 5;

/// Worst-case runner work for `EnsurePackages`:
/// 3x dpkg-query (30s) + bounded lock wait (10s) + maintenance admission (15s) +
/// apt-get update (180s) + apt-get install (180s) + teardown grace (5s) = 420s.
pub(crate) const ENSURE_PACKAGES_MAX_SERVER_DURATION: Duration = Duration::from_secs(
    (3 * COMMAND_TIMEOUT.as_secs())
        + PACKAGE_LOCK_TIMEOUT.as_secs()
        + MAINTENANCE_ADMISSION_BUDGET_SECS
        + (2 * APT_STEP_TIMEOUT.as_secs())
        + COMMAND_TEARDOWN_GRACE_SECS,
);

/// Worst-case runner work for WireGuard mutations (including rollback & verified teardown):
/// config lock (5s) + up to 16 bounded commands (160s) + teardown grace (5s) = 170s.
pub(crate) const PEER_MUTATION_MAX_SERVER_DURATION: Duration = Duration::from_secs(
    CONFIG_LOCK_TIMEOUT.as_secs() + (16 * COMMAND_TIMEOUT.as_secs()) + COMMAND_TEARDOWN_GRACE_SECS,
);

/// Client socket deadlines strictly exceed worst-case server execution budgets.
pub(crate) const PEER_ENSURE_PACKAGES_CLIENT_TIMEOUT: Duration =
    Duration::from_secs(ENSURE_PACKAGES_MAX_SERVER_DURATION.as_secs() + 30);
pub(crate) const PEER_DEFAULT_CLIENT_TIMEOUT: Duration =
    Duration::from_secs(PEER_MUTATION_MAX_SERVER_DURATION.as_secs() + 10);

pub(crate) fn client_timeout_for_request(req: &PeerNetworkRequest) -> Duration {
    match req {
        PeerNetworkRequest::EnsurePackages => PEER_ENSURE_PACKAGES_CLIENT_TIMEOUT,
        _ => PEER_DEFAULT_CLIENT_TIMEOUT,
    }
}

const REDACTED_MARKER: &str = "[REDACTED]";

type PeerWgLockMap = HashMap<(PathBuf, PathBuf), Arc<RwLock<()>>>;
type PeerCredLockMap = HashMap<PathBuf, Arc<RwLock<()>>>;

static PEER_WG_LOCKS: Lazy<StdMutex<PeerWgLockMap>> = Lazy::new(|| StdMutex::new(HashMap::new()));
static PEER_CRED_LOCKS: Lazy<StdMutex<PeerCredLockMap>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn peer_wg_lock_for(wg_dir: &Path, state_dir: &Path) -> Arc<RwLock<()>> {
    let key = (wg_dir.to_path_buf(), state_dir.to_path_buf());
    let mut map = PEER_WG_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(key)
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

fn peer_cred_lock_for(state_dir: &Path) -> Arc<RwLock<()>> {
    let mut map = PEER_CRED_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(state_dir.to_path_buf())
        .or_insert_with(|| Arc::new(RwLock::new(())))
        .clone()
}

pub(crate) fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid exclusive mutable reference within `bytes`.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn zeroize_string(s: &mut String) {
    // SAFETY: Writing zero bytes produces valid UTF-8 and the buffer is immediately cleared.
    unsafe {
        zeroize_bytes(s.as_bytes_mut());
    }
    s.clear();
}

static SAFE_CREDENTIAL_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("constant peer credential id regex")
});

static REDACT_SECRETS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(PrivateKey\s*=\s*)\S+|(PresharedKey\s*=\s*)\S+|(X-AF-(?:Link|Grant)-Token\s*:\s*)\S+|[A-Za-z0-9+/]{43}=",
    )
    .expect("constant peer secret redaction regex")
});

/// Typed credential storage slots managed by `af-runner` on behalf of `af-api`.
///
/// Intentionally excludes the WireGuard private key (`afpeer0.key`), which never leaves the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCredentialSlot {
    /// Held outbound link token: `/etc/aetherflow/peers/tokens/<id>.token` (0640, group `aetherflow`).
    LinkToken,
    /// Held outbound grant token: `/etc/aetherflow/peers/tokens/<id>.grant.token` (0640, group `aetherflow`).
    GrantToken,
    /// Attempt-scoped temporary issuer token for handshake retries:
    /// `/etc/aetherflow/peers/pending/<id>.token` (0600, root-only).
    PendingIssuerToken,
}

impl PeerCredentialSlot {
    fn subdir(self) -> &'static str {
        match self {
            Self::LinkToken | Self::GrantToken => PEER_TOKENS_SUBDIR,
            Self::PendingIssuerToken => PEER_PENDING_SUBDIR,
        }
    }

    fn dir_kind(self) -> DirKind {
        match self {
            Self::LinkToken | Self::GrantToken => DirKind::StateGroupReadable,
            Self::PendingIssuerToken => DirKind::Private,
        }
    }

    fn file_mode(self) -> u32 {
        match self {
            Self::LinkToken | Self::GrantToken => 0o640,
            Self::PendingIssuerToken => 0o600,
        }
    }

    fn allow_group_read(self) -> bool {
        matches!(self, Self::LinkToken | Self::GrantToken)
    }

    fn file_name(self, validated_id: &str) -> String {
        match self {
            Self::LinkToken => format!("{validated_id}.token"),
            Self::GrantToken => format!("{validated_id}.grant.token"),
            Self::PendingIssuerToken => format!("{validated_id}.token"),
        }
    }
}

/// Request payload dispatched over `/v1/peer-network`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerNetworkRequest {
    EnsureIdentity {
        #[serde(default)]
        tunnel_ip: Option<String>,
        #[serde(default)]
        avoid_tunnel_ips: Vec<String>,
        #[serde(default)]
        wg_port: Option<u16>,
        #[serde(default)]
        tunnel_cidr: Option<String>,
    },
    AddPeer {
        pubkey: String,
        endpoint: String,
        port: u16,
        tunnel_ip: String,
    },
    RemovePeer {
        pubkey: String,
    },
    SetEndpoint {
        pubkey: String,
        endpoint: String,
        port: u16,
    },
    Status,
    EnsurePackages,
    WriteCredential {
        slot: PeerCredentialSlot,
        id: String,
        value: String,
    },
    ReadCredential {
        slot: PeerCredentialSlot,
        id: String,
    },
    DeleteCredential {
        slot: PeerCredentialSlot,
        id: String,
    },
    DeleteLinkCredentials {
        link_id: String,
    },
}

impl PeerNetworkRequest {
    pub(crate) fn is_mutating(&self) -> bool {
        !matches!(self, Self::Status | Self::ReadCredential { .. })
    }
}

impl Drop for PeerNetworkRequest {
    fn drop(&mut self) {
        if let Self::WriteCredential { value, .. } = self {
            zeroize_string(value);
        }
    }
}

impl fmt::Debug for PeerNetworkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnsureIdentity {
                tunnel_ip,
                avoid_tunnel_ips,
                wg_port,
                tunnel_cidr,
            } => f
                .debug_struct("EnsureIdentity")
                .field("tunnel_ip", tunnel_ip)
                .field("avoid_tunnel_ips", avoid_tunnel_ips)
                .field("wg_port", wg_port)
                .field("tunnel_cidr", tunnel_cidr)
                .finish(),
            Self::AddPeer {
                pubkey,
                endpoint,
                port,
                tunnel_ip,
            } => f
                .debug_struct("AddPeer")
                .field("pubkey", pubkey)
                .field("endpoint", endpoint)
                .field("port", port)
                .field("tunnel_ip", tunnel_ip)
                .finish(),
            Self::RemovePeer { pubkey } => f
                .debug_struct("RemovePeer")
                .field("pubkey", pubkey)
                .finish(),
            Self::SetEndpoint {
                pubkey,
                endpoint,
                port,
            } => f
                .debug_struct("SetEndpoint")
                .field("pubkey", pubkey)
                .field("endpoint", endpoint)
                .field("port", port)
                .finish(),
            Self::Status => f.write_str("Status"),
            Self::EnsurePackages => f.write_str("EnsurePackages"),
            Self::WriteCredential { slot, id, .. } => f
                .debug_struct("WriteCredential")
                .field("slot", slot)
                .field("id", id)
                .field("value", &REDACTED_MARKER)
                .finish(),
            Self::ReadCredential { slot, id } => f
                .debug_struct("ReadCredential")
                .field("slot", slot)
                .field("id", id)
                .finish(),
            Self::DeleteCredential { slot, id } => f
                .debug_struct("DeleteCredential")
                .field("slot", slot)
                .field("id", id)
                .finish(),
            Self::DeleteLinkCredentials { link_id } => f
                .debug_struct("DeleteLinkCredentials")
                .field("link_id", link_id)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentityResponse {
    pub interface: String,
    pub public_key: String,
    pub tunnel_ip: String,
    pub tunnel_cidr: String,
    pub interface_address: String,
    pub wg_port: u16,
    pub service_state: String,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMutationResponse {
    pub interface: String,
    pub pubkey: String,
    pub applied_live: bool,
    pub service_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatusPeer {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub latest_handshake: String,
    pub latest_handshake_epoch: i64,
    pub handshake_age_secs: Option<u64>,
    pub transfer_rx: String,
    pub transfer_tx: String,
    pub persistent_keepalive: u16,
    /// True when the peer has a recent WireGuard handshake (within 180s).
    pub active: bool,
    /// True when the peer is persisted in `afpeer0.conf`.
    pub persistent: bool,
    /// True when the peer is currently present in the live `wg show afpeer0 dump` output.
    pub present_live: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatusResponse {
    pub installed: bool,
    pub state: String,
    pub interface: String,
    pub public_key: String,
    pub listen_port: String,
    pub tunnel_ip: String,
    pub tunnel_cidr: String,
    pub interface_address: String,
    pub service_state: String,
    pub config_available: bool,
    pub key_available: bool,
    pub route_prefix_ready: bool,
    pub peers: Vec<PeerStatusPeer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEnsurePackagesResponse {
    pub installed: bool,
    pub already_installed: bool,
    pub packages: Vec<String>,
    pub versions: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentialWriteResponse {
    pub slot: PeerCredentialSlot,
    pub id: String,
    pub written: bool,
}

/// Secret credential value returned by `ReadCredential`.
///
/// Always redacts on `Debug` and `Display` and volatile-zeroizes its bytes on `Drop`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerCredentialSecret(String);

impl PeerCredentialSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for PeerCredentialSecret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for PeerCredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl fmt::Display for PeerCredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl Drop for PeerCredentialSecret {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentialReadResponse {
    pub slot: PeerCredentialSlot,
    pub id: String,
    pub present: bool,
    #[serde(default)]
    pub value: Option<PeerCredentialSecret>,
}

impl PeerCredentialReadResponse {
    pub fn secret(&self) -> Option<&PeerCredentialSecret> {
        self.value.as_ref()
    }

    pub fn into_secret(mut self) -> Option<PeerCredentialSecret> {
        self.value.take()
    }
}

impl fmt::Debug for PeerCredentialReadResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCredentialReadResponse")
            .field("slot", &self.slot)
            .field("id", &self.id)
            .field("present", &self.present)
            .field("value", &self.value.as_ref().map(|_| REDACTED_MARKER))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentialDeleteResponse {
    pub slot: PeerCredentialSlot,
    pub id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerLinkCredentialsDeleteResponse {
    pub link_id: String,
    pub link_token_deleted: bool,
    pub grant_token_deleted: bool,
}

/// Typed response returned by `dispatch_peer_network` and `execute_peer_network_local`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerNetworkResponse {
    Identity(PeerIdentityResponse),
    Mutation(PeerMutationResponse),
    Status(PeerStatusResponse),
    Packages(PeerEnsurePackagesResponse),
    CredentialWritten(PeerCredentialWriteResponse),
    CredentialRead(PeerCredentialReadResponse),
    CredentialDeleted(PeerCredentialDeleteResponse),
    LinkCredentialsDeleted(PeerLinkCredentialsDeleteResponse),
}

impl PeerNetworkResponse {
    pub fn into_identity(self) -> Result<PeerIdentityResponse, PeerNetworkError> {
        match self {
            Self::Identity(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected identity)".to_string(),
            )),
        }
    }

    pub fn into_mutation(self) -> Result<PeerMutationResponse, PeerNetworkError> {
        match self {
            Self::Mutation(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected mutation)".to_string(),
            )),
        }
    }

    pub fn into_status(self) -> Result<PeerStatusResponse, PeerNetworkError> {
        match self {
            Self::Status(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected status)".to_string(),
            )),
        }
    }

    pub fn into_packages(self) -> Result<PeerEnsurePackagesResponse, PeerNetworkError> {
        match self {
            Self::Packages(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected packages)".to_string(),
            )),
        }
    }

    pub fn into_credential_written(self) -> Result<PeerCredentialWriteResponse, PeerNetworkError> {
        match self {
            Self::CredentialWritten(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected credential_written)"
                    .to_string(),
            )),
        }
    }

    pub fn into_credential_read(self) -> Result<PeerCredentialReadResponse, PeerNetworkError> {
        match self {
            Self::CredentialRead(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected credential_read)".to_string(),
            )),
        }
    }

    pub fn into_credential_deleted(self) -> Result<PeerCredentialDeleteResponse, PeerNetworkError> {
        match self {
            Self::CredentialDeleted(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected credential_deleted)"
                    .to_string(),
            )),
        }
    }

    pub fn into_link_credentials_deleted(
        self,
    ) -> Result<PeerLinkCredentialsDeleteResponse, PeerNetworkError> {
        match self {
            Self::LinkCredentialsDeleted(v) => Ok(v),
            _ => Err(PeerNetworkError::Runtime(
                "Unexpected peer-network response variant (expected link_credentials_deleted)"
                    .to_string(),
            )),
        }
    }

    fn serialize_wire_output(&self) -> Result<String, PeerNetworkError> {
        let encoded = match self {
            Self::Identity(v) => serde_json::to_string(v),
            Self::Mutation(v) => serde_json::to_string(v),
            Self::Status(v) => serde_json::to_string(v),
            Self::Packages(v) => serde_json::to_string(v),
            Self::CredentialWritten(v) => serde_json::to_string(v),
            Self::CredentialRead(v) => serde_json::to_string(v),
            Self::CredentialDeleted(v) => serde_json::to_string(v),
            Self::LinkCredentialsDeleted(v) => serde_json::to_string(v),
        };
        encoded.map_err(|_| {
            PeerNetworkError::Runtime("Failed serializing peer-network response".to_string())
        })
    }
}

pub(crate) fn decode_peer_network_response(
    req: &PeerNetworkRequest,
    output: &str,
) -> Result<PeerNetworkResponse, PeerNetworkError> {
    let parse_err = || {
        PeerNetworkError::Runtime(
            "Invalid typed response payload from peer-network runner".to_string(),
        )
    };
    match req {
        PeerNetworkRequest::EnsureIdentity { .. } => Ok(PeerNetworkResponse::Identity(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::AddPeer { .. }
        | PeerNetworkRequest::RemovePeer { .. }
        | PeerNetworkRequest::SetEndpoint { .. } => Ok(PeerNetworkResponse::Mutation(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::Status => Ok(PeerNetworkResponse::Status(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::EnsurePackages => Ok(PeerNetworkResponse::Packages(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::WriteCredential { .. } => Ok(PeerNetworkResponse::CredentialWritten(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::ReadCredential { .. } => Ok(PeerNetworkResponse::CredentialRead(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::DeleteCredential { .. } => Ok(PeerNetworkResponse::CredentialDeleted(
            serde_json::from_str(output).map_err(|_| parse_err())?,
        )),
        PeerNetworkRequest::DeleteLinkCredentials { .. } => {
            Ok(PeerNetworkResponse::LinkCredentialsDeleted(
                serde_json::from_str(output).map_err(|_| parse_err())?,
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerNetworkError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Busy(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    PeerNotFound(String),
    #[error("{0}")]
    PeerAlreadyExists(String),
    #[error("{0}")]
    TunnelIpConflict(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Runtime(String),
}

impl PeerNetworkError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Self::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound(_) | Self::PeerNotFound(_) => StatusCode::NOT_FOUND,
            Self::PeerAlreadyExists(_) | Self::TunnelIpConflict(_) | Self::Conflict(_) => {
                StatusCode::CONFLICT
            }
            Self::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::Busy(_) => "busy",
            Self::NotFound(_) => "not_found",
            Self::PeerNotFound(_) => "peer_not_found",
            Self::PeerAlreadyExists(_) => "peer_already_exists",
            Self::TunnelIpConflict(_) => "tunnel_ip_conflict",
            Self::Conflict(_) => "conflict",
            Self::Runtime(_) => "runtime",
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }

    pub fn is_peer_not_found(&self) -> bool {
        matches!(self, Self::PeerNotFound(_))
    }

    pub fn is_peer_already_exists(&self) -> bool {
        matches!(self, Self::PeerAlreadyExists(_))
    }

    pub fn is_tunnel_ip_conflict(&self) -> bool {
        matches!(self, Self::TunnelIpConflict(_))
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
                "peer_not_found" => return Self::PeerNotFound(msg),
                "peer_already_exists" => return Self::PeerAlreadyExists(msg),
                "tunnel_ip_conflict" => return Self::TunnelIpConflict(msg),
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
            br#"{"success":false,"error":"Internal peer-network serialization error"}"#.to_vec()
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

/// Sensitive string buffer that redacts on `Debug` and clears its bytes on `Drop`.
#[derive(Clone, PartialEq, Eq)]
struct SecretString(String);

impl SecretString {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

pub(crate) fn redact_secrets(text: &str) -> String {
    REDACT_SECRETS_RE
        .replace_all(text, |caps: &regex::Captures<'_>| {
            if let Some(prefix) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
                format!("{}{REDACTED_MARKER}", prefix.as_str())
            } else {
                REDACTED_MARKER.to_string()
            }
        })
        .into_owned()
}

pub(crate) fn valid_wg_key(key: &str) -> bool {
    key.len() == 44
        && !key
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32 && bytes.iter().any(|b| *b != 0))
}

pub(crate) fn validate_credential_id(id: &str) -> Result<&str, PeerNetworkError> {
    if SAFE_CREDENTIAL_ID_RE.is_match(id) {
        Ok(id)
    } else {
        Err(PeerNetworkError::InvalidInput(
            "Invalid peer credential identifier; expected 1-64 ASCII letters, digits, '-' or '_'"
                .to_string(),
        ))
    }
}

fn validate_credential_value(value: &str) -> Result<&str, PeerNetworkError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES {
        return Err(PeerNetworkError::InvalidInput(format!(
            "Credential value must be between 1 and {MAX_CREDENTIAL_BYTES} bytes"
        )));
    }
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(PeerNetworkError::InvalidInput(
            "Credential value must contain only printable non-whitespace ASCII characters"
                .to_string(),
        ));
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TunnelCidr {
    pub(crate) ip: IpAddr,
    pub(crate) prefix: u8,
}

impl TunnelCidr {
    pub(crate) fn parse_subnet(raw: &str) -> Result<Self, PeerNetworkError> {
        let trimmed = raw.trim();
        if trimmed.chars().any(char::is_control) {
            return Err(PeerNetworkError::InvalidInput(
                "Invalid tunnel CIDR".to_string(),
            ));
        }
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            PeerNetworkError::InvalidInput("Tunnel CIDR must use address/prefix format".to_string())
        })?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| PeerNetworkError::InvalidInput("Invalid tunnel CIDR IP".to_string()))?;
        let prefix: u8 = prefix_str.parse().map_err(|_| {
            PeerNetworkError::InvalidInput("Invalid tunnel CIDR prefix".to_string())
        })?;
        let valid_prefix = match ip {
            IpAddr::V4(_) => (1..=30).contains(&prefix),
            IpAddr::V6(_) => (1..=126).contains(&prefix),
        };
        if !valid_prefix {
            return Err(PeerNetworkError::InvalidInput(
                "Tunnel CIDR prefix must provide a routable multi-peer subnet (IPv4 /1../30 or IPv6 /1../126)".to_string(),
            ));
        }
        Ok(Self { ip, prefix })
    }

    fn parse_any(raw: &str) -> Result<Self, PeerNetworkError> {
        let trimmed = raw.trim();
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            PeerNetworkError::InvalidInput("Invalid CIDR: expected address/prefix".to_string())
        })?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| PeerNetworkError::InvalidInput("Invalid CIDR IP address".to_string()))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| PeerNetworkError::InvalidInput("Invalid CIDR prefix".to_string()))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(PeerNetworkError::InvalidInput(
                "CIDR prefix out of range".to_string(),
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
        Self::ip_bits(self.ip)
    }

    fn mask(&self) -> u128 {
        let width = if self.ip.is_ipv4() { 32 } else { 128 };
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (width - self.prefix)
        }
    }

    fn network_bits(&self) -> u128 {
        self.bits() & self.mask()
    }

    fn network_string(&self) -> String {
        let bits = self.network_bits();
        let ip = match self.ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(bits as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(bits)),
        };
        format!("{ip}/{}", self.prefix)
    }

    fn interface_string(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }

    fn host_prefix(&self) -> u8 {
        if self.ip.is_ipv4() {
            32
        } else {
            128
        }
    }

    fn same_family(&self, ip: IpAddr) -> bool {
        self.ip.is_ipv4() == ip.is_ipv4()
    }

    fn contains_ip(&self, ip: IpAddr) -> bool {
        self.same_family(ip) && (Self::ip_bits(ip) & self.mask()) == self.network_bits()
    }

    fn is_usable_host(&self, ip: IpAddr) -> bool {
        if !self.contains_ip(ip) {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                let addr = u32::from(v4);
                let mask = self.mask() as u32;
                let net = addr & mask;
                let bcast = net | !mask;
                addr != net && addr != bcast
            }
            IpAddr::V6(v6) => {
                let addr = u128::from(v6);
                addr != self.network_bits()
            }
        }
    }

    fn usable_host_count(&self) -> u128 {
        match self.ip {
            IpAddr::V4(_) => {
                let host_bits = 32 - self.prefix;
                (1u128 << host_bits).saturating_sub(2)
            }
            IpAddr::V6(_) => {
                let host_bits = (128 - self.prefix).min(64);
                (1u128 << host_bits).saturating_sub(1)
            }
        }
    }

    fn host_at_offset(&self, offset: u128) -> Option<IpAddr> {
        let base = self.network_bits();
        let candidate = base.checked_add(offset)?;
        let ip = match self.ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(candidate as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(candidate)),
        };
        self.is_usable_host(ip).then_some(ip)
    }

    fn pick_usable_host(&self, avoid: &HashSet<IpAddr>) -> Result<IpAddr, PeerNetworkError> {
        let usable = self.usable_host_count();
        if usable == 0 {
            return Err(PeerNetworkError::InvalidInput(
                "Configured tunnel CIDR has no usable host addresses".to_string(),
            ));
        }
        // Try random offsets first so independently initialized servers almost never collide.
        for _ in 0..64 {
            let random = u128::from_be_bytes(*uuid::Uuid::new_v4().as_bytes());
            let offset = (random % usable) + 1;
            if let Some(ip) = self.host_at_offset(offset) {
                if !avoid.contains(&ip) {
                    return Ok(ip);
                }
            }
        }
        // Deterministic fallback scan for small subnets.
        let scan_limit = usable.min(65536);
        for offset in 1..=scan_limit {
            if let Some(ip) = self.host_at_offset(offset) {
                if !avoid.contains(&ip) {
                    return Ok(ip);
                }
            }
        }
        Err(PeerNetworkError::TunnelIpConflict(
            "TUNNEL_IP_CONFLICT: no unused tunnel IP remains in the configured peer CIDR"
                .to_string(),
        ))
    }
}

fn parse_bare_ip(raw: &str, label: &str) -> Result<IpAddr, PeerNetworkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains(',')
        || trimmed.chars().any(char::is_control)
    {
        return Err(PeerNetworkError::InvalidInput(format!(
            "{label} must be a single bare IP address without a CIDR prefix"
        )));
    }
    trimmed
        .parse::<IpAddr>()
        .map_err(|_| PeerNetworkError::InvalidInput(format!("{label} is not a valid IP address")))
}

fn validate_tunnel_ip(raw: &str, cidr: &TunnelCidr) -> Result<IpAddr, PeerNetworkError> {
    let ip = parse_bare_ip(raw, "Tunnel IP")?;
    if !cidr.contains_ip(ip) {
        return Err(PeerNetworkError::InvalidInput(format!(
            "Tunnel IP {ip} is outside the configured peer tunnel CIDR {}",
            cidr.network_string()
        )));
    }
    if !cidr.is_usable_host(ip) {
        return Err(PeerNetworkError::InvalidInput(format!(
            "Tunnel IP {ip} cannot be a subnet network or broadcast address"
        )));
    }
    Ok(ip)
}

fn endpoints_match(saved: &str, requested: &str) -> bool {
    let saved = saved.trim();
    let requested = requested.trim();
    if let (Ok(a), Ok(b)) = (saved.parse::<SocketAddr>(), requested.parse::<SocketAddr>()) {
        return a == b;
    }
    saved.eq_ignore_ascii_case(requested)
}

fn endpoints_match_live(live: &str, requested: &str, requested_port: u16) -> bool {
    let live = live.trim();
    let requested = requested.trim();
    if let (Ok(a), Ok(b)) = (live.parse::<SocketAddr>(), requested.parse::<SocketAddr>()) {
        return a == b;
    }
    if live.eq_ignore_ascii_case(requested) {
        return true;
    }
    // WireGuard resolves DNS hostname endpoints to an IP in `wg showconf`; when the requested
    // endpoint is a hostname (not an IP literal), require the live endpoint to exist on the
    // matching UDP port.
    if requested.parse::<SocketAddr>().is_err() {
        if let Ok(live_sock) = live.parse::<SocketAddr>() {
            return live_sock.port() == requested_port;
        }
    }
    false
}

fn validate_peer_endpoint(endpoint: &str, port: u16) -> Result<String, PeerNetworkError> {
    if port == 0 {
        return Err(PeerNetworkError::InvalidInput(
            "Peer WireGuard port must be between 1 and 65535".to_string(),
        ));
    }
    let trimmed = endpoint.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.starts_with('-')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PeerNetworkError::InvalidInput(
            "Peer endpoint must be a valid IP address or hostname".to_string(),
        ));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => format!("{v4}:{port}"),
            IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        });
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(v6) = inner.parse::<Ipv6Addr>() {
            return Ok(format!("[{v6}]:{port}"));
        }
        return Err(PeerNetworkError::InvalidInput(
            "Bracketed peer endpoint must be a valid IPv6 address".to_string(),
        ));
    }
    if trimmed.contains(':') || trimmed.contains('[') || trimmed.contains(']') {
        return Err(PeerNetworkError::InvalidInput(
            "Peer endpoint must be a bare IP address or hostname (supply port separately)"
                .to_string(),
        ));
    }
    let valid_host = !trimmed.ends_with('.')
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !valid_host {
        return Err(PeerNetworkError::InvalidInput(
            "Peer endpoint must be a valid hostname or IP address".to_string(),
        ));
    }
    Ok(format!("{trimmed}:{port}"))
}

fn parse_ini_fields(raw: &str) -> HashMap<String, String> {
    let mut values: HashMap<String, String> = HashMap::new();
    for line in raw.lines() {
        let stripped = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let val = value.trim();
        if matches!(key.as_str(), "address" | "allowedips") {
            values
                .entry(key)
                .and_modify(|old| {
                    old.push_str(", ");
                    old.push_str(val);
                })
                .or_insert_with(|| val.to_string());
        } else {
            values.insert(key, val.to_string());
        }
    }
    values
}

#[derive(Clone)]
struct PeerBlock {
    raw: String,
    fields: HashMap<String, String>,
}

impl fmt::Debug for PeerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerBlock")
            .field("public_key", &self.pubkey())
            .field("allowed_ips", &self.allowed_ips())
            .field("endpoint", &self.endpoint())
            .finish()
    }
}

impl PeerBlock {
    fn parse(raw: String) -> Self {
        let fields = parse_ini_fields(&raw);
        Self { raw, fields }
    }

    fn build(pubkey: &str, allowed_ips: &str, endpoint: &str) -> Self {
        let raw = format!(
            "[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {allowed_ips}\nEndpoint = {endpoint}\nPersistentKeepalive = {PEER_PERSISTENT_KEEPALIVE}\n"
        );
        Self::parse(raw)
    }

    fn pubkey(&self) -> &str {
        self.fields
            .get("publickey")
            .map(String::as_str)
            .unwrap_or("")
    }

    fn allowed_ips(&self) -> &str {
        self.fields
            .get("allowedips")
            .map(String::as_str)
            .unwrap_or("")
    }

    fn endpoint(&self) -> &str {
        self.fields
            .get("endpoint")
            .map(String::as_str)
            .unwrap_or("")
    }

    fn persistent_keepalive(&self) -> u16 {
        self.fields
            .get("persistentkeepalive")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0)
    }

    fn with_updated_endpoint(&self, new_endpoint: &str) -> Self {
        let mut out = String::new();
        let mut replaced = false;
        for line in self.raw.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if let Some((key, _)) = trimmed.split_once('=') {
                if key.trim().eq_ignore_ascii_case("endpoint") {
                    if !replaced {
                        out.push_str(&format!("Endpoint = {new_endpoint}\n"));
                        replaced = true;
                    }
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        if !replaced {
            out.push_str(&format!("Endpoint = {new_endpoint}\n"));
        }
        Self::parse(out)
    }

    fn status_peer(&self) -> PeerStatusPeer {
        PeerStatusPeer {
            public_key: self.pubkey().to_string(),
            endpoint: self.endpoint().to_string(),
            allowed_ips: self.allowed_ips().to_string(),
            latest_handshake: "0".to_string(),
            latest_handshake_epoch: 0,
            handshake_age_secs: None,
            transfer_rx: "0".to_string(),
            transfer_tx: "0".to_string(),
            persistent_keepalive: self.persistent_keepalive(),
            active: false,
            persistent: true,
            present_live: false,
        }
    }
}

#[derive(Clone)]
struct PeerWireGuardConfig {
    header: String,
    peers: Vec<PeerBlock>,
}

impl fmt::Debug for PeerWireGuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerWireGuardConfig")
            .field("peer_count", &self.peers.len())
            .finish()
    }
}

impl Drop for PeerWireGuardConfig {
    fn drop(&mut self) {
        zeroize_string(&mut self.header);
    }
}

impl PeerWireGuardConfig {
    fn new_initial(interface_addr: &TunnelCidr, private_key: &SecretString, wg_port: u16) -> Self {
        let header = format!(
            "# Managed by AetherFlow Peer Clustering. Do not edit manually.\n[Interface]\nAddress = {}\nPrivateKey = {}\nListenPort = {}\nSaveConfig = false\n",
            interface_addr.interface_string(),
            private_key.as_str(),
            wg_port
        );
        Self {
            header,
            peers: Vec::new(),
        }
    }

    fn parse(raw: &str) -> Result<Self, PeerNetworkError> {
        if raw.len() > MAX_CONFIG_BYTES {
            return Err(PeerNetworkError::InvalidInput(
                "Peer WireGuard configuration exceeds size limit".to_string(),
            ));
        }
        let mut header = String::new();
        let mut peers = Vec::new();
        let mut current = String::new();
        let mut in_peer = false;
        let mut seen_interface = false;

        for line in raw.lines() {
            let section = line.split('#').next().unwrap_or("").trim();
            if section.starts_with('[') {
                if section.eq_ignore_ascii_case("[Peer]") {
                    if in_peer {
                        peers.push(PeerBlock::parse(std::mem::take(&mut current)));
                    } else {
                        header = std::mem::take(&mut current);
                    }
                    in_peer = true;
                } else if section.eq_ignore_ascii_case("[Interface]") && !seen_interface && !in_peer
                {
                    seen_interface = true;
                } else {
                    return Err(PeerNetworkError::InvalidInput(
                        "Unsupported or duplicate WireGuard section in afpeer0.conf".to_string(),
                    ));
                }
            }
            current.push_str(line);
            current.push('\n');
        }
        if in_peer {
            peers.push(PeerBlock::parse(current));
        } else {
            header = current;
        }
        if !seen_interface {
            return Err(PeerNetworkError::InvalidInput(
                "Peer WireGuard configuration has no [Interface] section".to_string(),
            ));
        }
        if peers.len() > MAX_PEERS {
            return Err(PeerNetworkError::InvalidInput(
                "Too many WireGuard peers in afpeer0.conf".to_string(),
            ));
        }
        let keys: HashSet<&str> = peers.iter().map(PeerBlock::pubkey).collect();
        if keys.len() != peers.len() || peers.iter().any(|p| !valid_wg_key(p.pubkey())) {
            return Err(PeerNetworkError::InvalidInput(
                "Peer WireGuard configuration has invalid or duplicate peer keys".to_string(),
            ));
        }
        if parse_ini_fields(&header)
            .get("saveconfig")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            return Err(PeerNetworkError::InvalidInput(
                "SaveConfig=true is forbidden in AetherFlow-managed afpeer0.conf".to_string(),
            ));
        }
        Ok(Self { header, peers })
    }

    fn header_fields(&self) -> HashMap<String, String> {
        parse_ini_fields(&self.header)
    }

    fn private_key(&self) -> Option<SecretString> {
        self.header_fields()
            .get("privatekey")
            .cloned()
            .map(SecretString::new)
    }

    fn interface_address(&self) -> Result<TunnelCidr, PeerNetworkError> {
        let fields = self.header_fields();
        let raw = fields.get("address").map(String::as_str).unwrap_or("");
        let parts: Vec<&str> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() != 1 {
            return Err(PeerNetworkError::InvalidInput(
                "afpeer0.conf [Interface] must declare exactly one tunnel subnet Address"
                    .to_string(),
            ));
        }
        let cidr = TunnelCidr::parse_subnet(parts[0])?;
        if !cidr.is_usable_host(cidr.ip) {
            return Err(PeerNetworkError::InvalidInput(
                "afpeer0.conf [Interface] Address must use a usable host IP within its subnet"
                    .to_string(),
            ));
        }
        Ok(cidr)
    }

    fn listen_port(&self) -> Result<u16, PeerNetworkError> {
        let fields = self.header_fields();
        let raw = fields.get("listenport").map(String::as_str).unwrap_or("");
        let port = raw.parse::<u16>().map_err(|_| {
            PeerNetworkError::InvalidInput("Invalid WireGuard ListenPort in afpeer0.conf".into())
        })?;
        if port == 0 {
            return Err(PeerNetworkError::InvalidInput(
                "WireGuard ListenPort in afpeer0.conf must be between 1 and 65535".to_string(),
            ));
        }
        Ok(port)
    }

    fn validate_server(&self) -> Result<(TunnelCidr, u16, SecretString), PeerNetworkError> {
        let address = self.interface_address()?;
        let private_key = self
            .private_key()
            .filter(|k| valid_wg_key(k.as_str()))
            .ok_or_else(|| {
                PeerNetworkError::Runtime(
                    "Invalid WireGuard server private key; repair afpeer0.conf without changing its identity"
                        .to_string(),
                )
            })?;
        let port = self.listen_port()?;
        let mut seen_ips = HashSet::new();
        for peer in &self.peers {
            let ips = peer_allowed_host_ips(peer.allowed_ips())?;
            if ips.is_empty() {
                return Err(PeerNetworkError::InvalidInput(
                    "Peer in afpeer0.conf is missing AllowedIPs".to_string(),
                ));
            }
            for ip in ips {
                if !address.contains_ip(ip) || !address.is_usable_host(ip) || ip == address.ip {
                    return Err(PeerNetworkError::InvalidInput(
                        "Peer AllowedIPs in afpeer0.conf must be usable host addresses inside the tunnel subnet"
                            .to_string(),
                    ));
                }
                if !seen_ips.insert(ip) {
                    return Err(PeerNetworkError::TunnelIpConflict(
                        "TUNNEL_IP_CONFLICT: duplicate peer AllowedIPs in afpeer0.conf".to_string(),
                    ));
                }
            }
        }
        Ok((address, port, private_key))
    }

    fn render(&self) -> SecretString {
        let mut text = self.header.trim_end().to_string();
        text.push('\n');
        for peer in &self.peers {
            text.push('\n');
            text.push_str(peer.raw.trim_end());
            text.push('\n');
        }
        SecretString::new(text)
    }
}

fn peer_allowed_host_ips(raw: &str) -> Result<Vec<IpAddr>, PeerNetworkError> {
    let mut ips = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let cidr = TunnelCidr::parse_any(entry)?;
        if cidr.prefix != cidr.host_prefix() {
            return Err(PeerNetworkError::InvalidInput(
                "Peer AllowedIPs must be restricted to single-host /32 or /128 addresses"
                    .to_string(),
            ));
        }
        ips.push(cidr.ip);
    }
    Ok(ips)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirKind {
    /// `/etc/wireguard` — private root-only WireGuard config directory (`0o700`).
    Config,
    /// `/etc/aetherflow/peers` and `/etc/aetherflow/peers/tokens` (`0o750`, group `aetherflow`).
    StateGroupReadable,
    /// `/etc/aetherflow/peers/pending` and `/etc/aetherflow/peers/.staging` (`0o700`, root-only).
    Private,
}

impl DirKind {
    fn create_mode(self) -> u32 {
        match self {
            Self::Config | Self::Private => 0o700,
            Self::StateGroupReadable => 0o750,
        }
    }

    fn forbidden_bits(self) -> u32 {
        match self {
            // Forbid setuid/setgid/sticky and all group/world access.
            Self::Config | Self::Private => 0o7077,
            // Forbid setuid/setgid/sticky, group-write, and all world access.
            Self::StateGroupReadable => 0o7027,
        }
    }

    fn group_required(self) -> bool {
        matches!(self, Self::StateGroupReadable)
    }
}

#[derive(Clone, Debug)]
enum GroupPolicy {
    /// Production default: when running as root, resolve the named system group via `getgrnam_r`
    /// and fail closed if it does not exist. Non-root isolated fixtures skip `fchown`/GID checks
    /// unless overridden in tests.
    System { name: String },
    /// Always resolve the named system group (even when non-root) to test lookup failure clearly.
    #[cfg(test)]
    RequireSystemLookup { name: String },
    /// Always require this exact GID on group-readable directories and credential files.
    #[cfg(test)]
    FixedGid(u32),
}

#[derive(Clone, Debug)]
struct FsSecurityPolicy {
    expected_uid: Option<u32>,
    group_policy: GroupPolicy,
}

impl FsSecurityPolicy {
    fn default_for_process() -> Self {
        Self {
            expected_uid: running_as_root().then_some(0),
            group_policy: GroupPolicy::System {
                name: REQUIRED_CREDENTIAL_GROUP.to_string(),
            },
        }
    }

    fn resolve_required_group_gid(&self) -> Result<Option<u32>, PeerNetworkError> {
        match &self.group_policy {
            GroupPolicy::System { name } => {
                if !running_as_root() {
                    return Ok(None);
                }
                lookup_group_gid(name).map(Some).ok_or_else(|| {
                    PeerNetworkError::Runtime(format!(
                        "Required system group '{name}' could not be resolved; cannot secure peer credential storage"
                    ))
                })
            }
            #[cfg(test)]
            GroupPolicy::RequireSystemLookup { name } => {
                lookup_group_gid(name).map(Some).ok_or_else(|| {
                    PeerNetworkError::Runtime(format!(
                        "Required system group '{name}' could not be resolved; cannot secure peer credential storage"
                    ))
                })
            }
            #[cfg(test)]
            GroupPolicy::FixedGid(gid) => Ok(Some(*gid)),
        }
    }
}

/// FD-anchored advisory file lock held over a verified `ReceiptDirectory`.
struct ConfinedLockGuard {
    _dir: ReceiptDirectory,
    file: File,
}

impl Drop for ConfinedLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Runner-owned temporary file containing secret config/key data.
/// Zeroes its contents and unlinks on drop.
struct TemporarySecretFile {
    dir: ReceiptDirectory,
    name: String,
    full_path: PathBuf,
}

impl TemporarySecretFile {
    fn create(
        manager: &PeerNetworkManager,
        prefix: &str,
        contents: &[u8],
    ) -> Result<Self, PeerNetworkError> {
        let _ = manager.ensure_confined_dir(&manager.state_dir, DirKind::StateGroupReadable)?;
        let staging_dir_path = manager.state_dir.join(".staging");
        let dir = manager.ensure_confined_dir(&staging_dir_path, DirKind::Private)?;
        let name = format!(".{prefix}-{}.conf", uuid::Uuid::new_v4().simple());
        let name_os = OsStr::new(&name);
        let mut file = dir
            .open_file(
                name_os,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
            .map_err(|err| {
                PeerNetworkError::Runtime(format!("Failed to stage runner temp file: {err}"))
            })?;
        let result = (|| -> std::io::Result<()> {
            enforce_root_ownership_and_mode(&file, 0o600, None)?;
            file.write_all(contents)?;
            file.sync_all()?;
            dir.verify()?;
            verify_entry(dir.file(), name_os, &file, false)?;
            Ok(())
        })();
        if let Err(err) = result {
            if let Ok(name_c) = c_name(name_os) {
                unsafe {
                    libc::unlinkat(dir.file().as_raw_fd(), name_c.as_ptr(), 0);
                }
            }
            return Err(PeerNetworkError::Runtime(format!(
                "Failed to write staged runner temp file: {err}"
            )));
        }
        Ok(Self {
            dir,
            full_path: staging_dir_path.join(&name),
            name,
        })
    }

    fn path(&self) -> &Path {
        &self.full_path
    }
}

impl Drop for TemporarySecretFile {
    fn drop(&mut self) {
        let name_os = OsStr::new(&self.name);
        if let Ok(mut file) = self.dir.open_file(name_os, libc::O_RDWR, 0) {
            if let Ok(meta) = file.metadata() {
                if meta.is_file() {
                    let len = (meta.len() as usize).min(MAX_CONFIG_BYTES);
                    if file.seek(SeekFrom::Start(0)).is_ok() {
                        let zeros = vec![0u8; len];
                        let _ = file.write_all(&zeros);
                        let _ = file.sync_all();
                    }
                }
            }
        }
        if let Ok(name_c) = c_name(name_os) {
            unsafe {
                libc::unlinkat(self.dir.file().as_raw_fd(), name_c.as_ptr(), 0);
            }
        }
    }
}

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn enforce_root_ownership_and_mode(
    file: &File,
    mode: u32,
    required_gid: Option<u32>,
) -> std::io::Result<()> {
    if running_as_root() {
        let gid = required_gid.unwrap_or(0);
        let meta = file.metadata()?;
        if (meta.uid() != 0 || meta.gid() != gid)
            && unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn validate_lock_file_metadata(
    file: &File,
    lock_name: &str,
    security: &FsSecurityPolicy,
) -> Result<(), PeerNetworkError> {
    let meta = file.metadata().map_err(|err| {
        PeerNetworkError::Runtime(format!("Cannot stat peer lock {lock_name}: {err}"))
    })?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(PeerNetworkError::Runtime(format!(
            "Refusing non-regular or hard-linked peer lock {lock_name}"
        )));
    }
    if let Some(uid) = security.expected_uid {
        if meta.uid() != uid {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing peer lock {lock_name} not owned by expected uid {uid}"
            )));
        }
        if meta.gid() != 0 {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing peer lock {lock_name} not owned by root group"
            )));
        }
    }
    let perm = meta.mode() & 0o7777;
    if perm != 0o600 {
        return Err(PeerNetworkError::Runtime(format!(
            "Refusing peer lock {lock_name} with non-strict mode {perm:04o} (expected 0600)"
        )));
    }
    Ok(())
}

async fn poll_flock_until(
    file: &File,
    lock_op: libc::c_int,
    deadline: Instant,
    busy_message: &str,
) -> Result<(), PeerNetworkError> {
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
                return Err(PeerNetworkError::Busy(busy_message.to_string()));
            }
            let remaining = deadline.saturating_duration_since(now);
            tokio::time::sleep(Duration::from_millis(15).min(remaining)).await;
            continue;
        }
        return Err(PeerNetworkError::Runtime(format!(
            "Failed acquiring peer advisory file lock: {err}"
        )));
    }
}

fn delete_secret_file_confined(
    dir: &ReceiptDirectory,
    name: &str,
    expected_uid: Option<u32>,
) -> Result<bool, PeerNetworkError> {
    let name_os = OsStr::new(name);
    dir.verify().map_err(|err| {
        PeerNetworkError::Runtime(format!("Directory verification failed: {err}"))
    })?;
    let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing to remove unsafe or symlink entry {name}: {err}"
            )))
        }
    };
    if let Some(uid) = expected_uid {
        let meta = file.metadata().map_err(|err| {
            PeerNetworkError::Runtime(format!("Cannot stat {name} before deletion: {err}"))
        })?;
        if meta.uid() != uid {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing to remove {name} not owned by expected uid {uid}"
            )));
        }
    }
    verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
        PeerNetworkError::Runtime(format!(
            "Refusing to remove non-regular entry {name}: {err}"
        ))
    })?;
    let name_c = c_name(name_os)
        .map_err(|err| PeerNetworkError::Runtime(format!("Invalid entry name {name}: {err}")))?;
    if unsafe { libc::unlinkat(dir.file().as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(PeerNetworkError::Runtime(format!(
            "Failed to delete {name}: {err}"
        )));
    }
    let _ = dir.file().sync_all();
    Ok(true)
}

struct CmdOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> Result<Vec<u8>, PeerNetworkError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await.map_err(|err| {
            PeerNetworkError::Runtime(format!("Command stream read failed: {err}"))
        })?;
        if n == 0 {
            return Ok(out);
        }
        if n > limit.saturating_sub(out.len()) {
            return Err(PeerNetworkError::Runtime(
                "Peer network command output exceeded its size limit".to_string(),
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

/// Ensures a spawned command's process group is killed even if the calling future is dropped.
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

/// Manages the dedicated `afpeer0` WireGuard interface and runner-owned peer credentials.
#[derive(Clone, Debug)]
pub struct PeerNetworkManager {
    wg_dir: PathBuf,
    state_dir: PathBuf,
    bin: Option<PathBuf>,
    fs_root: Option<PathBuf>,
    tunnel_cidr: TunnelCidr,
    wg_port: u16,
    command_timeout: Duration,
    apt_timeout: Duration,
    lock_timeout: Duration,
    package_lock_timeout: Duration,
    security: FsSecurityPolicy,
}

impl PeerNetworkManager {
    /// Builds the production manager from operator configuration env vars
    /// (`AF_PEER_TUNNEL_CIDR`, `AF_PEER_WG_PORT`). Performs no filesystem or OS side effects.
    pub fn from_env() -> Result<Self, PeerNetworkError> {
        let cidr_raw = env::var("AF_PEER_TUNNEL_CIDR")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PEER_TUNNEL_CIDR.to_string());
        let tunnel_cidr = TunnelCidr::parse_subnet(&cidr_raw)?;

        let wg_port = match env::var("AF_PEER_WG_PORT") {
            Ok(raw) if !raw.trim().is_empty() => {
                let parsed = raw.trim().parse::<u16>().map_err(|_| {
                    PeerNetworkError::InvalidInput(
                        "AF_PEER_WG_PORT must be a valid UDP port (1-65535)".to_string(),
                    )
                })?;
                if parsed == 0 {
                    return Err(PeerNetworkError::InvalidInput(
                        "AF_PEER_WG_PORT must be between 1 and 65535".to_string(),
                    ));
                }
                parsed
            }
            _ => DEFAULT_PEER_WG_PORT,
        };

        Ok(Self {
            wg_dir: PathBuf::from(DEFAULT_PEER_WG_DIR),
            state_dir: PathBuf::from(DEFAULT_PEER_STATE_DIR),
            bin: None,
            fs_root: None,
            tunnel_cidr,
            wg_port,
            command_timeout: COMMAND_TIMEOUT,
            apt_timeout: APT_STEP_TIMEOUT,
            lock_timeout: CONFIG_LOCK_TIMEOUT,
            package_lock_timeout: PACKAGE_LOCK_TIMEOUT,
            security: FsSecurityPolicy::default_for_process(),
        })
    }

    /// Constructs an isolated manager for fixture tests (never touches `/etc/wireguard`,
    /// `/etc/aetherflow/peers`, or host binaries).
    pub fn new_isolated(
        root: PathBuf,
        bin_dir: PathBuf,
        tunnel_cidr: &str,
        wg_port: u16,
    ) -> Result<Self, PeerNetworkError> {
        let parsed_cidr = TunnelCidr::parse_subnet(tunnel_cidr)?;
        if wg_port == 0 {
            return Err(PeerNetworkError::InvalidInput(
                "WireGuard port must be between 1 and 65535".to_string(),
            ));
        }
        Ok(Self {
            wg_dir: root.join("etc/wireguard"),
            state_dir: root.join("etc/aetherflow/peers"),
            bin: Some(bin_dir),
            fs_root: Some(root),
            tunnel_cidr: parsed_cidr,
            wg_port,
            command_timeout: COMMAND_TIMEOUT,
            apt_timeout: APT_STEP_TIMEOUT,
            lock_timeout: CONFIG_LOCK_TIMEOUT,
            package_lock_timeout: PACKAGE_LOCK_TIMEOUT,
            security: FsSecurityPolicy::default_for_process(),
        })
    }

    #[cfg(test)]
    fn with_command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
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
        self.security.expected_uid = uid;
        self
    }

    #[cfg(test)]
    fn with_required_group_name(mut self, group_name: &str) -> Self {
        self.security.group_policy = GroupPolicy::RequireSystemLookup {
            name: group_name.to_string(),
        };
        self
    }

    #[cfg(test)]
    fn with_expected_group_gid(mut self, gid: u32) -> Self {
        self.security.group_policy = GroupPolicy::FixedGid(gid);
        self
    }

    fn program(&self, name: &str) -> PathBuf {
        self.bin
            .as_ref()
            .map_or_else(|| PathBuf::from(name), |bin| bin.join(name))
    }

    pub(crate) fn config_path(&self) -> PathBuf {
        self.wg_dir.join(PEER_WG_CONF_NAME)
    }

    #[cfg(test)]
    pub(crate) fn key_path(&self) -> PathBuf {
        self.state_dir.join(PEER_WG_KEY_NAME)
    }

    /// Returns `"afpeer0"` in production (`/etc/wireguard`) and `<wg_dir>/afpeer0.conf` in
    /// isolated fixture directories so both real `wg-quick` and test fakes target `afpeer0.conf`.
    pub(crate) fn strip_target(&self) -> String {
        if self.wg_dir == Path::new(DEFAULT_PEER_WG_DIR) {
            PEER_WG_INTERFACE.to_string()
        } else {
            self.config_path().to_string_lossy().into_owned()
        }
    }

    fn validate_managed_ancestors(&self, path: &Path) -> Result<(), PeerNetworkError> {
        let anchor = self.fs_root.as_deref().unwrap_or_else(|| Path::new("/"));
        let Ok(rel) = path.strip_prefix(anchor) else {
            return Ok(());
        };
        let components: Vec<&OsStr> = rel
            .components()
            .filter_map(|comp| match comp {
                std::path::Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        if components.len() <= 1 {
            return Ok(());
        }
        let mut cursor = anchor.to_path_buf();
        // Check each intermediate managed parent directory strictly below `anchor` and above leaf.
        for name in &components[..components.len() - 1] {
            cursor.push(name);
            let Some(anc_dir) = ReceiptDirectory::open_existing(&cursor).map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Refusing unsafe or inaccessible ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?
            else {
                return Err(PeerNetworkError::Runtime(format!(
                    "Managed ancestor directory {} disappeared",
                    cursor.display()
                )));
            };
            if let Some(uid) = self.security.expected_uid {
                anc_dir.verify_owners(&[uid]).map_err(|err| {
                    PeerNetworkError::Runtime(format!(
                        "Ancestor directory {} is not owned by expected uid {uid}: {err}",
                        cursor.display()
                    ))
                })?;
            }
            let meta = anc_dir.file().metadata().map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Cannot stat ancestor directory {}: {err}",
                    cursor.display()
                ))
            })?;
            let perm = meta.mode() & 0o7777;
            if perm & 0o6022 != 0 {
                return Err(PeerNetworkError::Runtime(format!(
                    "Refusing writable or privileged ancestor directory {} (mode {perm:04o})",
                    cursor.display()
                )));
            }
        }
        Ok(())
    }

    fn validate_confined_dir(
        &self,
        path: &Path,
        dir: &ReceiptDirectory,
        kind: DirKind,
    ) -> Result<(), PeerNetworkError> {
        dir.verify().map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Directory verification failed for {}: {err}",
                path.display()
            ))
        })?;
        if let Some(uid) = self.security.expected_uid {
            dir.verify_owners(&[uid]).map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Directory {} is not owned by expected uid {uid}: {err}",
                    path.display()
                ))
            })?;
        }
        self.validate_managed_ancestors(path)?;
        let meta = dir.file().metadata().map_err(|err| {
            PeerNetworkError::Runtime(format!("Cannot stat directory {}: {err}", path.display()))
        })?;
        if !meta.is_dir() {
            return Err(PeerNetworkError::Runtime(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        if let Some(uid) = self.security.expected_uid {
            if meta.uid() != uid {
                return Err(PeerNetworkError::Runtime(format!(
                    "Directory {} is not owned by expected uid {uid}",
                    path.display()
                )));
            }
        }
        let perm = meta.mode() & 0o7777;
        if perm & kind.forbidden_bits() != 0 {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing overly permissive directory {} (mode {perm:04o})",
                path.display()
            )));
        }
        if kind.group_required() {
            if let Some(expected_gid) = self.security.resolve_required_group_gid()? {
                if perm & 0o050 != 0 && meta.gid() != expected_gid && meta.gid() != 0 {
                    return Err(PeerNetworkError::Runtime(format!(
                        "Refusing directory {} with unexpected group gid {}",
                        path.display(),
                        meta.gid()
                    )));
                }
            }
        }
        Ok(())
    }

    fn open_existing_confined_dir(
        &self,
        path: &Path,
        kind: DirKind,
    ) -> Result<Option<ReceiptDirectory>, PeerNetworkError> {
        if path != self.state_dir && path.starts_with(&self.state_dir) {
            let Some(state_dir) =
                self.open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?
            else {
                return Ok(None);
            };
            drop(state_dir);
        }
        let dir = ReceiptDirectory::open_existing(path).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Refusing unsafe or inaccessible directory {}: {err}",
                path.display()
            ))
        })?;
        if let Some(ref directory) = dir {
            self.validate_confined_dir(path, directory, kind)?;
        }
        Ok(dir)
    }

    fn ensure_confined_dir(
        &self,
        path: &Path,
        kind: DirKind,
    ) -> Result<ReceiptDirectory, PeerNetworkError> {
        if path != self.state_dir && path.starts_with(&self.state_dir) {
            let _ = self.ensure_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?;
        }
        let required_gid = if kind.group_required() {
            self.security.resolve_required_group_gid()?
        } else {
            None
        };
        if let Some(existing) = self.open_existing_confined_dir(path, kind)? {
            // Existing directory already passed strict validation (no forbidden mode bits, valid
            // owner/group). Only apply mode/group when tightening/provisioning a managed state dir.
            if kind.group_required() {
                enforce_root_ownership_and_mode(existing.file(), kind.create_mode(), required_gid)
                    .map_err(|err| {
                        PeerNetworkError::Runtime(format!(
                            "Failed to secure directory {}: {err}",
                            path.display()
                        ))
                    })?;
                self.validate_confined_dir(path, &existing, kind)?;
            }
            return Ok(existing);
        }
        let dir =
            ReceiptDirectory::open_confined(path, true, kind.create_mode()).map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Refusing unsafe or inaccessible directory {}: {err}",
                    path.display()
                ))
            })?;
        enforce_root_ownership_and_mode(dir.file(), kind.create_mode(), required_gid).map_err(
            |err| {
                PeerNetworkError::Runtime(format!(
                    "Failed to secure directory {}: {err}",
                    path.display()
                ))
            },
        )?;
        self.validate_confined_dir(path, &dir, kind)?;
        Ok(dir)
    }

    fn write_secret_file_atomic(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        bytes: &[u8],
        mode: u32,
        group_required: bool,
    ) -> Result<(), PeerNetworkError> {
        let name_os = OsStr::new(name);
        let required_gid = if group_required {
            self.security.resolve_required_group_gid()?
        } else {
            None
        };
        dir.verify().map_err(|err| {
            PeerNetworkError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let previous = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => {
                if let Some(uid) = self.security.expected_uid {
                    let meta = file.metadata().map_err(|err| {
                        PeerNetworkError::Runtime(format!("Cannot stat existing {name}: {err}"))
                    })?;
                    if meta.uid() != uid {
                        return Err(PeerNetworkError::Runtime(format!(
                            "Refusing to overwrite {name} not owned by expected uid {uid}"
                        )));
                    }
                }
                Some(file)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PeerNetworkError::Runtime(format!(
                    "Refusing to overwrite non-regular or symlink file {name}: {err}"
                )))
            }
        };
        let tmp_name = format!(".{name}.tmp.{}", uuid::Uuid::new_v4().simple());
        let tmp_os = OsStr::new(&tmp_name);
        let mut tmp_file = dir
            .open_file(tmp_os, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Failed to create temporary file for {name}: {err}"
                ))
            })?;
        let parent_fd = dir.file().as_raw_fd();
        let result = (|| -> std::io::Result<()> {
            tmp_file.write_all(bytes)?;
            enforce_root_ownership_and_mode(&tmp_file, mode, required_gid)?;
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
                        ))
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
            return Err(PeerNetworkError::Runtime(format!(
                "Atomic write of {name} failed: {err}"
            )));
        }
        Ok(())
    }

    fn read_secret_file_confined(
        &self,
        dir: &ReceiptDirectory,
        name: &str,
        max_bytes: usize,
        allow_group_read: bool,
    ) -> Result<Option<SecretString>, PeerNetworkError> {
        let name_os = OsStr::new(name);
        dir.verify().map_err(|err| {
            PeerNetworkError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        let mut file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerNetworkError::Runtime(format!(
                    "Cannot safely read {name}: {err}"
                )))
            }
        };
        let meta = file
            .metadata()
            .map_err(|err| PeerNetworkError::Runtime(format!("Cannot stat {name}: {err}")))?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(PeerNetworkError::Runtime(format!(
                "{name} is not a regular single-link file"
            )));
        }
        let perm = meta.mode() & 0o7777;
        // Forbid setuid/setgid/sticky (0o7000), execute bits (0o111), group-write (0o020),
        // world bits (0o007), and for private files also group-read (0o040).
        let forbidden_bits = if allow_group_read { 0o7127 } else { 0o7177 };
        if perm & forbidden_bits != 0 {
            return Err(PeerNetworkError::Runtime(format!(
                "Refusing overly permissive secret file {name} (mode {perm:04o})"
            )));
        }
        if let Some(uid) = self.security.expected_uid {
            if meta.uid() != uid {
                return Err(PeerNetworkError::Runtime(format!(
                    "Refusing secret file {name} not owned by expected uid {uid}"
                )));
            }
        }
        if allow_group_read {
            if let Some(expected_gid) = self.security.resolve_required_group_gid()? {
                if perm & 0o040 != 0 && meta.gid() != expected_gid {
                    return Err(PeerNetworkError::Runtime(format!(
                        "Refusing credential file {name} with unexpected group gid {} (expected {expected_gid})",
                        meta.gid()
                    )));
                }
            }
        }
        let mut content = String::new();
        Read::by_ref(&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_string(&mut content)
            .map_err(|err| PeerNetworkError::Runtime(format!("Failed reading {name}: {err}")))?;
        if content.len() > max_bytes {
            zeroize_string(&mut content);
            return Err(PeerNetworkError::Runtime(format!(
                "Secret file {name} exceeds size limit"
            )));
        }
        dir.verify().map_err(|err| {
            zeroize_string(&mut content);
            PeerNetworkError::Runtime(format!("Directory verification failed: {err}"))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            zeroize_string(&mut content);
            PeerNetworkError::Runtime(format!(
                "File identity verification failed for {name}: {err}"
            ))
        })?;
        Ok(Some(SecretString::new(content)))
    }

    async fn output(
        &self,
        program: &str,
        args: &[String],
        input: Option<&str>,
    ) -> Result<CmdOutput, PeerNetworkError> {
        let mut cmd = Command::new(self.program(program));
        cmd.args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let mut child = cmd.spawn().map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "{program} is unavailable; run ensure_packages to install {PEER_WG_PACKAGE} ({err})"
            ))
        })?;
        let pgid = child.id();
        let mut pg_guard = ProcessGroupKillGuard(pgid);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PeerNetworkError::Runtime("Missing command stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PeerNetworkError::Runtime("Missing command stderr".to_string()))?;
        let stdin = child.stdin.take();

        let task = async {
            let write_input = async {
                if let (Some(mut pipe), Some(data)) = (stdin, input) {
                    pipe.write_all(data.as_bytes()).await.map_err(|err| {
                        PeerNetworkError::Runtime(format!("Failed writing command stdin: {err}"))
                    })?;
                    pipe.shutdown().await.map_err(|err| {
                        PeerNetworkError::Runtime(format!("Failed closing command stdin: {err}"))
                    })?;
                }
                Ok::<(), PeerNetworkError>(())
            };
            let (out_bytes, err_bytes, ()) = tokio::try_join!(
                read_bounded(stdout, MAX_CONFIG_BYTES),
                read_bounded(stderr, MAX_CONFIG_BYTES),
                write_input
            )?;
            let status = child.wait().await.map_err(|err| {
                PeerNetworkError::Runtime(format!("Failed waiting for {program}: {err}"))
            })?;
            Ok::<CmdOutput, PeerNetworkError>(CmdOutput {
                status,
                stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
                stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
            })
        };

        let result = match tokio::time::timeout(self.command_timeout, task).await {
            Ok(res) => res,
            Err(_) => {
                kill_process_group(pgid);
                let _ = child.start_kill();
                let _ = child.wait().await;
                pg_guard.disarm();
                return Err(PeerNetworkError::Runtime(format!(
                    "{program} timed out after {}; inspect {PEER_WG_SERVICE_UNIT} logs",
                    format_duration_human(self.command_timeout)
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

    async fn run_checked(
        &self,
        program: &str,
        args: &[String],
        input: Option<&str>,
        suppress_stderr: bool,
    ) -> Result<String, PeerNetworkError> {
        let out = self.output(program, args, input).await?;
        if !out.status.success() {
            if suppress_stderr {
                return Err(PeerNetworkError::Runtime(format!(
                    "{program} failed ({})",
                    out.status
                )));
            }
            let detail: String = redact_secrets(out.stderr.trim())
                .chars()
                .take(512)
                .collect();
            if detail.is_empty() {
                return Err(PeerNetworkError::Runtime(format!(
                    "{program} failed ({})",
                    out.status
                )));
            }
            return Err(PeerNetworkError::Runtime(format!(
                "{program} failed ({}): {detail}",
                out.status
            )));
        }
        Ok(out.stdout)
    }

    async fn installed(&self, program: &str) -> bool {
        self.output(program, &strings(&["--version"]), None)
            .await
            .is_ok_and(|out| out.status.success())
    }

    async fn service_state(&self) -> String {
        match self
            .output(
                "systemctl",
                &strings(&["is-active", PEER_WG_SERVICE_UNIT]),
                None,
            )
            .await
        {
            Ok(out) if !out.stdout.trim().is_empty() => out.stdout.trim().to_string(),
            _ => "unknown".to_string(),
        }
    }

    async fn derive_public_key(
        &self,
        private_key: &SecretString,
    ) -> Result<String, PeerNetworkError> {
        let pubkey = self
            .run_checked(
                "wg",
                &strings(&["pubkey"]),
                Some(private_key.as_str()),
                true,
            )
            .await?
            .trim()
            .to_string();
        if !valid_wg_key(&pubkey) {
            return Err(PeerNetworkError::Runtime(
                "WireGuard returned an invalid public key".to_string(),
            ));
        }
        Ok(pubkey)
    }

    async fn generate_private_key(&self) -> Result<SecretString, PeerNetworkError> {
        let raw = self
            .run_checked("wg", &strings(&["genkey"]), None, true)
            .await?;
        let key = SecretString::new(raw.trim().to_string());
        if !valid_wg_key(key.as_str()) {
            return Err(PeerNetworkError::Runtime(
                "WireGuard returned an invalid private key".to_string(),
            ));
        }
        Ok(key)
    }

    async fn open_and_lock_exclusive(
        &self,
        dir: ReceiptDirectory,
        lock_name: &str,
        deadline: Instant,
        busy_message: &str,
    ) -> Result<ConfinedLockGuard, PeerNetworkError> {
        let name_os = OsStr::new(lock_name);
        let (file, created) = match dir.open_file(name_os, libc::O_RDWR, 0) {
            Ok(file) => (file, false),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match dir.open_file(name_os, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) {
                    Ok(file) => (file, true),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                        let file = dir.open_file(name_os, libc::O_RDWR, 0).map_err(|e| {
                            PeerNetworkError::Runtime(format!(
                                "Refusing unsafe peer lock {lock_name}: {e}"
                            ))
                        })?;
                        (file, false)
                    }
                    Err(err) => {
                        return Err(PeerNetworkError::Runtime(format!(
                            "Failed creating peer lock {lock_name}: {err}"
                        )));
                    }
                }
            }
            Err(err) => {
                return Err(PeerNetworkError::Runtime(format!(
                    "Refusing unsafe peer lock {lock_name}: {err}"
                )));
            }
        };
        if created {
            enforce_root_ownership_and_mode(&file, 0o600, None).map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Failed securing newly created peer lock {lock_name}: {err}"
                ))
            })?;
        }
        validate_lock_file_metadata(&file, lock_name, &self.security)?;
        poll_flock_until(&file, libc::LOCK_EX, deadline, busy_message).await?;
        dir.verify().map_err(|err| {
            PeerNetworkError::Runtime(format!("Peer lock directory verification failed: {err}"))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Peer lock {lock_name} identity changed during acquisition: {err}"
            ))
        })?;
        validate_lock_file_metadata(&file, lock_name, &self.security)?;
        Ok(ConfinedLockGuard { _dir: dir, file })
    }

    async fn open_and_lock_shared_if_exists(
        &self,
        dir: ReceiptDirectory,
        lock_name: &str,
        deadline: Instant,
        busy_message: &str,
    ) -> Result<Option<ConfinedLockGuard>, PeerNetworkError> {
        let name_os = OsStr::new(lock_name);
        let file = match dir.open_file(name_os, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(PeerNetworkError::Runtime(format!(
                    "Refusing unsafe peer lock {lock_name}: {err}"
                )));
            }
        };
        validate_lock_file_metadata(&file, lock_name, &self.security)?;
        poll_flock_until(&file, libc::LOCK_SH, deadline, busy_message).await?;
        dir.verify().map_err(|err| {
            PeerNetworkError::Runtime(format!("Peer lock directory verification failed: {err}"))
        })?;
        verify_entry(dir.file(), name_os, &file, false).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Peer lock {lock_name} identity changed during shared acquisition: {err}"
            ))
        })?;
        validate_lock_file_metadata(&file, lock_name, &self.security)?;
        Ok(Some(ConfinedLockGuard { _dir: dir, file }))
    }

    async fn acquire_locks(
        &self,
    ) -> Result<(OwnedRwLockWriteGuard<()>, ConfinedLockGuard), PeerNetworkError> {
        const BUSY: &str = "Peer WireGuard configuration is busy; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_wg_lock_for(&self.wg_dir, &self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.write_owned())
            .await
            .map_err(|_| PeerNetworkError::Busy(BUSY.to_string()))?;
        let state_dir = self.ensure_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?;
        let file_lock = self
            .open_and_lock_exclusive(state_dir, PEER_LOCK_FILE_NAME, deadline, BUSY)
            .await?;
        Ok((mem_guard, file_lock))
    }

    async fn acquire_status_read_locks(
        &self,
    ) -> Result<
        (
            OwnedRwLockReadGuard<()>,
            Result<Option<ConfinedLockGuard>, PeerNetworkError>,
        ),
        PeerNetworkError,
    > {
        const BUSY: &str = "Peer WireGuard configuration is busy; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_wg_lock_for(&self.wg_dir, &self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.read_owned())
            .await
            .map_err(|_| PeerNetworkError::Busy(BUSY.to_string()))?;
        let file_lock_res = match self
            .open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)
        {
            Ok(Some(state_dir)) => {
                match self
                    .open_and_lock_shared_if_exists(state_dir, PEER_LOCK_FILE_NAME, deadline, BUSY)
                    .await
                {
                    Ok(opt) => Ok(opt),
                    Err(err @ PeerNetworkError::Busy(_)) => return Err(err),
                    Err(err) => Err(err),
                }
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        };
        Ok((mem_guard, file_lock_res))
    }

    async fn acquire_credential_write_locks(
        &self,
        create_state_dir: bool,
    ) -> Result<(OwnedRwLockWriteGuard<()>, Option<ConfinedLockGuard>), PeerNetworkError> {
        const BUSY: &str = "Peer credential store is busy; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_cred_lock_for(&self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.write_owned())
            .await
            .map_err(|_| PeerNetworkError::Busy(BUSY.to_string()))?;
        let state_dir = if create_state_dir {
            Some(self.ensure_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?)
        } else {
            self.open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?
        };
        let file_lock = match state_dir {
            Some(dir) => Some(
                self.open_and_lock_exclusive(dir, PEER_CRED_LOCK_FILE_NAME, deadline, BUSY)
                    .await?,
            ),
            None => None,
        };
        Ok((mem_guard, file_lock))
    }

    async fn acquire_credential_read_locks(
        &self,
    ) -> Result<(OwnedRwLockReadGuard<()>, Option<ConfinedLockGuard>), PeerNetworkError> {
        const BUSY: &str = "Peer credential store is busy; retry shortly";
        let deadline = Instant::now() + self.lock_timeout;
        let lock = peer_cred_lock_for(&self.state_dir);
        let mem_guard = tokio::time::timeout_at(deadline, lock.read_owned())
            .await
            .map_err(|_| PeerNetworkError::Busy(BUSY.to_string()))?;
        let file_lock = match self
            .open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?
        {
            Some(dir) => {
                self.open_and_lock_shared_if_exists(dir, PEER_CRED_LOCK_FILE_NAME, deadline, BUSY)
                    .await?
            }
            None => None,
        };
        Ok((mem_guard, file_lock))
    }

    fn read_saved_config(
        &self,
    ) -> Result<Option<(SecretString, PeerWireGuardConfig)>, PeerNetworkError> {
        let Some(dir) = self.open_existing_confined_dir(&self.wg_dir, DirKind::Config)? else {
            return Ok(None);
        };
        let Some(raw) =
            self.read_secret_file_confined(&dir, PEER_WG_CONF_NAME, MAX_CONFIG_BYTES, false)?
        else {
            return Ok(None);
        };
        let parsed = PeerWireGuardConfig::parse(raw.as_str())?;
        parsed.validate_server()?;
        Ok(Some((raw, parsed)))
    }

    fn read_saved_key(&self) -> Result<Option<SecretString>, PeerNetworkError> {
        let Some(dir) =
            self.open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?
        else {
            return Ok(None);
        };
        let Some(raw) = self.read_secret_file_confined(&dir, PEER_WG_KEY_NAME, 512, false)? else {
            return Ok(None);
        };
        let key = SecretString::new(raw.as_str().trim().to_string());
        if !valid_wg_key(key.as_str()) {
            return Err(PeerNetworkError::Runtime(
                "Saved afpeer0.key contains an invalid WireGuard private key".to_string(),
            ));
        }
        Ok(Some(key))
    }

    fn write_saved_config(&self, contents: &SecretString) -> Result<(), PeerNetworkError> {
        let wg_dir = self.ensure_confined_dir(&self.wg_dir, DirKind::Config)?;
        self.write_secret_file_atomic(
            &wg_dir,
            PEER_WG_CONF_NAME,
            contents.as_str().as_bytes(),
            0o600,
            false,
        )
    }

    fn write_saved_key(&self, key: &SecretString) -> Result<(), PeerNetworkError> {
        let state_dir = self.ensure_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?;
        let buf = SecretString::new(format!("{}\n", key.as_str()));
        let res = self.write_secret_file_atomic(
            &state_dir,
            PEER_WG_KEY_NAME,
            buf.as_str().as_bytes(),
            0o600,
            false,
        );
        drop(buf);
        res
    }

    fn remove_saved_config_checked(&self) -> Result<bool, PeerNetworkError> {
        let Some(dir) = self.open_existing_confined_dir(&self.wg_dir, DirKind::Config)? else {
            return Ok(false);
        };
        delete_secret_file_confined(&dir, PEER_WG_CONF_NAME, self.security.expected_uid)
    }

    fn remove_saved_key_checked(&self) -> Result<bool, PeerNetworkError> {
        let Some(dir) =
            self.open_existing_confined_dir(&self.state_dir, DirKind::StateGroupReadable)?
        else {
            return Ok(false);
        };
        delete_secret_file_confined(&dir, PEER_WG_KEY_NAME, self.security.expected_uid)
    }

    /// Queries `ip -j addr show dev afpeer0` and `ip -j -4/-6 route show exact <subnet>` and verifies:
    /// 1. Interface `afpeer0` has the `UP` flag and is not in a down operational state.
    /// 2. Interface holds `expected_addr.ip/expected_addr.prefix` in an available address state
    ///    (not tentative, dadfailed, detached, or expired).
    /// 3. The kernel routing table contains a live unicast route for the configured peer subnet
    ///    whose winning lowest-metric route(s) exclusively egress through `afpeer0`.
    async fn inspect_live_interface_link_and_route(
        &self,
        expected_addr: &TunnelCidr,
    ) -> Result<(bool, bool, Option<String>), PeerNetworkError> {
        let raw = self
            .run_checked(
                "ip",
                &strings(&["-j", "addr", "show", "dev", PEER_WG_INTERFACE]),
                None,
                false,
            )
            .await?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Invalid ip addr JSON for {PEER_WG_INTERFACE}: {err}"
            ))
        })?;
        let Some(row) = parsed
            .as_array()
            .and_then(|rows| rows.first())
            .filter(|row| {
                row.get("ifname")
                    .and_then(Value::as_str)
                    .is_none_or(|name| name == PEER_WG_INTERFACE)
            })
        else {
            return Ok((
                false,
                false,
                Some(format!("{PEER_WG_INTERFACE} device is not present")),
            ));
        };
        let oper_down = row
            .get("operstate")
            .and_then(Value::as_str)
            .is_some_and(|s| matches!(s, "DOWN" | "LOWERLAYERDOWN" | "NOTPRESENT"));
        let is_up = !oper_down
            && row["flags"]
                .as_array()
                .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"));
        if !is_up {
            return Ok((false, false, None));
        }

        let expected_family = match expected_addr.ip {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        };
        let mut unavailable_reason: Option<String> = None;
        let mut addr_ready = false;
        if let Some(addrs) = row["addr_info"].as_array() {
            for entry in addrs {
                let matches_addr = entry["family"].as_str() == Some(expected_family)
                    && entry["local"]
                        .as_str()
                        .and_then(|ip| ip.parse::<IpAddr>().ok())
                        == Some(expected_addr.ip)
                    && entry["prefixlen"].as_u64() == Some(u64::from(expected_addr.prefix));
                if !matches_addr {
                    continue;
                }
                if entry.get("dadfailed").and_then(Value::as_bool) == Some(true) {
                    unavailable_reason = Some(format!(
                        "Live {PEER_WG_INTERFACE} address {} failed duplicate address detection (dadfailed)",
                        expected_addr.interface_string()
                    ));
                    continue;
                }
                if entry.get("tentative").and_then(Value::as_bool) == Some(true) {
                    unavailable_reason = Some(format!(
                        "Live {PEER_WG_INTERFACE} address {} is still tentative and unavailable",
                        expected_addr.interface_string()
                    ));
                    continue;
                }
                if entry.get("detached").and_then(Value::as_bool) == Some(true) {
                    unavailable_reason = Some(format!(
                        "Live {PEER_WG_INTERFACE} address {} is detached and unavailable",
                        expected_addr.interface_string()
                    ));
                    continue;
                }
                if entry.get("valid_life_time").and_then(Value::as_u64) == Some(0) {
                    unavailable_reason = Some(format!(
                        "Live {PEER_WG_INTERFACE} address {} has expired (valid_life_time=0)",
                        expected_addr.interface_string()
                    ));
                    continue;
                }
                addr_ready = true;
                break;
            }
        }
        if !addr_ready {
            let reason = unavailable_reason.unwrap_or_else(|| {
                format!(
                    "Live {PEER_WG_INTERFACE} interface address prefix does not match configured tunnel CIDR {}; restart {PEER_WG_SERVICE_UNIT} to restore subnet routing",
                    expected_addr.interface_string()
                )
            });
            return Ok((true, false, Some(reason)));
        }

        let family_flag = if expected_addr.ip.is_ipv4() {
            "-4"
        } else {
            "-6"
        };
        let expected_network = expected_addr.network_string();
        let route_raw = self
            .run_checked(
                "ip",
                &strings(&[
                    "-j",
                    family_flag,
                    "route",
                    "show",
                    "exact",
                    &expected_network,
                ]),
                None,
                false,
            )
            .await?;
        let route_parsed: Value = serde_json::from_str(&route_raw).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Invalid ip route JSON for peer subnet {expected_network}: {err}"
            ))
        })?;
        let Some(routes) = route_parsed.as_array() else {
            return Err(PeerNetworkError::Runtime(format!(
                "Unexpected non-array ip route JSON for peer subnet {expected_network}"
            )));
        };

        let matching_routes: Vec<&Value> = routes
            .iter()
            .filter(|entry| {
                entry
                    .get("dst")
                    .and_then(Value::as_str)
                    .and_then(|dst| TunnelCidr::parse_subnet(dst).ok())
                    .is_some_and(|dst| {
                        dst.same_family(expected_addr.ip)
                            && dst.prefix == expected_addr.prefix
                            && dst.network_bits() == expected_addr.network_bits()
                    })
            })
            .collect();
        if matching_routes.is_empty() {
            return Ok((
                true,
                false,
                Some(format!(
                    "Live {PEER_WG_INTERFACE} is missing kernel subnet route {expected_network}; restart {PEER_WG_SERVICE_UNIT} to restore subnet routing"
                )),
            ));
        }

        let best_metric = matching_routes
            .iter()
            .map(|r| r.get("metric").and_then(Value::as_u64).unwrap_or(0))
            .min()
            .unwrap_or(0);
        let winning: Vec<&Value> = matching_routes
            .into_iter()
            .filter(|r| r.get("metric").and_then(Value::as_u64).unwrap_or(0) == best_metric)
            .collect();

        let mut saw_valid_afpeer = false;
        for route in winning {
            let dev = route.get("dev").and_then(Value::as_str).unwrap_or("");
            let route_type = route.get("type").and_then(Value::as_str);
            let bad_flag = route
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|f| {
                    f.iter()
                        .any(|flag| matches!(flag.as_str(), Some("dead" | "linkdown")))
                });
            if dev != PEER_WG_INTERFACE {
                return Ok((
                    true,
                    false,
                    Some(format!(
                        "Kernel subnet route {expected_network} resolves via unexpected interface '{dev}' instead of {PEER_WG_INTERFACE}"
                    )),
                ));
            }
            if route_type.is_some_and(|t| t != "unicast") {
                return Ok((
                    true,
                    false,
                    Some(format!(
                        "Kernel subnet route {expected_network} has non-unicast route type '{}'",
                        route_type.unwrap_or("unknown")
                    )),
                ));
            }
            if bad_flag {
                return Ok((
                    true,
                    false,
                    Some(format!(
                        "Kernel subnet route {expected_network} on {PEER_WG_INTERFACE} is marked dead or linkdown"
                    )),
                ));
            }
            saw_valid_afpeer = true;
        }

        if !saw_valid_afpeer {
            return Ok((
                true,
                false,
                Some(format!(
                    "Live {PEER_WG_INTERFACE} is missing an active unicast subnet route for {expected_network}"
                )),
            ));
        }

        Ok((true, true, None))
    }

    /// Queries the kernel FIB via `ip -j -4/-6 route get <peer_ip>` to confirm that the winning
    /// effective route for a newly synced peer egresses through `afpeer0`.
    async fn verify_peer_effective_route(&self, peer_ip: IpAddr) -> Result<(), PeerNetworkError> {
        let family_flag = if peer_ip.is_ipv4() { "-4" } else { "-6" };
        let peer_ip_str = peer_ip.to_string();
        let raw = self
            .run_checked(
                "ip",
                &strings(&["-j", family_flag, "route", "get", &peer_ip_str]),
                None,
                false,
            )
            .await
            .map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Kernel route lookup failed for peer tunnel IP {peer_ip}: {err}"
                ))
            })?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|err| {
            PeerNetworkError::Runtime(format!(
                "Invalid ip route get JSON for peer tunnel IP {peer_ip}: {err}"
            ))
        })?;
        let Some(row) = parsed.as_array().and_then(|rows| rows.first()) else {
            return Err(PeerNetworkError::Runtime(format!(
                "Kernel returned no effective route for peer tunnel IP {peer_ip}"
            )));
        };
        if let Some(dst_raw) = row.get("dst").and_then(Value::as_str) {
            if dst_raw.parse::<IpAddr>().ok() != Some(peer_ip) {
                return Err(PeerNetworkError::Runtime(format!(
                    "Kernel route lookup returned unexpected destination '{dst_raw}' for peer tunnel IP {peer_ip}"
                )));
            }
        }
        if let Some(route_type) = row.get("type").and_then(Value::as_str) {
            if route_type != "unicast" {
                return Err(PeerNetworkError::Runtime(format!(
                    "Effective kernel route for peer tunnel IP {peer_ip} has non-unicast type '{route_type}'"
                )));
            }
        }
        let dev = row.get("dev").and_then(Value::as_str).unwrap_or("");
        if dev != PEER_WG_INTERFACE {
            return Err(PeerNetworkError::Runtime(format!(
                "Effective kernel route for peer tunnel IP {peer_ip} resolves via unexpected interface '{dev}' instead of {PEER_WG_INTERFACE}"
            )));
        }
        let bad_flag = row.get("flags").and_then(Value::as_array).is_some_and(|f| {
            f.iter()
                .any(|flag| matches!(flag.as_str(), Some("dead" | "linkdown")))
        });
        if bad_flag {
            return Err(PeerNetworkError::Runtime(format!(
                "Effective kernel route for peer tunnel IP {peer_ip} on {PEER_WG_INTERFACE} is marked dead or linkdown"
            )));
        }
        Ok(())
    }

    /// Reconciles live `wg showconf afpeer0` private key with saved `afpeer0.conf` identity.
    async fn reconcile_live_identity(
        &self,
        saved_privkey: &SecretString,
        live_config: &PeerWireGuardConfig,
    ) -> Result<(), PeerNetworkError> {
        let live_key = live_config
            .private_key()
            .filter(|k| valid_wg_key(k.as_str()))
            .ok_or_else(|| {
                PeerNetworkError::Runtime(
                    "Live afpeer0 configuration does not contain a valid private key".to_string(),
                )
            })?;
        if saved_privkey.as_str() != live_key.as_str() {
            let saved_pub = self.derive_public_key(saved_privkey).await?;
            let live_pub = self.derive_public_key(&live_key).await?;
            if saved_pub != live_pub {
                return Err(PeerNetworkError::Conflict(
                    "Invalid server identity: live afpeer0 and saved configuration differ; reconcile them before changing peers"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    async fn verify_live_identity_and_route(
        &self,
        privkey: &SecretString,
        expected_addr: &TunnelCidr,
    ) -> Result<String, PeerNetworkError> {
        let svc_state = self.service_state().await;
        if svc_state != "active" {
            return Err(PeerNetworkError::Runtime(format!(
                "{PEER_WG_SERVICE_UNIT} did not become active ({svc_state})"
            )));
        }
        let live_after = self
            .output("wg", &strings(&["showconf", PEER_WG_INTERFACE]), None)
            .await?;
        if !live_after.status.success() {
            return Err(PeerNetworkError::Runtime(
                "Unable to verify live afpeer0 identity after service start".to_string(),
            ));
        }
        let live_cfg = PeerWireGuardConfig::parse(&live_after.stdout)?;
        self.reconcile_live_identity(privkey, &live_cfg).await?;
        let (is_up, route_ready, detail) = self
            .inspect_live_interface_link_and_route(expected_addr)
            .await?;
        if !is_up || !route_ready {
            let reason = detail.unwrap_or_else(|| {
                format!(
                    "{PEER_WG_INTERFACE} is not up with configured subnet address {}",
                    expected_addr.interface_string()
                )
            });
            return Err(PeerNetworkError::Runtime(reason));
        }
        Ok(svc_state)
    }

    async fn rollback_fresh_identity_activation(
        &self,
        created_key: bool,
        activate_err: PeerNetworkError,
    ) -> PeerNetworkError {
        let disable_res = self
            .output(
                "systemctl",
                &strings(&["disable", "--now", PEER_WG_SERVICE_UNIT]),
                None,
            )
            .await;
        let disable_ok = disable_res.as_ref().is_ok_and(|out| out.status.success());

        let wg_gone = self
            .output("wg", &strings(&["showconf", PEER_WG_INTERFACE]), None)
            .await
            .is_ok_and(|out| !out.status.success());
        let ip_gone = match self
            .output(
                "ip",
                &strings(&["-j", "addr", "show", "dev", PEER_WG_INTERFACE]),
                None,
            )
            .await
        {
            Ok(out) if !out.status.success() => true,
            Ok(out) => serde_json::from_str::<Value>(&out.stdout)
                .ok()
                .and_then(|v| v.as_array().map(Vec::is_empty))
                .unwrap_or(false),
            Err(_) => false,
        };
        let svc_after = self.service_state().await;
        let svc_stopped = matches!(svc_after.as_str(), "inactive" | "failed");

        if !disable_ok || !wg_gone || !ip_gone || !svc_stopped {
            return PeerNetworkError::Runtime(format!(
                "Failed to initialize {PEER_WG_INTERFACE} and teardown verification was incomplete (disable_ok={disable_ok}, wg_gone={wg_gone}, ip_gone={ip_gone}, service={svc_after}); preserved saved configuration for recovery: {activate_err}"
            ));
        }

        let conf_rm = self.remove_saved_config_checked();
        let key_rm = if created_key {
            self.remove_saved_key_checked()
        } else {
            Ok(false)
        };
        if conf_rm.is_err() || key_rm.is_err() {
            return PeerNetworkError::Runtime(format!(
                "Failed to initialize {PEER_WG_INTERFACE} and cleanup of newly created files was incomplete: {activate_err}"
            ));
        }

        if svc_after == "failed" {
            let reset_ok = self
                .output(
                    "systemctl",
                    &strings(&["reset-failed", PEER_WG_SERVICE_UNIT]),
                    None,
                )
                .await
                .is_ok_and(|out| out.status.success());
            let svc_after_reset = self.service_state().await;
            if !reset_ok || svc_after_reset == "failed" {
                return PeerNetworkError::Runtime(format!(
                    "Failed to initialize {PEER_WG_INTERFACE}; newly created files were removed, but clearing failed systemd state was incomplete (service={svc_after_reset}): {activate_err}"
                ));
            }
        }

        PeerNetworkError::Runtime(format!(
            "Failed to initialize {PEER_WG_INTERFACE}; newly created configuration was rolled back: {activate_err}"
        ))
    }

    pub async fn ensure_identity(
        &self,
        tunnel_ip: Option<&str>,
        avoid_tunnel_ips: &[String],
        wg_port: Option<u16>,
        tunnel_cidr: Option<&str>,
    ) -> Result<PeerIdentityResponse, PeerNetworkError> {
        let (_mem_guard, _file_lock) = self.acquire_locks().await?;

        let requested_cidr = tunnel_cidr
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(TunnelCidr::parse_subnet)
            .transpose()?;
        let effective_cidr = requested_cidr.unwrap_or(self.tunnel_cidr);
        let effective_port = match wg_port {
            Some(0) => {
                return Err(PeerNetworkError::InvalidInput(
                    "WireGuard listen port must be between 1 and 65535".to_string(),
                ))
            }
            Some(p) => p,
            None => self.wg_port,
        };

        let mut avoid_set = HashSet::new();
        for raw_avoid in avoid_tunnel_ips {
            let ip = parse_bare_ip(raw_avoid, "Excluded tunnel IP")?;
            avoid_set.insert(ip);
        }
        let requested_ip_raw = tunnel_ip
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|raw| parse_bare_ip(raw, "Tunnel IP"))
            .transpose()?;
        if let Some(ip) = requested_ip_raw {
            if avoid_set.contains(&ip) {
                return Err(PeerNetworkError::TunnelIpConflict(
                    "TUNNEL_IP_CONFLICT: requested local tunnel IP conflicts with an excluded peer address"
                        .to_string(),
                ));
            }
        }

        let saved_conf = self.read_saved_config()?;
        let saved_key = self.read_saved_key()?;

        if let Some((_raw, config)) = saved_conf {
            let (saved_addr, saved_port, conf_privkey) = config.validate_server()?;
            if let Some(ref key_file_priv) = saved_key {
                if key_file_priv.as_str() != conf_privkey.as_str() {
                    return Err(PeerNetworkError::Conflict(
                        "Saved afpeer0.key differs from PrivateKey in afpeer0.conf; reconcile identity before continuing"
                            .to_string(),
                    ));
                }
            }
            if avoid_set.contains(&saved_addr.ip) {
                return Err(PeerNetworkError::TunnelIpConflict(
                    "TUNNEL_IP_CONFLICT: existing afpeer0 tunnel IP conflicts with an excluded address"
                        .to_string(),
                ));
            }
            if let Some(req_ip) = requested_ip_raw {
                if req_ip != saved_addr.ip {
                    return Err(PeerNetworkError::Conflict(
                        "CONFLICT: existing afpeer0 identity already uses a different tunnel IP"
                            .to_string(),
                    ));
                }
            }
            if wg_port.is_some_and(|p| p != saved_port) {
                return Err(PeerNetworkError::Conflict(
                    "CONFLICT: existing afpeer0 identity already uses a different listen port"
                        .to_string(),
                ));
            }
            if let Some(req_cidr) = requested_cidr {
                if !req_cidr.contains_ip(saved_addr.ip) || req_cidr.prefix != saved_addr.prefix {
                    return Err(PeerNetworkError::Conflict(
                        "CONFLICT: existing afpeer0 identity does not match requested tunnel CIDR"
                            .to_string(),
                    ));
                }
            }
            let saved_pubkey = self.derive_public_key(&conf_privkey).await?;

            // Reconcile against live interface if already up.
            let live_out = self
                .output("wg", &strings(&["showconf", PEER_WG_INTERFACE]), None)
                .await?;
            if live_out.status.success() {
                let live_cfg = PeerWireGuardConfig::parse(&live_out.stdout)?;
                self.reconcile_live_identity(&conf_privkey, &live_cfg)
                    .await?;
            }

            if saved_key.is_none() {
                self.write_saved_key(&conf_privkey)?;
            }

            self.run_checked(
                "systemctl",
                &strings(&["enable", "--now", PEER_WG_SERVICE_UNIT]),
                None,
                false,
            )
            .await?;
            let svc_state = self
                .verify_live_identity_and_route(&conf_privkey, &saved_addr)
                .await?;

            return Ok(PeerIdentityResponse {
                interface: PEER_WG_INTERFACE.to_string(),
                public_key: saved_pubkey,
                tunnel_ip: saved_addr.ip.to_string(),
                tunnel_cidr: saved_addr.network_string(),
                interface_address: saved_addr.interface_string(),
                wg_port: saved_port,
                service_state: svc_state,
                created: false,
            });
        }

        let requested_ip = match tunnel_ip.map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(validate_tunnel_ip(raw, &effective_cidr)?),
            None => None,
        };

        // No saved afpeer0.conf exists yet: fail closed if an unmanaged live afpeer0 is running.
        let live_out = self
            .output("wg", &strings(&["showconf", PEER_WG_INTERFACE]), None)
            .await?;
        if live_out.status.success() {
            return Err(PeerNetworkError::Conflict(
                "Live afpeer0 interface exists without saved afpeer0.conf; reconcile it before provisioning identity"
                    .to_string(),
            ));
        }

        let (privkey, created_key) = match saved_key {
            Some(existing_key) => (existing_key, false),
            None => (self.generate_private_key().await?, true),
        };
        let pubkey = self.derive_public_key(&privkey).await?;

        let chosen_ip = match requested_ip {
            Some(ip) => ip,
            None => effective_cidr.pick_usable_host(&avoid_set)?,
        };
        let interface_addr = TunnelCidr {
            ip: chosen_ip,
            prefix: effective_cidr.prefix,
        };
        let config = PeerWireGuardConfig::new_initial(&interface_addr, &privkey, effective_port);
        let rendered = config.render();

        if created_key {
            self.write_saved_key(&privkey)?;
        }
        if let Err(err) = self.write_saved_config(&rendered) {
            if created_key {
                if let Err(rm_err) = self.remove_saved_key_checked() {
                    return Err(PeerNetworkError::Runtime(format!(
                        "Failed writing afpeer0.conf and cleanup of newly created afpeer0.key was incomplete ({err}; cleanup: {rm_err})"
                    )));
                }
            }
            return Err(err);
        }

        let activate_res = async {
            self.run_checked(
                "systemctl",
                &strings(&["enable", "--now", PEER_WG_SERVICE_UNIT]),
                None,
                false,
            )
            .await?;
            self.verify_live_identity_and_route(&privkey, &interface_addr)
                .await
        }
        .await;

        let svc_state = match activate_res {
            Ok(state) => state,
            Err(err) => {
                return Err(self
                    .rollback_fresh_identity_activation(created_key, err)
                    .await);
            }
        };

        Ok(PeerIdentityResponse {
            interface: PEER_WG_INTERFACE.to_string(),
            public_key: pubkey,
            tunnel_ip: chosen_ip.to_string(),
            tunnel_cidr: interface_addr.network_string(),
            interface_address: interface_addr.interface_string(),
            wg_port: effective_port,
            service_state: svc_state,
            created: true,
        })
    }

    pub async fn add_peer(
        &self,
        pubkey: &str,
        endpoint: &str,
        port: u16,
        tunnel_ip: &str,
    ) -> Result<PeerMutationResponse, PeerNetworkError> {
        if !valid_wg_key(pubkey) {
            return Err(PeerNetworkError::InvalidInput(
                "Invalid WireGuard public key; expected 32 bytes of base64".to_string(),
            ));
        }
        let formatted_endpoint = validate_peer_endpoint(endpoint, port)?;

        let (_mem_guard, _file_lock) = self.acquire_locks().await?;
        let (old_text, mut config, saved_addr, saved_privkey, saved_pubkey) =
            self.load_verified_identity_for_mutation().await?;

        if pubkey == saved_pubkey {
            return Err(PeerNetworkError::InvalidInput(
                "Cannot add this server's own public key as a peer".to_string(),
            ));
        }
        let parsed_tunnel_ip = validate_tunnel_ip(tunnel_ip, &saved_addr)?;
        if parsed_tunnel_ip == saved_addr.ip {
            return Err(PeerNetworkError::TunnelIpConflict(
                "TUNNEL_IP_CONFLICT: peer tunnel IP collides with this server's tunnel IP"
                    .to_string(),
            ));
        }

        let (service, old_runtime, live_peers) = self
            .load_live_state_for_mutation(&saved_privkey, &saved_addr, true)
            .await?;

        let saved_existing = config.peers.iter().find(|p| p.pubkey() == pubkey);
        let live_existing = live_peers.iter().find(|p| p.pubkey() == pubkey);

        if let Some(saved_peer) = saved_existing {
            let saved_ips = peer_allowed_host_ips(saved_peer.allowed_ips())?;
            let saved_matches = saved_ips == [parsed_tunnel_ip]
                && endpoints_match(saved_peer.endpoint(), &formatted_endpoint);
            if saved_matches {
                if old_runtime.is_some() {
                    let live_matches = live_existing.is_some_and(|lp| {
                        peer_allowed_host_ips(lp.allowed_ips()).ok().as_deref()
                            == Some(&[parsed_tunnel_ip][..])
                            && endpoints_match_live(lp.endpoint(), &formatted_endpoint, port)
                    });
                    if live_matches {
                        return Err(PeerNetworkError::PeerAlreadyExists(
                            "PEER_ALREADY_EXISTS: matching WireGuard peer already exists on afpeer0"
                                .to_string(),
                        ));
                    }
                    return Err(PeerNetworkError::Conflict(
                        "CONFLICT: matching peer exists in afpeer0.conf but live afpeer0 state differs"
                            .to_string(),
                    ));
                }
                return Err(PeerNetworkError::PeerAlreadyExists(
                    "PEER_ALREADY_EXISTS: matching WireGuard peer already exists in afpeer0.conf"
                        .to_string(),
                ));
            }
            return Err(PeerNetworkError::Conflict(
                "CONFLICT: WireGuard peer already exists on afpeer0 with a different tunnel IP or endpoint"
                    .to_string(),
            ));
        }

        if live_existing.is_some() {
            return Err(PeerNetworkError::Conflict(
                "CONFLICT: unmanaged live WireGuard peer with this public key exists on afpeer0"
                    .to_string(),
            ));
        }

        if config.peers.len() >= MAX_PEERS {
            return Err(PeerNetworkError::InvalidInput(
                "Maximum number of afpeer0 peers reached".to_string(),
            ));
        }

        for existing in config.peers.iter().chain(live_peers.iter()) {
            let existing_ips = peer_allowed_host_ips(existing.allowed_ips())?;
            if existing_ips.contains(&parsed_tunnel_ip) {
                return Err(PeerNetworkError::TunnelIpConflict(
                    "CONFLICT: TUNNEL_IP_CONFLICT: peer tunnel IP overlaps an existing peer"
                        .to_string(),
                ));
            }
        }

        let allowed_ips = format!("{parsed_tunnel_ip}/{}", saved_addr.host_prefix());
        config
            .peers
            .push(PeerBlock::build(pubkey, &allowed_ips, &formatted_endpoint));
        let new_text = config.render();

        let applied_live = self
            .apply_config_change(
                &old_text,
                &new_text,
                old_runtime.as_ref(),
                Some(parsed_tunnel_ip),
            )
            .await?;

        Ok(PeerMutationResponse {
            interface: PEER_WG_INTERFACE.to_string(),
            pubkey: pubkey.to_string(),
            applied_live,
            service_state: service,
            tunnel_ip: Some(parsed_tunnel_ip.to_string()),
            allowed_ips: Some(allowed_ips),
            endpoint: Some(formatted_endpoint),
            message: if applied_live {
                "Peer added and synced to afpeer0".to_string()
            } else {
                format!("Peer saved to afpeer0.conf; start {PEER_WG_SERVICE_UNIT} to activate it")
            },
        })
    }

    pub async fn set_endpoint(
        &self,
        pubkey: &str,
        endpoint: &str,
        port: u16,
    ) -> Result<PeerMutationResponse, PeerNetworkError> {
        if !valid_wg_key(pubkey) {
            return Err(PeerNetworkError::InvalidInput(
                "Invalid WireGuard public key; expected 32 bytes of base64".to_string(),
            ));
        }
        let formatted_endpoint = validate_peer_endpoint(endpoint, port)?;

        let (_mem_guard, _file_lock) = self.acquire_locks().await?;
        let (old_text, mut config, saved_addr, saved_privkey, _saved_pubkey) =
            self.load_verified_identity_for_mutation().await?;

        let (service, old_runtime, _live_peers) = self
            .load_live_state_for_mutation(&saved_privkey, &saved_addr, false)
            .await?;

        let Some(peer) = config.peers.iter_mut().find(|p| p.pubkey() == pubkey) else {
            return Err(PeerNetworkError::PeerNotFound(
                "PEER_NOT_FOUND: WireGuard peer does not exist on afpeer0".to_string(),
            ));
        };
        *peer = peer.with_updated_endpoint(&formatted_endpoint);
        let allowed_ips = peer.allowed_ips().to_string();
        let new_text = config.render();

        let applied_live = self
            .apply_config_change(&old_text, &new_text, old_runtime.as_ref(), None)
            .await?;

        Ok(PeerMutationResponse {
            interface: PEER_WG_INTERFACE.to_string(),
            pubkey: pubkey.to_string(),
            applied_live,
            service_state: service,
            tunnel_ip: None,
            allowed_ips: Some(allowed_ips),
            endpoint: Some(formatted_endpoint),
            message: if applied_live {
                "Peer endpoint updated and synced to afpeer0".to_string()
            } else {
                format!(
                    "Peer endpoint saved to afpeer0.conf; start {PEER_WG_SERVICE_UNIT} to activate it"
                )
            },
        })
    }

    pub async fn remove_peer(
        &self,
        pubkey: &str,
    ) -> Result<PeerMutationResponse, PeerNetworkError> {
        if !valid_wg_key(pubkey) {
            return Err(PeerNetworkError::InvalidInput(
                "Invalid WireGuard public key; expected 32 bytes of base64".to_string(),
            ));
        }

        let (_mem_guard, _file_lock) = self.acquire_locks().await?;
        let (old_text, mut config, saved_addr, saved_privkey, _saved_pubkey) =
            self.load_verified_identity_for_mutation().await?;

        let (service, old_runtime, live_peers) = self
            .load_live_state_for_mutation(&saved_privkey, &saved_addr, false)
            .await?;

        let existed_saved = config.peers.iter().any(|p| p.pubkey() == pubkey);
        let existed_live = live_peers.iter().any(|p| p.pubkey() == pubkey);
        if !existed_saved && !existed_live {
            return Err(PeerNetworkError::PeerNotFound(
                "PEER_NOT_FOUND: WireGuard peer does not exist on afpeer0".to_string(),
            ));
        }

        config.peers.retain(|p| p.pubkey() != pubkey);
        let new_text = config.render();

        let applied_live = self
            .apply_config_change(&old_text, &new_text, old_runtime.as_ref(), None)
            .await?;

        Ok(PeerMutationResponse {
            interface: PEER_WG_INTERFACE.to_string(),
            pubkey: pubkey.to_string(),
            applied_live,
            service_state: service,
            tunnel_ip: None,
            allowed_ips: None,
            endpoint: None,
            message: if applied_live {
                "Peer removed and synced to afpeer0".to_string()
            } else {
                format!(
                    "Peer removed from afpeer0.conf; start {PEER_WG_SERVICE_UNIT} to activate it"
                )
            },
        })
    }

    async fn load_verified_identity_for_mutation(
        &self,
    ) -> Result<
        (
            SecretString,
            PeerWireGuardConfig,
            TunnelCidr,
            SecretString,
            String,
        ),
        PeerNetworkError,
    > {
        let Some((old_text, config)) = self.read_saved_config()? else {
            return Err(PeerNetworkError::NotFound(
                "Peer WireGuard identity is not initialized; run ensure_identity first".to_string(),
            ));
        };
        let (saved_addr, _port, conf_privkey) = config.validate_server()?;
        let Some(saved_key) = self.read_saved_key()? else {
            return Err(PeerNetworkError::Runtime(
                "Saved afpeer0.key is missing; run ensure_identity to reconcile".to_string(),
            ));
        };
        if saved_key.as_str() != conf_privkey.as_str() {
            return Err(PeerNetworkError::Conflict(
                "Saved afpeer0.key differs from PrivateKey in afpeer0.conf; reconcile identity before changing peers"
                    .to_string(),
            ));
        }
        let saved_pubkey = self.derive_public_key(&conf_privkey).await?;
        Ok((old_text, config, saved_addr, conf_privkey, saved_pubkey))
    }

    async fn load_live_state_for_mutation(
        &self,
        saved_privkey: &SecretString,
        saved_addr: &TunnelCidr,
        require_route_prefix: bool,
    ) -> Result<(String, Option<SecretString>, Vec<PeerBlock>), PeerNetworkError> {
        let service = self.service_state().await;
        let live = self
            .output("wg", &strings(&["showconf", PEER_WG_INTERFACE]), None)
            .await?;
        if live.status.success() {
            let live_secret = SecretString::new(live.stdout);
            let live_cfg = PeerWireGuardConfig::parse(live_secret.as_str())?;
            self.reconcile_live_identity(saved_privkey, &live_cfg)
                .await?;
            if require_route_prefix {
                let (is_up, route_ready, detail) = self
                    .inspect_live_interface_link_and_route(saved_addr)
                    .await?;
                if !is_up || !route_ready {
                    let reason = detail.unwrap_or_else(|| {
                        format!(
                            "Live {PEER_WG_INTERFACE} is missing configured subnet route {}; restart {PEER_WG_SERVICE_UNIT} before adding peers",
                            saved_addr.interface_string()
                        )
                    });
                    return Err(PeerNetworkError::Runtime(reason));
                }
            }
            let live_peers = live_cfg.peers.clone();
            Ok((service, Some(live_secret), live_peers))
        } else if service == "active" {
            Err(PeerNetworkError::Runtime(
                "Cannot read live WireGuard configuration for afpeer0; no changes were saved"
                    .to_string(),
            ))
        } else {
            Ok((service, None, Vec::new()))
        }
    }

    async fn apply_config_change(
        &self,
        old_text: &SecretString,
        new_text: &SecretString,
        old_runtime: Option<&SecretString>,
        post_sync_verify_peer_ip: Option<IpAddr>,
    ) -> Result<bool, PeerNetworkError> {
        let Some(runtime_before) = old_runtime else {
            self.write_saved_config(new_text)?;
            return Ok(false);
        };

        let original_runtime_file = TemporarySecretFile::create(
            self,
            "afpeer0-runtime",
            runtime_before.as_str().as_bytes(),
        )?;

        self.write_saved_config(new_text)?;

        let strip_target = self.strip_target();
        let stripped_raw = match self
            .run_checked("wg-quick", &strings(&["strip", &strip_target]), None, true)
            .await
        {
            Ok(out) => SecretString::new(out),
            Err(strip_err) => {
                if let Err(restore_err) = self.write_saved_config(old_text) {
                    return Err(PeerNetworkError::Runtime(format!(
                        "wg-quick strip failed and persistent afpeer0.conf rollback failed; inspect {PEER_WG_INTERFACE} before retrying ({strip_err}; rollback: {restore_err})"
                    )));
                }
                return Err(PeerNetworkError::Runtime(format!(
                    "wg-quick strip failed; previous afpeer0.conf was restored ({strip_err})"
                )));
            }
        };

        let staged_stripped_file = match TemporarySecretFile::create(
            self,
            "afpeer0-strip",
            stripped_raw.as_str().as_bytes(),
        ) {
            Ok(file) => file,
            Err(stage_err) => {
                if let Err(restore_err) = self.write_saved_config(old_text) {
                    return Err(PeerNetworkError::Runtime(format!(
                        "Staging stripped config failed and persistent afpeer0.conf rollback failed; inspect {PEER_WG_INTERFACE} before retrying ({stage_err}; rollback: {restore_err})"
                    )));
                }
                return Err(PeerNetworkError::Runtime(format!(
                    "Staging stripped config failed; previous afpeer0.conf was restored ({stage_err})"
                )));
            }
        };
        drop(stripped_raw);

        let sync_args = vec![
            "syncconf".to_string(),
            PEER_WG_INTERFACE.to_string(),
            staged_stripped_file.path().to_string_lossy().into_owned(),
        ];
        let sync_and_verify = async {
            self.run_checked("wg", &sync_args, None, false).await?;
            if let Some(peer_ip) = post_sync_verify_peer_ip {
                self.verify_peer_effective_route(peer_ip).await?;
            }
            Ok::<(), PeerNetworkError>(())
        }
        .await;

        if let Err(sync_err) = sync_and_verify {
            let rollback_args = vec![
                "syncconf".to_string(),
                PEER_WG_INTERFACE.to_string(),
                original_runtime_file.path().to_string_lossy().into_owned(),
            ];
            let runtime_restore = self.run_checked("wg", &rollback_args, None, false).await;
            let disk_restore = self.write_saved_config(old_text);
            if runtime_restore.is_err() || disk_restore.is_err() {
                return Err(PeerNetworkError::Runtime(format!(
                    "WireGuard {PEER_WG_INTERFACE} update failed and recovery was incomplete; inspect {PEER_WG_INTERFACE} before retrying ({sync_err})"
                )));
            }
            return Err(PeerNetworkError::Runtime(format!(
                "WireGuard {PEER_WG_INTERFACE} live sync failed; previous runtime and persistent configuration were restored ({sync_err})"
            )));
        }

        Ok(true)
    }

    pub async fn status(&self) -> Result<PeerStatusResponse, PeerNetworkError> {
        let (_mem_read_guard, file_lock_res) = self.acquire_status_read_locks().await?;

        let installed = self.installed("wg").await;
        let service_state = self.service_state().await;
        let mut status = PeerStatusResponse {
            installed,
            state: "not_installed".to_string(),
            interface: PEER_WG_INTERFACE.to_string(),
            public_key: String::new(),
            listen_port: String::new(),
            tunnel_ip: String::new(),
            tunnel_cidr: self.tunnel_cidr.network_string(),
            interface_address: String::new(),
            service_state: service_state.clone(),
            config_available: false,
            key_available: false,
            route_prefix_ready: false,
            peers: Vec::new(),
            error: None,
        };
        let _file_lock = match file_lock_res {
            Ok(guard) => guard,
            Err(err) => {
                status.state = "error".to_string();
                status.error = Some(redact_secrets(&err.to_string()));
                return Ok(status);
            }
        };
        if !installed {
            return Ok(status);
        }

        let saved_key = match self.read_saved_key() {
            Ok(key) => key,
            Err(err) => {
                status.state = "error".to_string();
                status.error = Some(redact_secrets(&err.to_string()));
                return Ok(status);
            }
        };
        status.key_available = saved_key.is_some();

        let mut saved_addr_opt = None;
        let saved_config = match self.read_saved_config() {
            Ok(Some((_raw, cfg))) => match cfg.validate_server() {
                Ok((addr, port, conf_privkey)) => {
                    if let Some(ref key_file_priv) = saved_key {
                        if key_file_priv.as_str() != conf_privkey.as_str() {
                            status.state = "error".to_string();
                            status.error = Some(
                                "Saved afpeer0.key differs from PrivateKey in afpeer0.conf; reconcile identity before continuing"
                                    .to_string(),
                            );
                            return Ok(status);
                        }
                    }
                    match self.derive_public_key(&conf_privkey).await {
                        Ok(pubkey) => {
                            status.public_key = pubkey;
                        }
                        Err(_) => {
                            status.state = "error".to_string();
                            status.error = Some(
                                "Could not derive the configured afpeer0 server public key"
                                    .to_string(),
                            );
                            return Ok(status);
                        }
                    }
                    status.tunnel_ip = addr.ip.to_string();
                    status.tunnel_cidr = addr.network_string();
                    status.interface_address = addr.interface_string();
                    status.listen_port = port.to_string();
                    status.peers = cfg.peers.iter().map(PeerBlock::status_peer).collect();
                    saved_addr_opt = Some(addr);
                    Some(cfg)
                }
                Err(err) => {
                    status.state = "error".to_string();
                    status.error = Some(redact_secrets(&err.to_string()));
                    return Ok(status);
                }
            },
            Ok(None) => None,
            Err(err) => {
                status.state = "error".to_string();
                status.error = Some(redact_secrets(&err.to_string()));
                return Ok(status);
            }
        };

        status.config_available = saved_config.is_some();
        status.state = if saved_config.is_some() {
            "stopped".to_string()
        } else {
            "unconfigured".to_string()
        };

        match self
            .output("wg", &strings(&["show", PEER_WG_INTERFACE, "dump"]), None)
            .await
        {
            Ok(out) if out.status.success() => match parse_wg_dump(&out.stdout) {
                Ok(dump) => {
                    let Some(saved_addr) = saved_addr_opt else {
                        status.state = "error".to_string();
                        status.error = Some(
                            "Live afpeer0 interface exists without saved afpeer0.conf; reconcile it before continuing"
                                .to_string(),
                        );
                        return Ok(status);
                    };
                    if status.public_key != dump.public_key {
                        status.state = "error".to_string();
                        status.error = Some(
                            "Live WireGuard server identity differs from afpeer0.conf; reconcile it before pairing or changing peers"
                                .to_string(),
                        );
                        return Ok(status);
                    }
                    let mut peers = status.peers.clone();
                    for dumped in dump.peers {
                        if let Some(existing) =
                            peers.iter_mut().find(|p| p.public_key == dumped.public_key)
                        {
                            existing.endpoint = dumped.endpoint;
                            existing.allowed_ips = dumped.allowed_ips;
                            existing.latest_handshake = dumped.latest_handshake;
                            existing.latest_handshake_epoch = dumped.latest_handshake_epoch;
                            existing.handshake_age_secs = dumped.handshake_age_secs;
                            existing.transfer_rx = dumped.transfer_rx;
                            existing.transfer_tx = dumped.transfer_tx;
                            existing.persistent_keepalive = dumped.persistent_keepalive;
                            existing.active = dumped.active;
                            existing.present_live = true;
                        } else {
                            peers.push(PeerStatusPeer {
                                public_key: dumped.public_key,
                                endpoint: dumped.endpoint,
                                allowed_ips: dumped.allowed_ips,
                                latest_handshake: dumped.latest_handshake,
                                latest_handshake_epoch: dumped.latest_handshake_epoch,
                                handshake_age_secs: dumped.handshake_age_secs,
                                transfer_rx: dumped.transfer_rx,
                                transfer_tx: dumped.transfer_tx,
                                persistent_keepalive: dumped.persistent_keepalive,
                                active: dumped.active,
                                persistent: false,
                                present_live: true,
                            });
                        }
                    }
                    status.public_key = dump.public_key;
                    status.listen_port = dump.listen_port;
                    status.peers = peers;

                    match self
                        .inspect_live_interface_link_and_route(&saved_addr)
                        .await
                    {
                        Ok((is_up, route_ready, detail)) => {
                            status.route_prefix_ready = route_ready;
                            if is_up && route_ready {
                                status.state = "running".to_string();
                            } else if is_up {
                                status.state = "error".to_string();
                                status.error = Some(detail.unwrap_or_else(|| {
                                    format!(
                                        "Live {PEER_WG_INTERFACE} interface routing does not match configured tunnel CIDR {}; restart {PEER_WG_SERVICE_UNIT} to restore subnet routing",
                                        saved_addr.interface_string()
                                    )
                                }));
                            } else {
                                status.state = "stopped".to_string();
                            }
                        }
                        Err(err) => {
                            status.state = "error".to_string();
                            status.error = Some(redact_secrets(&err.to_string()));
                        }
                    }
                }
                Err(err) => {
                    status.state = "error".to_string();
                    status.error = Some(redact_secrets(&err.to_string()));
                }
            },
            Ok(out) if matches!(service_state.as_str(), "active" | "failed") => {
                status.state = "error".to_string();
                status.error = Some(format!(
                    "{PEER_WG_INTERFACE} status failed; service is {service_state}. {}",
                    redact_secrets(out.stderr.trim())
                ));
            }
            Err(err) => {
                status.state = "error".to_string();
                status.error = Some(redact_secrets(&err.to_string()));
            }
            _ => {}
        }

        Ok(status)
    }

    /// Runs a command via `TokioCommandRunner` with a bounded timeout that triggers cooperative
    /// cancellation and awaits `TokioCommandRunner`'s process-group teardown (`SIGTERM` -> grace
    /// -> `SIGKILL` -> reap) instead of dropping the command future.
    async fn run_package_command_with_timeout(
        runner: &TokioCommandRunner,
        program: &str,
        args: &[String],
        env_vars: &[(String, String)],
        timeout: Duration,
        label: &str,
    ) -> Result<CommandOutput, PeerNetworkError> {
        let step_cancel = CancellationToken::new();
        let mut cmd_fut = runner.run_command(program, args, env_vars, &step_cancel);
        tokio::select! {
            res = &mut cmd_fut => {
                res.map_err(|err| PeerNetworkError::Runtime(format!("{label} failed: {err}")))
            }
            _ = tokio::time::sleep(timeout) => {
                step_cancel.cancel();
                let _ = cmd_fut.await;
                Err(PeerNetworkError::Runtime(format!(
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
    ) -> Result<Option<String>, PeerNetworkError> {
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

    async fn acquire_package_locks_bounded(
        &self,
        env_cfg: &PackageExecutionEnv,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'static, ()>,
            CrossProcessLockGuard,
            af_release::ReleaseLockGuard,
        ),
        PeerNetworkError,
    > {
        const BUSY: &str =
            "Package maintenance or another lifecycle operation is busy; retry shortly";
        let deadline = Instant::now() + self.package_lock_timeout;

        let pkg_mutex = tokio::time::timeout_at(deadline, crate::PACKAGE_MUTEX.lock())
            .await
            .map_err(|_| PeerNetworkError::Busy(BUSY.to_string()))?;

        let flock_guard = loop {
            match CrossProcessLockGuard::try_acquire(env_cfg, PEER_WG_PACKAGE) {
                Ok(guard) => break guard,
                Err(PackageExecutorError::LockConflict(_)) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(PeerNetworkError::Busy(BUSY.to_string()));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(Duration::from_millis(25).min(remaining)).await;
                }
                Err(err) => {
                    return Err(PeerNetworkError::Runtime(format!(
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
                        return Err(PeerNetworkError::Busy(BUSY.to_string()));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(Duration::from_millis(25).min(remaining)).await;
                }
                Err(err) if crate::is_lifecycle_busy(&err) => {
                    return Err(PeerNetworkError::Busy(redact_secrets(&err.to_string())));
                }
                Err(err) => {
                    return Err(PeerNetworkError::Runtime(redact_secrets(&err.to_string())));
                }
            }
        };

        Ok((pkg_mutex, flock_guard, maintenance_guard))
    }

    /// Installs `wireguard-tools` through the runner's existing Marketplace apt serialization and
    /// `TokioCommandRunner` execution path using `ReservationTarget::System` so all competing
    /// lifecycle reservations are respected without requiring a Marketplace catalog entry.
    pub async fn ensure_packages(&self) -> Result<PeerEnsurePackagesResponse, PeerNetworkError> {
        let runner = TokioCommandRunner {
            respect_dry_run_env: self.bin.is_none(),
        };

        if let Some(version) = self
            .query_dpkg_installed_version(&runner, PEER_WG_PACKAGE)
            .await?
        {
            let mut versions = HashMap::new();
            versions.insert(PEER_WG_PACKAGE.to_string(), version);
            return Ok(PeerEnsurePackagesResponse {
                installed: true,
                already_installed: true,
                packages: vec![PEER_WG_PACKAGE.to_string()],
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

        // Re-check after acquiring the package locks.
        if let Some(version) = self
            .query_dpkg_installed_version(&runner, PEER_WG_PACKAGE)
            .await?
        {
            let mut versions = HashMap::new();
            versions.insert(PEER_WG_PACKAGE.to_string(), version);
            return Ok(PeerEnsurePackagesResponse {
                installed: true,
                already_installed: true,
                packages: vec![PEER_WG_PACKAGE.to_string()],
                versions,
            });
        }

        let apt_prog = self.program("apt-get").to_string_lossy().into_owned();
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];

        let update_args = strings(&["-o", "DPkg::Lock::Timeout=120", "update", "-y", "-qq"]);
        let install_args = strings(&[
            "-o",
            "DPkg::Lock::Timeout=120",
            "-o",
            "DPkg::Options::=--force-confdef",
            "-o",
            "DPkg::Options::=--force-confold",
            "install",
            "-y",
            "-qq",
            PEER_WG_PACKAGE,
        ]);

        let apt_timeout = self.apt_timeout;
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
                return Err(PeerNetworkError::Runtime(format!(
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
                return Err(PeerNetworkError::Runtime(format!(
                    "apt-get install {PEER_WG_PACKAGE} exited with {}: {}",
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

        let version = self
            .query_dpkg_installed_version(&runner, PEER_WG_PACKAGE)
            .await?
            .ok_or_else(|| {
                PeerNetworkError::Runtime(format!(
                    "{PEER_WG_PACKAGE} did not report as installed after apt-get install"
                ))
            })?;

        drop(maintenance_lease);

        let mut versions = HashMap::new();
        versions.insert(PEER_WG_PACKAGE.to_string(), version);
        Ok(PeerEnsurePackagesResponse {
            installed: true,
            already_installed: false,
            packages: vec![PEER_WG_PACKAGE.to_string()],
            versions,
        })
    }

    pub async fn write_credential(
        &self,
        slot: PeerCredentialSlot,
        id: &str,
        value: &str,
    ) -> Result<PeerCredentialWriteResponse, PeerNetworkError> {
        let valid_id = validate_credential_id(id)?;
        let valid_value = validate_credential_value(value)?;

        let (_mem_guard, _file_lock) = self.acquire_credential_write_locks(true).await?;
        let slot_dir_path = self.state_dir.join(slot.subdir());
        let slot_dir = self.ensure_confined_dir(&slot_dir_path, slot.dir_kind())?;
        let filename = slot.file_name(valid_id);
        let payload = SecretString::new(format!("{valid_value}\n"));
        self.write_secret_file_atomic(
            &slot_dir,
            &filename,
            payload.as_str().as_bytes(),
            slot.file_mode(),
            slot.allow_group_read(),
        )?;
        Ok(PeerCredentialWriteResponse {
            slot,
            id: valid_id.to_string(),
            written: true,
        })
    }

    pub async fn read_credential(
        &self,
        slot: PeerCredentialSlot,
        id: &str,
    ) -> Result<PeerCredentialReadResponse, PeerNetworkError> {
        let valid_id = validate_credential_id(id)?;

        let (_mem_guard, _file_lock) = self.acquire_credential_read_locks().await?;
        let slot_dir_path = self.state_dir.join(slot.subdir());
        let Some(slot_dir) = self.open_existing_confined_dir(&slot_dir_path, slot.dir_kind())?
        else {
            return Ok(PeerCredentialReadResponse {
                slot,
                id: valid_id.to_string(),
                present: false,
                value: None,
            });
        };
        let filename = slot.file_name(valid_id);
        let Some(raw) = self.read_secret_file_confined(
            &slot_dir,
            &filename,
            MAX_CREDENTIAL_BYTES + 2,
            slot.allow_group_read(),
        )?
        else {
            return Ok(PeerCredentialReadResponse {
                slot,
                id: valid_id.to_string(),
                present: false,
                value: None,
            });
        };
        let trimmed = raw.as_str().trim_end_matches(['\r', '\n']);
        validate_credential_value(trimmed)?;
        let secret = PeerCredentialSecret::new(trimmed.to_string());
        drop(raw);
        Ok(PeerCredentialReadResponse {
            slot,
            id: valid_id.to_string(),
            present: true,
            value: Some(secret),
        })
    }

    fn delete_credential_unlocked(
        &self,
        slot: PeerCredentialSlot,
        valid_id: &str,
    ) -> Result<bool, PeerNetworkError> {
        let slot_dir_path = self.state_dir.join(slot.subdir());
        let Some(slot_dir) = self.open_existing_confined_dir(&slot_dir_path, slot.dir_kind())?
        else {
            return Ok(false);
        };
        let filename = slot.file_name(valid_id);
        delete_secret_file_confined(&slot_dir, &filename, self.security.expected_uid)
    }

    pub async fn delete_credential(
        &self,
        slot: PeerCredentialSlot,
        id: &str,
    ) -> Result<PeerCredentialDeleteResponse, PeerNetworkError> {
        let valid_id = validate_credential_id(id)?;
        let (_mem_guard, _file_lock) = self.acquire_credential_write_locks(false).await?;
        let deleted = self.delete_credential_unlocked(slot, valid_id)?;
        Ok(PeerCredentialDeleteResponse {
            slot,
            id: valid_id.to_string(),
            deleted,
        })
    }

    pub async fn delete_link_credentials(
        &self,
        link_id: &str,
    ) -> Result<PeerLinkCredentialsDeleteResponse, PeerNetworkError> {
        let valid_id = validate_credential_id(link_id)?;
        let (_mem_guard, _file_lock) = self.acquire_credential_write_locks(false).await?;
        let link_deleted =
            self.delete_credential_unlocked(PeerCredentialSlot::LinkToken, valid_id)?;
        let grant_deleted =
            self.delete_credential_unlocked(PeerCredentialSlot::GrantToken, valid_id)?;
        Ok(PeerLinkCredentialsDeleteResponse {
            link_id: valid_id.to_string(),
            link_token_deleted: link_deleted,
            grant_token_deleted: grant_deleted,
        })
    }

    pub async fn execute(
        &self,
        req: &PeerNetworkRequest,
    ) -> Result<PeerNetworkResponse, PeerNetworkError> {
        match req {
            PeerNetworkRequest::EnsureIdentity {
                tunnel_ip,
                avoid_tunnel_ips,
                wg_port,
                tunnel_cidr,
            } => Ok(PeerNetworkResponse::Identity(
                self.ensure_identity(
                    tunnel_ip.as_deref(),
                    avoid_tunnel_ips,
                    *wg_port,
                    tunnel_cidr.as_deref(),
                )
                .await?,
            )),
            PeerNetworkRequest::AddPeer {
                pubkey,
                endpoint,
                port,
                tunnel_ip,
            } => Ok(PeerNetworkResponse::Mutation(
                self.add_peer(pubkey, endpoint, *port, tunnel_ip).await?,
            )),
            PeerNetworkRequest::RemovePeer { pubkey } => Ok(PeerNetworkResponse::Mutation(
                self.remove_peer(pubkey).await?,
            )),
            PeerNetworkRequest::SetEndpoint {
                pubkey,
                endpoint,
                port,
            } => Ok(PeerNetworkResponse::Mutation(
                self.set_endpoint(pubkey, endpoint, *port).await?,
            )),
            PeerNetworkRequest::Status => Ok(PeerNetworkResponse::Status(self.status().await?)),
            PeerNetworkRequest::EnsurePackages => {
                Ok(PeerNetworkResponse::Packages(self.ensure_packages().await?))
            }
            PeerNetworkRequest::WriteCredential { slot, id, value } => {
                Ok(PeerNetworkResponse::CredentialWritten(
                    self.write_credential(*slot, id, value).await?,
                ))
            }
            PeerNetworkRequest::ReadCredential { slot, id } => Ok(
                PeerNetworkResponse::CredentialRead(self.read_credential(*slot, id).await?),
            ),
            PeerNetworkRequest::DeleteCredential { slot, id } => Ok(
                PeerNetworkResponse::CredentialDeleted(self.delete_credential(*slot, id).await?),
            ),
            PeerNetworkRequest::DeleteLinkCredentials { link_id } => {
                Ok(PeerNetworkResponse::LinkCredentialsDeleted(
                    self.delete_link_credentials(link_id).await?,
                ))
            }
        }
    }
}

pub async fn execute_peer_network_local(
    req: &PeerNetworkRequest,
) -> Result<PeerNetworkResponse, PeerNetworkError> {
    let manager = PeerNetworkManager::from_env()?;
    manager.execute(req).await
}

pub(crate) async fn handle_peer_network(
    manager_ext: Option<Extension<Arc<PeerNetworkManager>>>,
    payload: Result<Json<PeerNetworkRequest>, JsonRejection>,
) -> Response {
    let req = match payload {
        Ok(Json(req)) => req,
        Err(_) => {
            return PeerNetworkError::InvalidInput(
                "Invalid peer-network request payload".to_string(),
            )
            .into_http_response();
        }
    };
    let manager = match manager_ext {
        Some(Extension(mgr)) => mgr,
        None => match PeerNetworkManager::from_env() {
            Ok(mgr) => Arc::new(mgr),
            Err(err) => return err.into_http_response(),
        },
    };
    // Run mutating operations in a detached Tokio task so caller disconnect cannot abort an
    // in-flight apply, rollback, subprocess cleanup, or lock release.
    let result = if req.is_mutating() {
        let mgr = Arc::clone(&manager);
        match tokio::spawn(async move { mgr.execute(&req).await }).await {
            Ok(res) => res,
            Err(_) => Err(PeerNetworkError::Runtime(
                "Peer-network operation task terminated unexpectedly".to_string(),
            )),
        }
    } else {
        manager.execute(&req).await
    };

    match result {
        Ok(typed_resp) => {
            let mut output = match typed_resp.serialize_wire_output() {
                Ok(out) => out,
                Err(err) => return err.into_http_response(),
            };
            let mut runner_resp = RunnerResponse {
                success: true,
                output: std::mem::take(&mut output),
                error: String::new(),
            };
            let encoded = serde_json::to_vec(&runner_resp);
            zeroize_string(&mut runner_resp.output);
            match encoded {
                Ok(body) => Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| Response::new(Body::empty())),
                Err(_) => PeerNetworkError::Runtime(
                    "Failed encoding peer-network runner response".to_string(),
                )
                .into_http_response(),
            }
        }
        Err(err) => err.into_http_response(),
    }
}
