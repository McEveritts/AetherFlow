//! Peer NFS media sharing (Design File 39): exports, mounts, authenticated export catalog,
//! WireGuard + sentinel mount health gating, scoped revocation cleanup, and media-app safety hooks.
//!
//! Security & Concurrency Invariants:
//! - Admin endpoints (`/api/v1/admin/peers/:id/exports` and `/api/v1/admin/peers/:id/mounts`) live
//!   strictly in the local same-origin admin router behind `auth_middleware`, `csrf_middleware`,
//!   `admin_only_middleware`, and `reject_peer_principal_middleware`. They are explicitly denied
//!   both on the WireGuard tunnel management router (`peers::scopes`) and by the browser peer
//!   management proxy (`peers::proxy`).
//! - The internal tunnel export catalog (`GET /peer/v1/exports`) requires the caller's active link
//!   WireGuard source IP and constant-time verified `X-AF-Link-Token`, returning ONLY exports
//!   owned by `auth.link.id`. No cross-link export discovery is possible.
//! - Mount creation resolves the selected export afresh by `export_id` through `GET /peer/v1/exports`
//!   over the pinned live WireGuard tunnel using the held link credential. Browser-supplied remote
//!   paths, socket addresses, or mount options are rejected (`deny_unknown_fields`). Mounts default
//!   to read-only (`writable = false`) and reject writable mounting unless the remote export allows
//!   writes.
//! - Exports default to read-only (`writable = false`). Writable exports auto-derive `(uid, gid)`
//!   from the validated canonical folder owner (confirmed by `af-runner` `EnsureSentinel`) and
//!   refuse root (`uid == 0 || gid == 0`). Re-exporting peer mounts (`/mnt/af-peers`) or sensitive
//!   system directories is forbidden.
//! - Mutations stage privileged runner changes with deterministic rollback on failure and serialize
//!   under `runtime.lock_link` (never held across outbound tunnel HTTP calls).
//! - Health gating stops mounts immediately on the first tick that detects an explicitly removed
//!   WireGuard peer (or stale handshake > 180s), stops mounts after two consecutive 5-second
//!   sentinel probe failures (`.af-peer-sentinel`), and restores stopped mounts once the link and
//!   sentinel recover.
//! - Media-app safety hooks prevent pointing libraries or scans at the mount root itself (requiring
//!   an interior subfolder such as `/mnt/af-peers/<link>/<export>/library`), refuse scans of
//!   unmounted peer paths, and disable Plex automatic trash emptying (`autoEmptyTrash=0`) when a
//!   configured Plex server uses a peer-mounted library.

use super::errors::{redact_sensitive_text, PeerError, PeerErrorBody, PeerErrorDetail};
use super::health::{evaluate_compatibility, CompatibilityStatus, WG_HANDSHAKE_STALE_SECS};
use super::listener::authenticate_active_link;
use super::pairing::{is_valid_credential_id, map_runner_error};
use super::{
    is_active_link_state, is_down_link_state, is_live_link_state, is_pending_link_state,
    is_revoked_or_revoking_state, PeerRuntime, TunnelHttpError,
};
use crate::auth::AuthUser;
use crate::routes::{get_allowed_fs_roots, is_fs_path_allowed};
use crate::ws::{extract_client_ip_for_peer, PeerIp};
use af_db::peers::{self as db_peers, PeerExport, PeerLink, PeerMount};
use af_runner::{
    derive_peer_mount_path, is_managed_peer_mount_unit, validate_peer_mount_path,
    validate_peer_mount_segment, PeerCredentialSecret, PeerCredentialSlot, PeerNetworkError,
    PeerNetworkRequest, PeerStorageError, PeerStorageExportSpec, PeerStorageRequest,
    PeerStorageResponse, DEFAULT_PEER_MOUNTS_ROOT, DEFAULT_SENTINEL_PROBE_TIMEOUT_MS,
    PEER_SENTINEL_FILE_NAME as RUNNER_SENTINEL_FILE_NAME,
};
use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use futures::future::BoxFuture;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use uuid::Uuid;

pub const PEER_MOUNTS_BASE_DIR: &str = DEFAULT_PEER_MOUNTS_ROOT;
pub const PEER_SENTINEL_FILE_NAME: &str = RUNNER_SENTINEL_FILE_NAME;
pub const SENTINEL_PROBE_TIMEOUT_MS: u64 = DEFAULT_SENTINEL_PROBE_TIMEOUT_MS;
pub const SENTINEL_FAILURE_THRESHOLD: u32 = 2;
pub const MOUNT_PURPOSE_MEDIA: &str = "media";
pub const MOUNT_STATE_MOUNTED: &str = "mounted";
pub const MOUNT_STATE_STOPPED: &str = "stopped";
pub const MOUNT_STATE_ERROR: &str = "error";

const ADMIN_STORAGE_BODY_LIMIT_BYTES: usize = 8192;
const MAX_EXPORT_PATH_BYTES: usize = 4096;
const PLEX_SAFETY_TIMEOUT: Duration = Duration::from_secs(4);
const PLEX_SAFETY_MAX_BODY_BYTES: usize = 512 * 1024;

const FORBIDDEN_EXPORT_PREFIXES: &[&str] = &[
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/mnt/af-peers",
    "/opt/AetherFlow",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var/lib/aetherflow",
    "/var/run",
];

const FORBIDDEN_EXACT_EXPORT_ROOTS: &[&str] = &["/", "/tmp", "/var/tmp", "/var", "/home"];

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Storage Runner Trait & Mount Health Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Privileged storage runner abstraction matching [`super::PeerRunner`]: production dispatches
/// over `/v1/peer-storage` via `af_runner::dispatch_peer_storage`, while local tests inject
/// deterministic fake runners or isolated `af_runner::PeerStorageManager` instances.
pub(crate) trait PeerStorageRunner: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerStorageRequest,
    ) -> BoxFuture<'a, Result<PeerStorageResponse, PeerStorageError>>;
}

pub(crate) struct ProductionPeerStorageRunner;

impl PeerStorageRunner for ProductionPeerStorageRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerStorageRequest,
    ) -> BoxFuture<'a, Result<PeerStorageResponse, PeerStorageError>> {
        Box::pin(af_runner::dispatch_peer_storage(req))
    }
}

/// Tracks consecutive sentinel probe failures per mount ID in memory so two consecutive failures
/// trigger a mount stop while a single transient blip recovers cleanly on the next tick.
#[derive(Default)]
pub(crate) struct MountHealthTracker {
    consecutive_failures: StdMutex<HashMap<String, u32>>,
}

impl MountHealthTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_success(&self, mount_id: &str) {
        self.consecutive_failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(mount_id);
    }

    pub(crate) fn record_failure(&self, mount_id: &str) -> u32 {
        let mut map = self
            .consecutive_failures
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(mount_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    pub(crate) fn clear(&self, mount_id: &str) {
        self.consecutive_failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(mount_id);
    }

    #[cfg(test)]
    pub(crate) fn failure_count(&self, mount_id: &str) -> u32 {
        self.consecutive_failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(mount_id)
            .copied()
            .unwrap_or(0)
    }
}

fn map_storage_runner_error(err: PeerStorageError, server: &str, step: &str) -> PeerError {
    match err {
        PeerStorageError::InvalidInput(msg) => PeerError::invalid_request(
            server,
            step,
            msg,
            "Verify the folder path, ownership, and peer storage parameters and retry",
        ),
        PeerStorageError::NotFound(msg) => PeerError::not_found(server, step, msg),
        PeerStorageError::Conflict(msg) => PeerError::conflict(
            server,
            step,
            msg,
            "Refresh the Cluster page and verify current exports and mounts",
        ),
        PeerStorageError::Busy(msg) => PeerError::busy(server, step, msg),
        PeerStorageError::Runtime(msg) => PeerError::internal(server, step, msg),
    }
}

fn export_spec_from_row(export: &PeerExport) -> PeerStorageExportSpec {
    PeerStorageExportSpec {
        path: export.path.clone(),
        writable: export.writable,
        squash_uid: export.squash_uid,
        squash_gid: export.squash_gid,
    }
}

async fn apply_link_exports_on_runner(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_tunnel_ip: &str,
    specs: &[PeerStorageExportSpec],
) -> Result<(), PeerStorageError> {
    let req = if specs.is_empty() {
        PeerStorageRequest::RemoveExports {
            link: link_id.to_string(),
        }
    } else {
        PeerStorageRequest::WriteExports {
            link: link_id.to_string(),
            tunnel_ip: peer_tunnel_ip.to_string(),
            exports: specs.to_vec(),
        }
    };
    runtime
        .storage_runner
        .dispatch(&req)
        .await
        .and_then(|resp| resp.into_exports_written())?;
    Ok(())
}

async fn probe_mount_sentinel_via_runner(
    runtime: &PeerRuntime,
    mount_path: &str,
) -> Result<(), String> {
    let req = PeerStorageRequest::ProbeSentinel {
        mount_path: mount_path.to_string(),
        timeout_ms: Some(SENTINEL_PROBE_TIMEOUT_MS),
    };
    match runtime
        .storage_runner
        .dispatch(&req)
        .await
        .and_then(|resp| resp.into_sentinel_probed())
    {
        Ok(probe) if probe.healthy => Ok(()),
        Ok(probe) => {
            if probe.timed_out {
                Err(probe.error.unwrap_or_else(|| {
                    format!("sentinel probe timed out after {SENTINEL_PROBE_TIMEOUT_MS}ms")
                }))
            } else {
                Err(probe
                    .error
                    .unwrap_or_else(|| "sentinel file is missing or unreadable".to_string()))
            }
        }
        Err(err) => Err(redact_sensitive_text(&err.to_string())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request & Response Wire Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePeerExportReq {
    path: String,
    #[serde(default)]
    writable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePeerExportReq {
    export_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePeerMountReq {
    export_id: String,
    #[serde(default)]
    writable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePeerMountReq {
    mount_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerExportListPayload {
    exports: Vec<PeerExport>,
}

#[derive(Debug, Serialize)]
struct PeerMountListPayload {
    mounts: Vec<PeerMount>,
    available_exports: Vec<PeerExport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exports_error: Option<PeerErrorBody>,
}

fn parse_bounded_json<T: for<'de> Deserialize<'de>>(
    raw_body: &[u8],
    server: &str,
    step: &str,
    usage_hint: &str,
) -> Result<T, PeerError> {
    if raw_body.len() > ADMIN_STORAGE_BODY_LIMIT_BYTES {
        return Err(PeerError::payload_too_large(
            server,
            step,
            format!("Request body exceeds the {ADMIN_STORAGE_BODY_LIMIT_BYTES}-byte limit"),
            usage_hint,
        ));
    }
    serde_json::from_slice(raw_body).map_err(|err| {
        PeerError::invalid_request(
            server,
            step,
            format!("Invalid peer storage request payload: {err}"),
            usage_hint,
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Path Validation, Owner Mapping & Mount Path Derivation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedLocalExport {
    pub(crate) canonical_path: String,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
}

fn has_disallowed_path_chars(path: &str) -> bool {
    path.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '"' | '\'' | '#' | ';' | ',' | ':' | '(' | ')' | '*' | '?' | '[' | ']' | '\\'
            )
    })
}

fn is_forbidden_export_target(path: &StdPath) -> bool {
    if FORBIDDEN_EXACT_EXPORT_ROOTS
        .iter()
        .any(|exact| path == StdPath::new(exact))
    {
        return true;
    }
    FORBIDDEN_EXPORT_PREFIXES.iter().any(|prefix| {
        let p = StdPath::new(prefix);
        path == p || path.starts_with(p)
    })
}

pub(crate) fn validate_local_export_path_with_roots(
    raw_path: &str,
    allowed_roots: &[PathBuf],
    server: &str,
    step: &str,
) -> Result<ValidatedLocalExport, PeerError> {
    if raw_path.is_empty() || raw_path.len() > MAX_EXPORT_PATH_BYTES {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Export path must be a non-empty absolute folder path",
            "Select an existing directory under an allowed host storage root",
        ));
    }
    if raw_path != raw_path.trim() || !raw_path.starts_with('/') {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Export path must start with '/' without leading or trailing whitespace",
            "Provide a clean absolute directory path such as /srv/media/movies",
        ));
    }
    if has_disallowed_path_chars(raw_path) {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Export path contains disallowed control or NFS configuration characters",
            "Choose a folder path without special shell or NFS export characters",
        ));
    }

    let raw = StdPath::new(raw_path);
    for comp in raw.components() {
        if matches!(comp, Component::CurDir | Component::ParentDir) {
            return Err(PeerError::invalid_request(
                server,
                step,
                "Export path must not contain '.' or '..' traversal segments",
                "Provide a canonical absolute directory path",
            ));
        }
    }

    let sym_meta = fs::symlink_metadata(raw).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PeerError::invalid_request(
                server,
                step,
                format!("Export directory '{raw_path}' does not exist"),
                "Create or select an existing local directory before exporting it",
            )
        } else {
            PeerError::invalid_request(
                server,
                step,
                format!("Could not inspect export directory '{raw_path}': {err}"),
                "Verify directory permissions and retry",
            )
        }
    })?;
    if sym_meta.file_type().is_symlink() {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Export path must be a real directory, not a symbolic link",
            "Select the underlying target directory directly",
        ));
    }
    if !sym_meta.is_dir() {
        return Err(PeerError::invalid_request(
            server,
            step,
            format!("Export path '{raw_path}' is not a directory"),
            "Select a folder rather than a regular file",
        ));
    }

    let canonical = fs::canonicalize(raw).map_err(|err| {
        PeerError::invalid_request(
            server,
            step,
            format!("Could not resolve canonical path for '{raw_path}': {err}"),
            "Select an accessible local directory",
        )
    })?;

    if is_forbidden_export_target(&canonical) {
        return Err(PeerError::invalid_request(
            server,
            step,
            format!(
                "Directory '{}' cannot be exported over peer NFS (system or peer mount root)",
                canonical.display()
            ),
            "Choose a local media folder under /srv, /media, /data, /mnt, or /home (outside /mnt/af-peers)",
        ));
    }

    if !is_fs_path_allowed(&canonical, allowed_roots) {
        return Err(PeerError::invalid_request(
            server,
            step,
            format!(
                "Directory '{}' is outside allowed host storage roots",
                canonical.display()
            ),
            "Choose a folder under an allowed storage root or configure AF_ALLOWED_FS_ROOTS",
        ));
    }

    let meta = fs::metadata(&canonical).map_err(|err| {
        PeerError::invalid_request(
            server,
            step,
            format!(
                "Could not read metadata for '{}': {err}",
                canonical.display()
            ),
            "Verify directory permissions and retry",
        )
    })?;
    if !meta.is_dir() {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Resolved export target is not a directory",
            "Select a local directory",
        ));
    }

    let canonical_str = canonical
        .to_str()
        .ok_or_else(|| {
            PeerError::invalid_request(
                server,
                step,
                "Export directory path is not valid UTF-8",
                "Use a UTF-8 directory path",
            )
        })?
        .to_string();
    if has_disallowed_path_chars(&canonical_str) || canonical_str.len() > MAX_EXPORT_PATH_BYTES {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Resolved export path contains disallowed characters or exceeds length limit",
            "Choose a clean directory path",
        ));
    }

    #[cfg(unix)]
    let (owner_uid, owner_gid) = {
        use std::os::unix::fs::MetadataExt;
        (meta.uid(), meta.gid())
    };
    #[cfg(not(unix))]
    let (owner_uid, owner_gid) = (0u32, 0u32);

    Ok(ValidatedLocalExport {
        canonical_path: canonical_str,
        owner_uid,
        owner_gid,
    })
}

pub(crate) fn resolve_export_owner_mapping(
    writable: bool,
    owner_uid: u32,
    owner_gid: u32,
    server: &str,
    step: &str,
) -> Result<(Option<u32>, Option<u32>), PeerError> {
    if !writable {
        return Ok((None, None));
    }
    if owner_uid == 0 || owner_gid == 0 {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Writable peer exports cannot squash remote writes to root (uid 0 or gid 0)",
            "Assign a non-root owner and group to this folder before enabling writes, or export read-only",
        ));
    }
    Ok((Some(owner_uid), Some(owner_gid)))
}

pub(crate) fn validate_remote_export_path(
    raw_path: &str,
    server: &str,
    step: &str,
) -> Result<String, PeerError> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty()
        || trimmed != raw_path
        || trimmed.len() > MAX_EXPORT_PATH_BYTES
        || !trimmed.starts_with('/')
        || trimmed == "/"
        || trimmed.contains("//")
        || has_disallowed_path_chars(trimmed)
    {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Peer export catalog returned an invalid remote folder path",
            "Inspect the export configuration on the remote peer and retry",
        ));
    }
    let normalized = trimmed.trim_end_matches('/');
    if normalized.is_empty() {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Peer export catalog returned root path '/' which cannot be mounted",
            "Export a specific media folder on the remote peer",
        ));
    }
    let p = StdPath::new(normalized);
    for comp in p.components() {
        if matches!(comp, Component::CurDir | Component::ParentDir) {
            return Err(PeerError::invalid_request(
                server,
                step,
                "Peer export catalog path contains traversal segments",
                "Recreate the export on the remote peer using a canonical path",
            ));
        }
    }
    if is_forbidden_export_target(p) {
        return Err(PeerError::invalid_request(
            server,
            step,
            "Peer export catalog path targets a forbidden system or peer mount directory",
            "Export a regular media folder on the remote peer",
        ));
    }
    Ok(normalized.to_string())
}

fn sanitize_mount_segment(raw: &str, fallback_prefix: &str, id_hint: &str) -> String {
    let mut cleaned = String::with_capacity(64);
    let mut prev_dot = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
            cleaned.push(ch);
            prev_dot = false;
        } else if ch == '.' && !prev_dot && !cleaned.is_empty() {
            cleaned.push('.');
            prev_dot = true;
        } else if !cleaned.is_empty() && !cleaned.ends_with('-') {
            cleaned.push('-');
            prev_dot = false;
        }
        if cleaned.len() >= 48 {
            break;
        }
    }
    while cleaned.ends_with('.') || cleaned.ends_with('-') {
        cleaned.pop();
    }
    if cleaned
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && validate_peer_mount_segment(&cleaned).is_ok()
    {
        return cleaned;
    }
    let short_id: String = id_hint
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect();
    if short_id.is_empty() {
        format!("{fallback_prefix}-export")
    } else {
        format!("{fallback_prefix}-{short_id}")
    }
}

fn derive_unique_mount_path_for_export(
    conn: &rusqlite::Connection,
    link: &PeerLink,
    remote_path: &str,
    export_id: &str,
    server: &str,
    step: &str,
) -> Result<String, PeerError> {
    let link_seg = if validate_peer_mount_segment(&link.name).is_ok() {
        link.name.clone()
    } else {
        sanitize_mount_segment(&link.id, "peer", &link.id)
    };

    let base_name = StdPath::new(remote_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("media");
    let primary_export_seg = sanitize_mount_segment(base_name, "export", export_id);

    let short_id: String = export_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let suffix = if short_id.is_empty() {
        "alt".to_string()
    } else {
        short_id
    };

    let mut candidates = vec![primary_export_seg.clone()];
    let truncated_primary: String = primary_export_seg.chars().take(48).collect();
    candidates.push(format!("{truncated_primary}-{suffix}"));
    candidates.push(format!(
        "export-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));

    for seg in candidates {
        let Ok(candidate_path) = derive_peer_mount_path(&link_seg, &seg) else {
            continue;
        };
        let exists = db_peers::get_peer_mount_by_mount_path(conn, &candidate_path)
            .map_err(|err| PeerError::internal(server, step, err.to_string()))?
            .is_some();
        if !exists {
            return Ok(candidate_path);
        }
    }

    Err(PeerError::conflict(
        server,
        step,
        "Could not allocate a unique managed mount path for this export",
        "Remove conflicting peer mounts and retry",
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Link Credential & Remote Export Catalog Helper
// ─────────────────────────────────────────────────────────────────────────────

async fn read_held_link_token(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_name: &str,
    step: &str,
) -> Result<PeerCredentialSecret, PeerError> {
    let resp = runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: link_id.to_string(),
        })
        .await
        .map_err(|err| match err {
            PeerNetworkError::Busy(msg) => PeerError::busy(peer_name, step, msg),
            other => PeerError::internal(
                peer_name,
                step,
                format!("Failed reading held link credential: {other}"),
            ),
        })?;
    let read = resp.into_credential_read().map_err(|err| {
        PeerError::internal(
            peer_name,
            step,
            format!("Invalid runner credential response: {err}"),
        )
    })?;
    if read.slot != PeerCredentialSlot::LinkToken || read.id != link_id {
        return Err(PeerError::internal(
            peer_name,
            step,
            "Runner returned a mismatched peer link credential slot",
        ));
    }
    if !read.present {
        return Err(PeerError::unauthorized(
            peer_name,
            step,
            format!(
                "Held outbound link credential for '{}' is missing",
                peer_name
            ),
        ));
    }
    read.into_secret().ok_or_else(|| {
        PeerError::internal(
            peer_name,
            step,
            "Runner reported a present link credential without a secret value",
        )
    })
}

fn check_peer_storage_capability(link: &PeerLink, step: &str) -> Result<(), PeerError> {
    let remote_caps: Vec<String> = link
        .capabilities
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();

    let compat = evaluate_compatibility(link.peer_protocol, &remote_caps);
    match compat.status {
        CompatibilityStatus::Compatible => Ok(()),
        CompatibilityStatus::Limited => {
            if compat.missing_capabilities.iter().any(|c| c == "storage") {
                Err(PeerError::version_incompatible(
                    &link.name,
                    step,
                    format!(
                        "'{}' does not advertise peer media storage support; update '{}' to use this",
                        link.name, link.name
                    ),
                ))
            } else {
                Ok(())
            }
        }
        CompatibilityStatus::Incompatible => Err(PeerError::version_incompatible(
            &link.name,
            step,
            format!(
                "'{}' peer protocol version is incompatible with media storage",
                link.name
            ),
        )),
        // Protocol not yet observed by a health tick; proceed to `/peer/v1/exports` and map
        // HTTP 404 / PEER_ROUTE_UNCLASSIFIED to `VERSION_INCOMPATIBLE`.
        CompatibilityStatus::Unknown => Ok(()),
    }
}

/// Fetches the authenticated export catalog assigned to this server from `link` over the pinned
/// WireGuard tunnel (`GET /peer/v1/exports`). Caller MUST NOT hold `link_lock`.
async fn fetch_remote_export_catalog(
    runtime: &PeerRuntime,
    link: &PeerLink,
    step: &str,
) -> Result<Vec<PeerExport>, PeerError> {
    if is_revoked_or_revoking_state(&link.state) {
        return Err(PeerError::link_revoked(
            &link.name,
            step,
            format!("Peer link '{}' has been revoked", link.name),
        ));
    }
    if is_pending_link_state(&link.state) {
        return Err(PeerError::conflict(
            &link.name,
            step,
            format!(
                "Peer link '{}' is still pending pairing confirmation",
                link.name
            ),
            "Complete pairing confirmation before listing or mounting remote exports",
        ));
    }
    if is_down_link_state(&link.state) {
        return Err(PeerError::link_down(
            &link.name,
            step,
            format!("Peer link '{}' is currently down", link.name),
        ));
    }
    if !is_active_link_state(&link.state) {
        return Err(PeerError::conflict(
            &link.name,
            step,
            format!("Peer link '{}' is in state '{}'", link.name, link.state),
            "Wait for the link to become active and retry",
        ));
    }

    check_peer_storage_capability(link, step)?;

    let held_token = read_held_link_token(runtime, &link.id, &link.name, step).await?;
    let res = runtime
        .send_tunnel_request(
            Method::GET,
            &link.tunnel_ip,
            "/peer/v1/exports",
            Some(&held_token),
            None,
            runtime.tunnel_request_timeout,
        )
        .await;
    drop(held_token);

    let (status, body, _rtt_ms) = match res {
        Ok(ok) => ok,
        Err(TunnelHttpError::Timeout(msg)) => {
            return Err(PeerError::handshake_timeout(&link.name, step, msg));
        }
        Err(TunnelHttpError::Unreachable(msg)) => {
            return Err(PeerError::link_down(&link.name, step, msg));
        }
        Err(TunnelHttpError::InvalidTarget(msg)) => {
            return Err(PeerError::invalid_request(
                &link.name,
                step,
                msg,
                "Verify local and remote peer tunnel IP configuration",
            ));
        }
    };

    if status == StatusCode::NOT_FOUND {
        return Err(PeerError::version_incompatible(
            &link.name,
            step,
            format!(
                "'{}' does not support /peer/v1/exports (HTTP 404); update '{}' to use media mounts",
                link.name, link.name
            ),
        ));
    }

    if !status.is_success() {
        let parsed_err = PeerError::from_remote_http(status, &body, &link.name, step);
        if matches!(parsed_err, PeerError::PeerRouteUnclassified(_)) {
            return Err(PeerError::version_incompatible(
                &link.name,
                step,
                format!(
                    "'{}' does not support peer media storage (/peer/v1/exports); update '{}' to use this",
                    link.name, link.name
                ),
            ));
        }
        return Err(parsed_err);
    }

    let catalog: PeerExportListPayload = serde_json::from_slice(&body).map_err(|_| {
        PeerError::link_down(
            &link.name,
            step,
            format!(
                "'{}' returned malformed JSON from /peer/v1/exports",
                link.name
            ),
        )
    })?;

    for export in &catalog.exports {
        if !is_valid_credential_id(&export.id) {
            return Err(PeerError::invalid_request(
                &link.name,
                step,
                "Peer export catalog returned an invalid export identifier",
                "Inspect exports on the remote peer and retry",
            ));
        }
        validate_remote_export_path(&export.path, &link.name, step)?;
    }

    Ok(catalog.exports)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Tunnel Route: GET /peer/v1/exports (Active Link Authenticated Only)
// ─────────────────────────────────────────────────────────────────────────────

/// Lists ONLY the local `peer_exports` rows assigned to the authenticated calling link.
/// Never accepts cross-link parameters or leaks another peer's export catalog.
pub(crate) async fn handle_tunnel_list_exports(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let (auth, _permit) =
        match authenticate_active_link(&runtime, connect_info, &headers, "GET /peer/v1/exports")
            .await
        {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    let local_server = runtime.local_server_name();
    let link_id = auth.link.id.clone();
    let res = runtime
        .db
        .read(&local_server, "tunnel_list_exports", move |conn| {
            db_peers::list_peer_exports_for_link(conn, &link_id).map_err(|err| {
                PeerError::internal(
                    "local",
                    "tunnel_list_exports",
                    format!("Failed listing link exports: {err}"),
                )
            })
        })
        .await;

    match res {
        Ok(exports) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(PeerExportListPayload { exports }),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Routes: GET / POST / DELETE /api/v1/admin/peers/:id/exports
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_peer_exports(
    State(runtime): State<Arc<PeerRuntime>>,
    Path(link_id): Path<String>,
) -> Response {
    match list_peer_exports_inner(&runtime, &link_id).await {
        Ok(payload) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(payload),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn list_peer_exports_inner(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<PeerExportListPayload, PeerError> {
    let server = runtime.local_server_name();
    let step = "list_peer_exports";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let id_c = link_id.to_string();
    let server_c = server.clone();
    let exports = runtime
        .db
        .read(&server, step, move |conn| {
            let _link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            db_peers::list_peer_exports_for_link(conn, &id_c).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed loading peer exports: {err}"),
                )
            })
        })
        .await?;

    Ok(PeerExportListPayload { exports })
}

pub async fn create_peer_export(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match create_peer_export_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(export) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "export": export })),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn create_peer_export_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<PeerExport, PeerError> {
    let server = runtime.local_server_name();
    let step = "create_peer_export";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let req: CreatePeerExportReq = parse_bounded_json(
        raw_body,
        &server,
        step,
        "Send JSON {\"path\":\"/srv/media/...\",\"writable\":false}",
    )?;

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c = link_id.to_string();
    let server_c = server.clone();
    let (local_identity, link, prev_exports) = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&link.state) {
                return Err(PeerError::link_revoked(
                    &link.name,
                    step,
                    format!("Cannot create export for revoked link '{}'", link.name),
                ));
            }
            if is_pending_link_state(&link.state) {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot create export for pending link '{}'; complete pairing first",
                        link.name
                    ),
                    "Confirm pairing before exporting folders to this peer",
                ));
            }
            if !is_live_link_state(&link.state) || link.inbound_token_hash.is_none() {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot create export for link '{}' in state '{}'",
                        link.name, link.state
                    ),
                    "Verify the peer link is active and retry",
                ));
            }
            let identity = db_peers::get_peer_identity(conn)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::conflict(
                        &server_c,
                        step,
                        "Local peer WireGuard identity is not configured",
                        "Complete peer pairing before configuring NFS exports",
                    )
                })?;
            let exports = db_peers::list_peer_exports_for_link(conn, &id_c).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed listing existing exports: {err}"),
                )
            })?;
            Ok((identity, link, exports))
        })
        .await?;

    #[cfg(test)]
    let allowed_roots = runtime
        .allowed_fs_roots_override
        .clone()
        .unwrap_or_else(get_allowed_fs_roots);
    #[cfg(not(test))]
    let allowed_roots = get_allowed_fs_roots();
    let validated =
        validate_local_export_path_with_roots(&req.path, &allowed_roots, &server, step)?;
    // Pre-validate owner mapping before invoking privileged runner actions.
    let _ = resolve_export_owner_mapping(
        req.writable,
        validated.owner_uid,
        validated.owner_gid,
        &server,
        step,
    )?;

    if prev_exports
        .iter()
        .any(|existing| existing.path == validated.canonical_path)
    {
        return Err(PeerError::conflict(
            &link.name,
            step,
            format!(
                "Folder '{}' is already exported to '{}'",
                validated.canonical_path, link.name
            ),
            "Remove the existing export before changing its write mode",
        ));
    }

    // Stage privileged NFS server configuration, sentinel file (which confirms authoritative
    // folder owner uid/gid at the privileged boundary), and per-link exports drop-in BEFORE
    // committing the database row.
    runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::EnsurePackages)
        .await
        .and_then(|resp| resp.into_packages())
        .map_err(|err| map_storage_runner_error(err, &server, step))?;
    runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::ConfigureNfsd {
            tunnel_ip: local_identity.tunnel_ip.clone(),
        })
        .await
        .and_then(|resp| resp.into_nfsd_configured())
        .map_err(|err| map_storage_runner_error(err, &server, step))?;
    let sentinel = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::EnsureSentinel {
            path: validated.canonical_path.clone(),
            require_non_root_owner: req.writable,
        })
        .await
        .and_then(|resp| resp.into_sentinel_ensured())
        .map_err(|err| map_storage_runner_error(err, &server, step))?;

    let (squash_uid, squash_gid) = resolve_export_owner_mapping(
        req.writable,
        sentinel.owner_uid,
        sentinel.owner_gid,
        &server,
        step,
    )?;

    let new_export = PeerExport {
        id: Uuid::new_v4().to_string(),
        link_id: link.id.clone(),
        path: validated.canonical_path.clone(),
        writable: req.writable,
        squash_uid,
        squash_gid,
        created_at: runtime.now().to_rfc3339(),
    };

    let prev_specs: Vec<PeerStorageExportSpec> =
        prev_exports.iter().map(export_spec_from_row).collect();
    let mut staged_specs = prev_specs.clone();
    staged_specs.push(export_spec_from_row(&new_export));

    apply_link_exports_on_runner(runtime, &link.id, &link.tunnel_ip, &staged_specs)
        .await
        .map_err(|err| map_storage_runner_error(err, &server, step))?;

    // Commit to SQLite under identity and link-state guards; roll back the runner export table if
    // the commit fails so disk and database never diverge.
    let export_to_save = new_export.clone();
    let expected_pk = link.wg_pubkey.clone();
    let expected_ip = link.tunnel_ip.clone();
    let server_c = server.clone();

    let commit_res = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting export commit transaction: {err}"),
                    )
                },
            )?;
            let current = db_peers::get_peer_link(&tx, &export_to_save.link_id)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::not_found(
                        &server_c,
                        step,
                        "Peer link disappeared before export commit",
                    )
                })?;
            if is_revoked_or_revoking_state(&current.state) {
                return Err(PeerError::link_revoked(
                    &current.name,
                    step,
                    format!("Link '{}' was revoked during export creation", current.name),
                ));
            }
            if !is_live_link_state(&current.state)
                || current.wg_pubkey != expected_pk
                || current.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    "Peer link identity or state changed during export creation",
                    "Refresh the Cluster page and retry",
                ));
            }
            let duplicate = db_peers::list_peer_exports_for_link(&tx, &export_to_save.link_id)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .into_iter()
                .any(|e| e.path == export_to_save.path);
            if duplicate {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    format!(
                        "Folder '{}' is already exported to '{}'",
                        export_to_save.path, current.name
                    ),
                    "Remove the existing export before recreating it",
                ));
            }
            db_peers::insert_peer_export(&tx, &export_to_save).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed saving peer export record: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing peer export: {err}"),
                )
            })?;
            Ok(export_to_save)
        })
        .await;

    let saved = match commit_res {
        Ok(export) => export,
        Err(commit_err) => {
            if let Err(rb_err) =
                apply_link_exports_on_runner(runtime, &link.id, &link.tunnel_ip, &prev_specs).await
            {
                tracing::error!(
                    link_id = %link.id,
                    path = %new_export.path,
                    %rb_err,
                    "Rollback of staged peer NFS export failed after SQLite error"
                );
            }
            return Err(commit_err);
        }
    };

    drop(_link_guard);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_export_created".to_string(),
            "peer_export".to_string(),
            saved.id.clone(),
            format!(
                "Exported '{}' to '{}' (writable={}, squash_uid={:?}, squash_gid={:?})",
                saved.path, link.name, saved.writable, saved.squash_uid, saved.squash_gid
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(saved)
}

pub async fn delete_peer_export(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match delete_peer_export_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(()) => (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn delete_peer_export_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let step = "delete_peer_export";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let req: DeletePeerExportReq =
        parse_bounded_json(raw_body, &server, step, "Send JSON {\"export_id\":\"...\"}")?;

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c = link_id.to_string();
    let export_id_c = req.export_id.clone();
    let server_c = server.clone();
    let (link, prev_exports, target_export) = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if !is_valid_credential_id(&export_id_c) {
                return Err(PeerError::invalid_request(
                    &server_c,
                    step,
                    "Invalid export identifier",
                    "Refresh the Cluster page and select a valid export",
                ));
            }
            let exports = db_peers::list_peer_exports_for_link(conn, &id_c).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed loading peer exports: {err}"),
                )
            })?;
            let target = exports
                .iter()
                .find(|e| e.id == export_id_c && e.link_id == id_c)
                .cloned()
                .ok_or_else(|| {
                    PeerError::not_found(&server_c, step, "Peer export was not found for this link")
                })?;
            Ok((link, exports, target))
        })
        .await?;

    let prev_specs: Vec<PeerStorageExportSpec> =
        prev_exports.iter().map(export_spec_from_row).collect();
    let remaining_specs: Vec<PeerStorageExportSpec> = prev_exports
        .iter()
        .filter(|e| e.id != target_export.id)
        .map(export_spec_from_row)
        .collect();

    apply_link_exports_on_runner(runtime, &link.id, &link.tunnel_ip, &remaining_specs)
        .await
        .map_err(|err| map_storage_runner_error(err, &server, step))?;

    let del_export_id = target_export.id.clone();
    let del_link_id = link.id.clone();
    let server_c = server.clone();
    let delete_res = runtime
        .db
        .write(&server, step, move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM peer_exports WHERE id = ?1 AND link_id = ?2",
                    params![del_export_id, del_link_id],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed deleting peer export record: {err}"),
                    )
                })?;
            if changed != 1 {
                return Err(PeerError::not_found(
                    &server_c,
                    step,
                    "Peer export was already removed",
                ));
            }
            Ok(())
        })
        .await;

    if let Err(db_err) = delete_res {
        if let Err(rb_err) =
            apply_link_exports_on_runner(runtime, &link.id, &link.tunnel_ip, &prev_specs).await
        {
            tracing::error!(
                link_id = %link.id,
                export_id = %target_export.id,
                %rb_err,
                "Rollback of peer NFS exports failed after SQLite delete error"
            );
        }
        return Err(db_err);
    }

    drop(_link_guard);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_export_deleted".to_string(),
            "peer_export".to_string(),
            target_export.id,
            format!(
                "Removed NFS export '{}' for '{}'",
                target_export.path, link.name
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Routes: GET / POST / DELETE /api/v1/admin/peers/:id/mounts
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_peer_mounts(
    State(runtime): State<Arc<PeerRuntime>>,
    Path(link_id): Path<String>,
) -> Response {
    match list_peer_mounts_inner(&runtime, &link_id).await {
        Ok(payload) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(payload),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn list_peer_mounts_inner(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<PeerMountListPayload, PeerError> {
    let server = runtime.local_server_name();
    let step = "list_peer_mounts";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let id_c = link_id.to_string();
    let server_c = server.clone();
    let (link, mounts) = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            let mounts = db_peers::list_peer_mounts_for_link(conn, &id_c).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed loading local peer mounts: {err}"),
                )
            })?;
            Ok((link, mounts))
        })
        .await?;

    match fetch_remote_export_catalog(runtime, &link, step).await {
        Ok(available_exports) => Ok(PeerMountListPayload {
            mounts,
            available_exports,
            exports_error: None,
        }),
        Err(err) => Ok(PeerMountListPayload {
            mounts,
            available_exports: Vec::new(),
            exports_error: Some(err.body()),
        }),
    }
}

pub async fn create_peer_mount(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match create_peer_mount_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(mount) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "mount": mount })),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn verify_live_wireguard_peer(
    runtime: &PeerRuntime,
    link: &PeerLink,
    step: &str,
) -> Result<(), PeerError> {
    let status = runtime
        .runner
        .dispatch(&PeerNetworkRequest::Status)
        .await
        .and_then(|resp| resp.into_status())
        .map_err(|err| map_runner_error(err, &link.name, step))?;

    let Some(peer) = status.peers.iter().find(|p| p.public_key == link.wg_pubkey) else {
        return Err(PeerError::link_down(
            &link.name,
            step,
            format!("WireGuard peer '{}' is missing from afpeer0", link.name),
        ));
    };
    if !peer.present_live {
        return Err(PeerError::link_down(
            &link.name,
            step,
            format!(
                "WireGuard peer '{}' is not active in live afpeer0 runtime",
                link.name
            ),
        ));
    }
    if let Some(age) = peer.handshake_age_secs {
        if age > WG_HANDSHAKE_STALE_SECS {
            return Err(PeerError::link_down(
                &link.name,
                step,
                format!(
                    "WireGuard handshake with '{}' is stale ({age}s > {WG_HANDSHAKE_STALE_SECS}s)",
                    link.name
                ),
            ));
        }
    }
    Ok(())
}

async fn rollback_staged_mount(runtime: &PeerRuntime, mount_path: &str, was_started: bool) {
    if was_started {
        if let Err(stop_err) = runtime
            .storage_runner
            .dispatch(&PeerStorageRequest::StopMount {
                mount_path: mount_path.to_string(),
            })
            .await
        {
            if !stop_err.is_not_found() {
                tracing::error!(
                    mount_path = %mount_path,
                    %stop_err,
                    "Rollback StopMount failed for staged peer mount"
                );
            }
        }
    }
    if let Err(rm_err) = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::RemoveMount {
            mount_path: mount_path.to_string(),
        })
        .await
    {
        if !rm_err.is_not_found() {
            tracing::error!(
                mount_path = %mount_path,
                %rm_err,
                "Rollback RemoveMount failed for staged peer mount"
            );
        }
    }
}

async fn create_peer_mount_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<PeerMount, PeerError> {
    let server = runtime.local_server_name();
    let step = "create_peer_mount";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let req: CreatePeerMountReq = parse_bounded_json(
        raw_body,
        &server,
        step,
        "Send JSON {\"export_id\":\"...\",\"writable\":false}",
    )?;

    // Phase 1 (NO link_lock held across outbound tunnel HTTP):
    // Verify link exists, fetch remote export catalog afresh over the pinned active tunnel,
    // resolve the requested `export_id`, and verify read-only/writable policy.
    let id_c = link_id.to_string();
    let server_c = server.clone();
    let link = runtime
        .db
        .read(&server, step, move |conn| {
            db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))
        })
        .await?;

    if !is_valid_credential_id(&req.export_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid remote export identifier",
            "Select an export from the peer's authorized export catalog",
        ));
    }

    let catalog = fetch_remote_export_catalog(runtime, &link, step).await?;
    let remote_export = catalog
        .into_iter()
        .find(|e| e.id == req.export_id)
        .ok_or_else(|| {
            PeerError::not_found(
                &link.name,
                step,
                format!(
                    "Export '{}' was not found in '{}' authorized export catalog",
                    req.export_id, link.name
                ),
            )
        })?;

    let remote_path = validate_remote_export_path(&remote_export.path, &link.name, step)?;
    if req.writable && !remote_export.writable {
        return Err(PeerError::PeerScopeDenied(PeerErrorDetail::new(
            &link.name,
            step,
            format!(
                "Export '{}' on '{}' is read-only and does not permit writable mounting",
                remote_path, link.name
            ),
            "Mount read-only, or opt in to writable exports on the exporting server first",
        )));
    }

    // Phase 2 (under canonical per-link lock):
    // Revalidate live link identity, confirm live WireGuard peer on afpeer0, derive unique
    // managed mount path, check duplicates, stage runner mount + start + sentinel probe, and
    // commit to SQLite with full rollback on any failure.
    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c2 = link.id.clone();
    let expected_pk = link.wg_pubkey.clone();
    let expected_ip = link.tunnel_ip.clone();
    let remote_path_c = remote_path.clone();
    let export_id_c = remote_export.id.clone();
    let server_c = server.clone();
    let (current_link, derived_mount_path) = runtime
        .db
        .read(&server, step, move |conn| {
            let current = db_peers::get_peer_link(conn, &id_c2)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::not_found(
                        &server_c,
                        step,
                        "Peer link was removed before mount creation completed",
                    )
                })?;
            if is_revoked_or_revoking_state(&current.state) {
                return Err(PeerError::link_revoked(
                    &current.name,
                    step,
                    format!("Peer link '{}' has been revoked", current.name),
                ));
            }
            if is_down_link_state(&current.state) {
                return Err(PeerError::link_down(
                    &current.name,
                    step,
                    format!("Peer link '{}' went down during mount setup", current.name),
                ));
            }
            if !is_active_link_state(&current.state)
                || current.wg_pubkey != expected_pk
                || current.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    "Peer link identity or state changed concurrently during mount setup",
                    "Refresh the Cluster page and retry mounting the export",
                ));
            }
            let existing_mounts =
                db_peers::list_peer_mounts_for_link(conn, &id_c2).map_err(|err| {
                    PeerError::internal(&server_c, step, format!("Failed listing mounts: {err}"))
                })?;
            if existing_mounts
                .iter()
                .any(|m| m.remote_path == remote_path_c)
            {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    format!(
                        "Remote export '{}' from '{}' is already mounted",
                        remote_path_c, current.name
                    ),
                    "Remove the existing mount before recreating it",
                ));
            }
            let mount_path = derive_unique_mount_path_for_export(
                conn,
                &current,
                &remote_path_c,
                &export_id_c,
                &server_c,
                step,
            )?;
            Ok((current, mount_path))
        })
        .await?;

    verify_live_wireguard_peer(runtime, &current_link, step).await?;

    runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::EnsurePackages)
        .await
        .and_then(|resp| resp.into_packages())
        .map_err(|err| map_storage_runner_error(err, &server, step))?;

    let written = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::WriteMount {
            mount_path: derived_mount_path.clone(),
            tunnel_ip: current_link.tunnel_ip.clone(),
            remote_path: remote_path.clone(),
            writable: req.writable,
        })
        .await
        .and_then(|resp| resp.into_mount_written())
        .map_err(|err| map_storage_runner_error(err, &server, step))?;

    if validate_peer_mount_path(&written.mount_path).is_err()
        || !is_managed_peer_mount_unit(&written.unit_name)
    {
        rollback_staged_mount(runtime, &derived_mount_path, false).await;
        return Err(PeerError::internal(
            &server,
            step,
            "Runner returned an invalid managed peer mount path or unit name",
        ));
    }

    if let Err(err) = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::StartMount {
            mount_path: written.mount_path.clone(),
        })
        .await
        .and_then(|resp| resp.into_mount_state())
    {
        rollback_staged_mount(runtime, &written.mount_path, false).await;
        return Err(map_storage_runner_error(err, &current_link.name, step));
    }

    if let Err(sentinel_err) = probe_mount_sentinel_via_runner(runtime, &written.mount_path).await {
        rollback_staged_mount(runtime, &written.mount_path, true).await;
        return Err(PeerError::link_down(
            &current_link.name,
            step,
            format!(
                "Mounted peer export '{}' failed sentinel verification: {sentinel_err}",
                remote_path
            ),
        ));
    }

    let new_mount = PeerMount {
        id: Uuid::new_v4().to_string(),
        link_id: current_link.id.clone(),
        remote_path: remote_path.clone(),
        mount_path: written.mount_path.clone(),
        unit_name: written.unit_name.clone(),
        writable: req.writable,
        purpose: MOUNT_PURPOSE_MEDIA.to_string(),
        state: MOUNT_STATE_MOUNTED.to_string(),
        last_error: None,
    };

    let mount_to_save = new_mount.clone();
    let expected_pk = current_link.wg_pubkey.clone();
    let expected_ip = current_link.tunnel_ip.clone();
    let server_c = server.clone();
    let commit_res = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting mount commit transaction: {err}"),
                    )
                },
            )?;
            let current = db_peers::get_peer_link(&tx, &mount_to_save.link_id)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::not_found(
                        &server_c,
                        step,
                        "Peer link disappeared before mount commit",
                    )
                })?;
            if is_revoked_or_revoking_state(&current.state) {
                return Err(PeerError::link_revoked(
                    &current.name,
                    step,
                    format!(
                        "Peer link '{}' was revoked during mount setup",
                        current.name
                    ),
                ));
            }
            if !is_active_link_state(&current.state)
                || current.wg_pubkey != expected_pk
                || current.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    "Peer link identity or state changed before mount commit",
                    "Refresh the Cluster page and retry",
                ));
            }
            if db_peers::get_peer_mount_by_mount_path(&tx, &mount_to_save.mount_path)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .is_some()
            {
                return Err(PeerError::conflict(
                    &current.name,
                    step,
                    format!(
                        "Mount path '{}' is already in use",
                        mount_to_save.mount_path
                    ),
                    "Remove the conflicting mount before retrying",
                ));
            }
            db_peers::insert_peer_mount(&tx, &mount_to_save).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed saving peer mount record: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing peer mount: {err}"),
                )
            })?;
            Ok(mount_to_save)
        })
        .await;

    let saved = match commit_res {
        Ok(mount) => mount,
        Err(commit_err) => {
            rollback_staged_mount(runtime, &written.mount_path, true).await;
            return Err(commit_err);
        }
    };

    runtime.mount_health.record_success(&saved.id);
    drop(_link_guard);

    // Best-effort Plex media-app safety hook (dormant unless Plex is configured & enabled).
    apply_plex_peer_mount_safety_best_effort(runtime).await;

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_mount_created".to_string(),
            "peer_mount".to_string(),
            saved.id.clone(),
            format!(
                "Mounted '{}:{}' from '{}' at '{}' (writable={}, unit={})",
                current_link.tunnel_ip,
                saved.remote_path,
                current_link.name,
                saved.mount_path,
                saved.writable,
                saved.unit_name
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(saved)
}

pub async fn delete_peer_mount(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match delete_peer_mount_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(()) => (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn delete_peer_mount_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let step = "delete_peer_mount";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let req: DeletePeerMountReq =
        parse_bounded_json(raw_body, &server, step, "Send JSON {\"mount_id\":\"...\"}")?;

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c = link_id.to_string();
    let mount_id_c = req.mount_id.clone();
    let server_c = server.clone();
    let (link, mount) = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if !is_valid_credential_id(&mount_id_c) {
                return Err(PeerError::invalid_request(
                    &server_c,
                    step,
                    "Invalid mount identifier",
                    "Refresh the Cluster page and select a valid mount",
                ));
            }
            let mount = db_peers::get_peer_mount(conn, &mount_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .filter(|m| m.link_id == id_c)
                .ok_or_else(|| {
                    PeerError::not_found(&server_c, step, "Peer mount was not found for this link")
                })?;
            Ok((link, mount))
        })
        .await?;

    match runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::StopMount {
            mount_path: mount.mount_path.clone(),
        })
        .await
    {
        Ok(_) => {}
        Err(err) if err.is_not_found() => {}
        Err(err) => return Err(map_storage_runner_error(err, &server, step)),
    }
    match runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::RemoveMount {
            mount_path: mount.mount_path.clone(),
        })
        .await
    {
        Ok(_) => {}
        Err(err) if err.is_not_found() => {}
        Err(err) => return Err(map_storage_runner_error(err, &server, step)),
    }

    let del_mount_id = mount.id.clone();
    let del_link_id = link.id.clone();
    let server_c = server.clone();
    let delete_res = runtime
        .db
        .write(&server, step, move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM peer_mounts WHERE id = ?1 AND link_id = ?2",
                    params![del_mount_id, del_link_id],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed deleting peer mount record: {err}"),
                    )
                })?;
            if changed != 1 {
                return Err(PeerError::not_found(
                    &server_c,
                    step,
                    "Peer mount was already removed",
                ));
            }
            Ok(())
        })
        .await;

    if let Err(db_err) = delete_res {
        let upd_id = mount.id.clone();
        let upd_link = link.id.clone();
        let _ = runtime
            .db
            .write(&server, step, move |conn| {
                let _ = conn.execute(
                    "UPDATE peer_mounts SET state = ?3, last_error = ?4 WHERE id = ?1 AND link_id = ?2",
                    params![
                        upd_id,
                        upd_link,
                        MOUNT_STATE_STOPPED,
                        "Mount unit removed; database delete failed and must be retried",
                    ],
                );
                Ok(())
            })
            .await;
        return Err(db_err);
    }

    runtime.mount_health.clear(&mount.id);
    drop(_link_guard);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_mount_deleted".to_string(),
            "peer_mount".to_string(),
            mount.id,
            format!(
                "Removed peer NFS mount '{}' (remote '{}', unit={}) for '{}'",
                mount.mount_path, mount.remote_path, mount.unit_name, link.name
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Loop Gating: WireGuard Removal, Consecutive Sentinel Failures & Recovery
// ─────────────────────────────────────────────────────────────────────────────

async fn persist_mount_state(
    runtime: &PeerRuntime,
    mount_id: &str,
    link_id: &str,
    new_state: &str,
    last_error: Option<String>,
) -> bool {
    let server = runtime.local_server_name();
    let mid = mount_id.to_string();
    let lid = link_id.to_string();
    let st = new_state.to_string();
    runtime
        .db
        .write(&server, "health_mount_state", move |conn| {
            let changed = conn
                .execute(
                    "UPDATE peer_mounts SET state = ?3, last_error = ?4 \
                     WHERE id = ?1 AND link_id = ?2",
                    params![mid, lid, st, last_error],
                )
                .map_err(|err| {
                    PeerError::internal("local", "health_mount_state", err.to_string())
                })?;
            Ok(changed == 1)
        })
        .await
        .unwrap_or(false)
}

async fn load_live_mounts_for_link(runtime: &PeerRuntime, link_id: &str) -> Vec<PeerMount> {
    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    runtime
        .db
        .read(&server, "health_mount_load", move |conn| {
            Ok(db_peers::list_peer_mounts_for_link(conn, &lid).unwrap_or_default())
        })
        .await
        .unwrap_or_default()
}

async fn stop_mount_verified(
    runtime: &PeerRuntime,
    mount: &PeerMount,
) -> Result<(), PeerStorageError> {
    let state = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::StopMount {
            mount_path: mount.mount_path.clone(),
        })
        .await?
        .into_mount_state()?;
    if state.active {
        return Err(PeerStorageError::Runtime(
            "Runner still reports the peer mount as active".to_string(),
        ));
    }
    Ok(())
}

async fn stop_unverified_mount_locked(runtime: &PeerRuntime, mount: &PeerMount, reason: &str) {
    let (state, message) = match stop_mount_verified(runtime, mount).await {
        Err(err) if !err.is_not_found() => (
            MOUNT_STATE_ERROR,
            format!("Failed stopping mount after {reason}: {err}"),
        ),
        _ => {
            runtime.mount_health.clear(&mount.id);
            (MOUNT_STATE_STOPPED, format!("Stopped: {reason}"))
        }
    };
    let _ = persist_mount_state(runtime, &mount.id, &mount.link_id, state, Some(message)).await;
}

/// Immediately stops every active mount belonging to `link` when WireGuard peer removal or a
/// stale WireGuard handshake (> 180s) is detected on the very first health tick.
pub(crate) async fn gate_mounts_for_link_down_immediate(
    runtime: &PeerRuntime,
    link: &PeerLink,
    reason: &str,
) {
    // Fast-path dormancy check: avoid acquiring locks or calling runner when no mounts exist.
    if load_live_mounts_for_link(runtime, &link.id)
        .await
        .is_empty()
    {
        return;
    }

    let Ok(_link_guard) = runtime.lock_link(&link.id, "health_mount_gate").await else {
        return;
    };

    let mounts = load_live_mounts_for_link(runtime, &link.id).await;
    if mounts.is_empty() {
        return;
    }

    let formatted_error = format!("Stopped: link down ({reason})");
    for mount in mounts {
        if mount.state == MOUNT_STATE_STOPPED {
            runtime.mount_health.clear(&mount.id);
            continue;
        }
        let was_mounted = mount.state == MOUNT_STATE_MOUNTED;
        match stop_mount_verified(runtime, &mount).await {
            Ok(()) => {
                runtime.mount_health.clear(&mount.id);
                let updated = persist_mount_state(
                    runtime,
                    &mount.id,
                    &link.id,
                    MOUNT_STATE_STOPPED,
                    Some(formatted_error.clone()),
                )
                .await;
                if updated && was_mounted {
                    runtime
                        .db
                        .emit_notification(
                            "warning",
                            format!("Peer mount stopped: {}", link.name),
                            format!("{} — {}", mount.mount_path, formatted_error),
                        )
                        .await;
                    runtime
                        .db
                        .record_audit(
                            0,
                            "peer-health".to_string(),
                            "peer_mount_stopped".to_string(),
                            "peer_mount".to_string(),
                            mount.id.clone(),
                            format!(
                                "Stopped mount '{}' for '{}' ({})",
                                mount.mount_path, link.name, formatted_error
                            ),
                            link.tunnel_ip.clone(),
                            String::new(),
                        )
                        .await;
                }
            }
            Err(err) if err.is_not_found() => {
                runtime.mount_health.clear(&mount.id);
                let _ = persist_mount_state(
                    runtime,
                    &mount.id,
                    &link.id,
                    MOUNT_STATE_STOPPED,
                    Some(formatted_error.clone()),
                )
                .await;
            }
            Err(err) => {
                tracing::warn!(
                    link_id = %link.id,
                    mount_id = %mount.id,
                    %err,
                    "Failed stopping peer mount unit on WireGuard link-down gate"
                );
                let _ = persist_mount_state(
                    runtime,
                    &mount.id,
                    &link.id,
                    MOUNT_STATE_ERROR,
                    Some(format!("Failed stopping mount after link down: {err}")),
                )
                .await;
            }
        }
    }
}

/// Probes currently mounted peer mounts when the WireGuard peer is still present/fresh (or status
/// unavailable) while tunnel `/health` failed. Two consecutive sentinel failures stop the mount,
/// and unconfirmed stops are retried on the next tick.
pub(crate) async fn probe_mounts_while_link_degraded(
    runtime: &PeerRuntime,
    link: &PeerLink,
    link_reason: &str,
) {
    if load_live_mounts_for_link(runtime, &link.id)
        .await
        .is_empty()
    {
        return;
    }

    let Ok(_link_guard) = runtime.lock_link(&link.id, "health_mount_probe").await else {
        return;
    };

    let mounts = load_live_mounts_for_link(runtime, &link.id).await;
    for mount in mounts {
        match mount.state.as_str() {
            MOUNT_STATE_MOUNTED => {
                probe_mounted_mount_locked(runtime, link, &mount, Some(link_reason)).await;
            }
            MOUNT_STATE_ERROR => {
                let reason = format!("link degradation ({link_reason})");
                stop_unverified_mount_locked(runtime, &mount, &reason).await;
            }
            _ => {}
        }
    }
}

/// Reconciles all mounts for a healthy link (WireGuard live + fresh handshake + tunnel `/health`
/// OK): probes mounted mounts (stopping after 2 consecutive sentinel failures) and recovers
/// stopped mounts. A mount in error must stop successfully before the next recovery attempt.
pub(crate) async fn reconcile_mounts_for_healthy_link(runtime: &PeerRuntime, link: &PeerLink) {
    if load_live_mounts_for_link(runtime, &link.id)
        .await
        .is_empty()
    {
        return;
    }

    let Ok(_link_guard) = runtime.lock_link(&link.id, "health_mount_reconcile").await else {
        return;
    };

    // Re-verify link is still active inside the lock so concurrent revocation is never raced.
    let lid = link.id.clone();
    let expected_pk = link.wg_pubkey.clone();
    let still_active = runtime
        .db
        .read(
            &runtime.local_server_name(),
            "health_mount_reconcile",
            move |conn| {
                Ok(db_peers::get_peer_link(conn, &lid)
                    .ok()
                    .flatten()
                    .is_some_and(|l| l.wg_pubkey == expected_pk && is_active_link_state(&l.state)))
            },
        )
        .await
        .unwrap_or(false);
    if !still_active {
        return;
    }

    let mounts = load_live_mounts_for_link(runtime, &link.id).await;
    for mount in mounts {
        match mount.state.as_str() {
            MOUNT_STATE_MOUNTED => {
                probe_mounted_mount_locked(runtime, link, &mount, None).await;
            }
            MOUNT_STATE_STOPPED => {
                recover_stopped_mount_locked(runtime, link, &mount).await;
            }
            MOUNT_STATE_ERROR => {
                stop_unverified_mount_locked(runtime, &mount, "an unconfirmed stop").await;
            }
            _ => {}
        }
    }
}

async fn probe_mounted_mount_locked(
    runtime: &PeerRuntime,
    link: &PeerLink,
    mount: &PeerMount,
    link_reason: Option<&str>,
) {
    match probe_mount_sentinel_via_runner(runtime, &mount.mount_path).await {
        Ok(()) => {
            runtime.mount_health.record_success(&mount.id);
            if mount.last_error.is_some() {
                let _ =
                    persist_mount_state(runtime, &mount.id, &link.id, MOUNT_STATE_MOUNTED, None)
                        .await;
            }
        }
        Err(probe_err) => {
            let failures = runtime.mount_health.record_failure(&mount.id);
            if failures < SENTINEL_FAILURE_THRESHOLD {
                let warn_msg = format!(
                    "Sentinel check failed ({failures}/{SENTINEL_FAILURE_THRESHOLD}): {probe_err}"
                );
                tracing::warn!(
                    link_id = %link.id,
                    mount_id = %mount.id,
                    failures,
                    %probe_err,
                    "Transient peer mount sentinel failure; waiting for second consecutive failure before stopping"
                );
                let _ = persist_mount_state(
                    runtime,
                    &mount.id,
                    &link.id,
                    MOUNT_STATE_MOUNTED,
                    Some(warn_msg),
                )
                .await;
                return;
            }

            let stop_reason = match link_reason {
                Some(lr) => format!(
                    "Stopped: link down ({lr}; sentinel failed {failures} consecutive times: {probe_err})"
                ),
                None => format!(
                    "Stopped: sentinel probe failed {failures} consecutive times ({probe_err})"
                ),
            };
            match stop_mount_verified(runtime, mount).await {
                Ok(()) => {
                    runtime.mount_health.clear(&mount.id);
                    let updated = persist_mount_state(
                        runtime,
                        &mount.id,
                        &link.id,
                        MOUNT_STATE_STOPPED,
                        Some(stop_reason.clone()),
                    )
                    .await;
                    if updated {
                        runtime
                            .db
                            .emit_notification(
                                "warning",
                                format!("Peer mount stopped: {}", link.name),
                                format!("{} — {}", mount.mount_path, stop_reason),
                            )
                            .await;
                        runtime
                            .db
                            .record_audit(
                                0,
                                "peer-health".to_string(),
                                "peer_mount_stopped".to_string(),
                                "peer_mount".to_string(),
                                mount.id.clone(),
                                format!(
                                    "Stopped mount '{}' for '{}' ({stop_reason})",
                                    mount.mount_path, link.name
                                ),
                                link.tunnel_ip.clone(),
                                String::new(),
                            )
                            .await;
                    }
                }
                Err(err) if err.is_not_found() => {
                    runtime.mount_health.clear(&mount.id);
                    let _ = persist_mount_state(
                        runtime,
                        &mount.id,
                        &link.id,
                        MOUNT_STATE_STOPPED,
                        Some(stop_reason),
                    )
                    .await;
                }
                Err(err) => {
                    tracing::error!(
                        link_id = %link.id,
                        mount_id = %mount.id,
                        %err,
                        "Failed stopping peer mount unit after consecutive sentinel failures"
                    );
                    let _ = persist_mount_state(
                        runtime,
                        &mount.id,
                        &link.id,
                        MOUNT_STATE_ERROR,
                        Some(format!(
                            "Sentinel failed {failures} times; failed to stop mount: {err}"
                        )),
                    )
                    .await;
                }
            }
        }
    }
}

async fn recover_stopped_mount_locked(runtime: &PeerRuntime, link: &PeerLink, mount: &PeerMount) {
    if let Err(err) = runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::StartMount {
            mount_path: mount.mount_path.clone(),
        })
        .await
        .and_then(|resp| resp.into_mount_state())
        .and_then(|state| {
            if state.active {
                Ok(())
            } else {
                Err(PeerStorageError::Runtime(
                    "Runner did not confirm the peer mount was active".to_string(),
                ))
            }
        })
    {
        let reason = format!("recovery start failed ({err})");
        stop_unverified_mount_locked(runtime, mount, &reason).await;
        return;
    }

    match probe_mount_sentinel_via_runner(runtime, &mount.mount_path).await {
        Ok(()) => {
            runtime.mount_health.record_success(&mount.id);
            let updated =
                persist_mount_state(runtime, &mount.id, &link.id, MOUNT_STATE_MOUNTED, None).await;
            if updated {
                runtime
                    .db
                    .emit_notification(
                        "info",
                        format!("Peer mount recovered: {}", link.name),
                        format!("{} is mounted and healthy again.", mount.mount_path),
                    )
                    .await;
                runtime
                    .db
                    .record_audit(
                        0,
                        "peer-health".to_string(),
                        "peer_mount_recovered".to_string(),
                        "peer_mount".to_string(),
                        mount.id.clone(),
                        format!("Recovered mount '{}' for '{}'", mount.mount_path, link.name),
                        link.tunnel_ip.clone(),
                        String::new(),
                    )
                    .await;
            }
        }
        Err(probe_err) => {
            // Never leave an unverified or empty mount folder exposed to media apps after a failed
            // recovery attempt; immediately re-stop the mount unit.
            let reason = format!("recovery sentinel check failed ({probe_err})");
            stop_unverified_mount_locked(runtime, mount, &reason).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoped Storage Cleanup on Link Revocation / Deletion
// ─────────────────────────────────────────────────────────────────────────────

/// Marks all `peer_mounts` rows for `link_id` as `stopped` inside the revocation transaction so
/// status reflects revocation immediately even before privileged cleanup finishes.
pub(crate) fn mark_link_mounts_stopped_for_revocation_in_tx(
    tx: &rusqlite::Connection,
    link_id: &str,
    peer_name: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    tx.execute(
        "UPDATE peer_mounts SET state = ?2, last_error = ?3 WHERE link_id = ?1",
        params![
            link_id,
            MOUNT_STATE_STOPPED,
            format!("Stopped: link revoked ({peer_name})"),
        ],
    )
    .map_err(|err| {
        PeerError::internal(
            server,
            step,
            format!("Failed marking peer mounts stopped during revocation: {err}"),
        )
    })?;
    Ok(())
}

/// Cleans up all local mounts and NFS exports strictly scoped to `link_id` under `link_lock`.
///
/// - Completely dormant (zero storage runner calls) when `link_id` owns no mounts or exports.
/// - Attempts every mount and export cleanup before returning the first transient error so
///   partial progress is persisted and durable retries finish remaining items cleanly.
pub(crate) async fn cleanup_revoked_link_storage_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_tunnel_ip: &str,
    peer_name: &str,
    step: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    let (mounts, exports) = runtime
        .db
        .read(&server, step, move |conn| {
            let mounts = db_peers::list_peer_mounts_for_link(conn, &lid).unwrap_or_default();
            let exports = db_peers::list_peer_exports_for_link(conn, &lid).unwrap_or_default();
            Ok((mounts, exports))
        })
        .await?;

    if mounts.is_empty() && exports.is_empty() {
        return Ok(());
    }

    let mut first_error: Option<PeerError> = None;

    for mount in mounts {
        if mount.link_id != link_id {
            continue;
        }
        if let Err(err) = runtime
            .storage_runner
            .dispatch(&PeerStorageRequest::StopMount {
                mount_path: mount.mount_path.clone(),
            })
            .await
        {
            if !err.is_not_found() {
                tracing::warn!(
                    link_id = %link_id,
                    mount_id = %mount.id,
                    %err,
                    "Transient error stopping mount during link revocation cleanup"
                );
                if first_error.is_none() {
                    first_error = Some(map_storage_runner_error(err, peer_name, step));
                }
                continue;
            }
        }

        if let Err(err) = runtime
            .storage_runner
            .dispatch(&PeerStorageRequest::RemoveMount {
                mount_path: mount.mount_path.clone(),
            })
            .await
        {
            if !err.is_not_found() {
                tracing::warn!(
                    link_id = %link_id,
                    mount_id = %mount.id,
                    %err,
                    "Transient error removing mount unit during link revocation cleanup"
                );
                if first_error.is_none() {
                    first_error = Some(map_storage_runner_error(err, peer_name, step));
                }
                continue;
            }
        }

        runtime.mount_health.clear(&mount.id);
        let del_mid = mount.id.clone();
        let del_lid = link_id.to_string();
        if let Err(err) = runtime
            .db
            .write(&server, step, move |conn| {
                conn.execute(
                    "DELETE FROM peer_mounts WHERE id = ?1 AND link_id = ?2",
                    params![del_mid, del_lid],
                )
                .map_err(|e| PeerError::internal("local", "revocation_cleanup", e.to_string()))?;
                Ok(())
            })
            .await
        {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    if !exports.is_empty() {
        match apply_link_exports_on_runner(runtime, link_id, peer_tunnel_ip, &[]).await {
            Ok(()) => {
                let del_lid = link_id.to_string();
                if let Err(err) = runtime
                    .db
                    .write(&server, step, move |conn| {
                        conn.execute(
                            "DELETE FROM peer_exports WHERE link_id = ?1",
                            params![del_lid],
                        )
                        .map_err(|e| {
                            PeerError::internal("local", "revocation_cleanup", e.to_string())
                        })?;
                        Ok(())
                    })
                    .await
                {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
            Err(err) if err.is_not_found() => {
                let del_lid = link_id.to_string();
                let _ = runtime
                    .db
                    .write(&server, step, move |conn| {
                        let _ = conn.execute(
                            "DELETE FROM peer_exports WHERE link_id = ?1",
                            params![del_lid],
                        );
                        Ok(())
                    })
                    .await;
            }
            Err(err) => {
                tracing::warn!(
                    link_id = %link_id,
                    %err,
                    "Transient error removing NFS exports during link revocation cleanup"
                );
                if first_error.is_none() {
                    first_error = Some(map_storage_runner_error(err, peer_name, step));
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Media-App Safety Hooks (Library Subfolder Enforcement & Plex Empty-Trash Guard)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the recommended interior library path below a peer mount location (never the mount root).
#[allow(dead_code)]
pub fn recommended_library_path(mount_path: &str) -> String {
    format!("{}/library", mount_path.trim_end_matches('/'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaLibraryPathError {
    MountRootDisallowed(String),
    MountUnavailable(String),
}

impl std::fmt::Display for MediaLibraryPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MountRootDisallowed(msg) | Self::MountUnavailable(msg) => f.write_str(msg),
        }
    }
}

/// Validates a media app library or scan path against peer-mount safety rules:
/// - Ordinary local paths outside `/mnt/af-peers` pass untouched.
/// - Paths under `/mnt/af-peers` MUST point at an interior subfolder strictly below the mount root
///   (`/mnt/af-peers/<link>/<export>/<subfolder...>`) so the library path vanishes when unmounted.
/// - The enclosing peer mount root MUST have a present regular `.af-peer-sentinel` file so an
///   unmounted mount directory is never scanned as an empty library.
pub fn validate_media_library_path(path: &StdPath) -> Result<(), MediaLibraryPathError> {
    validate_media_library_path_with_base(path, StdPath::new(PEER_MOUNTS_BASE_DIR))
}

pub(crate) fn validate_media_library_path_with_base(
    path: &StdPath,
    peer_mounts_base: &StdPath,
) -> Result<(), MediaLibraryPathError> {
    let base_canon =
        fs::canonicalize(peer_mounts_base).unwrap_or_else(|_| peer_mounts_base.to_path_buf());
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    let rel = if let Ok(r) = candidate.strip_prefix(&base_canon) {
        r
    } else if let Ok(r) = path.strip_prefix(peer_mounts_base) {
        r
    } else {
        return Ok(());
    };

    let normal_parts: Vec<_> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();

    if normal_parts.len() < 3 {
        let mount_hint = if normal_parts.len() == 2 {
            format!(
                "{}/{}/{}/library",
                peer_mounts_base.display(),
                normal_parts[0].to_string_lossy(),
                normal_parts[1].to_string_lossy(),
            )
        } else {
            format!("{}/<peer>/<export>/library", peer_mounts_base.display())
        };
        return Err(MediaLibraryPathError::MountRootDisallowed(format!(
            "Media libraries must point to an interior subfolder below the peer mount root (for example {mount_hint}), never the mount root itself"
        )));
    }

    let mount_root = base_canon.join(normal_parts[0]).join(normal_parts[1]);
    let sentinel = mount_root.join(PEER_SENTINEL_FILE_NAME);
    let sentinel_ok = fs::symlink_metadata(&sentinel)
        .map(|m| !m.file_type().is_symlink() && m.is_file())
        .unwrap_or(false);
    if !sentinel_ok {
        return Err(MediaLibraryPathError::MountUnavailable(format!(
            "Peer mount '{}' is not currently mounted (missing {PEER_SENTINEL_FILE_NAME}); refusing media library access",
            mount_root.display()
        )));
    }

    Ok(())
}

/// Outcome of inspecting a configured Plex Media Server for peer-mounted libraries and applying
/// the automatic empty-trash safeguard (`autoEmptyTrash=0`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PlexPeerMountSafetyOutcome {
    pub(crate) peer_libraries: Vec<String>,
    pub(crate) mount_root_warnings: Vec<String>,
    pub(crate) auto_empty_trash_disabled: bool,
}

fn is_path_under_peer_mounts_base(raw_path: &str, peer_mounts_base: &str) -> bool {
    let base = peer_mounts_base.trim_end_matches('/');
    let trimmed = raw_path.trim().trim_end_matches('/');
    trimmed == base || trimmed.starts_with(&format!("{base}/"))
}

fn is_path_at_or_above_mount_root(raw_path: &str, peer_mounts_base: &str) -> bool {
    let base = StdPath::new(peer_mounts_base);
    let Ok(rel) = StdPath::new(raw_path.trim()).strip_prefix(base) else {
        return false;
    };
    let depth = rel
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    depth < 3
}

/// Inspects Plex `/library/sections` and, whenever any library references a path under
/// `peer_mounts_base`, disables Plex's `"Empty trash automatically after every scan"` preference
/// (`PUT /:/prefs?autoEmptyTrash=0`) so transient peer outages never wipe Plex library items.
pub(crate) async fn enforce_plex_peer_mount_safety_at_base(
    server_url: &str,
    plex_token: &str,
    expected_server_id: &str,
    peer_mounts_base: &str,
) -> Result<PlexPeerMountSafetyOutcome, String> {
    let clean_url = af_services::validate_server_url(server_url)
        .map_err(|err| format!("Invalid Plex server URL: {err}"))?;
    if plex_token.trim().is_empty() {
        return Err("Plex token is not configured".to_string());
    }
    let mut token = header::HeaderValue::from_str(plex_token.trim())
        .map_err(|_| "Plex token is not a valid HTTP header".to_string())?;
    token.set_sensitive(true);

    let client = af_services::streaming_http_client_builder()
        .connect_timeout(PLEX_SAFETY_TIMEOUT)
        .timeout(PLEX_SAFETY_TIMEOUT)
        .build()
        .map_err(|err| format!("Failed building Plex safety HTTP client: {err}"))?;
    let plex_request = |method, path: &str| {
        client
            .request(method, format!("{clean_url}{path}"))
            .header(header::ACCEPT, "application/json")
            .header("X-Plex-Client-Identifier", "aetherflow-nexus")
            .header("X-Plex-Product", "AetherFlow")
            .header("X-Plex-Token", token.clone())
    };

    let expected_server_id = expected_server_id.trim();
    if !expected_server_id.is_empty() {
        let identity = plex_request(reqwest::Method::GET, "/identity")
            .send()
            .await
            .map_err(|_| "Failed checking the pinned Plex identity".to_string())?;
        if !identity.status().is_success() {
            return Err(format!(
                "Plex identity check returned HTTP {}",
                identity.status().as_u16()
            ));
        }
        let body = super::read_bounded_reqwest_body(identity, PLEX_SAFETY_MAX_BODY_BYTES).await?;
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| "Plex returned an invalid identity response".to_string())?;
        let container = parsed.get("MediaContainer").unwrap_or(&parsed);
        if !container
            .get("machineIdentifier")
            .and_then(|id| id.as_str())
            .is_some_and(|id| id.trim().eq_ignore_ascii_case(expected_server_id))
        {
            return Err(
                "Plex server identity changed; explicitly reconfigure the connection".to_string(),
            );
        }
    }

    let resp = plex_request(reqwest::Method::GET, "/library/sections")
        .send()
        .await
        .map_err(|err| redact_sensitive_text(&format!("Failed querying Plex libraries: {err}")))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Plex /library/sections returned HTTP {}",
            resp.status().as_u16()
        ));
    }

    let body = super::read_bounded_reqwest_body(resp, PLEX_SAFETY_MAX_BODY_BYTES).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|err| format!("Plex /library/sections returned invalid JSON: {err}"))?;

    let mut outcome = PlexPeerMountSafetyOutcome::default();
    let mc = parsed.get("MediaContainer").unwrap_or(&parsed);
    if let Some(dirs) = mc.get("Directory").and_then(|d| d.as_array()) {
        for dir in dirs {
            if let Some(locs) = dir.get("Location").and_then(|l| l.as_array()) {
                for loc in locs {
                    if let Some(loc_path) = loc.get("path").and_then(|p| p.as_str()) {
                        if is_path_under_peer_mounts_base(loc_path, peer_mounts_base) {
                            outcome.peer_libraries.push(loc_path.to_string());
                            if is_path_at_or_above_mount_root(loc_path, peer_mounts_base) {
                                outcome.mount_root_warnings.push(loc_path.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    if outcome.peer_libraries.is_empty() {
        return Ok(outcome);
    }

    let put_resp = plex_request(reqwest::Method::PUT, "/:/prefs?autoEmptyTrash=0")
        .send()
        .await
        .map_err(|err| {
            redact_sensitive_text(&format!(
                "Failed disabling Plex autoEmptyTrash preference: {err}"
            ))
        })?;

    if !put_resp.status().is_success() {
        return Err(format!(
            "Plex /:/prefs?autoEmptyTrash=0 returned HTTP {}",
            put_resp.status().as_u16()
        ));
    }
    outcome.auto_empty_trash_disabled = true;
    Ok(outcome)
}

struct PlexSafetyConfig {
    url: String,
    token: String,
    server_id: String,
}

impl PlexSafetyConfig {
    async fn enforce(&self) -> Result<PlexPeerMountSafetyOutcome, String> {
        enforce_plex_peer_mount_safety_at_base(
            &self.url,
            &self.token,
            &self.server_id,
            PEER_MOUNTS_BASE_DIR,
        )
        .await
    }
}

fn load_enabled_plex_server_from_conn(conn: &rusqlite::Connection) -> Option<PlexSafetyConfig> {
    if !crate::auth::table_exists(conn, "streaming_servers").unwrap_or(false) {
        return None;
    }
    let (url, stored_key, server_id): (String, String, String) = conn
        .query_row(
            "SELECT COALESCE(url, ''), COALESCE(api_key, ''), COALESCE(server_id, '') \
             FROM streaming_servers WHERE provider = 'plex' AND enabled = 1 LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    if url.trim().is_empty() || stored_key.trim().is_empty() {
        return None;
    }
    let token = if stored_key.starts_with("enc:v1:") {
        af_db::decrypt_key(&stored_key).ok()?
    } else {
        stored_key
    };
    if token.trim().is_empty() || token.starts_with("enc:v1:") {
        return None;
    }
    Some(PlexSafetyConfig {
        url: url.trim().to_string(),
        token: token.trim().to_string(),
        server_id,
    })
}

/// Best-effort Plex empty-trash safety hook triggered when a peer media mount is created.
/// Completely dormant (zero HTTP I/O) when Plex is not configured/enabled.
pub(crate) async fn apply_plex_peer_mount_safety_best_effort(runtime: &PeerRuntime) {
    let plex_cfg = runtime
        .db
        .read(&runtime.local_server_name(), "plex_peer_safety", |conn| {
            Ok(load_enabled_plex_server_from_conn(conn))
        })
        .await
        .ok()
        .flatten();

    let Some(plex) = plex_cfg else {
        return;
    };

    match plex.enforce().await {
        Ok(outcome) if outcome.auto_empty_trash_disabled => {
            tracing::info!(
                libraries = outcome.peer_libraries.len(),
                mount_root_warnings = outcome.mount_root_warnings.len(),
                "Disabled Plex autoEmptyTrash for peer-mounted libraries"
            );
            if !outcome.mount_root_warnings.is_empty() {
                runtime
                    .db
                    .emit_notification(
                        "warning",
                        "Plex library points at peer mount root".to_string(),
                        format!(
                            "Move Plex libraries ({}) to an interior subfolder such as /mnt/af-peers/<peer>/<export>/library",
                            outcome.mount_root_warnings.join(", ")
                        ),
                    )
                    .await;
            }
            runtime
                .db
                .record_audit(
                    0,
                    "peer-storage".to_string(),
                    "plex_peer_mount_safety_applied".to_string(),
                    "streaming_server".to_string(),
                    "plex".to_string(),
                    format!(
                        "Disabled Plex autoEmptyTrash for {} peer-mounted library location(s)",
                        outcome.peer_libraries.len()
                    ),
                    String::new(),
                    String::new(),
                )
                .await;
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(%err, "Best-effort Plex peer-mount safety check could not complete");
        }
    }
}

/// Best-effort Plex safety hook called when an admin configures Plex in `routes/streaming.rs`.
/// Completely dormant (zero HTTP I/O) when no `peer_mounts` rows exist.
pub(crate) async fn apply_plex_safety_on_streaming_save_if_peer_mounts_exist() {
    let maybe_plex = tokio::task::spawn_blocking(|| -> Option<PlexSafetyConfig> {
        let conn = af_db::get_read_conn().ok()?;
        let has_mounts = !db_peers::list_peer_mounts(&conn).ok()?.is_empty();
        if !has_mounts {
            return None;
        }
        load_enabled_plex_server_from_conn(&conn)
    })
    .await
    .ok()
    .flatten();

    let Some(plex) = maybe_plex else {
        return;
    };

    if let Err(err) = plex.enforce().await {
        tracing::warn!(%err, "Best-effort Plex peer-mount safety sync failed after Plex configuration save");
    }
}
