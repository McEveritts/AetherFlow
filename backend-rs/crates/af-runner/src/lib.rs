use af_models::{
    AppMetaRunnerRequest, BackupRunnerRequest, BackupRunnerResponse, NetworkRunnerRequest, Package,
    PackageAutomation, PackageLifecycleSnapshotRequest, PackageRunnerRequest,
    PluginRunnerStartRequest, PluginRunnerStatusRequest, PluginRunnerStatusResponse,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest, QuotaRunnerRequest,
    RunnerApacheVhostRequest, RunnerResponse, SandboxRunnerRequest, SelfUpdateJobStatus,
    SelfUpdateRequest, SelfUpdateStatusRequest, SystemctlRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerPeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostsUpdateRequest {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub domain: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_domains: Option<Vec<String>>,
}

pub type HostsRunnerRequest = HostsUpdateRequest;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;

pub use af_host;
pub use af_release;

mod adguard_dns;
pub mod blueprint;
pub mod bounded_command;
pub mod job_receipts;
#[cfg(test)]
mod legacy_stream_output;
#[cfg(all(test, unix))]
mod lifecycle_tests;
pub mod network;
pub mod peer_network;
pub use peer_network::{
    execute_peer_network_local, PeerCredentialDeleteResponse, PeerCredentialReadResponse,
    PeerCredentialSecret, PeerCredentialSlot, PeerCredentialWriteResponse,
    PeerEnsurePackagesResponse, PeerIdentityResponse, PeerLinkCredentialsDeleteResponse,
    PeerMutationResponse, PeerNetworkError, PeerNetworkManager, PeerNetworkRequest,
    PeerNetworkResponse, PeerStatusPeer, PeerStatusResponse,
};
pub mod peer_storage;
pub use peer_storage::{
    derive_peer_export_file_name, derive_peer_mount_path, execute_peer_storage_local,
    is_managed_peer_mount_unit, peer_sentinel_path, probe_sentinel_file, systemd_escape_mount_unit,
    systemd_escape_path, validate_export_path_syntax, validate_peer_mount_path,
    validate_peer_mount_segment, validate_peer_storage_link_id, PeerExportsWriteResponse,
    PeerMountRemoveResponse, PeerMountStateResponse, PeerMountWriteResponse,
    PeerNfsdConfigResponse, PeerSentinelProbeResponse, PeerSentinelResponse, PeerStorageError,
    PeerStorageExportSpec, PeerStorageManager, PeerStoragePackagesResponse, PeerStorageRequest,
    PeerStorageResponse, DEFAULT_PEER_EXPORTS_DIR, DEFAULT_PEER_MOUNTS_ROOT,
    DEFAULT_PEER_NFS_CONF_DIR, DEFAULT_PEER_SYSTEMD_DIR, DEFAULT_SENTINEL_PROBE_TIMEOUT_MS,
    MAX_CONCURRENT_SENTINEL_PROBES, PEER_MANAGED_HEADER, PEER_NFSD_CONF_NAME,
    PEER_NFSD_DROPIN_DIR_NAME, PEER_NFSD_DROPIN_NAME, PEER_NFSD_SERVICE_UNIT,
    PEER_SENTINEL_FILE_NAME, PEER_STORAGE_PACKAGES,
};
pub mod peer_transcode;
pub use peer_transcode::{
    client_timeout_for_request, decode_peer_transcode_response,
    derive_peer_transcode_export_file_name, execute_peer_transcode_local, handle_peer_transcode,
    parse_jellyfin_transcoding_temp_path, JellyfinTranscodePaths, ParityFileCleanupReport,
    PeerTranscodeError, PeerTranscodeManager, PeerTranscodePathsConfig, PeerTranscodeRequest,
    PeerTranscodeResponse, TranscodeMutationReport, API_SERVICE_UNIT, API_TRANSCODE_DROPIN_NAME,
    DEFAULT_DISPATCHER_RUNTIME_DIR, DEFAULT_JELLYFIN_CACHE_DIR, DEFAULT_JELLYFIN_ENCODING_XML,
    DEFAULT_JELLYFIN_TMP_DIR, DEFAULT_JELLYFIN_TRANSCODE_DIR, DEFAULT_REAL_FFPROBE_PATH,
    DEFAULT_TMPFILES_DIR, DEFAULT_TRANSCODE_FFPROBE_SYMLINK, DEFAULT_TRANSCODE_SHIM_DIR,
    DEFAULT_TRANSCODE_SHIM_PATH, DEFAULT_WORKER_RUNTIME_DIR, JELLYFIN_SERVICE_UNIT,
    JELLYFIN_TRANSCODE_DROPIN_NAME, PEER_TRANSCODE_WORKER_UNIT, TRANSCODE_TMPFILES_CONF_NAME,
};
pub mod package_executor;
pub use package_executor::check_domain_tls_ready;
pub mod package_lifecycle;
pub mod package_purge;
pub use package_purge::{
    candidate_package_sqlite_dbs, format_ambiguous_purge_error, inspect_package_purge_state,
    inspect_package_purge_state_with_conn, PackagePurgeEligibility, PackagePurgeInspection,
};
pub mod plugins;
pub use plugins::PluginRunnerError;
pub mod probe_metadata;
pub mod quota;

pub const RUNNER_REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_RUNNER_REQUEST_ID_LEN: usize = 128;

/// Validates and trims a correlation request ID (1..=128 ASCII chars in `[A-Za-z0-9._:-]`).
pub fn sanitize_runner_request_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_RUNNER_REQUEST_ID_LEN
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return None;
    }
    Some(trimmed.to_string())
}

tokio::task_local! {
    pub static PACKAGE_JOB_ID: String;
    static PACKAGE_MAINTENANCE_LEASE: std::sync::Arc<af_release::ReleaseLockGuard>;
    static RUNNER_REQUEST_ID: String;
}

/// Executes `fut` with `request_id` bound to the runner client task-local correlation slot so
/// outbound Unix-socket requests attach `x-request-id` automatically.
pub async fn with_runner_request_id<F: std::future::Future>(
    request_id: String,
    fut: F,
) -> F::Output {
    let sanitized = sanitize_runner_request_id(&request_id).unwrap_or_default();
    RUNNER_REQUEST_ID.scope(sanitized, fut).await
}

/// Returns the active sanitized runner correlation request ID for the current task, if any.
pub fn current_runner_request_id() -> Option<String> {
    RUNNER_REQUEST_ID
        .try_with(|id| sanitize_runner_request_id(id))
        .ok()
        .flatten()
}

pub fn current_package_job_id() -> String {
    PACKAGE_JOB_ID.try_with(Clone::clone).unwrap_or_default()
}
pub use package_executor::*;

pub const DEFAULT_RUNNER_SOCKET_PATH: &str = "/run/aetherflow/runner.sock";

pub(crate) const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../config/packages.json");
pub(crate) const EMBEDDED_AUTOMATION_JSON: &str =
    include_str!("../../../../config/package_automation.json");

pub(crate) static PACKAGE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
pub(crate) static BACKUP_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub static SAFE_SCRIPT_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap());
pub static SAFE_PKG_ID: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap());
pub static SAFE_SERVICE_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap());
pub static SAFE_USERNAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z_][a-z0-9_-]{0,31}$").unwrap());
pub static SAFE_USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{1,64}$").unwrap());
pub static SAFE_QUOTA_SIZE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?$").unwrap());
pub use SAFE_QUOTA_SIZE as SAFE_QUOTA_SIZE_REGEX;

static ALLOWED_SERVICE_ACTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "start",
        "stop",
        "restart",
        "reload",
        "enable",
        "disable",
        "status",
        "heal",
        "restart-deferred",
    ]
    .into()
});
static ALLOWED_BACKUP_ACTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "create",
        "create_sqlite",
        "create_archive",
        "verify",
        "list",
        "delete",
        "prune",
        "restore_preflight",
        "restore_execute",
        "recover_interrupted",
    ]
    .into()
});

/// Release engine execution mode selected by the runner for `/v1/self-update`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEngineMode {
    /// Executed by the typed Rust `af-release` engine (`ReleaseManager`).
    NativeRustRelease,
    /// Executed by the legacy `deploy/release-manager.sh` script.
    LegacyBashRelease,
}

/// Evaluates release engine selection given rollout flags (`_rust_enabled`, `force_bash`).
///
/// Certified `af-release` (`NativeRustRelease`) is the default engine unless an explicit Bash
/// escape hatch (`force_bash`) is requested.
pub fn select_release_engine_with_flags(rust_enabled: bool, force_bash: bool) -> ReleaseEngineMode {
    let _ = rust_enabled;
    if force_bash {
        ReleaseEngineMode::LegacyBashRelease
    } else {
        ReleaseEngineMode::NativeRustRelease
    }
}

/// Selects the active release engine for `/v1/self-update`.
///
/// Rollout control:
/// Certified `af-release` (`NativeRustRelease`) is enabled by default. The legacy
/// `AETHERFLOW_ENABLE_RUST_RELEASE`, `AETHERFLOW_USE_RUST_RELEASE`, and
/// `AETHERFLOW_RELEASE_ENGINE=rust` aliases remain accepted for backwards compatibility.
/// Setting `AETHERFLOW_FORCE_BASH_RELEASE=1`/`true` or `AETHERFLOW_RELEASE_ENGINE=bash`
/// selects the legacy Bash escape hatch (`LegacyBashRelease`).
pub fn select_release_engine() -> ReleaseEngineMode {
    let enabled = |key| {
        env::var(key)
            .is_ok_and(|value| value.trim() == "1" || value.trim().eq_ignore_ascii_case("true"))
    };
    let engine = env::var("AETHERFLOW_RELEASE_ENGINE").unwrap_or_default();
    let rust_enabled = engine.trim().eq_ignore_ascii_case("rust")
        || enabled("AETHERFLOW_ENABLE_RUST_RELEASE")
        || enabled("AETHERFLOW_USE_RUST_RELEASE");
    let force_bash =
        engine.trim().eq_ignore_ascii_case("bash") || enabled("AETHERFLOW_FORCE_BASH_RELEASE");
    select_release_engine_with_flags(rust_enabled, force_bash)
}

pub fn resolve_runner_socket_path() -> String {
    if let Ok(p) = env::var("AETHERFLOW_RUNNER_SOCK") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_RUNNER_SOCKET_PATH.to_string()
}

pub fn runner_socket_path() -> String {
    resolve_runner_socket_path()
}

pub fn is_runner_available() -> bool {
    let p = resolve_runner_socket_path();
    let path = Path::new(&p);
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        fs::metadata(path)
            .map(|meta| meta.file_type().is_socket())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

#[cfg(unix)]
pub(crate) fn runner_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub(crate) fn runner_is_root() -> bool {
    false
}

/// Verifies that a resolved runner executable or helper script is a regular file,
/// and when executing as root (`running_as_root == true`), verifies root ownership
/// (`uid == 0`, including any leaf symlink itself), non-group/world-writable permissions
/// (`mode & 0o022 == 0`), and root-owned non-group/world-writable non-symlink ancestor
/// directories (allowing only the confined `<root>/opt/AetherFlow/current -> releases/<epoch>`
/// release symlink) (`SEC-03`).
pub(crate) fn is_trusted_runner_target(path: &Path, running_as_root: bool) -> bool {
    if !running_as_root {
        return path.is_file();
    }
    #[cfg(unix)]
    {
        is_trusted_runner_target_root_depth(path, 4)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(unix)]
fn normalize_lexical_target_against_symlink_free_parent(
    parent: &Path,
    raw_target: &Path,
) -> Option<PathBuf> {
    use std::path::Component;

    let combined = if raw_target.is_absolute() {
        raw_target.to_path_buf()
    } else {
        parent.join(raw_target)
    };
    let mut normalized = PathBuf::new();
    for comp in combined.components() {
        match comp {
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(unix)]
fn is_trusted_runner_target_root_depth(path: &Path, remaining_hops: u8) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let resolved = match resolve_managed_current_release_path(path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !resolved.is_absolute()
        || resolved
            .components()
            .any(|comp| matches!(comp, Component::CurDir | Component::ParentDir))
    {
        return false;
    }
    if let Some(parent) = resolved.parent() {
        if !parent.as_os_str().is_empty() {
            let mut cursor = PathBuf::new();
            for comp in parent.components() {
                cursor.push(comp.as_os_str());
                if matches!(comp, Component::RootDir | Component::Prefix(_)) {
                    continue;
                }
                let Ok(anc_meta) = fs::symlink_metadata(&cursor) else {
                    return false;
                };
                if anc_meta.file_type().is_symlink()
                    || !anc_meta.is_dir()
                    || anc_meta.uid() != 0
                    || (anc_meta.mode() & 0o022) != 0
                {
                    return false;
                }
            }
        }
    }
    let Ok(lmeta) = fs::symlink_metadata(resolved.as_ref()) else {
        return false;
    };
    if lmeta.uid() != 0 {
        return false;
    }
    if lmeta.file_type().is_symlink() {
        if remaining_hops == 0 {
            return false;
        }
        let Ok(raw_target) = fs::read_link(resolved.as_ref()) else {
            return false;
        };
        let parent = resolved.parent().unwrap_or_else(|| Path::new("/"));
        let Some(next_target) =
            normalize_lexical_target_against_symlink_free_parent(parent, &raw_target)
        else {
            return false;
        };
        return is_trusted_runner_target_root_depth(&next_target, remaining_hops - 1);
    }
    lmeta.is_file() && lmeta.uid() == 0 && (lmeta.mode() & 0o022) == 0
}

pub fn resolve_package_script_path(action: &str, script_name: &str) -> Option<PathBuf> {
    resolve_package_script_in_roots(action, script_name, &package_script_roots())
}

fn package_script_roots_for_exe_dir_with_root(
    exe_dir: Option<&Path>,
    running_as_root: bool,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = exe_dir {
        roots.push(dir.join("packages/package"));
        roots.push(dir.join("../packages/package"));
    }
    roots.extend([
        PathBuf::from("/opt/AetherFlow/current/packages/package"),
        PathBuf::from("/opt/AetherFlow/packages/package"),
        PathBuf::from("/usr/local/bin/AetherFlow/package"),
    ]);
    if !running_as_root {
        roots.extend([
            PathBuf::from("packages/package"),
            PathBuf::from("../packages/package"),
            PathBuf::from("../../packages/package"),
        ]);
    }
    roots
}

fn package_script_roots_for_exe_dir(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    package_script_roots_for_exe_dir_with_root(exe_dir, runner_is_root())
}

fn package_script_roots() -> Vec<PathBuf> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    package_script_roots_for_exe_dir(exe_dir.as_deref())
}

fn resolve_package_script_in_roots(
    action: &str,
    script_name: &str,
    roots: &[PathBuf],
) -> Option<PathBuf> {
    if !SAFE_SCRIPT_NAME.is_match(script_name) {
        return None;
    }
    let subdir = match action {
        "install" | "reinstall" => "install",
        "remove" | "uninstall" => "remove",
        "update" => "update",
        _ => return None,
    };

    let mut script_names = vec![script_name.to_string()];
    if subdir == "update" {
        if let Some(package) = script_name.strip_prefix("updatepackage-") {
            script_names.push(format!("installpackage-{package}"));
        } else if let Some(package) = script_name.strip_prefix("installpackage-") {
            script_names.insert(0, format!("updatepackage-{package}"));
        }
    }
    let subdirs: &[&str] = if subdir == "update" {
        &["update", "install"]
    } else {
        &[subdir]
    };

    let running_as_root = runner_is_root();
    // Finish all fallbacks within a release before consulting stale roots.
    for root in roots {
        for dir in subdirs {
            for name in &script_names {
                let candidate = root.join(dir).join(name);
                if is_trusted_runner_target(&candidate, running_as_root) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

pub(crate) fn release_manager_script_candidates_with_root(
    exe_dir: Option<&Path>,
    running_as_root: bool,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("deploy/release-manager.sh"));
        candidates.push(dir.join("../deploy/release-manager.sh"));
    }
    candidates.extend([
        PathBuf::from("/opt/AetherFlow/current/deploy/release-manager.sh"),
        PathBuf::from("/opt/AetherFlow/deploy/release-manager.sh"),
    ]);
    if !running_as_root {
        candidates.extend([
            PathBuf::from("deploy/release-manager.sh"),
            PathBuf::from("../deploy/release-manager.sh"),
        ]);
    }
    candidates
}

#[cfg(test)]
pub(crate) fn release_manager_script_candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    release_manager_script_candidates_with_root(exe_dir, runner_is_root())
}

pub fn resolve_release_manager_script() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AETHERFLOW_RELEASE_MANAGER_SCRIPT") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if is_trusted_runner_target(&candidate_path, running_as_root) {
                return Some(candidate_path);
            }
        }
    }
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    release_manager_script_candidates_with_root(exe_dir.as_deref(), running_as_root)
        .into_iter()
        .find(|cand| is_trusted_runner_target(cand, running_as_root))
}

pub fn resolve_systemd_run_binary() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AETHERFLOW_SYSTEMD_RUN_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if is_trusted_runner_target(&candidate_path, running_as_root) {
                return Some(candidate_path);
            }
        }
    }
    let candidates = [
        PathBuf::from("/usr/bin/systemd-run"),
        PathBuf::from("/bin/systemd-run"),
    ];
    candidates
        .into_iter()
        .find(|cand| is_trusted_runner_target(cand, running_as_root))
}

pub(crate) fn af_cli_binary_candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("bin/af"));
        candidates.push(dir.join("af"));
    }
    candidates.extend([
        PathBuf::from("/opt/AetherFlow/current/bin/af"),
        PathBuf::from("/opt/AetherFlow/current/af"),
        PathBuf::from("/usr/local/bin/af"),
    ]);
    candidates
}

pub fn resolve_af_cli_binary() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AETHERFLOW_CLI_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if is_trusted_runner_target(&candidate_path, running_as_root) {
                return Some(candidate_path);
            }
        }
    }
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    af_cli_binary_candidates(exe_dir.as_deref())
        .into_iter()
        .find(|cand| is_trusted_runner_target(cand, running_as_root))
}

pub(crate) fn af_transcode_binary_candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("bin/af-transcode"));
        candidates.push(dir.join("af-transcode"));
    }
    candidates.extend([
        PathBuf::from("/opt/AetherFlow/current/bin/af-transcode"),
        PathBuf::from("/opt/AetherFlow/current/af-transcode"),
    ]);
    candidates
}

fn is_trusted_transcode_binary(path: &Path, running_as_root: bool) -> bool {
    peer_transcode::is_valid_transcode_binary(path)
        && is_trusted_runner_target(path, running_as_root)
}

pub fn resolve_af_transcode_binary() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AETHERFLOW_TRANSCODE_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if is_trusted_transcode_binary(&candidate_path, running_as_root) {
                return Some(candidate_path);
            }
        }
    }
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    af_transcode_binary_candidates(exe_dir.as_deref())
        .into_iter()
        .find(|cand| is_trusted_transcode_binary(cand, running_as_root))
}

async fn runner_request_id_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use tracing::Instrument;

    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let valid_rid = req
        .headers()
        .get(RUNNER_REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_runner_request_id);
    let span_rid = valid_rid.as_deref().unwrap_or("none");
    let span = tracing::info_span!(
        "runner_request",
        request_id = %span_rid,
        path = %path,
    );
    let scope_rid = valid_rid.clone();

    let run = async move {
        let mut resp = next.run(req).await;
        let status = resp.status();
        if let Some(ref rid) = valid_rid {
            if let Ok(val) = HeaderValue::from_str(rid) {
                resp.headers_mut().insert(
                    axum::http::header::HeaderName::from_static(RUNNER_REQUEST_ID_HEADER),
                    val,
                );
            }
        }
        tracing::info!(
            request_id = %valid_rid.as_deref().unwrap_or("none"),
            method = %method,
            path = %path,
            status = status.as_u16(),
            "Runner request completed"
        );
        resp
    };

    if let Some(rid) = scope_rid {
        with_runner_request_id(rid, run).instrument(span).await
    } else {
        run.instrument(span).await
    }
}

/// Builds the Axum router for the Privileged Root Socket Daemon (`aetherflow-api runner`).
pub fn build_runner_router() -> Router {
    Router::new()
        .route("/v1/health", get(handle_health).post(handle_health))
        .route("/v1/systemctl", post(handle_systemctl))
        .route("/v1/package", post(handle_package))
        .route("/v1/package/cancel", post(handle_package_cancel))
        .route(
            "/v1/package/lifecycle-snapshot",
            post(handle_package_lifecycle_snapshot),
        )
        .route("/v1/self-update", post(handle_self_update))
        .route("/v1/self-update/status", post(handle_self_update_status))
        .route("/v1/backup", post(handle_backup))
        .route("/v1/sandbox", post(handle_sandbox))
        .route("/v1/hosts", post(handle_hosts))
        .route("/v1/blueprint/apply", post(handle_blueprint_apply))
        .route("/v1/network", post(handle_network))
        .route("/v1/peer-network", post(peer_network::handle_peer_network))
        .route("/v1/peer-storage", post(peer_storage::handle_peer_storage))
        .route(
            "/v1/peer-transcode",
            post(peer_transcode::handle_peer_transcode),
        )
        .route("/v1/quota", post(handle_quota))
        .route("/v1/quota/usage", post(quota::handle))
        .route("/v1/app-meta", post(handle_app_meta))
        .route(
            "/v1/package/probe-version",
            post(handle_package_version_probe),
        )
        .route(
            "/v1/dispatcharr-credentials",
            post(handle_dispatcharr_credentials),
        )
        .route("/v1/ingress/vhost", post(handle_ingress_vhost))
        .route("/v1/certbot-sync", post(handle_certbot_sync))
        .route("/v1/plugins/start", post(plugins::handle_plugin_start))
        .route("/v1/plugins/stop", post(plugins::handle_plugin_stop))
        .route("/v1/plugins/status", post(plugins::handle_plugin_status))
        .route(
            "/v1/plugins/token",
            post(plugins::handle_plugin_token_rotate),
        )
        .layer(axum::middleware::from_fn(runner_request_id_middleware))
}

async fn handle_health() -> Json<RunnerResponse> {
    Json(RunnerResponse {
        success: true,
        output: "ready".to_string(),
        error: String::new(),
    })
}

pub(crate) fn sandbox_script_candidates_with_root(
    exe_dir: Option<&Path>,
    running_as_root: bool,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("deploy/security/af-systemd-sandbox"));
        candidates.push(dir.join("../deploy/security/af-systemd-sandbox"));
        candidates.push(dir.join("packages/system/af-systemd-sandbox"));
        candidates.push(dir.join("../packages/system/af-systemd-sandbox"));
    }
    candidates.extend([
        PathBuf::from("/opt/AetherFlow/current/packages/system/af-systemd-sandbox"),
        PathBuf::from("/opt/AetherFlow/packages/system/af-systemd-sandbox"),
        PathBuf::from("/usr/local/bin/AetherFlow/system/af-systemd-sandbox"),
        PathBuf::from("/usr/local/bin/af-systemd-sandbox"),
        PathBuf::from("/usr/bin/af-systemd-sandbox"),
    ]);
    if !running_as_root {
        candidates.extend([
            PathBuf::from("deploy/security/af-systemd-sandbox"),
            PathBuf::from("../deploy/security/af-systemd-sandbox"),
            PathBuf::from("packages/system/af-systemd-sandbox"),
            PathBuf::from("../packages/system/af-systemd-sandbox"),
        ]);
    }
    candidates
}

#[cfg(test)]
pub(crate) fn sandbox_script_candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    sandbox_script_candidates_with_root(exe_dir, runner_is_root())
}

pub fn resolve_sandbox_script_path() -> Option<PathBuf> {
    let running_as_root = runner_is_root();
    if let Ok(explicit) = env::var("AETHERFLOW_SANDBOX_SCRIPT") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if is_trusted_runner_target(&p, running_as_root) {
                return Some(p);
            }
        }
    }

    let exe_dir = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    sandbox_script_candidates_with_root(exe_dir.as_deref(), running_as_root)
        .into_iter()
        .find(|c| is_trusted_runner_target(c, running_as_root))
}

#[cfg(unix)]
fn resolve_non_root_leading_parent_dirs(
    path: &Path,
) -> std::io::Result<std::borrow::Cow<'_, Path>> {
    use std::path::Component;

    if path.is_absolute() || runner_is_root() {
        return Ok(std::borrow::Cow::Borrowed(path));
    }
    let mut comps = path.components().peekable();
    let mut parent_pops = 0usize;
    while matches!(comps.peek(), Some(Component::ParentDir)) {
        comps.next();
        parent_pops += 1;
    }
    if parent_pops == 0 {
        return Ok(std::borrow::Cow::Borrowed(path));
    }
    let mut base = env::current_dir()?;
    for _ in 0..parent_pops {
        if !base.pop() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "config path traverses above filesystem root",
            ));
        }
    }
    for comp in comps {
        match comp {
            Component::CurDir => {}
            Component::Normal(part) => base.push(part),
            // Preserve embedded `..` so confined_fs rejects mid-path traversal.
            Component::ParentDir => base.push(".."),
            Component::RootDir | Component::Prefix(_) => {
                return Ok(std::borrow::Cow::Borrowed(path));
            }
        }
    }
    Ok(std::borrow::Cow::Owned(base))
}

/// Safely resolves the single managed `<root>/opt/AetherFlow/current` release symlink (when
/// present) to its direct `<root>/opt/AetherFlow/releases/<epoch>` target before passing the
/// resulting path into `confined_fs::read_confined_text`.
///
/// Any symlinked ancestor above `opt/AetherFlow`, any non-root-owned `opt/AetherFlow` or `current`
/// link under root, any `..` component in the link target, or any target outside
/// `<root>/opt/AetherFlow/releases/<epoch>` fails closed with `PermissionDenied`.
#[cfg(unix)]
fn resolve_managed_current_release_path(
    path: &Path,
) -> std::io::Result<std::borrow::Cow<'_, Path>> {
    use std::ffi::OsStr;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let components: Vec<Component<'_>> = path.components().collect();
    let mut current_idx = None;
    for idx in 2..components.len() {
        if matches!(components[idx - 2], Component::Normal(s) if s == OsStr::new("opt"))
            && matches!(components[idx - 1], Component::Normal(s) if s == OsStr::new("AetherFlow"))
            && matches!(components[idx], Component::Normal(s) if s == OsStr::new("current"))
        {
            current_idx = Some(idx);
            break;
        }
    }
    let Some(idx) = current_idx else {
        return Ok(std::borrow::Cow::Borrowed(path));
    };
    if idx + 1 >= components.len() {
        return Ok(std::borrow::Cow::Borrowed(path));
    }

    let mut opt_af_dir = PathBuf::new();
    for comp in &components[..idx] {
        opt_af_dir.push(comp.as_os_str());
    }
    let current_link = opt_af_dir.join("current");
    let link_meta = match fs::symlink_metadata(&current_link) {
        Ok(meta) => meta,
        Err(_) => return Ok(std::borrow::Cow::Borrowed(path)),
    };
    if !link_meta.file_type().is_symlink() {
        return Ok(std::borrow::Cow::Borrowed(path));
    }

    // Verify `opt_af_dir` itself is a real directory with no symlink ancestors, and root-owned
    // + non-group/world-writable when executing as root.
    let mut cursor = PathBuf::new();
    for comp in opt_af_dir.components() {
        cursor.push(comp.as_os_str());
        if matches!(comp, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let anc_meta = fs::symlink_metadata(&cursor)?;
        if anc_meta.file_type().is_symlink() || !anc_meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing symlinked or non-directory release ancestor: {}",
                    cursor.display()
                ),
            ));
        }
    }
    let running_as_root = unsafe { libc::geteuid() == 0 };
    if running_as_root {
        let opt_af_meta = fs::symlink_metadata(&opt_af_dir)?;
        if opt_af_meta.uid() != 0 || (opt_af_meta.mode() & 0o022) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing untrusted release directory ownership/mode: {}",
                    opt_af_dir.display()
                ),
            ));
        }
        if link_meta.uid() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing non-root-owned current release symlink: {}",
                    current_link.display()
                ),
            ));
        }
    }

    let raw_target = fs::read_link(&current_link)?;
    if raw_target
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing parent traversal in current release symlink: {}",
                current_link.display()
            ),
        ));
    }
    let resolved_release = if raw_target.is_absolute() {
        raw_target
    } else {
        opt_af_dir.join(raw_target)
    };
    let expected_releases_dir = opt_af_dir.join("releases");
    if resolved_release.parent() != Some(expected_releases_dir.as_path()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing current release symlink outside {}: {}",
                expected_releases_dir.display(),
                resolved_release.display()
            ),
        ));
    }

    let mut rebuilt = resolved_release;
    for comp in &components[idx + 1..] {
        rebuilt.push(comp.as_os_str());
    }
    Ok(std::borrow::Cow::Owned(rebuilt))
}

pub fn open_and_read_regular_config(path: &Path) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        let resolved = resolve_non_root_leading_parent_dirs(path)?;
        let resolved = resolve_managed_current_release_path(&resolved)?;
        confined_fs::read_confined_text(&resolved, &[])
    }
    #[cfg(not(unix))]
    {
        use std::io::Read;
        const LIMIT: u64 = 2 * 1024 * 1024;
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config file is a symlink: {}", path.display()),
            ));
        }
        let file = fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config file is not a regular file: {}", path.display()),
            ));
        }
        let mut contents = String::new();
        file.take(LIMIT + 1).read_to_string(&mut contents)?;
        if contents.len() as u64 > LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "configuration exceeds 2 MiB",
            ));
        }
        Ok(contents)
    }
}

pub fn is_missing_config_candidate(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::ENOTDIR)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn package_fs_root_override() -> Option<PathBuf> {
    af_models::resolve_package_fs_root(None)
}

fn installed_config_candidates(root: &Path, filename: &str) -> [PathBuf; 4] {
    [
        "opt/AetherFlow/current/config",
        "opt/AetherFlow/config",
        // Legacy v3 host upgrade fallback.
        "opt/AetherFlow/current/backend/config",
        "opt/AetherFlow/backend/config",
    ]
    .map(|directory| root.join(directory).join(filename))
}

pub fn canonical_config_candidates(filename: &str) -> Vec<PathBuf> {
    if let Some(root) = package_fs_root_override() {
        return installed_config_candidates(&root, filename).into();
    }

    #[cfg(unix)]
    let running_as_root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let running_as_root = false;

    let mut candidates = Vec::new();
    if !running_as_root {
        candidates.extend([
            PathBuf::from("config").join(filename),
            PathBuf::from("../config").join(filename),
            PathBuf::from("../../config").join(filename),
        ]);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("config").join(filename));
            if let Some(release_root) = exe_dir.parent() {
                candidates.push(release_root.join("config").join(filename));
            }
        }
    }
    candidates.extend(installed_config_candidates(Path::new("/"), filename));
    candidates
}

fn try_load_runner_config_or_embedded_in_root(
    env_var: &str,
    filename: &str,
    embedded: &str,
    explicit_root: Option<&Path>,
) -> anyhow::Result<String> {
    if let Ok(explicit) = env::var(env_var) {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = Path::new(trimmed);
            return open_and_read_regular_config(p)
                .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", p.display()));
        }
    }
    let candidates: Vec<PathBuf> = match af_models::resolve_package_fs_root(explicit_root) {
        Some(root) => installed_config_candidates(&root, filename).into(),
        None => canonical_config_candidates(filename),
    };
    for c in candidates {
        match open_and_read_regular_config(&c) {
            Ok(s) => return Ok(s),
            Err(err) if is_missing_config_candidate(&err) => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "refusing unsafe or unreadable config candidate {}: {err}",
                    c.display()
                ))
            }
        }
    }
    Ok(embedded.to_string())
}

pub(crate) fn try_load_runner_config_or_embedded(
    env_var: &str,
    filename: &str,
    embedded: &str,
) -> anyhow::Result<String> {
    try_load_runner_config_or_embedded_in_root(env_var, filename, embedded, None)
}

pub fn load_runner_package_definitions_in_root(
    explicit_root: Option<&Path>,
) -> anyhow::Result<impl Iterator<Item = Package>> {
    let raw_pkgs = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
        explicit_root,
    )?;
    let raw_auto = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
        explicit_root,
    )?;

    let pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs)?;
    let auto_map: HashMap<String, PackageAutomation> =
        serde_json::from_str(&raw_auto).unwrap_or_default();

    Ok(pkgs.into_iter().map(move |mut package| {
        if let Some(automation) = auto_map.get(&package.name) {
            af_models::merge_package_automation(&mut package, automation);
        }
        package
    }))
}

pub fn get_runner_package_definition_in_root(
    pkg_id: &str,
    explicit_root: Option<&Path>,
) -> Option<Package> {
    load_runner_package_definitions_in_root(explicit_root)
        .ok()?
        .find(|package| package.name == pkg_id)
}

pub fn get_runner_package_definition(pkg_id: &str) -> Option<Package> {
    get_runner_package_definition_in_root(pkg_id, None)
}

mod app_metadata;
pub use app_metadata::*;

mod backup_ops;
use backup_ops::handle_backup;
pub use backup_ops::{dispatch_backup_request, execute_backup_local};

mod confined_fs;
pub(crate) use confined_fs::{
    confined_file_name, create_package_lock_directory, lookup_group_gid, open_confined_file,
    read_confined_text, replace_confined_file, replace_confined_text, write_hosts_file_atomically,
};
pub use confined_fs::{
    dns_provider_directory_exists, read_dns_provider_text, remove_dns_provider_file,
    write_dns_provider_text,
};

mod daemon;
#[cfg(unix)]
pub(crate) use daemon::lookup_passwd_uid_reentrant;
pub use daemon::{authorize_runner_peer_credentials, run_privileged_daemon, shutdown_signal};
#[cfg(all(test, unix))]
use daemon::{authorize_runner_socket_peer, serve_runner_connections, trusted_runner_peer_exe};

mod hosts_dns;
#[cfg(test)]
use hosts_dns::resolve_hosts_lock_path;
pub use hosts_dns::{
    apply_hosts_update, execute_hosts_cli_command, filter_hosts_line, modify_hosts_file_at_path,
    reconcile_hosts_file, reconcile_hosts_file_at_path, reconcile_pihole_custom_list_content,
    remove_dns_provider_domain, remove_dns_provider_files, remove_hosts_file_at_path,
    remove_pihole_custom_list_content, run_hosts_cli, sync_adguard_dns, sync_dns_provider_files,
    sync_dns_provider_files_for_root, sync_dns_provider_files_with_mode, update_hosts_file,
    update_hosts_file_at_path, update_hosts_file_local, update_hosts_file_with_ip_at_path,
    validate_hosts_domain, validate_hosts_ip, HostsModifyAction, RunnerError,
};
use hosts_dns::{handle_hosts, resolve_provider_dir};

mod ingress_vhost;
#[cfg(test)]
use ingress_vhost::{apply_ingress_vhost_with_hooks, execute_certbot_sync_with_candidates};
#[allow(unused_imports)]
pub(crate) use ingress_vhost::{
    enable_managed_apache_modules, reload_apache_after_rollback_if_live, restore_app_vhost_backups,
    snapshot_app_vhost_backups, validate_ingress_vhost_request, PrevEnabledVhostState, VhostBackup,
};
use ingress_vhost::{handle_certbot_sync, handle_ingress_vhost};
pub use ingress_vhost::{
    sync_apache_vhost_local, sync_apache_vhost_via_runner, sync_certbot_and_managed_ingress,
    trigger_certbot_sync_via_runner,
};

mod network_quota_handlers;
pub use network_quota_handlers::{
    execute_network_action_local, execute_set_quota_local, parse_quota_size_to_1k_blocks,
    resolve_setdisk_script_path,
};
use network_quota_handlers::{handle_network, handle_quota};

mod runner_client;
pub(crate) use runner_client::post_runner_json;
#[cfg(test)]
use runner_client::{
    consume_package_output, IncrementalPackageLineDecoder, MAX_PACKAGE_STREAM_LINE_BYTES,
};
pub use runner_client::{
    dispatch_app_meta, dispatch_core_restart, dispatch_heal_restart, dispatch_hosts_reconcile,
    dispatch_hosts_reconcile_with_provider, dispatch_hosts_remove, dispatch_hosts_request,
    dispatch_hosts_update, dispatch_hosts_update_with_provider, dispatch_network_action,
    dispatch_network_control, dispatch_package_action, dispatch_package_action_with_options,
    dispatch_package_action_with_target, dispatch_package_cancel,
    dispatch_package_lifecycle_snapshot_capture, dispatch_package_lifecycle_snapshot_discard,
    dispatch_package_lifecycle_snapshot_discard_for_job,
    dispatch_package_lifecycle_snapshot_restore, dispatch_package_stream, dispatch_peer_network,
    dispatch_peer_storage, dispatch_peer_transcode, dispatch_plugin_start, dispatch_plugin_status,
    dispatch_plugin_stop, dispatch_plugin_token_rotate, dispatch_quota_set, dispatch_sandbox,
    dispatch_sandbox_apply, dispatch_self_update, dispatch_self_update_request,
    dispatch_self_update_status_request, dispatch_set_quota, dispatch_systemctl,
    execute_package_local, is_lifecycle_busy, reconcile_hosts_file_via_runner,
    remove_hosts_file_via_runner, runner_is_ready, start_self_update, update_hosts_file_via_runner,
    LifecycleBusy,
};

mod sandbox_ops;
pub use sandbox_ops::{
    apply_package_sandbox_local, dispatch_blueprint_apply, render_systemd_sandbox_dropin,
};
#[allow(unused_imports)]
pub(crate) use sandbox_ops::{
    apply_package_sandbox_reserved, is_exempt_sandbox_unit, open_runner_state_database,
    render_systemd_sandbox_dropin_in_root,
};
#[cfg(test)]
use sandbox_ops::{
    apply_sandbox_dropins_in_dir, expand_sandbox_path, handle_sandbox_with, sandbox_master_user,
};
use sandbox_ops::{
    handle_blueprint_apply, handle_sandbox, remove_file_if_exists, write_file_atomically_with_mode,
};

mod self_update;
pub use self_update::{
    acquire_lifecycle_admission_lock, acquire_service_maintenance_guard, claim_self_update_job,
    execute_self_update_request, query_self_update_status_local,
    validate_self_update_job_unit_name, write_self_update_job_status_atomic,
};
pub(crate) use self_update::{
    acquire_owned_lifecycle_snapshot_guard, acquire_package_maintenance_guard,
    build_self_update_transient_unit_name, resolve_self_update_isolated_root_from_env,
};
#[cfg(test)]
use self_update::{
    discover_system_update, query_self_update_job_at, query_self_update_job_in,
    resolve_self_update_jobs_dir_from_env, spawn_self_update_transient_unit,
    update_status_allows_launch,
};
use self_update::{
    handle_self_update, handle_self_update_status, resolve_self_update_jobs_dir_for_cfg,
    resolve_self_update_lock_path_for_cfg, resolve_validated_self_update_config,
    service_reservation_target,
};

mod systemctl_handlers;
#[cfg(test)]
use systemctl_handlers::deferred_restart_arguments;
pub(crate) use systemctl_handlers::handle_systemctl;
pub use systemctl_handlers::is_managed_runner_systemd_unit;
use systemctl_handlers::{
    handle_package, handle_package_cancel, handle_package_lifecycle_snapshot,
};

#[cfg(test)]
pub(crate) static ENV_TEST_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
mod tests;

#[cfg(test)]
mod request_id_tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing::instrument::WithSubscriber;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Default)]
    struct RecordedTelemetry {
        spans: Vec<(String, HashMap<String, String>)>,
        events: Vec<(tracing::Level, HashMap<String, String>)>,
    }

    struct MapVisitor(HashMap<String, String>);

    impl Visit for MapVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct CapturingSubscriber {
        recorded: Arc<StdMutex<RecordedTelemetry>>,
        next_id: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &Attributes<'_>) -> Id {
            let mut visitor = MapVisitor(HashMap::new());
            span.record(&mut visitor);
            let mut rec = self.recorded.lock().unwrap_or_else(|e| e.into_inner());
            rec.spans
                .push((span.metadata().name().to_string(), visitor.0));
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            Id::from_u64(id)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = MapVisitor(HashMap::new());
            event.record(&mut visitor);
            let mut rec = self.recorded.lock().unwrap_or_else(|e| e.into_inner());
            rec.events.push((*event.metadata().level(), visitor.0));
        }

        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn sanitize_runner_request_id_validates_charset_and_length() {
        assert_eq!(
            sanitize_runner_request_id("req-123_4.5:ABC"),
            Some("req-123_4.5:ABC".to_string())
        );
        assert_eq!(
            sanitize_runner_request_id("  trimmed-id  "),
            Some("trimmed-id".to_string())
        );
        let max_len = "a".repeat(128);
        assert_eq!(sanitize_runner_request_id(&max_len), Some(max_len));

        for invalid in [
            "",
            "   ",
            &"a".repeat(129),
            "bad space",
            "bad\r\ninject",
            "bad/slash",
            "bad;semi",
            "bad\x00nul",
        ] {
            assert_eq!(
                sanitize_runner_request_id(invalid),
                None,
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn with_runner_request_id_scopes_and_sanitizes_task_local() {
        assert_eq!(current_runner_request_id(), None);
        let seen = with_runner_request_id("  peer-req:42_a.b  ".to_string(), async {
            current_runner_request_id()
        })
        .await;
        assert_eq!(seen.as_deref(), Some("peer-req:42_a.b"));

        let invalid = with_runner_request_id("bad\r\nid".to_string(), async {
            current_runner_request_id()
        })
        .await;
        assert_eq!(invalid, None);
        assert_eq!(current_runner_request_id(), None);
    }

    #[tokio::test]
    async fn runner_router_middleware_correlates_echoes_and_logs_request_id() {
        let subscriber = CapturingSubscriber::default();
        let recorded = Arc::clone(&subscriber.recorded);

        let app = build_runner_router();

        // 1. Valid x-request-id is echoed and attached to the runner_request span and log event.
        let req = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/v1/health")
            .header(RUNNER_REQUEST_ID_HEADER, "api-corr-777")
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .with_subscriber(subscriber.clone())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(RUNNER_REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("api-corr-777")
        );

        {
            let rec = recorded.lock().unwrap();
            assert!(
                rec.spans.iter().any(|(name, fields)| {
                    name == "runner_request"
                        && fields.get("request_id").map(String::as_str) == Some("api-corr-777")
                        && fields.get("path").map(String::as_str) == Some("/v1/health")
                }),
                "expected runner_request span with request_id=api-corr-777, got {:?}",
                rec.spans
            );
            assert!(
                rec.events.iter().any(|(_, fields)| {
                    fields.get("request_id").map(String::as_str) == Some("api-corr-777")
                        && fields.get("status").map(String::as_str) == Some("200")
                }),
                "expected completion log event with request_id=api-corr-777, got {:?}",
                rec.events
            );
        }

        // 2. Missing x-request-id defaults span/log request_id to "none" and omits response header.
        recorded.lock().unwrap().spans.clear();
        recorded.lock().unwrap().events.clear();
        let missing_req = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let missing_resp = app
            .clone()
            .oneshot(missing_req)
            .with_subscriber(subscriber.clone())
            .await
            .unwrap();
        assert_eq!(missing_resp.status(), StatusCode::OK);
        assert!(missing_resp
            .headers()
            .get(RUNNER_REQUEST_ID_HEADER)
            .is_none());
        {
            let rec = recorded.lock().unwrap();
            assert!(rec.spans.iter().any(|(name, fields)| {
                name == "runner_request"
                    && fields.get("request_id").map(String::as_str) == Some("none")
            }));
        }

        // 3. Malformed x-request-id is rejected (falls back to "none", never echoed).
        recorded.lock().unwrap().spans.clear();
        let bad_req = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/v1/health")
            .header(RUNNER_REQUEST_ID_HEADER, "bad header/value")
            .body(Body::empty())
            .unwrap();
        let bad_resp = app
            .oneshot(bad_req)
            .with_subscriber(subscriber)
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::OK);
        assert!(bad_resp.headers().get(RUNNER_REQUEST_ID_HEADER).is_none());
        {
            let rec = recorded.lock().unwrap();
            assert!(rec.spans.iter().any(|(name, fields)| {
                name == "runner_request"
                    && fields.get("request_id").map(String::as_str) == Some("none")
            }));
        }
    }
}

#[cfg(all(test, unix))]
mod sec03_sec04_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn sec03_resolvers_prefer_exe_dir_and_gate_cwd_fallbacks_when_root() {
        let exe_dir = PathBuf::from("/opt/AetherFlow/releases/20261126-slot");

        // af-transcode must prefer current_exe().parent() ahead of /opt/AetherFlow/current/...
        let tc = af_transcode_binary_candidates(Some(&exe_dir));
        assert_eq!(tc[0], exe_dir.join("bin/af-transcode"));
        assert_eq!(tc[1], exe_dir.join("af-transcode"));
        assert_eq!(
            tc[2],
            PathBuf::from("/opt/AetherFlow/current/bin/af-transcode")
        );

        // setdisk must prefer current_exe().parent() ahead of /opt/AetherFlow/current/...
        // and omit relative CWD fallbacks when running as root.
        let sd_root =
            network_quota_handlers::setdisk_script_candidates_with_root(Some(&exe_dir), true);
        assert_eq!(sd_root[0], exe_dir.join("packages/system/setdisk"));
        assert_eq!(sd_root[1], exe_dir.join("../packages/system/setdisk"));
        assert_eq!(
            sd_root[2],
            PathBuf::from("/opt/AetherFlow/current/packages/system/setdisk")
        );
        assert!(
            sd_root.iter().all(|p| p.is_absolute()),
            "root setdisk resolver must not include relative CWD fallbacks: {sd_root:?}"
        );
        let sd_non_root =
            network_quota_handlers::setdisk_script_candidates_with_root(Some(&exe_dir), false);
        assert!(sd_non_root.contains(&PathBuf::from("packages/system/setdisk")));

        // All 3 root resolvers in lib.rs must omit relative CWD fallbacks when running as root.
        let pkg_root = package_script_roots_for_exe_dir_with_root(Some(&exe_dir), true);
        assert!(
            pkg_root.iter().all(|p| p.is_absolute()),
            "root package script resolver must omit relative CWD paths: {pkg_root:?}"
        );
        let rm_root = release_manager_script_candidates_with_root(Some(&exe_dir), true);
        assert!(
            rm_root.iter().all(|p| p.is_absolute()),
            "root release-manager resolver must omit relative CWD paths: {rm_root:?}"
        );
        let sb_root = sandbox_script_candidates_with_root(Some(&exe_dir), true);
        assert!(
            sb_root.iter().all(|p| p.is_absolute()),
            "root sandbox script resolver must omit relative CWD paths: {sb_root:?}"
        );
        assert!(sb_root.contains(&PathBuf::from("/usr/local/bin/af-systemd-sandbox")));
    }

    #[test]
    fn sec03_root_target_validation_rejects_non_root_and_world_writable_files() {
        let dir = env::temp_dir().join(format!("af-sec03-target-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("helper");
        fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();

        // Non-root test mode accepts regular file.
        assert!(is_trusted_runner_target(&file, false));
        // Under root check: non-root owned file (when test runs unprivileged) OR group/world-writable must be rejected.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            !is_trusted_runner_target(&file, true),
            "root target verifier must reject world-writable files"
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            !is_trusted_runner_target(&file, true),
            "root target verifier must reject group-writable files"
        );
        if !runner_is_root() {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                !is_trusted_runner_target(&file, true),
                "root target verifier must reject non-root-owned files"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sec04_open_and_read_regular_config_enforces_confinement_nlink_and_2mib_cap() {
        let root = env::temp_dir().join(format!("af-sec04-cfg-{}", uuid::Uuid::new_v4()));
        let real_dir = root.join("real");
        fs::create_dir_all(&real_dir).unwrap();

        let valid = real_dir.join("ok.json");
        fs::write(&valid, "{\"ok\":true}").unwrap();
        assert_eq!(
            open_and_read_regular_config(&valid).unwrap(),
            "{\"ok\":true}"
        );

        // Leaf symlink rejected
        let leaf_sym = real_dir.join("leaf-sym.json");
        std::os::unix::fs::symlink(&valid, &leaf_sym).unwrap();
        assert!(open_and_read_regular_config(&leaf_sym).is_err());

        // Ancestor directory symlink rejected (O_NOFOLLOW | O_DIRECTORY)
        let dir_sym = root.join("sym-dir");
        std::os::unix::fs::symlink(&real_dir, &dir_sym).unwrap();
        assert!(
            open_and_read_regular_config(&dir_sym.join("ok.json")).is_err(),
            "ancestor directory symlink must be rejected"
        );

        // Hardlink (st_nlink > 1) rejected
        let hard_orig = real_dir.join("hard-a.json");
        let hard_alias = real_dir.join("hard-b.json");
        fs::write(&hard_orig, "[]").unwrap();
        fs::hard_link(&hard_orig, &hard_alias).unwrap();
        assert!(
            open_and_read_regular_config(&hard_orig).is_err(),
            "hardlinked config with st_nlink > 1 must be rejected"
        );

        // Oversized (> 2 MiB) rejected with InvalidData
        let oversized = real_dir.join("big.json");
        let big_data = vec![b' '; (2 * 1024 * 1024) + 1];
        fs::write(&oversized, &big_data).unwrap();
        let err = open_and_read_regular_config(&oversized).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let _ = fs::remove_dir_all(&root);
    }
}
