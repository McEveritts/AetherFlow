//! `af-cli`: Bounded unified Rust administrative CLI (`af`) and resumable provisioning foundation
//! for AetherFlow (`v4.0.0` pure bare-metal `systemd` + `Apache2`, zero Docker).
//!
//! # Core Responsibilities
//! 1. **Manual CLI Parser & Legacy Compatibility (`cli`)**:
//!    Supports both legacy `packages/system/af` shorthands (`af install`, `af remove`, `af list`,
//!    `af update`, `af upgrade`, `af -h`) and structured domain subcommands (`package`, `service`,
//!    `quota`, `sandbox`, `release`, `backup`, `provision`, `health`) with `--json`, `--dry-run`,
//!    `--socket`, and `--root` flags.
//! 2. **Privileged Runner Unix Socket Client (`client`)**:
//!    Dispatches validated `af-models` IPC structs (`PackageRunnerRequest`, `SystemctlRequest`,
//!    `QuotaRunnerRequest`, `SandboxRunnerRequest`, `SelfUpdateRequest`) over `/run/aetherflow/runner.sock`
//!    via [`RunnerClientTransport`] and [`UnixSocketRunnerClient`].
//! 3. **Release Engine & Self-Update Integration**:
//!    Reuses `af-release` (`ReleaseConfig`, `ReleaseEngine`, `ReleaseOptions`, `validate_self_update_request`)
//!    and `af-runner`'s `/v1/self-update` contract without inventing custom wire formats.
//! 4. **Host Backup & Non-Destructive Restore Preflight**:
//!    Reuses `af-host` (`create_host_archive_backup`, `create_sqlite_snapshot_backup`,
//!    `list_backup_inventory`, `verify_backup_artifact`, `preflight_tar_gz_archive`,
//!    `preflight_restore_directory`, `plan_restore_from_manifest`, `execute_destructive_restore`)
//!    while keeping live destructive restore (`af backup restore`) explicitly unsupported.
//! 5. **Resumable Provisioning Foundation (`provision`)**:
//!    Persists `# STATE_VERSION=2` step completion (`/install/.aetherflow.state`), atomic key-value
//!    configuration (`/install/.aetherflow.conf`), PID lockfile (`/var/run/aetherflow-setup.lock`),
//!    preflight checks, SHA-256 sidecar config overlays, and explicit `--repair` / `--resume` / `--dry-run`
//!    semantics while retaining `setup/AetherFlow-Setup` for interactive shell bootstrap.

pub mod cli;
pub mod client;
pub mod error;
pub mod provision;

pub use cli::{
    build_hosts_runner_request, build_package_runner_request,
    build_package_runner_request_with_target, build_quota_runner_request,
    build_release_engine_options, build_sandbox_runner_request, build_self_update_runner_request,
    parse_byte_size_arg, parse_cli_args, render_help_text, resolve_package_lock_name,
    validate_service_request, AfCommand, BackupCliCommand, BackupCreateKind, GlobalOptions,
    HelpTopic, HostsCliCommand, MaintenanceCliCommand, PackageCommand, ParsedInvocation,
    ProvisionCliCommand, QuotaCommand, ReleaseCliCommand, ReleaseDispatchMode, SandboxCommand,
    ServiceCommand, ALLOWED_SYSTEMCTL_ACTIONS,
};
pub use client::{
    format_human_progress_line, parse_package_stream_body, parse_package_stream_line,
    PackageExecutionReceipt, PackageStreamAccumulator, PackageStreamEvent, RunnerClientTransport,
    UnixSocketRunnerClient, MAX_PACKAGE_STREAM_LINE_CARRY_BYTES, MAX_RETAINED_PACKAGE_LOG_LINES,
};
pub use error::{CliError, CliExitCode, CliResponseEnvelope, CliResult};
pub use provision::{
    canonical_step_catalog, ensure_no_symlink_ancestors, execute_provision_steps,
    is_canonical_step, is_effective_root_user, parse_and_validate_os_release,
    run_provision_preflight, safe_overlay_config_file, validate_step_id, ConfigOverlayOutcome,
    ConfigOverlayReceipt, OsReleaseInfo, ProvisionLockGuard, ProvisionPaths,
    ProvisionPreflightReport, ProvisionRunReport, ProvisionStateStore, ProvisionStatusReport,
    ProvisionStepDescriptor, ProvisionStepTier, StepExecutionRecord, StepExecutionStatus,
    CANONICAL_ALL_STEPS, PROVISION_STATE_VERSION, STATE_VERSION_HEADER,
};

pub use af_host::{
    apply_network_tuning, assemble_verified_chunks, clean_system_logs,
    compute_sysctl_network_tuning, create_host_archive_backup, create_sqlite_snapshot_backup,
    delete_backup_artifacts, execute_destructive_restore, inspect_home_disk_space,
    list_backup_inventory, maintenance_helper_ownership_registry,
    plan_restore_from_manifest_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid, prune_backup_inventory,
    safe_backup_file_path, sentinel_scan_auth_log, split_backup_into_chunks,
    verify_backup_artifact_with_trusted_uid, BackupManifest, HostBackupConfig, RestorePlan,
    RestorePreflightOptions,
};
use af_models::SelfUpdateJobStatus;
use af_release::{ReleaseConfig, ReleaseEngine, ReleaseOutcome};
use af_runner::{
    get_runner_package_definition, get_runner_package_definition_in_root,
    parse_quota_size_to_1k_blocks, render_systemd_sandbox_dropin,
    write_self_update_job_status_atomic,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

/// Canonical package lockfile status entry returned by `af list` / `af package list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageListEntry {
    pub package_id: String,
    pub lock_name: String,
    pub lock_path: PathBuf,
    pub installed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retained_receipt_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_lock_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_receipt_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_lock_path: Option<PathBuf>,
    pub service_name: String,
    pub sandbox_profile: String,
}

/// Canonical list of allowlisted AetherFlow package identifiers matching `config/packages.json` (77 packages).
pub const KNOWN_CLI_PACKAGE_IDS: &[&str] = &[
    "adguardhome",
    "audiobookshelf",
    "autobrr",
    "autoscan",
    "bazarr",
    "calibreweb",
    "cloudplow",
    "deluge",
    "dispatcharr",
    "duplicati",
    "emby",
    "fail2ban",
    "filebot",
    "filebrowser",
    "flaresolverr",
    "flood",
    "gitea",
    "grafana",
    "homeassistant",
    "invidious",
    "jackett",
    "jellyfin",
    "jellyseerr",
    "kasmvnc",
    "kavita",
    "librespeed",
    "lidarr",
    "listenarr",
    "maintainerr",
    "mcvnc",
    "mergerfs",
    "n8n",
    "navidrome",
    "netdata",
    "nextcloud",
    "notifiarr",
    "novnc",
    "nzbget",
    "ombi",
    "organizr",
    "overseerr",
    "palate",
    "paperless-ngx",
    "pihole",
    "piped",
    "plex",
    "prometheus",
    "prowlarr",
    "pyload",
    "qbittorrent",
    "quassel",
    "qui",
    "radarr",
    "rclone",
    "readarr",
    "recyclarr",
    "requestrr",
    "rtorrent",
    "rutorrent",
    "sabnzbd",
    "scrutiny",
    "seedcross",
    "sonarr",
    "syncthing",
    "tailscale",
    "tautulli",
    "thelounge",
    "threadfin",
    "transmission",
    "unmanic",
    "unpackerr",
    "uptimekuma",
    "vaultwarden",
    "wireguard",
    "x2go",
    "xrdp",
    "znc",
];

/// Parses raw CLI arguments and executes the resulting command using the default
/// [`UnixSocketRunnerClient`] resolved from `--socket` or `AETHERFLOW_RUNNER_SOCK`.
pub fn run_cli_from_args<I, S>(raw_args: I) -> CliResponseEnvelope
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_args(raw_args) {
        Ok(invocation) => {
            let client = UnixSocketRunnerClient::new(&invocation.global.socket_path);
            execute_invocation(&invocation, &client)
        }
        Err(err) => err.to_error_envelope("cli", "parse"),
    }
}

/// Executes a parsed [`ParsedInvocation`] using the supplied [`RunnerClientTransport`].
pub fn execute_invocation(
    invocation: &ParsedInvocation,
    transport: &dyn RunnerClientTransport,
) -> CliResponseEnvelope {
    let domain = invocation.command.domain_name();
    let action = invocation.command.action_name();
    match execute_command_inner(&invocation.global, &invocation.command, transport) {
        Ok(envelope) => envelope,
        Err(err) => err.to_error_envelope(domain, action),
    }
}

fn execute_command_inner(
    global: &GlobalOptions,
    command: &AfCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match command {
        AfCommand::Help { topic } => {
            let text = render_help_text(*topic);
            Ok(CliResponseEnvelope::success(
                "help",
                "help",
                text,
                Some(json!({ "topic": topic })),
            ))
        }
        AfCommand::Version => {
            let ver = env!("CARGO_PKG_VERSION");
            let msg = format!(
                "af (af-cli) v{} ({}/{}) - AetherFlow Bare-Metal Control Plane CLI",
                ver,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(CliResponseEnvelope::success(
                "version",
                "version",
                msg,
                Some(json!({
                    "name": "af-cli",
                    "binary": "af",
                    "version": ver,
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                })),
            ))
        }
        AfCommand::Health => {
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "health",
                    "check",
                    format!(
                        "[DRY-RUN] Would check /v1/health on runner socket {}",
                        global.socket_path.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "socket_path": global.socket_path,
                    })),
                ));
            }
            let resp = transport.check_health()?;
            Ok(CliResponseEnvelope::success(
                "health",
                "check",
                format!(
                    "Privileged runner healthy ({}): {}",
                    global.socket_path.display(),
                    resp.output.trim()
                ),
                Some(json!({
                    "socket_path": global.socket_path,
                    "runner_response": resp,
                })),
            ))
        }
        AfCommand::Package(pkg_cmd) => execute_package_command(global, pkg_cmd, transport),
        AfCommand::Service(svc_cmd) => execute_service_command(global, svc_cmd, transport),
        AfCommand::Quota(quota_cmd) => execute_quota_command(global, quota_cmd, transport),
        AfCommand::Sandbox(sbx_cmd) => execute_sandbox_command(global, sbx_cmd, transport),
        AfCommand::Release(rel_cmd) => execute_release_command(global, rel_cmd, transport),
        AfCommand::Backup(bak_cmd) => execute_backup_command(global, bak_cmd),
        AfCommand::Provision(prov_cmd) => execute_provision_command(global, prov_cmd),
        AfCommand::Maintenance(maint_cmd) => execute_maintenance_command(global, maint_cmd),
        AfCommand::Hosts(hosts_cmd) => execute_hosts_command(global, hosts_cmd, transport),
    }
}

fn execute_hosts_command(
    global: &GlobalOptions,
    cmd: &HostsCliCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    let req = build_hosts_runner_request(cmd)?;
    if global.dry_run {
        return Ok(CliResponseEnvelope::success(
            "hosts",
            cmd.action_name(),
            format!("[DRY-RUN] Would dispatch hosts {} to /v1/hosts", req.action),
            Some(json!({ "dry_run": true, "request": req })),
        ));
    }

    let resp = transport.execute_hosts(&req)?;
    let msg = if resp.output.trim().is_empty() {
        format!("Hosts {} completed", req.action)
    } else {
        format!("Hosts {} completed: {}", req.action, resp.output.trim())
    };
    Ok(CliResponseEnvelope::success(
        "hosts",
        cmd.action_name(),
        msg,
        Some(json!({
            "request": req,
            "runner_response": resp,
        })),
    ))
}

fn execute_maintenance_command(
    global: &GlobalOptions,
    cmd: &MaintenanceCliCommand,
) -> CliResult<CliResponseEnvelope> {
    match cmd {
        MaintenanceCliCommand::Tune { root, dry_run } => {
            let effective_root = root
                .as_deref()
                .or(global.root.as_deref())
                .unwrap_or_else(|| Path::new("/"));
            let is_dry_run = *dry_run || global.dry_run;
            let report = apply_network_tuning(effective_root, is_dry_run)?;
            let msg = if is_dry_run {
                format!(
                    "[DRY-RUN] Would apply sysctl network tuning to {}",
                    report.config_path.display()
                )
            } else {
                format!(
                    "Applied sysctl network tuning configuration to {}",
                    report.config_path.display()
                )
            };
            Ok(CliResponseEnvelope::success(
                "maintenance",
                "tune",
                msg,
                Some(json!(report)),
            ))
        }
        MaintenanceCliCommand::Sentinel {
            log_path,
            threshold,
        } => {
            let path = log_path.clone().unwrap_or_else(|| {
                if let Some(ref r) = global.root {
                    r.join("var/log/auth.log")
                } else {
                    PathBuf::from("/var/log/auth.log")
                }
            });
            let report = sentinel_scan_auth_log(&path, *threshold)?;
            let msg = format!(
                "Sentinel scanned {} lines in {}: {} failed event(s), {} offending IP(s) exceeding threshold {}",
                report.scanned_lines,
                report.log_path.display(),
                report.failed_event_count,
                report.offending_ips.len(),
                report.threshold,
            );
            Ok(CliResponseEnvelope::success(
                "maintenance",
                "sentinel",
                msg,
                Some(json!(report)),
            ))
        }
        MaintenanceCliCommand::CleanLogs {
            root,
            max_size_bytes,
            dry_run,
        } => {
            let effective_root = root
                .as_deref()
                .or(global.root.as_deref())
                .unwrap_or_else(|| Path::new("/"));
            let is_dry_run = *dry_run || global.dry_run;
            let max_size = max_size_bytes.unwrap_or(10 * 1024 * 1024);
            let report = clean_system_logs(effective_root, max_size, is_dry_run)?;
            let msg = format!(
                "Cleaned {} log file(s) across {} directories, freed {} bytes (dry_run={})",
                report.cleaned_files.len(),
                report.scanned_directories.len(),
                report.total_bytes_freed,
                report.dry_run,
            );
            Ok(CliResponseEnvelope::success(
                "maintenance",
                "clean-logs",
                msg,
                Some(json!(report)),
            ))
        }
        MaintenanceCliCommand::Showspace { root, user } => {
            let effective_root = root
                .as_deref()
                .or(global.root.as_deref())
                .unwrap_or_else(|| Path::new("/"));
            let entries = inspect_home_disk_space(effective_root)?;
            let filtered: Vec<_> = if let Some(ref u) = user {
                entries.into_iter().filter(|e| &e.user == u).collect()
            } else {
                entries
            };
            let mut lines = vec![format!("Home disk space usage ({} users):", filtered.len())];
            for e in &filtered {
                lines.push(format!(
                    "{:>10} {}/ ({})",
                    e.human,
                    e.user,
                    e.home_path.display()
                ));
            }
            Ok(CliResponseEnvelope::success(
                "maintenance",
                "showspace",
                lines.join("\n"),
                Some(json!(filtered)),
            ))
        }
        MaintenanceCliCommand::OwnershipRegistry => {
            let reg = maintenance_helper_ownership_registry();
            let mut lines = vec![format!(
                "AetherFlow Host Maintenance Helper Ownership ({} entries):",
                reg.len()
            )];
            for item in reg {
                lines.push(format!(
                    "  {} -> {:?} ({})",
                    item.script_path, item.owner, item.rust_replacement_or_entry
                ));
            }
            Ok(CliResponseEnvelope::success(
                "maintenance",
                "ownership",
                lines.join("\n"),
                Some(json!(reg)),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 1: Package Management (`/v1/package`, `/v1/package/cancel`, `/install/.<pkg>.lock`)
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_cli_package_definition(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Option<af_models::Package> {
    let lock_name = resolve_package_lock_name(pkg_id);
    get_runner_package_definition_in_root(lock_name, global.root.as_deref())
        .or_else(|| get_runner_package_definition_in_root(pkg_id.trim(), global.root.as_deref()))
}

fn resolve_install_lock_dir(global: &GlobalOptions) -> PathBuf {
    let fs_root = af_models::resolve_package_fs_root(global.root.as_deref());
    af_models::resolve_path_for_fs_root("/install", fs_root.as_deref())
}

fn resolve_swizzin_lock_dir(global: &GlobalOptions) -> PathBuf {
    let fs_root = af_models::resolve_package_fs_root(global.root.as_deref());
    af_models::resolve_path_for_fs_root("/etc/Swizzin", fs_root.as_deref())
}

fn inspect_cli_package_receipts_for_def(
    global: &GlobalOptions,
    pkg_id: &str,
    def: Option<&af_models::Package>,
) -> CliResult<af_models::PackageReceiptStatus> {
    let explicit_lock = def
        .map(|d| d.lock_file.as_str())
        .filter(|s| !s.trim().is_empty());
    af_models::inspect_package_receipts(pkg_id, explicit_lock, global.root.as_deref())
        .map_err(CliError::PreflightOrIntegrity)
}

fn inspect_cli_package_receipts(
    global: &GlobalOptions,
    pkg_id: &str,
) -> CliResult<af_models::PackageReceiptStatus> {
    let def = resolve_cli_package_definition(global, pkg_id);
    inspect_cli_package_receipts_for_def(global, pkg_id, def.as_ref())
}

fn query_persisted_ingress_port_from_sqlite(db_path: &Path, app_name: &str) -> Option<i32> {
    if !db_path.is_file() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    if let Ok(port) = conn.query_row(
        "SELECT listen_port FROM app_ingress_configs WHERE LOWER(app_name) = LOWER(?1) LIMIT 1",
        [app_name],
        |r| r.get::<_, i32>(0),
    ) {
        if (1024..=65535).contains(&port) {
            return Some(port);
        }
    }
    if let Ok(json_raw) = conn.query_row(
        "SELECT config_json FROM retained_app_ingress_configs WHERE LOWER(app_name) = LOWER(?1) LIMIT 1",
        [app_name],
        |r| r.get::<_, String>(0),
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_raw) {
            if let Some(port) = val
                .get("listen_port")
                .and_then(|v| v.as_i64())
                .and_then(|p| i32::try_from(p).ok())
            {
                if (1..=65535).contains(&port) {
                    return Some(port);
                }
            }
        }
    }
    None
}

fn candidate_cli_sqlite_dbs(global: &GlobalOptions) -> Vec<PathBuf> {
    af_runner::candidate_package_sqlite_dbs(global.root.as_deref())
}

fn query_app_update_target_version_from_sqlite(db_path: &Path, pkg_id: &str) -> Option<String> {
    if !db_path.is_file() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let with_err_sql = "SELECT COALESCE(latest_version, ''), COALESCE(last_error, '') FROM app_updates WHERE LOWER(package_name) = LOWER(?1) LIMIT 1";
    let fallback_sql = "SELECT COALESCE(latest_version, ''), '' FROM app_updates WHERE LOWER(package_name) = LOWER(?1) LIMIT 1";
    let (latest, last_error) = match conn.query_row(with_err_sql, [pkg_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    }) {
        Ok(pair) => pair,
        Err(err) if err.to_string().contains("no such column") => conn
            .query_row(fallback_sql, [pkg_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .ok()?,
        Err(_) => return None,
    };
    if !last_error.trim().is_empty() {
        return None;
    }
    normalize_discovered_target_version(&latest)
}

fn normalize_discovered_target_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = if (trimmed.starts_with('v') || trimmed.starts_with('V'))
        && trimmed[1..].starts_with(|c: char| c.is_ascii_digit())
    {
        &trimmed[1..]
    } else {
        trimmed
    };
    if af_release::lifecycle::validate_target_version(stripped) {
        Some(stripped.to_string())
    } else if af_release::lifecycle::validate_target_version(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn decode_chunked_http_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < raw.len() {
        let Some(rel_end) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let line = String::from_utf8_lossy(&raw[idx..idx + rel_end]);
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        idx += rel_end + 2;
        if chunk_len == 0 || idx + chunk_len > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[idx..idx + chunk_len]);
        idx += chunk_len;
        if raw[idx..].starts_with(b"\r\n") {
            idx += 2;
        }
    }
    out
}

fn http_get_text(url: &str) -> Result<String, String> {
    if let Some(rest) = url.strip_prefix("http://") {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        let (authority, path_part) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, "/"),
        };
        let host_port = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };
        let addr = host_port
            .to_socket_addrs()
            .map_err(|e| format!("failed to resolve {host_port}: {e}"))?
            .next()
            .ok_or_else(|| format!("no socket address resolved for {host_port}"))?;
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("failed to connect to {host_port}: {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let req = format!(
            "GET {path_part} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: AetherFlow-CLI\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("failed writing HTTP request to {host_port}: {e}"))?;
        let mut buf = Vec::new();
        stream
            .take(2 * 1024 * 1024)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading HTTP response from {host_port}: {e}"))?;
        let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Err(format!("malformed HTTP response from {host_port}"));
        };
        let headers = String::from_utf8_lossy(&buf[..hdr_end]);
        let status_line = headers.lines().next().unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status_code) {
            return Err(format!("upstream HTTP {status_code} from {url}"));
        }
        let body_bytes = &buf[hdr_end + 4..];
        let decoded = if headers.lines().any(|l| {
            l.to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
        }) {
            decode_chunked_http_body(body_bytes)
        } else {
            body_bytes.to_vec()
        };
        return String::from_utf8(decoded)
            .map_err(|e| format!("non-UTF8 upstream response from {url}: {e}"));
    }

    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "-fsSL",
        "--max-time",
        "8",
        "-H",
        "Accept: application/json",
        "-A",
        "AetherFlow-CLI",
    ]);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() && url.contains("github.com") {
            cmd.arg("-H")
                .arg(format!("Authorization: Bearer {trimmed}"));
        }
    }
    let output = cmd
        .arg(url)
        .output()
        .map_err(|e| format!("failed to execute curl for upstream discovery: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "upstream request to {url} failed ({})",
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("invalid UTF-8 from upstream {url}: {e}"))
}

fn load_package_automation_spec(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Result<serde_json::Value, String> {
    let mut candidate_paths = Vec::new();
    if let Some(ref root) = global.root {
        candidate_paths.push(root.join("opt/AetherFlow/config/package_automation.json"));
        candidate_paths.push(root.join("etc/aetherflow/package_automation.json"));
        candidate_paths.push(root.join("config/package_automation.json"));
    } else {
        if let Ok(custom) = std::env::var("AETHERFLOW_PACKAGE_AUTOMATION_PATH") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                candidate_paths.push(PathBuf::from(trimmed));
            }
        }
        candidate_paths.push(PathBuf::from(
            "/opt/AetherFlow/config/package_automation.json",
        ));
        candidate_paths.push(PathBuf::from("/etc/aetherflow/package_automation.json"));
        candidate_paths.push(PathBuf::from("config/package_automation.json"));
    }

    let raw_catalog = candidate_paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            if global.root.is_none() {
                Some(include_str!("../../../../config/package_automation.json").to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| "no package_automation.json catalog available".to_string())?;

    let parsed: serde_json::Value = serde_json::from_str(&raw_catalog)
        .map_err(|e| format!("invalid package_automation.json: {e}"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| "package_automation.json root must be an object".to_string())?;

    let lock_name = resolve_package_lock_name(pkg_id);
    for candidate_key in [pkg_id, lock_name] {
        if let Some((_, v)) = obj
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(candidate_key))
        {
            return Ok(v.clone());
        }
    }
    Err(format!(
        "package '{}' has no upstream automation entry",
        pkg_id
    ))
}

fn spec_non_empty_str<'a>(spec: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    spec.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn resolve_cli_upstream_api_base(spec: &serde_json::Value, env_var: &str, default: &str) -> String {
    spec_non_empty_str(spec, "api_base_url")
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var(env_var)
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| default.to_string())
}

fn discover_latest_github_tag(
    api_base: &str,
    repo: &str,
    missing_label: &str,
    invalid_label: &str,
) -> Result<String, String> {
    let tags_url = format!("{api_base}/repos/{repo}/tags?per_page=1");
    let body = http_get_text(&tags_url)?;
    let val: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("invalid JSON from {tags_url}: {e}"))?;
    let tag = val
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no {missing_label} found for {repo}"))?;
    normalize_discovered_target_version(tag)
        .ok_or_else(|| format!("invalid {invalid_label} {:?} for {repo}", tag))
}

fn discover_listenarr_github_target_for_arch(
    api_base: &str,
    repo: &str,
    channel: &str,
    host_arch: &str,
) -> Result<String, String> {
    let asset_suffix = af_runner::listenarr_release_asset_suffix_for_arch(host_arch)?;
    let effective_channel = if channel.trim().eq_ignore_ascii_case("prerelease") {
        "prerelease"
    } else {
        "stable"
    };
    let is_stable = effective_channel == "stable";

    const PAGE_SIZE: usize = 100;
    const MAX_PAGES: usize = 10;
    let mut all_releases: Vec<serde_json::Value> = Vec::new();
    for page in 1..=MAX_PAGES {
        let releases_url =
            format!("{api_base}/repos/{repo}/releases?per_page={PAGE_SIZE}&page={page}");
        let body = http_get_text(&releases_url)?;
        let val: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("invalid JSON from {releases_url}: {e}"))?;
        let page_items: Vec<serde_json::Value> = match val {
            serde_json::Value::Array(arr) => arr,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => {
                return Err(format!(
                    "unexpected GitHub releases JSON shape from {releases_url}"
                ));
            }
        };
        let page_len = page_items.len();
        all_releases.extend(page_items);
        if page == MAX_PAGES && page_len >= PAGE_SIZE {
            return Err(format!(
                "GitHub release pagination exceeded maximum page limit ({MAX_PAGES}) for '{repo}'"
            ));
        }
        if page_len < PAGE_SIZE {
            break;
        }
    }

    let mut best_candidate: Option<(String, bool)> = None;
    for rel in &all_releases {
        if rel.get("draft").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let rel_prerelease = rel
            .get("prerelease")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_stable && rel_prerelease {
            continue;
        }
        let Some(tag_name) = rel
            .get("tag_name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let Some(version) = normalize_discovered_target_version(tag_name) else {
            continue;
        };
        let is_pre = rel_prerelease || version.contains('-');
        if is_stable && is_pre {
            continue;
        }

        let Some(assets) = rel.get("assets").and_then(|v| v.as_array()) else {
            continue;
        };
        let has_checksum_companion = assets.iter().any(|asset| {
            let name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let url = asset
                .get("browser_download_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            af_runner::listenarr_is_official_checksum_companion(tag_name, name, url)
        });
        let matching_assets: Vec<&serde_json::Value> = assets
            .iter()
            .filter(|asset| {
                asset
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .is_some_and(|name| name.ends_with(asset_suffix))
            })
            .collect();
        if matching_assets.len() != 1 {
            continue;
        }
        let asset = matching_assets[0];
        let asset_name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let asset_url = asset
            .get("browser_download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let asset_digest = asset.get("digest").and_then(|v| v.as_str());
        if !af_runner::listenarr_release_asset_is_eligible(
            tag_name,
            asset_name,
            asset_url,
            asset_digest,
            has_checksum_companion,
            asset_suffix,
        ) {
            continue;
        }

        match &best_candidate {
            None => {
                best_candidate = Some((version, is_pre));
            }
            Some((current_ver, current_is_pre)) => {
                let ord = af_release::lifecycle::compare_versions(&version, current_ver);
                let should_replace = match ord {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => !is_pre && *current_is_pre,
                    std::cmp::Ordering::Less => false,
                };
                if should_replace {
                    best_candidate = Some((version, is_pre));
                }
            }
        }
    }

    best_candidate.map(|(ver, _)| ver).ok_or_else(|| {
        format!(
            "no eligible official Listenarr release found in '{}' on channel '{}' with a verified {} asset for host architecture '{}'",
            repo,
            effective_channel,
            asset_suffix,
            host_arch.trim()
        )
    })
}

fn discover_live_upstream_target_version(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Result<String, String> {
    let spec = load_package_automation_spec(global, pkg_id)?;
    let source = spec_non_empty_str(&spec, "update_source").unwrap_or("");
    let api_base = resolve_cli_upstream_api_base(
        &spec,
        "AETHERFLOW_GITHUB_API_BASE",
        "https://api.github.com",
    );

    match source {
        "retired" => Err(format!(
            "package '{}' is retired upstream and has no active update feed",
            pkg_id
        )),
        "github" | "github_release" => {
            let repo = spec_non_empty_str(&spec, "update_repo")
                .ok_or_else(|| format!("missing update_repo for '{}'", pkg_id))?;
            if resolve_package_lock_name(pkg_id).eq_ignore_ascii_case("listenarr") {
                let channel = spec_non_empty_str(&spec, "update_channel").unwrap_or("prerelease");
                return discover_listenarr_github_target_for_arch(
                    &api_base,
                    repo,
                    channel,
                    std::env::consts::ARCH,
                );
            }
            let release_url = format!("{api_base}/repos/{repo}/releases/latest");
            if let Ok(body) = http_get_text(&release_url) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(tag) = val.get("tag_name").and_then(|v| v.as_str()) {
                        if let Some(ver) = normalize_discovered_target_version(tag) {
                            return Ok(ver);
                        }
                    }
                }
            }
            discover_latest_github_tag(
                &api_base,
                repo,
                "upstream release or tag",
                "upstream tag",
            )
        }
        "git_tags" => {
            let repo = spec_non_empty_str(&spec, "update_repo")
                .ok_or_else(|| format!("missing update_repo for '{}'", pkg_id))?;
            discover_latest_github_tag(&api_base, repo, "upstream git tags", "upstream git tag")
        }
        "pypi" => {
            let pypi_pkg = spec_non_empty_str(&spec, "update_package").unwrap_or(pkg_id);
            let pypi_base =
                resolve_cli_upstream_api_base(&spec, "AETHERFLOW_PYPI_API_BASE", "https://pypi.org");
            let url = format!("{pypi_base}/pypi/{pypi_pkg}/json");
            let body = http_get_text(&url)?;
            let val: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| format!("invalid PyPI JSON: {e}"))?;
            let ver = val
                .get("info")
                .and_then(|i| i.get("version"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing info.version from PyPI for {pypi_pkg}"))?;
            normalize_discovered_target_version(ver)
                .ok_or_else(|| format!("invalid PyPI version {:?} for {pypi_pkg}", ver))
        }
        "git" => {
            let normalize_short_sha =
                |sha: &str| normalize_discovered_target_version(sha.get(..12).unwrap_or(sha));
            if let Some(repo) = spec_non_empty_str(&spec, "update_repo") {
                let url = format!("{api_base}/repos/{repo}/commits/HEAD");
                if let Ok(body) = http_get_text(&url) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(ver) = val
                            .get("sha")
                            .and_then(|v| v.as_str())
                            .and_then(normalize_short_sha)
                        {
                            return Ok(ver);
                        }
                    }
                }
            }
            let repo_url = spec_non_empty_str(&spec, "update_repo_url")
                .ok_or_else(|| format!("missing update_repo_url for '{}'", pkg_id))?;
            let out = std::process::Command::new("git")
                .args(["ls-remote", repo_url, "HEAD"])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .map_err(|e| format!("git ls-remote failed for {repo_url}: {e}"))?;
            if !out.status.success() {
                return Err(format!("git ls-remote returned error for {repo_url}"));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let sha = stdout
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("empty git ls-remote output for {repo_url}"))?;
            normalize_short_sha(sha)
                .ok_or_else(|| format!("invalid git commit SHA {:?} for {repo_url}", sha))
        }
        "apt" => {
            if global.root.is_some() {
                return Err(format!(
                    "live apt candidate discovery is disabled under isolated --root for '{}'",
                    pkg_id
                ));
            }
            let apt_pkg = spec_non_empty_str(&spec, "update_package").unwrap_or(pkg_id);
            let out = std::process::Command::new("apt-cache")
                .args(["policy", apt_pkg])
                .output()
                .map_err(|e| format!("apt-cache policy failed for {apt_pkg}: {e}"))?;
            if !out.status.success() {
                return Err(format!("apt-cache policy returned non-zero for {apt_pkg}"));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            af_release::lifecycle::parse_apt_policy_candidate(&stdout)
                .and_then(normalize_discovered_target_version)
                .ok_or_else(|| format!("no apt candidate version available for {apt_pkg}"))
        }
        "vendor" => Err(format!(
            "package '{}' uses a multi-component vendor installer and does not support exact-version updates; use reinstall or the vendor updater instead",
            pkg_id
        )),
        "pinned" => spec_non_empty_str(&spec, "update_package")
            .and_then(normalize_discovered_target_version)
            .ok_or_else(|| {
                format!(
                    "package '{}' uses a pinned upstream source with no dynamic target version",
                    pkg_id
                )
            }),
        other => Err(format!(
            "unsupported upstream update_source {:?} for '{}'",
            other, pkg_id
        )),
    }
}

fn validate_cli_package_target_policy(
    global: &GlobalOptions,
    pkg_id: &str,
    action: &str,
    target_version: Option<&str>,
) -> CliResult<()> {
    let lock_name = resolve_package_lock_name(pkg_id);
    let Ok(spec) = load_package_automation_spec(global, pkg_id) else {
        if lock_name.eq_ignore_ascii_case("listenarr") {
            af_runner::validate_package_target_policy(
                lock_name,
                "github",
                "",
                action,
                target_version,
            )
            .map_err(CliError::Validation)?;
        }
        return Ok(());
    };
    let source = spec_non_empty_str(&spec, "update_source").unwrap_or("");
    let update_package = spec_non_empty_str(&spec, "update_package").unwrap_or("");
    af_runner::validate_package_target_policy(
        lock_name,
        source,
        update_package,
        action,
        target_version,
    )
    .map_err(CliError::Validation)
}

fn resolve_cli_package_target_version(
    global: &GlobalOptions,
    pkg_id: &str,
    explicit_target: Option<&str>,
    _transport: &dyn RunnerClientTransport,
) -> CliResult<String> {
    let validate_explicit = |raw: &str, label: &str| -> CliResult<String> {
        let trimmed = raw.trim();
        if !af_release::lifecycle::validate_target_version(trimmed) {
            return Err(CliError::Validation(format!(
                "invalid {label} {:?} (must be a concrete version, commit SHA, or component manifest)",
                raw
            )));
        }
        validate_cli_package_target_policy(global, pkg_id, "update", Some(trimmed))?;
        Ok(trimmed.to_string())
    };

    if let Some(explicit) = explicit_target {
        return validate_explicit(explicit, "--target-version");
    }

    if let Ok(env_target) = std::env::var("AF_TARGET_VERSION") {
        if !env_target.trim().is_empty() {
            return validate_explicit(&env_target, "AF_TARGET_VERSION");
        }
    }

    let lock_name = resolve_package_lock_name(pkg_id);
    if lock_name == "threadfin" {
        return af_runner::validate_threadfin_target_policy(None)
            .map(|(version, _)| version)
            .map_err(|error| CliError::Validation(error.to_string()));
    }
    validate_cli_package_target_policy(global, pkg_id, "update", None)?;

    for db_path in candidate_cli_sqlite_dbs(global) {
        if let Some(ver) = query_app_update_target_version_from_sqlite(&db_path, lock_name)
            .or_else(|| query_app_update_target_version_from_sqlite(&db_path, pkg_id))
        {
            validate_cli_package_target_policy(global, pkg_id, "update", Some(&ver))?;
            return Ok(ver);
        }
    }

    let discovered = discover_live_upstream_target_version(global, pkg_id).map_err(|reason| {
        CliError::PreflightOrIntegrity(format!(
            "unable to resolve upstream target version for package '{}' ({}); run an update check first to populate app_updates.latest_version or pass '--target-version <version>' explicitly when offline",
            pkg_id, reason
        ))
    })?;
    validate_cli_package_target_policy(global, pkg_id, "update", Some(&discovered))?;
    Ok(discovered)
}

fn resolve_cli_package_port(
    global: &GlobalOptions,
    pkg_id: &str,
    explicit_port: Option<i32>,
) -> Option<i32> {
    if let Some(p) = explicit_port {
        if (1024..=65535).contains(&p) {
            return Some(p);
        }
    }

    let lock_name = resolve_package_lock_name(pkg_id);
    let candidate_dbs = candidate_cli_sqlite_dbs(global);

    for db_path in &candidate_dbs {
        if let Some(p) = query_persisted_ingress_port_from_sqlite(db_path, lock_name)
            .or_else(|| query_persisted_ingress_port_from_sqlite(db_path, pkg_id))
        {
            return Some(p);
        }
    }

    if af_models::resolve_package_fs_root(global.root.as_deref()).is_none() {
        let runtime_meta = af_runner::extract_app_runtime_meta_local(lock_name);
        if (1024..=65535).contains(&runtime_meta.configured_port) {
            return Some(runtime_meta.configured_port);
        }
    }

    let def = resolve_cli_package_definition(global, pkg_id);
    if let Ok(Some(p)) = af_models::read_package_receipt_port(
        pkg_id,
        def.as_ref()
            .map(|d| d.lock_file.as_str())
            .filter(|s| !s.trim().is_empty()),
        global.root.as_deref(),
    ) {
        return Some(p);
    }

    def.map(|def| def.default_port)
        .filter(|p| (1024..=65535).contains(p))
}

fn execute_package_command(
    global: &GlobalOptions,
    cmd: &PackageCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    let install_dir = resolve_install_lock_dir(global);
    let swizzin_dir = resolve_swizzin_lock_dir(global);
    let emit_human_progress = !global.json;

    match cmd {
        PackageCommand::Install { packages, port } => {
            let mut receipts = Vec::new();
            let mut skipped_installed = Vec::new();
            let mut requests = Vec::new();

            for pkg in packages {
                let receipt = inspect_cli_package_receipts(global, pkg)?;
                if receipt.is_installed() {
                    skipped_installed.push(pkg.clone());
                    continue;
                }
                let effective_port = resolve_cli_package_port(global, pkg, *port);
                let action = if receipt.has_legacy_upgrade_receipt() {
                    "reinstall"
                } else {
                    "install"
                };
                let mut req = build_package_runner_request(action, pkg, effective_port)?;
                validate_cli_package_target_policy(
                    global,
                    pkg,
                    action,
                    req.expected_target_version.as_deref(),
                )?;
                if action == "reinstall" {
                    req.delete_data = false;
                }
                if global.dry_run {
                    requests.push(req);
                } else {
                    let receipt = transport.execute_package_streaming(&req, emit_human_progress)?;
                    receipts.push(receipt);
                }
            }

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "package",
                    "install",
                    format!(
                        "[DRY-RUN] Planned install for {} package(s) ({} already installed)",
                        requests.len(),
                        skipped_installed.len()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "planned_requests": requests,
                        "skipped_already_installed": skipped_installed,
                    })),
                ));
            }

            Ok(CliResponseEnvelope::success(
                "package",
                "install",
                format!(
                    "Installed {} package(s) ({} skipped as already installed)",
                    receipts.len(),
                    skipped_installed.len()
                ),
                Some(json!({
                    "receipts": receipts,
                    "skipped_already_installed": skipped_installed,
                })),
            ))
        }
        PackageCommand::Reinstall { packages, port } => {
            let mut receipts = Vec::new();
            let mut requests = Vec::new();

            for pkg in packages {
                let _receipt = inspect_cli_package_receipts(global, pkg)?;
                let effective_port = resolve_cli_package_port(global, pkg, *port);
                let mut req = build_package_runner_request("reinstall", pkg, effective_port)?;
                validate_cli_package_target_policy(
                    global,
                    pkg,
                    "reinstall",
                    req.expected_target_version.as_deref(),
                )?;
                req.delete_data = false;
                if global.dry_run {
                    requests.push(req);
                } else {
                    let receipt = transport.execute_package_streaming(&req, emit_human_progress)?;
                    receipts.push(receipt);
                }
            }

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "package",
                    "reinstall",
                    format!(
                        "[DRY-RUN] Planned reinstall for {} package(s)",
                        requests.len()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "planned_requests": requests,
                    })),
                ));
            }

            Ok(CliResponseEnvelope::success(
                "package",
                "reinstall",
                format!("Reinstalled {} package(s)", receipts.len()),
                Some(json!({
                    "receipts": receipts,
                })),
            ))
        }
        PackageCommand::Remove { packages, purge } => {
            let fs_root = af_models::resolve_package_fs_root(global.root.as_deref());
            let mut receipts = Vec::new();
            let mut skipped_not_installed = Vec::new();
            let mut retained_purge_targets = Vec::new();
            let mut requests = Vec::new();

            // Preflight all requested packages (allowlist, confinement, receipt & retained
            // ownership checks) before executing any live runner mutation.
            for pkg in packages {
                let mut req = build_package_runner_request("remove", pkg, None)?;
                req.delete_data = *purge;

                let def = resolve_cli_package_definition(global, pkg);
                let explicit_lock = def
                    .as_ref()
                    .map(|d| d.lock_file.as_str())
                    .filter(|s| !s.trim().is_empty());

                if !*purge {
                    let receipt =
                        inspect_cli_package_receipts_for_def(global, pkg, def.as_ref())?;
                    // If an isolated root was explicitly supplied or a lock directory
                    // exists on disk and neither canonical nor legacy receipt is present,
                    // report `skipped_not_installed`.
                    let has_lock_root = fs_root.is_some()
                        || install_dir.is_dir()
                        || swizzin_dir.is_dir()
                        || receipt
                            .canonical_path
                            .parent()
                            .is_some_and(|parent| parent.is_dir());
                    if has_lock_root && !receipt.has_any_receipt() {
                        skipped_not_installed.push(pkg.clone());
                        continue;
                    }
                    requests.push(req);
                } else {
                    let inspection = af_runner::inspect_package_purge_state(
                        pkg,
                        explicit_lock,
                        global.root.as_deref(),
                    )
                    .map_err(CliError::PreflightOrIntegrity)?;
                    match inspection.eligibility {
                        af_runner::PackagePurgeEligibility::Installed => {
                            requests.push(req);
                        }
                        af_runner::PackagePurgeEligibility::RetainedProven => {
                            retained_purge_targets.push(json!({
                                "package": pkg,
                                "ownership_evidence": inspection.ownership_evidence,
                            }));
                            requests.push(req);
                        }
                        af_runner::PackagePurgeEligibility::AmbiguousMarkerless => {
                            return Err(CliError::PreflightOrIntegrity(
                                af_runner::format_ambiguous_purge_error(&inspection),
                            ));
                        }
                        af_runner::PackagePurgeEligibility::NotPresent => {
                            skipped_not_installed.push(pkg.clone());
                        }
                    }
                }
            }

            if global.dry_run {
                let msg = if *purge && !retained_purge_targets.is_empty() {
                    format!(
                        "[DRY-RUN] Planned purge for {} package(s) ({} retained, {} not installed)",
                        requests.len(),
                        retained_purge_targets.len(),
                        skipped_not_installed.len()
                    )
                } else {
                    format!(
                        "[DRY-RUN] Planned remove for {} package(s) ({} not installed)",
                        requests.len(),
                        skipped_not_installed.len()
                    )
                };
                let mut payload = json!({
                    "dry_run": true,
                    "planned_requests": requests,
                    "skipped_not_installed": skipped_not_installed,
                });
                if !retained_purge_targets.is_empty() {
                    payload["retained_purge_targets"] = json!(retained_purge_targets);
                }
                return Ok(CliResponseEnvelope::success(
                    "package",
                    "remove",
                    msg,
                    Some(payload),
                ));
            }

            for req in &requests {
                let receipt = transport.execute_package_streaming(req, emit_human_progress)?;
                receipts.push(receipt);
            }

            let msg = if *purge && !retained_purge_targets.is_empty() {
                format!(
                    "Purged {} package(s) ({} retained, {} skipped as not installed)",
                    receipts.len(),
                    retained_purge_targets.len(),
                    skipped_not_installed.len()
                )
            } else {
                format!(
                    "Removed {} package(s) ({} skipped as not installed)",
                    receipts.len(),
                    skipped_not_installed.len()
                )
            };
            let mut payload = json!({
                "receipts": receipts,
                "skipped_not_installed": skipped_not_installed,
            });
            if !retained_purge_targets.is_empty() {
                payload["retained_purge_targets"] = json!(retained_purge_targets);
            }

            Ok(CliResponseEnvelope::success(
                "package",
                "remove",
                msg,
                Some(payload),
            ))
        }
        PackageCommand::Update {
            package,
            channel,
            target_version,
        } => {
            if let Some(ref pkg) = package {
                let effective_port = resolve_cli_package_port(global, pkg, None);
                let resolved_target = resolve_cli_package_target_version(
                    global,
                    pkg,
                    target_version.as_deref(),
                    transport,
                )?;
                let req = build_package_runner_request_with_target(
                    "update",
                    pkg,
                    effective_port,
                    Some(resolved_target),
                )?;
                if global.dry_run {
                    return Ok(CliResponseEnvelope::success(
                        "package",
                        "update",
                        format!("[DRY-RUN] Would update package '{}'", pkg),
                        Some(json!({ "dry_run": true, "request": req })),
                    ));
                }
                let receipt = transport.execute_package_streaming(&req, emit_human_progress)?;
                Ok(CliResponseEnvelope::success(
                    "package",
                    "update",
                    format!("Updated package '{}'", pkg),
                    Some(json!({ "receipt": receipt })),
                ))
            } else {
                ensure_runner_release_dispatch_has_no_local_overrides(
                    global,
                    None,
                    None,
                    None,
                    None,
                    "af update",
                )?;
                let req = build_self_update_runner_request("deploy", *channel)?;
                if global.dry_run {
                    return Ok(CliResponseEnvelope::success(
                        "package",
                        "update",
                        format!(
                            "[DRY-RUN] Would trigger control-plane self-update on channel '{}'",
                            channel.as_str()
                        ),
                        Some(json!({ "dry_run": true, "request": req })),
                    ));
                }
                let resp = transport.execute_self_update(&req)?;
                Ok(CliResponseEnvelope::success(
                    "package",
                    "update",
                    format!(
                        "Control-plane update initiated on channel '{}': {}",
                        channel.as_str(),
                        resp.output.trim()
                    ),
                    Some(json!({ "request": req, "runner_response": resp })),
                ))
            }
        }
        PackageCommand::Upgrade { channel } => {
            ensure_runner_release_dispatch_has_no_local_overrides(
                global,
                None,
                None,
                None,
                None,
                "af upgrade",
            )?;
            let req = build_self_update_runner_request("deploy", *channel)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "package",
                    "upgrade",
                    format!(
                        "[DRY-RUN] Would trigger control-plane upgrade on channel '{}'",
                        channel.as_str()
                    ),
                    Some(json!({ "dry_run": true, "request": req })),
                ));
            }
            let resp = transport.execute_self_update(&req)?;
            Ok(CliResponseEnvelope::success(
                "package",
                "upgrade",
                format!(
                    "Control-plane upgrade initiated on channel '{}': {}",
                    channel.as_str(),
                    resp.output.trim()
                ),
                Some(json!({ "request": req, "runner_response": resp })),
            ))
        }
        PackageCommand::List { installed_only } => {
            let mut entries = Vec::new();
            for &raw_id in KNOWN_CLI_PACKAGE_IDS {
                let id = raw_id.trim();
                if let Some(def) = get_runner_package_definition_in_root(id, global.root.as_deref())
                {
                    let lock_name = resolve_package_lock_name(id).to_string();
                    let receipt = inspect_cli_package_receipts_for_def(global, id, Some(&def))?;
                    let installed = receipt.is_installed();
                    let retained_lock_path = receipt
                        .retained_receipt_present
                        .then_some(receipt.retained_path.clone());
                    let legacy_lock_path = receipt
                        .legacy_receipt_present
                        .then_some(receipt.legacy_path)
                        .flatten();
                    if *installed_only && !installed {
                        continue;
                    }
                    entries.push(PackageListEntry {
                        package_id: def.name,
                        lock_name,
                        lock_path: receipt.canonical_path,
                        installed,
                        retained_receipt_present: receipt.retained_receipt_present,
                        retained_lock_path,
                        legacy_receipt_present: receipt.legacy_receipt_present,
                        legacy_lock_path,
                        service_name: def.service_name,
                        sandbox_profile: def.sandbox_profile,
                    });
                }
            }

            let installed_count = entries.iter().filter(|e| e.installed).count();
            let mut lines = vec![format!(
                "Packages ({} installed / {} total):",
                installed_count,
                entries.len()
            )];
            for item in &entries {
                let badge = if item.installed {
                    "[INSTALLED]"
                } else {
                    "[AVAILABLE]"
                };
                if !item.installed && item.legacy_receipt_present {
                    lines.push(format!(
                        "  {:<13} {:<20} (service: {}, legacy receipt pending upgrade)",
                        badge, item.package_id, item.service_name
                    ));
                } else if !item.installed && item.retained_receipt_present {
                    lines.push(format!(
                        "  {:<13} {:<20} (service: {}, retained config/data; use --purge to delete)",
                        badge, item.package_id, item.service_name
                    ));
                } else {
                    lines.push(format!(
                        "  {:<13} {:<20} (service: {})",
                        badge, item.package_id, item.service_name
                    ));
                }
            }

            Ok(CliResponseEnvelope::success(
                "package",
                "list",
                lines.join("\n"),
                Some(json!({
                    "installed_count": installed_count,
                    "total_count": entries.len(),
                    "packages": entries,
                })),
            ))
        }
        PackageCommand::Info { package } => {
            let def = resolve_cli_package_definition(global, package)
                .ok_or_else(|| CliError::Validation(format!("unknown package {:?}", package)))?;
            let explicit_lock = (!def.lock_file.trim().is_empty()).then_some(def.lock_file.as_str());
            let inspection = af_runner::inspect_package_purge_state(
                package,
                explicit_lock,
                global.root.as_deref(),
            )
            .map_err(CliError::PreflightOrIntegrity)?;
            let receipt = &inspection.receipt_status;
            let installed = receipt.is_installed();
            let retained_lock_path = receipt
                .retained_receipt_present
                .then_some(receipt.retained_path.clone());
            let legacy_lock_path = receipt
                .legacy_receipt_present
                .then_some(receipt.legacy_path.clone())
                .flatten();
            let msg = if !installed && receipt.legacy_receipt_present {
                format!(
                    "Package: {} (installed: false, legacy_receipt: true, service: {}, sandbox_profile: {})",
                    def.name, def.service_name, def.sandbox_profile
                )
            } else if !installed && inspection.is_retained_purge() {
                format!(
                    "Package: {} (installed: false, retained: true, service: {}, sandbox_profile: {})",
                    def.name, def.service_name, def.sandbox_profile
                )
            } else {
                format!(
                    "Package: {} (installed: {}, service: {}, sandbox_profile: {})",
                    def.name, installed, def.service_name, def.sandbox_profile
                )
            };
            let mut payload = json!({
                "package": def,
                "lock_path": receipt.canonical_path,
                "installed": installed,
                "retained_receipt_present": receipt.retained_receipt_present,
                "retained_lock_path": retained_lock_path,
                "legacy_receipt_present": receipt.legacy_receipt_present,
                "legacy_lock_path": legacy_lock_path,
                "purge_eligibility": inspection.eligibility,
            });
            if !inspection.ownership_evidence.is_empty() {
                payload["retained_ownership_evidence"] = json!(inspection.ownership_evidence);
            }
            if !inspection.ambiguous_paths.is_empty() {
                payload["ambiguous_markerless_paths"] = json!(inspection.ambiguous_paths);
            }
            Ok(CliResponseEnvelope::success(
                "package",
                "info",
                msg,
                Some(payload),
            ))
        }
        PackageCommand::Cancel { package } => {
            let req = build_sandbox_runner_request(package)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "package",
                    "cancel",
                    format!(
                        "[DRY-RUN] Would signal cancellation for package '{}'",
                        package
                    ),
                    Some(json!({ "dry_run": true, "request": req })),
                ));
            }
            let resp = transport.cancel_package(&req)?;
            Ok(CliResponseEnvelope::success(
                "package",
                "cancel",
                format!(
                    "Package cancellation for '{}': {}",
                    package,
                    resp.output.trim()
                ),
                Some(json!({ "request": req, "runner_response": resp })),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 2: Systemd Service Control (`/v1/systemctl`)
// ─────────────────────────────────────────────────────────────────────────────

fn execute_service_command(
    global: &GlobalOptions,
    cmd: &ServiceCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    let req = cmd.to_runner_request()?;
    if global.dry_run {
        return Ok(CliResponseEnvelope::success(
            "service",
            cmd.action_name(),
            format!(
                "[DRY-RUN] Would dispatch systemctl {} {}",
                req.action, req.service
            ),
            Some(json!({ "dry_run": true, "request": req })),
        ));
    }

    let resp = transport.execute_systemctl(&req)?;
    let detail = if resp.output.trim().is_empty() {
        format!("systemctl {} {} succeeded", req.action, req.service)
    } else {
        format!(
            "systemctl {} {} succeeded:\n{}",
            req.action,
            req.service,
            resp.output.trim()
        )
    };

    Ok(CliResponseEnvelope::success(
        "service",
        cmd.action_name(),
        detail,
        Some(json!({
            "request": req,
            "runner_response": resp,
        })),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 3: User Disk Quota Management (`/v1/quota` & `af_runner` block parser)
// ─────────────────────────────────────────────────────────────────────────────

fn execute_quota_command(
    global: &GlobalOptions,
    cmd: &QuotaCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match cmd {
        QuotaCommand::Set { username, size } => {
            let (req, blocks_1k) = build_quota_runner_request(username, size)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "quota",
                    "set",
                    format!(
                        "[DRY-RUN] Would set quota for user '{}' to '{}' ({} 1K blocks)",
                        req.username, req.size, blocks_1k
                    ),
                    Some(json!({
                        "dry_run": true,
                        "request": req,
                        "blocks_1k": blocks_1k,
                    })),
                ));
            }

            let resp = transport.execute_quota(&req)?;
            Ok(CliResponseEnvelope::success(
                "quota",
                "set",
                format!(
                    "Quota applied for user '{}' -> '{}' ({} 1K blocks)",
                    req.username, req.size, blocks_1k
                ),
                Some(json!({
                    "request": req,
                    "blocks_1k": blocks_1k,
                    "runner_response": resp,
                })),
            ))
        }
        QuotaCommand::CheckSize { size } => {
            let (blocks_1k, bytes) = parse_quota_size_to_1k_blocks(size).ok_or_else(|| {
                CliError::Validation(format!(
                    "invalid quota size {:?} (expected e.g. 50G, 500M, 1T)",
                    size
                ))
            })?;
            Ok(CliResponseEnvelope::success(
                "quota",
                "check-size",
                format!("Quota size '{}' = {} 1K blocks", size, blocks_1k),
                Some(json!({
                    "size": size,
                    "blocks_1k": blocks_1k,
                    "bytes": bytes,
                })),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 4: Systemd Sandbox Drop-In Management (`/v1/sandbox` & `af_runner`)
// ─────────────────────────────────────────────────────────────────────────────

fn execute_sandbox_command(
    global: &GlobalOptions,
    cmd: &SandboxCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match cmd {
        SandboxCommand::Apply { package } => {
            let req = build_sandbox_runner_request(package)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "sandbox",
                    "apply",
                    format!(
                        "[DRY-RUN] Would apply systemd sandbox drop-in for '{}'",
                        req.package_id
                    ),
                    Some(json!({ "dry_run": true, "request": req })),
                ));
            }
            let resp = transport.execute_sandbox(&req)?;
            Ok(CliResponseEnvelope::success(
                "sandbox",
                "apply",
                format!(
                    "Systemd sandbox for '{}': {}",
                    req.package_id,
                    resp.output.trim()
                ),
                Some(json!({
                    "request": req,
                    "runner_response": resp,
                })),
            ))
        }
        SandboxCommand::Render { package, username } => {
            let def = get_runner_package_definition(package);
            let profile = def
                .as_ref()
                .filter(|d| !d.sandbox_profile.is_empty())
                .map(|d| d.sandbox_profile.as_str())
                .unwrap_or("native");
            let unit = def
                .as_ref()
                .filter(|d| !d.service_name.is_empty())
                .map(|d| d.service_name.as_str())
                .unwrap_or(package.as_str());
            let mut rw_paths = def
                .as_ref()
                .map(|d| d.sandbox_read_write.clone())
                .unwrap_or_else(|| vec![format!("/var/lib/{}", package)]);
            if let Some(ref user) = username {
                rw_paths = rw_paths
                    .into_iter()
                    .map(|p| {
                        p.replace("{{SERVICE_USER}}", user)
                            .replace("{{MASTER_USER}}", user)
                    })
                    .collect();
            }
            let dropin = render_systemd_sandbox_dropin(profile, unit, &rw_paths);
            Ok(CliResponseEnvelope::success(
                "sandbox",
                "render",
                dropin.trim_end().to_string(),
                Some(json!({
                    "package": package,
                    "profile": profile,
                    "unit": unit,
                    "read_write_paths": rw_paths,
                    "dropin_content": dropin,
                })),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 5: Release Engine & Self-Update (`af-release` + `/v1/self-update`)
// ─────────────────────────────────────────────────────────────────────────────

fn load_release_config(
    global: &GlobalOptions,
    explicit_conf: Option<&Path>,
    keep_releases_override: Option<usize>,
) -> CliResult<ReleaseConfig> {
    let conf_to_use = explicit_conf
        .map(Path::to_path_buf)
        .or_else(|| af_release::resolve_release_manager_conf_for_root(global.root.as_deref()));
    let mut cfg = ReleaseConfig::load_for_root_from_process_env(
        global.root.as_deref(),
        conf_to_use.as_deref(),
    )?;

    if let Some(keep) = keep_releases_override {
        cfg.max_releases = keep;
    }

    Ok(cfg)
}

fn resolve_local_self_update_status_context(
    explicit_status_file: Option<&Path>,
    explicit_job_unit: Option<&str>,
) -> (Option<PathBuf>, String) {
    let status_file = explicit_status_file.map(Path::to_path_buf).or_else(|| {
        std::env::var("AETHERFLOW_SELF_UPDATE_STATUS_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    });
    let unit_name = explicit_job_unit
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("AETHERFLOW_SELF_UPDATE_JOB_UNIT")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default();
    (status_file, unit_name)
}

fn execute_local_release_with_status_receipt(
    global: &GlobalOptions,
    cmd: &ReleaseCliCommand,
    config_path: Option<&Path>,
    keep_releases: Option<usize>,
    explicit_status_file: Option<&Path>,
    explicit_job_unit: Option<&str>,
) -> CliResult<CliResponseEnvelope> {
    let action_str = cmd.action_name();
    let (status_file, unit_name) =
        resolve_local_self_update_status_context(explicit_status_file, explicit_job_unit);

    if let Some(ref path) = status_file {
        af_runner::claim_self_update_job(path, &unit_name).map_err(|error| {
            CliError::Validation(format!("Cannot claim self-update admission: {error}"))
        })?;
    }

    let result: CliResult<CliResponseEnvelope> = (|| {
        let cfg = load_release_config(global, config_path, keep_releases)?;
        let mut opts = build_release_engine_options(cmd, global.dry_run)
            .expect("deploy/rollback always yields ReleaseOptions");
        let is_channel_explicit = match cmd {
            ReleaseCliCommand::Deploy {
                channel_explicit, ..
            }
            | ReleaseCliCommand::Rollback {
                channel_explicit, ..
            } => *channel_explicit,
            _ => true,
        };
        if !is_channel_explicit {
            opts.channel = cfg.release_channel;
        }
        let engine = ReleaseEngine::new_production(cfg);
        let outcome = engine.execute(&opts)?;
        format_release_outcome(action_str, outcome)
    })();

    if let Some(ref path) = status_file {
        match result {
            Ok(_) => {
                write_self_update_job_status_atomic(
                    path,
                    &SelfUpdateJobStatus {
                        status: "succeeded".to_string(),
                        completed: true,
                        success: true,
                        job_unit: unit_name,
                        error: String::new(),
                        exit_code: Some(0),
                    },
                )
                .map_err(|error| {
                    CliError::io("persisting successful self-update receipt", error)
                })?;
            }
            Err(ref err) => {
                write_self_update_job_status_atomic(
                    path,
                    &SelfUpdateJobStatus {
                        status: "failed".to_string(),
                        completed: true,
                        success: false,
                        job_unit: unit_name,
                        error: err.to_string(),
                        exit_code: Some(err.exit_code().as_i32()),
                    },
                )
                .map_err(|error| {
                    CliError::io(
                        format!("persisting failed self-update receipt after {err}"),
                        error,
                    )
                })?;
            }
        }
    }

    result
}

fn ensure_runner_release_dispatch_has_no_local_overrides(
    global: &GlobalOptions,
    config_path: Option<&Path>,
    keep_releases: Option<usize>,
    job_status_file: Option<&Path>,
    job_unit: Option<&str>,
    operation_label: &str,
) -> CliResult<()> {
    let mut conflicting_flags: Vec<&str> = Vec::new();
    if global.root.is_some() {
        conflicting_flags.push("--root");
    }
    if config_path.is_some() {
        conflicting_flags.push("--config");
    }
    if keep_releases.is_some() {
        conflicting_flags.push("--keep-releases");
    }
    if job_status_file.is_some() {
        conflicting_flags.push("--job-status-file");
    }
    if job_unit.is_some() {
        conflicting_flags.push("--job-unit");
    }
    for env_key in ["AETHERFLOW_RELEASE_ROOT", "AETHERFLOW_RELEASE_CONF"] {
        if let Ok(raw_val) = std::env::var(env_key) {
            if !raw_val.trim().is_empty() {
                conflicting_flags.push(env_key);
            }
        }
    }
    if !conflicting_flags.is_empty() {
        return Err(CliError::Validation(format!(
            "{} cannot forward local target/config overrides ({}) over the runner socket (/v1/self-update); pass '--local' to execute against the local target/config",
            operation_label,
            conflicting_flags.join(", ")
        )));
    }
    Ok(())
}

fn execute_release_command(
    global: &GlobalOptions,
    cmd: &ReleaseCliCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match cmd {
        ReleaseCliCommand::Status { config_path } => {
            let cfg = load_release_config(global, config_path.as_deref(), None)?;
            let configured_channel = cfg.release_channel.as_str().to_string();
            let engine = ReleaseEngine::new_production(cfg);
            let status = engine.inspect_status()?;
            let prev_str = status
                .previous_release
                .as_ref()
                .map(|path_val| path_val.display().to_string())
                .unwrap_or_else(|| "none".to_string());
            let msg = format!(
                "Release Status: channel={}, current_version={}, previous_release={}, available_slots={}",
                configured_channel,
                status.current_version.as_deref().unwrap_or("none"),
                prev_str,
                status.available_releases.len()
            );
            let mut val = serde_json::to_value(&status).unwrap_or(json!({}));
            if let Some(obj) = val.as_object_mut() {
                obj.insert("configured_channel".to_string(), json!(configured_channel));
            }
            Ok(CliResponseEnvelope::success(
                "release",
                "status",
                msg,
                Some(val),
            ))
        }
        ReleaseCliCommand::Deploy {
            channel,
            channel_explicit,
            mode,
            config_path,
            keep_releases,
            job_status_file,
            job_unit,
            ..
        } => {
            let action_str = cmd.action_name();
            match mode {
                ReleaseDispatchMode::RunnerSocket => {
                    ensure_runner_release_dispatch_has_no_local_overrides(
                        global,
                        config_path.as_deref(),
                        *keep_releases,
                        job_status_file.as_deref(),
                        job_unit.as_deref(),
                        "af release deploy",
                    )?;
                    let effective_channel = if *channel_explicit {
                        *channel
                    } else {
                        load_release_config(global, None, None)
                            .map(|c| c.release_channel)
                            .unwrap_or(*channel)
                    };
                    let req = build_self_update_runner_request(action_str, effective_channel)?;
                    if global.dry_run {
                        return Ok(CliResponseEnvelope::success(
                            "release",
                            action_str,
                            format!(
                                "[DRY-RUN] Would dispatch /v1/self-update ({}, channel={})",
                                req.command, req.channel
                            ),
                            Some(json!({ "dry_run": true, "request": req })),
                        ));
                    }
                    let resp = transport.execute_self_update(&req)?;
                    Ok(CliResponseEnvelope::success(
                        "release",
                        action_str,
                        format!(
                            "Runner self-update '{}' (channel={}): {}",
                            req.command,
                            req.channel,
                            resp.output.trim()
                        ),
                        Some(json!({
                            "request": req,
                            "runner_response": resp,
                        })),
                    ))
                }
                ReleaseDispatchMode::LocalEngine => execute_local_release_with_status_receipt(
                    global,
                    cmd,
                    config_path.as_deref(),
                    *keep_releases,
                    job_status_file.as_deref(),
                    job_unit.as_deref(),
                ),
            }
        }
        ReleaseCliCommand::Rollback {
            channel,
            channel_explicit,
            mode,
            config_path,
            job_status_file,
            job_unit,
        } => {
            let action_str = cmd.action_name();
            match mode {
                ReleaseDispatchMode::RunnerSocket => {
                    ensure_runner_release_dispatch_has_no_local_overrides(
                        global,
                        config_path.as_deref(),
                        None,
                        job_status_file.as_deref(),
                        job_unit.as_deref(),
                        "af release rollback",
                    )?;
                    let effective_channel = if *channel_explicit {
                        *channel
                    } else {
                        load_release_config(global, None, None)
                            .map(|c| c.release_channel)
                            .unwrap_or(*channel)
                    };
                    let req = build_self_update_runner_request(action_str, effective_channel)?;
                    if global.dry_run {
                        return Ok(CliResponseEnvelope::success(
                            "release",
                            action_str,
                            format!(
                                "[DRY-RUN] Would dispatch /v1/self-update ({}, channel={})",
                                req.command, req.channel
                            ),
                            Some(json!({ "dry_run": true, "request": req })),
                        ));
                    }
                    let resp = transport.execute_self_update(&req)?;
                    Ok(CliResponseEnvelope::success(
                        "release",
                        action_str,
                        format!(
                            "Runner self-update '{}' (channel={}): {}",
                            req.command,
                            req.channel,
                            resp.output.trim()
                        ),
                        Some(json!({
                            "request": req,
                            "runner_response": resp,
                        })),
                    ))
                }
                ReleaseDispatchMode::LocalEngine => execute_local_release_with_status_receipt(
                    global,
                    cmd,
                    config_path.as_deref(),
                    None,
                    job_status_file.as_deref(),
                    job_unit.as_deref(),
                ),
            }
        }
        ReleaseCliCommand::Cleanup {
            keep_releases,
            config_path,
        } => {
            let action_str = cmd.action_name();
            let cfg = load_release_config(global, config_path.as_deref(), *keep_releases)?;
            let opts = build_release_engine_options(cmd, global.dry_run)
                .expect("cleanup always yields ReleaseOptions");
            let engine = ReleaseEngine::new_production(cfg);
            let outcome = engine.execute(&opts)?;
            format_release_outcome(action_str, outcome)
        }
        ReleaseCliCommand::MigrateSystemd { config_path } => {
            let action_str = cmd.action_name();
            let cfg = load_release_config(global, config_path.as_deref(), None)?;
            let opts = build_release_engine_options(cmd, global.dry_run)
                .expect("migrate-systemd always yields ReleaseOptions");
            let engine = ReleaseEngine::new_production(cfg);
            let outcome = engine.execute(&opts)?;
            format_release_outcome(action_str, outcome)
        }
    }
}

fn format_release_outcome(action: &str, outcome: ReleaseOutcome) -> CliResult<CliResponseEnvelope> {
    let val = serde_json::to_value(&outcome).unwrap_or(json!({}));
    let msg = match outcome {
        ReleaseOutcome::Deploy(rep) => format!(
            "Release deploy (dry_run={}): tag={} -> {} (epoch={})",
            rep.dry_run,
            rep.release_tag,
            rep.release_dir.display(),
            rep.epoch_id
        ),
        ReleaseOutcome::Rollback(rep) => format!(
            "Release rollback (dry_run={}): reverted_to={}",
            rep.dry_run,
            rep.reverted_to.display()
        ),
        ReleaseOutcome::Cleanup(rep) => format!(
            "Release cleanup: retained_max={}, pruned={}",
            rep.retained_max,
            rep.pruned_releases.len()
        ),
        ReleaseOutcome::MigrateSystemd(rep) => format!(
            "Release migrate-systemd (dry_run={}): resolved_db={} ({}), health={}",
            rep.dry_run,
            rep.resolved_db.path.display(),
            rep.resolved_db.source,
            rep.health_status.as_deref().unwrap_or("not probed")
        ),
    };
    Ok(CliResponseEnvelope::success(
        "release",
        action,
        msg,
        Some(val),
    ))
}

fn resolve_backup_config(
    global: &GlobalOptions,
    explicit_backup_dir: Option<&Path>,
    explicit_db_path: Option<&Path>,
    app_version: &str,
) -> CliResult<HostBackupConfig> {
    let active_db = af_models::try_resolve_active_db_path_from_env(
        global.root.as_deref(),
        "/var/lib/aetherflow/aetherflow.sqlite",
    )
    .map_err(CliError::Validation)?;
    let active_backup_dir = af_models::try_resolve_active_backup_dir_from_env(
        global.root.as_deref(),
        Some(&active_db),
        "/var/lib/aetherflow/backups",
    )
    .map_err(CliError::Validation)?;
    let (env_trusted_uid, _) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(global.root.as_deref())
            .map_err(CliError::Validation)?;

    let mut cfg = if let Some(ref root) = global.root {
        let mut isolated_cfg = HostBackupConfig::for_isolated_root(root, app_version);
        isolated_cfg.backup_dir = active_backup_dir;
        isolated_cfg.sqlite_db_path = Some(active_db);
        isolated_cfg
    } else {
        let mut base = HostBackupConfig::for_isolated_root(Path::new("/"), app_version);
        base.backup_dir = active_backup_dir;
        base.sqlite_db_path = Some(active_db);
        base
    };
    cfg.snapshot_options.trusted_source_uid = env_trusted_uid;
    if let Some(bdir) = explicit_backup_dir {
        if let Some(ref root) = global.root {
            let validated_bdir =
                af_models::validate_path_within_isolated_root(bdir, root, "--backup-dir")
                    .map_err(CliError::Validation)?;
            cfg.backup_dir = validated_bdir;
        } else {
            cfg.backup_dir = bdir.to_path_buf();
        }
    }
    if let Some(db) = explicit_db_path {
        if let Some(ref root) = global.root {
            let validated_db = af_models::validate_path_within_isolated_root(db, root, "--db-path")
                .map_err(CliError::Validation)?;
            cfg.sqlite_db_path = Some(validated_db);
        } else {
            cfg.sqlite_db_path = Some(db.to_path_buf());
        }
    }
    Ok(cfg)
}

fn require_backup_write_privilege(
    global: &GlobalOptions,
    backup_dir: &Path,
    operator_privileged: bool,
    operation: &str,
) -> CliResult<()> {
    if global.dry_run || global.root.is_some() || operator_privileged || is_effective_root_user() {
        return Ok(());
    }
    let is_system_path = backup_dir.starts_with("/var/lib/aetherflow")
        || backup_dir.starts_with("/etc")
        || backup_dir.starts_with("/opt");
    if is_system_path {
        return Err(CliError::PrivilegeRequired(format!(
            "local backup operation '{}' on system path '{}' requires root privileges (UID 0), '--operator-privileged', or an isolated '--root <dir>'",
            operation,
            backup_dir.display()
        )));
    }
    Ok(())
}

fn execute_backup_command(
    global: &GlobalOptions,
    cmd: &BackupCliCommand,
) -> CliResult<CliResponseEnvelope> {
    let (env_trusted_uid, env_trusted_gid) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(global.root.as_deref())
            .map_err(CliError::Validation)?;
    let mutating_backup_dir = match cmd {
        BackupCliCommand::RestoreDestructive {
            confirm_destructive_restore: false,
            ..
        } => None,
        BackupCliCommand::Create {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::RestoreDestructive {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::RecoverInterrupted {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Delete {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Prune {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Chunk {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Assemble {
            backup_dir,
            operator_privileged,
            ..
        } => Some((backup_dir.as_deref(), *operator_privileged)),
        _ => None,
    };
    let _maintenance_lock = if global.dry_run {
        None
    } else if let Some((backup_dir, operator_privileged)) = mutating_backup_dir {
        let cfg = resolve_backup_config(global, backup_dir, None, "v4.0.0")?;
        require_backup_write_privilege(
            global,
            &cfg.backup_dir,
            operator_privileged,
            cmd.action_name(),
        )?;
        let timeout = std::time::Duration::from_secs(30);
        Some(if backup_dir.is_none() {
            let lock_path = af_models::try_resolve_canonical_maintenance_lock_path_from_env(
                global.root.as_deref(),
                cfg.sqlite_db_path.as_deref(),
                Some(&cfg.backup_dir),
            )
            .map_err(CliError::Validation)?;
            af_host::HostMaintenanceLockGuard::acquire(lock_path, timeout)?
        } else {
            af_host::HostMaintenanceLockGuard::acquire_default(Some(&cfg.backup_dir), timeout)?
        })
    } else {
        None
    };
    match cmd {
        BackupCliCommand::Create {
            kind,
            backup_dir,
            db_path,
            app_version,
            chunk_size_bytes,
            timestamp_slug,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid: _,
        } => {
            let mut cfg = resolve_backup_config(
                global,
                backup_dir.as_deref(),
                db_path.as_deref(),
                app_version,
            )?;
            cfg.chunk_size_bytes = *chunk_size_bytes;
            cfg.snapshot_options.trusted_source_uid = (*trusted_sqlite_uid).or(env_trusted_uid);

            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup create",
            )?;

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "create",
                    format!(
                        "[DRY-RUN] Would create {:?} backup in {}",
                        kind,
                        cfg.backup_dir.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "kind": kind,
                        "config": cfg,
                    })),
                ));
            }

            let receipt = match kind {
                BackupCreateKind::Sqlite => {
                    create_sqlite_snapshot_backup(&cfg, timestamp_slug.as_deref())?
                }
                BackupCreateKind::Archive => {
                    create_host_archive_backup(&cfg, timestamp_slug.as_deref())?
                }
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "create",
                format!(
                    "Created verified backup '{}' (manifest: {}, chunks: {})",
                    receipt.primary_artifact_path.display(),
                    receipt.manifest_path.display(),
                    receipt.chunk_paths.len()
                ),
                Some(serde_json::to_value(&receipt).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::List { backup_dir } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            let items = list_backup_inventory(&cfg.backup_dir)?;
            let mut lines = vec![format!(
                "Backups in {} ({} total):",
                cfg.backup_dir.display(),
                items.len()
            )];
            for item in &items {
                lines.push(format!(
                    "  {} ({} bytes, sha256={}, manifest={}, chunks={})",
                    item.filename,
                    item.size_bytes,
                    item.checksum_present,
                    item.manifest_present,
                    item.chunk_count
                ));
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "list",
                lines.join("\n"),
                Some(json!({
                    "backup_dir": cfg.backup_dir,
                    "count": items.len(),
                    "items": items,
                })),
            ))
        }
        BackupCliCommand::Verify {
            filename,
            backup_dir,
            trusted_sqlite_uid,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            let effective_trusted_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            let (verification, manifest_opt) = verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                effective_trusted_uid,
            )?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "verify",
                format!(
                    "Verified backup '{}' (sha256={}, size={} bytes, manifest_loaded={})",
                    filename,
                    verification.actual_sha256,
                    verification.size_bytes,
                    manifest_opt.is_some()
                ),
                Some(json!({
                    "verification": verification,
                    "manifest": manifest_opt,
                })),
            ))
        }
        BackupCliCommand::RestorePreflight {
            filename,
            backup_dir,
            target_root,
            host_version,
            max_sqlite_user_version,
            overwrite_policy,
            trusted_sqlite_uid,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, host_version)?;
            let effective_trusted_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            let artifact_path = safe_backup_file_path(&cfg.backup_dir, filename)?;
            let manifest_path = cfg.backup_dir.join(format!("{}.manifest.json", filename));

            if !manifest_path.is_file() {
                return Err(CliError::PreflightOrIntegrity(format!(
                    "missing required backup manifest '{}' for non-destructive restore preflight",
                    manifest_path.display()
                )));
            }
            let manifest = BackupManifest::load_from_path(&manifest_path, true)?;
            let opts = RestorePreflightOptions {
                host_app_version: host_version.clone(),
                max_supported_sqlite_user_version: *max_sqlite_user_version,
                overwrite_policy: *overwrite_policy,
                require_artifact_sidecar: true,
            };

            let sqlite_override_buf =
                if global.root.is_none() || global.root.as_deref() == Some(target_root.as_path()) {
                    af_models::resolve_contained_sqlite_restore_override(
                        target_root,
                        cfg.sqlite_db_path.as_deref(),
                    )
                } else {
                    None
                };
            let sqlite_override = sqlite_override_buf.as_deref();
            let sqlite_target_rel = sqlite_override
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(target_root, db_p));
            let plan: RestorePlan = if filename.ends_with(".tar.gz") {
                preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
                    &artifact_path,
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    effective_trusted_uid,
                )?
            } else if filename.ends_with(".sqlite") {
                preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
                    &cfg.backup_dir,
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    effective_trusted_uid,
                )?
            } else {
                plan_restore_from_manifest_with_sqlite_overrides(
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "restore-preflight",
                format!(
                    "Non-destructive restore preflight PASSED for '{}' -> staging '{}' ({} entries, {} bytes, non_destructive_only={})",
                    filename,
                    plan.target_root.display(),
                    plan.items.len(),
                    plan.total_bytes,
                    plan.non_destructive_only
                ),
                Some(serde_json::to_value(&plan).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::RestoreDestructive {
            filename,
            backup_dir,
            target_root,
            confirm_destructive_restore,
            allow_overwrite,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            if !*confirm_destructive_restore {
                let dummy_manifest =
                    BackupManifest::new("v4.0.0", "aetherflow_placeholder.sqlite")?;
                let dummy_stage = target_root
                    .clone()
                    .unwrap_or_else(|| cfg.backup_dir.join("restore-stage"));
                let dummy_plan = RestorePlan {
                    backup_id: dummy_manifest.backup_id,
                    target_root: dummy_stage,
                    overwrite_policy: af_host::OverwritePolicy::RejectExisting,
                    compatibility: af_host::CompatibilityReport {
                        compatible: true,
                        manifest_schema_version: 1,
                        backup_app_version: "v4.0.0".to_string(),
                        host_app_version: "v4.0.0".to_string(),
                        entry_count: 0,
                        has_sqlite_snapshot: false,
                        warnings: vec![format!("requested artifact: {}", filename)],
                    },
                    items: Vec::new(),
                    total_bytes: 0,
                    sqlite_integrity_verified: false,
                    non_destructive_only: true,
                };
                execute_destructive_restore(&dummy_plan)?;
                unreachable!("execute_destructive_restore always fails closed")
            }

            let resolved_target = target_root
                .clone()
                .or_else(|| global.root.clone())
                .ok_or_else(|| {
                    CliError::Usage(
                        "confirmed restore requires '--target-root <dir>' or '--root <dir>'"
                            .to_string(),
                    )
                })?;

            require_backup_write_privilege(
                global,
                &resolved_target,
                *operator_privileged,
                "backup restore",
            )?;

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "restore",
                    format!(
                        "[DRY-RUN] Would execute confirmed staged restore of '{}' into '{}'",
                        filename,
                        resolved_target.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "filename": filename,
                        "backup_dir": cfg.backup_dir,
                        "target_root": resolved_target,
                    })),
                ));
            }

            let trusted_sqlite_db_path = if global.root.is_none()
                || global.root.as_deref() == Some(resolved_target.as_path())
            {
                af_models::resolve_contained_sqlite_restore_override(
                    &resolved_target,
                    cfg.sqlite_db_path.as_deref(),
                )
            } else {
                None
            };
            let exec_opts = af_host::RestoreExecutionOptions {
                host_app_version: "v4.0.0".to_string(),
                max_supported_sqlite_user_version: None,
                allow_overwrite: *allow_overwrite,
                confirm_destructive_restore: true,
                quiesce_services: Vec::new(),
                sqlite_target_rel_path: trusted_sqlite_db_path.as_deref().and_then(|db_p| {
                    af_models::derive_sqlite_target_rel_path(&resolved_target, db_p)
                }),
                trusted_sqlite_db_path,
                trusted_sqlite_uid: (*trusted_sqlite_uid).or(env_trusted_uid),
                trusted_sqlite_gid: (*trusted_sqlite_gid).or(env_trusted_gid),
                ..Default::default()
            };

            let isolated_target = global.root.is_some() && resolved_target != Path::new("/");
            let report = if isolated_target || !cfg!(target_os = "linux") {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &resolved_target,
                    &exec_opts,
                    &af_host::NoopQuiescenceController,
                )?
            } else {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &resolved_target,
                    &exec_opts,
                    &af_host::CommandQuiescenceController::default(),
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "restore",
                format!(
                    "Executed verified restore of '{}' into '{}' ({} file(s) restored)",
                    filename,
                    resolved_target.display(),
                    report.restored_files.len()
                ),
                Some(serde_json::to_value(&report).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::RecoverInterrupted {
            backup_dir,
            target_root,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            let resolved_target = target_root
                .clone()
                .or_else(|| global.root.clone())
                .unwrap_or_else(|| PathBuf::from("/"));

            require_backup_write_privilege(
                global,
                &resolved_target,
                *operator_privileged,
                "backup recover",
            )?;

            let trusted_sqlite_db_path = if global.root.is_none()
                || global.root.as_deref() == Some(resolved_target.as_path())
            {
                af_models::resolve_contained_sqlite_restore_override(
                    &resolved_target,
                    cfg.sqlite_db_path.as_deref(),
                )
            } else {
                None
            };
            let mut recovery_context = if resolved_target == Path::new("/") {
                af_host::RecoveryContext::for_canonical_host(trusted_sqlite_db_path)
            } else {
                af_host::RecoveryContext::for_target_root(
                    resolved_target.clone(),
                    trusted_sqlite_db_path,
                )
            };
            recovery_context.trusted_sqlite_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            recovery_context.trusted_sqlite_gid = (*trusted_sqlite_gid).or(env_trusted_gid);

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "recover-interrupted",
                    format!(
                        "[DRY-RUN] Would recover interrupted restores in '{}' for target '{}'",
                        cfg.backup_dir.display(),
                        resolved_target.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "backup_dir": cfg.backup_dir,
                        "target_root": resolved_target,
                    })),
                ));
            }

            let isolated_target = global.root.is_some() && resolved_target != Path::new("/");
            let recovered_directories = if isolated_target || !cfg!(target_os = "linux") {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::NoopQuiescenceController,
                )?
            } else {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::CommandQuiescenceController::default(),
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "recover-interrupted",
                format!(
                    "Recovered {} interrupted restore directory(s) in '{}'",
                    recovered_directories.len(),
                    cfg.backup_dir.display()
                ),
                Some(json!({
                    "backup_dir": cfg.backup_dir,
                    "target_root": resolved_target,
                    "recovered_directories": recovered_directories,
                })),
            ))
        }
        BackupCliCommand::Delete {
            filename,
            backup_dir,
            operator_privileged,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup delete",
            )?;
            if global.dry_run {
                let target = safe_backup_file_path(&cfg.backup_dir, filename)?;
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "delete",
                    format!(
                        "[DRY-RUN] Would delete backup artifacts for {}",
                        target.display()
                    ),
                    Some(json!({ "dry_run": true, "artifact": target })),
                ));
            }
            let removed = delete_backup_artifacts(&cfg.backup_dir, filename)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "delete",
                format!(
                    "Deleted {} file(s) for backup '{}'",
                    removed.len(),
                    filename
                ),
                Some(json!({ "filename": filename, "removed_paths": removed })),
            ))
        }
        BackupCliCommand::Prune {
            backup_dir,
            max_retained,
            retention_days,
            operator_privileged,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup prune",
            )?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "prune",
                    format!(
                        "[DRY-RUN] Would prune backups in {} (max_retained={}, retention_days={})",
                        cfg.backup_dir.display(),
                        max_retained,
                        retention_days
                    ),
                    Some(json!({
                        "dry_run": true,
                        "backup_dir": cfg.backup_dir,
                        "max_retained": max_retained,
                        "retention_days": retention_days,
                    })),
                ));
            }
            let pruned = prune_backup_inventory(&cfg.backup_dir, *max_retained, *retention_days)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "prune",
                format!("Pruned {} backup(s)", pruned.len()),
                Some(json!({ "pruned": pruned })),
            ))
        }
        BackupCliCommand::Chunk {
            filename,
            chunk_size_bytes,
            backup_dir,
            operator_privileged,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup chunk",
            )?;
            let target = safe_backup_file_path(&cfg.backup_dir, filename)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "chunk",
                    format!(
                        "[DRY-RUN] Would split {} into {}-byte chunks",
                        target.display(),
                        chunk_size_bytes
                    ),
                    Some(json!({
                        "dry_run": true,
                        "artifact": target,
                        "chunk_size_bytes": chunk_size_bytes,
                    })),
                ));
            }
            let chunks = split_backup_into_chunks(&target, *chunk_size_bytes)?;
            let manifest_path = PathBuf::from(format!("{}.manifest.json", target.display()));
            if manifest_path.exists() {
                let mut manifest = BackupManifest::load_from_path(&manifest_path, true)?;
                manifest.chunk_count = chunks.len();
                manifest.chunk_size_bytes = Some(*chunk_size_bytes);
                manifest.save_atomic(&manifest_path)?;
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "chunk",
                format!("Split '{}' into {} chunk(s)", filename, chunks.len()),
                Some(json!({
                    "filename": filename,
                    "chunk_size_bytes": chunk_size_bytes,
                    "chunks": chunks,
                })),
            ))
        }
        BackupCliCommand::Assemble {
            output_filename,
            expected_sha256,
            chunks,
            backup_dir,
            operator_privileged,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, "v4.0.0")?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup assemble",
            )?;
            let output_path = safe_backup_file_path(&cfg.backup_dir, output_filename)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "assemble",
                    format!(
                        "[DRY-RUN] Would assemble {} chunk(s) into {}",
                        chunks.len(),
                        output_path.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "output_path": output_path,
                        "expected_sha256": expected_sha256,
                        "chunks": chunks,
                    })),
                ));
            }
            let verification = assemble_verified_chunks(chunks, &output_path, expected_sha256)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "assemble",
                format!(
                    "Assembled and verified '{}' ({} bytes, sha256={})",
                    output_path.display(),
                    verification.size_bytes,
                    verification.actual_sha256
                ),
                Some(json!({ "verification": verification })),
            ))
        }
        BackupCliCommand::OwnershipRegistry => {
            let registry = maintenance_helper_ownership_registry();
            let mut lines = vec![format!(
                "Host Maintenance Script Ownership Registry ({} entries):",
                registry.len()
            )];
            for item in registry {
                lines.push(format!(
                    "  {} -> {:?} ({})",
                    item.script_path, item.owner, item.rust_replacement_or_entry
                ));
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "ownership",
                lines.join("\n"),
                Some(serde_json::to_value(registry).unwrap_or(json!([]))),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain 7: Resumable Bare-Metal Provisioning Foundation (`provision`)
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_provision_paths(global: &GlobalOptions) -> CliResult<ProvisionPaths> {
    let root = global.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    ProvisionPaths::for_root(root)
}

fn execute_provision_command(
    global: &GlobalOptions,
    cmd: &ProvisionCliCommand,
) -> CliResult<CliResponseEnvelope> {
    let paths = resolve_provision_paths(global)?;
    let store = ProvisionStateStore::new(paths.clone());

    match cmd {
        ProvisionCliCommand::Preflight {
            os_release_path,
            require_root,
        } => {
            let report =
                run_provision_preflight(&paths, os_release_path.as_deref(), *require_root)?;
            if !report.passed {
                return Err(CliError::PreflightOrIntegrity(format!(
                    "provisioning preflight failed: {}",
                    report.errors.join("; ")
                )));
            }
            Ok(CliResponseEnvelope::success(
                "provision",
                "preflight",
                format!(
                    "Provisioning preflight PASSED for root '{}' (warnings: {})",
                    paths.fs_root.display(),
                    report.warnings.len()
                ),
                Some(serde_json::to_value(&report).unwrap_or(json!({}))),
            ))
        }
        ProvisionCliCommand::Status => {
            let status = store.inspect_status()?;
            let msg = format!(
                "Provisioning Status: state_exists={}, version={:?}, completed={}/{} steps",
                status.state_exists,
                status.state_version,
                status.completed_count,
                status.total_canonical_steps
            );
            Ok(CliResponseEnvelope::success(
                "provision",
                "status",
                msg,
                Some(serde_json::to_value(&status).unwrap_or(json!({}))),
            ))
        }
        ProvisionCliCommand::ListSteps => {
            let catalog = canonical_step_catalog();
            let (_, completed) = store.read_state()?;
            let mut lines = vec![format!(
                "Canonical Provisioning Steps ({} total, STATE_VERSION={}):",
                catalog.len(),
                PROVISION_STATE_VERSION
            )];
            for item in &catalog {
                let done = completed.iter().any(|s| s == item.step_id);
                let state_tag = if done { "[DONE]" } else { "[PEND]" };
                lines.push(format!(
                    "  {:02}. {} {:<16} ({:?}) - {}",
                    item.index, state_tag, item.step_id, item.tier, item.summary
                ));
            }
            Ok(CliResponseEnvelope::success(
                "provision",
                "list-steps",
                lines.join("\n"),
                Some(json!({
                    "state_version": PROVISION_STATE_VERSION,
                    "completed_steps": completed,
                    "steps": catalog,
                })),
            ))
        }
        ProvisionCliCommand::Run {
            steps,
            fresh,
            require_root,
        } => {
            let report = execute_provision_steps(
                &store,
                steps,
                *fresh,
                false,
                *require_root,
                global.dry_run,
            )?;
            Ok(CliResponseEnvelope::success(
                "provision",
                "run",
                format!(
                    "Provisioning run finished (dry_run={}, processed={} step(s), total_completed={})",
                    report.dry_run,
                    report.records.len(),
                    report.completed_steps_after.len()
                ),
                Some(serde_json::to_value(&report).unwrap_or(json!({}))),
            ))
        }
        ProvisionCliCommand::Repair {
            steps,
            require_root,
        } => {
            let report =
                execute_provision_steps(&store, steps, false, true, *require_root, global.dry_run)?;
            Ok(CliResponseEnvelope::success(
                "provision",
                "repair",
                format!(
                    "Provisioning repair finished (dry_run={}, cleared={}, processed={} step(s))",
                    report.dry_run,
                    report.cleared_for_repair.len(),
                    report.records.len()
                ),
                Some(serde_json::to_value(&report).unwrap_or(json!({}))),
            ))
        }
        ProvisionCliCommand::OverlayConfig {
            source,
            target,
            force,
        } => {
            let receipt = safe_overlay_config_file(source, target, *force, global.dry_run)?;
            Ok(CliResponseEnvelope::success(
                "provision",
                "overlay-config",
                format!(
                    "Config overlay {:?} for {} -> {} (dry_run={})",
                    receipt.outcome,
                    receipt.source_path.display(),
                    receipt.target_path.display(),
                    receipt.dry_run
                ),
                Some(serde_json::to_value(&receipt).unwrap_or(json!({}))),
            ))
        }
        ProvisionCliCommand::Reset { confirm } => {
            if !confirm {
                return Err(CliError::Usage(
                    "af provision reset requires '--confirm' to delete /install/.aetherflow.state"
                        .to_string(),
                ));
            }
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "provision",
                    "reset",
                    format!(
                        "[DRY-RUN] Would reset provisioning state at {}",
                        paths.state_file.display()
                    ),
                    Some(json!({ "dry_run": true, "state_file": paths.state_file })),
                ));
            }
            store.reset_state()?;
            Ok(CliResponseEnvelope::success(
                "provision",
                "reset",
                format!("Reset provisioning state at {}", paths.state_file.display()),
                Some(json!({ "state_file": paths.state_file })),
            ))
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod p3_target_resolution_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn update_target_resolution_rejects_installed_and_marker_fallbacks_and_discovers_live_upstream()
    {
        let root = std::env::temp_dir().join(format!(
            "af-cli-p3-target-res-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(root.join("var/lib/aetherflow")).unwrap();
        std::fs::create_dir_all(root.join("install")).unwrap();
        std::fs::create_dir_all(root.join("opt/sonarr")).unwrap();

        // Populate `.af-version` and lockfile VERSION markers — must NEVER be used as update targets!
        std::fs::write(root.join("opt/sonarr/.af-version"), "4.0.1.999\n").unwrap();
        std::fs::write(root.join("install/.sonarr.version"), "4.0.1.999\n").unwrap();
        std::fs::write(root.join("install/.sonarr.lock"), "VERSION=4.0.1.999\n").unwrap();

        // Populate `app_updates` with `installed_version` ONLY (`latest_version` empty) — must NEVER fall back to `installed_version`!
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE app_updates (
                package_name TEXT PRIMARY KEY,
                installed_version TEXT DEFAULT '',
                latest_version TEXT DEFAULT '',
                last_error TEXT DEFAULT ''
            );
            INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
            VALUES ('sonarr', '4.0.1.999', '', '');
            INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
            VALUES ('prowlarr', '1.20.0', '1.28.1.4900', '');
            INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
            VALUES ('radarr', '5.10.0', '5.12.0', 'HTTP 500 upstream failure');",
        )
        .unwrap();
        drop(conn);

        let root_str = root.to_string_lossy().to_string();
        let client = UnixSocketRunnerClient::new(Path::new("/nonexistent/af-runner.sock"));

        // 1. Offline & empty `latest_version` fails fast with actionable message (never 4.0.1.999 or 0.0.0)
        let inv_offline = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "sonarr",
        ])
        .unwrap();
        let env_offline = execute_invocation(&inv_offline, &client);
        assert_eq!(env_offline.status, "error");
        assert!(
            env_offline.message.contains("--target-version"),
            "expected actionable --target-version guidance, got: {}",
            env_offline.message
        );

        // 2. Readarr without `--target-version` also fails fast instead of returning hardcoded 0.4.18.2805
        let inv_readarr = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "readarr",
        ])
        .unwrap();
        let env_readarr = execute_invocation(&inv_readarr, &client);
        assert_eq!(env_readarr.status, "error");

        // 3. Valid `app_updates.latest_version` with empty `last_error` is used directly
        let inv_prowlarr = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "prowlarr",
        ])
        .unwrap();
        let env_prowlarr = execute_invocation(&inv_prowlarr, &client);
        assert_eq!(env_prowlarr.status, "ok", "{}", env_prowlarr.message);
        assert_eq!(
            env_prowlarr.data.as_ref().unwrap()["request"]["expected_target_version"],
            "1.28.1.4900"
        );

        // 4. Stale `latest_version` accompanied by non-empty `last_error` is rejected when offline
        let inv_radarr = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "radarr",
        ])
        .unwrap();
        let env_radarr = execute_invocation(&inv_radarr, &client);
        assert_eq!(env_radarr.status, "error");

        // 5. Explicit `--target-version` always succeeds when valid
        let inv_explicit = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "sonarr",
            "--target-version",
            "4.0.11.2680",
        ])
        .unwrap();
        let env_explicit = execute_invocation(&inv_explicit, &client);
        assert_eq!(env_explicit.status, "ok", "{}", env_explicit.message);
        assert_eq!(
            env_explicit.data.as_ref().unwrap()["request"]["expected_target_version"],
            "4.0.11.2680"
        );

        // 6. Live upstream discovery resolves latest tag when `latest_version` is absent
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let body = r#"{"tag_name":"v4.0.12.2800"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::write(
            root.join("config/package_automation.json"),
            serde_json::to_string(&json!({
                "sonarr": {
                    "update_source": "github",
                    "update_repo": "Sonarr/Sonarr",
                    "api_base_url": format!("http://{}", addr)
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let inv_live = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "update",
            "sonarr",
        ])
        .unwrap();
        let env_live = execute_invocation(&inv_live, &client);
        server_handle.join().unwrap();
        assert_eq!(env_live.status, "ok", "{}", env_live.message);
        assert_eq!(
            env_live.data.as_ref().unwrap()["request"]["expected_target_version"],
            "4.0.12.2800"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
