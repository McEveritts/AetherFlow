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
    build_package_runner_request, build_quota_runner_request, build_release_engine_options,
    build_sandbox_runner_request, build_self_update_runner_request, parse_byte_size_arg,
    parse_cli_args, render_help_text, resolve_package_lock_name, validate_service_request,
    AfCommand, BackupCliCommand, BackupCreateKind, GlobalOptions, HelpTopic, MaintenanceCliCommand,
    PackageCommand, ParsedInvocation, ProvisionCliCommand, QuotaCommand, ReleaseCliCommand,
    ReleaseDispatchMode, SandboxCommand, ServiceCommand, ALLOWED_SYSTEMCTL_ACTIONS,
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
    assemble_verified_chunks, create_host_archive_backup, create_sqlite_snapshot_backup,
    delete_backup_artifacts, execute_destructive_restore, list_backup_inventory,
    maintenance_helper_ownership_registry, plan_restore_from_manifest_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid, prune_backup_inventory,
    safe_backup_file_path, split_backup_into_chunks, verify_backup_artifact_with_trusted_uid,
    BackupManifest, HostBackupConfig, RestorePlan, RestorePreflightOptions,
    apply_network_tuning, clean_system_logs, compute_sysctl_network_tuning,
    inspect_home_disk_space, sentinel_scan_auth_log,
};
use af_models::SelfUpdateJobStatus;
use af_release::{ReleaseConfig, ReleaseEngine, ReleaseOutcome};
use af_runner::{
    get_runner_package_definition, parse_quota_size_to_1k_blocks, render_systemd_sandbox_dropin,
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
    pub service_name: String,
    pub sandbox_profile: String,
}

/// Canonical list of legacy & modern allowlisted AetherFlow package identifiers.
pub const KNOWN_CLI_PACKAGE_IDS: &[&str] = &[
    "qbittorrent",
    "rtorrent",
    "deluge",
    "transmission",
    "sabnzbd",
    "nzbget",
    "sonarr",
    "radarr",
    "lidarr",
    "readarr",
    "prowlarr",
    "bazarr",
    "whisparr",
    "autobrr",
    "autodl",
    "autodlirssi",
    "plex",
    "jellyfin",
    "emby",
    "tautulli",
    "ombi",
    "overseerr",
    "jellyseerr",
    "jackett",
    "flaresolverr",
    "syncthing",
    "nextcloud",
    "filebrowser",
    "rclone",
    "mergerfs",
    "wireguard",
    "openvpn",
    "znc",
    "thelounge",
    "quassel",
    "pyload",
    "jdownloader",
    "flood",
    "rutorrent",
    "unpackerr",
    "recyclarr",
    "tdarr",
    "unmanic",
    "handbrake",
    "makemkv",
    "filebot",
    "komga",
    "kavita",
    "calibre",
    "calibre-web",
    "audiobookshelf",
    "navidrome",
    "airsonic",
    "funkwhale",
    "peertube",
    "immich",
    "photoprism",
    "librephotos",
    "piwigo",
    "lychee",
    "gitea",
    "code-server",
    "portainer",
    "netdata",
    "grafana",
    "prometheus",
    "uptime-kuma",
    "scrutiny",
    "glances",
    "vnstat",
    "fail2ban",
    "crowdsec",
    "pihole",
    "adguardhome",
    "unbound",
    "nginx-proxy-manager",
    "traefik",
    "caddy",
    "organizr",
    "homarr",
    "homepage",
    "heimdall",
    "dashy",
    "freshrss",
    "miniflux",
    "tt-rss",
    "wallabag",
    "paperless-ngx",
    "stirling-pdf",
    " mealie",
    "tandoor",
    "grocy",
    "homeassistant",
    "mosquitto",
    "zigbee2mqtt",
    "nodered",
    "vaultwarden",
    "bitwarden",
    "passbolt",
    "guacamole",
    "x2go",
    "novnc",
    "webmin",
    "cockpit",
    "phpmyadmin",
    "adminer",
    "mariadb",
    "postgresql",
    "redis",
    "memcached",
    "ffmpeg",
    "vsftpd",
    "bbr",
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
    }
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
                lines.push(format!("{:>10} {}/ ({})", e.human, e.user, e.home_path.display()));
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

fn resolve_install_lock_dir(global: &GlobalOptions) -> PathBuf {
    match global.root {
        Some(ref r) => r.join("install"),
        None => PathBuf::from("/install"),
    }
}

fn execute_package_command(
    global: &GlobalOptions,
    cmd: &PackageCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    let install_dir = resolve_install_lock_dir(global);
    let emit_human_progress = !global.json;

    match cmd {
        PackageCommand::Install { packages, port } => {
            let mut receipts = Vec::new();
            let mut skipped_installed = Vec::new();
            let mut requests = Vec::new();

            for pkg in packages {
                let lock_name = resolve_package_lock_name(pkg);
                let lock_path = install_dir.join(format!(".{}.lock", lock_name));
                if lock_path.exists() {
                    skipped_installed.push(pkg.clone());
                    continue;
                }
                let req = build_package_runner_request("install", pkg, *port)?;
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
        PackageCommand::Remove { packages, purge } => {
            let mut receipts = Vec::new();
            let mut skipped_not_installed = Vec::new();
            let mut requests = Vec::new();

            for pkg in packages {
                let lock_name = resolve_package_lock_name(pkg);
                let lock_path = install_dir.join(format!(".{}.lock", lock_name));
                // If an isolated root was explicitly supplied and the lockfile is absent,
                // report `skipped_not_installed` matching `packages/system/af`'s lock check.
                if global.root.is_some() && !lock_path.exists() {
                    skipped_not_installed.push(pkg.clone());
                    continue;
                }
                let mut req = build_package_runner_request("remove", pkg, None)?;
                req.delete_data = *purge;
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
                    "remove",
                    format!(
                        "[DRY-RUN] Planned remove for {} package(s) ({} not installed)",
                        requests.len(),
                        skipped_not_installed.len()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "planned_requests": requests,
                        "skipped_not_installed": skipped_not_installed,
                    })),
                ));
            }

            Ok(CliResponseEnvelope::success(
                "package",
                "remove",
                format!(
                    "Removed {} package(s) ({} skipped as not installed)",
                    receipts.len(),
                    skipped_not_installed.len()
                ),
                Some(json!({
                    "receipts": receipts,
                    "skipped_not_installed": skipped_not_installed,
                })),
            ))
        }
        PackageCommand::Update { package, channel } => {
            if let Some(ref pkg) = package {
                let req = build_package_runner_request("update", pkg, None)?;
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
                if id == "autodl" {
                    continue; // Avoid duplicate row with canonical `autodlirssi`
                }
                if let Some(def) = get_runner_package_definition(id) {
                    let lock_name = resolve_package_lock_name(id).to_string();
                    let lock_path = install_dir.join(format!(".{}.lock", lock_name));
                    let installed = lock_path.exists();
                    if *installed_only && !installed {
                        continue;
                    }
                    entries.push(PackageListEntry {
                        package_id: def.name,
                        lock_name,
                        lock_path,
                        installed,
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
                lines.push(format!("  {:<13} {:<20} (service: {})", badge, item.package_id, item.service_name));
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
            let lookup_id = resolve_package_lock_name(package);
            let def = get_runner_package_definition(lookup_id)
                .or_else(|| get_runner_package_definition(package))
                .ok_or_else(|| {
                    CliError::Validation(format!("unknown package {:?}", package))
                })?;
            let lock_path = install_dir.join(format!(".{}.lock", lookup_id));
            let installed = lock_path.exists();
            let msg = format!(
                "Package: {} (installed: {}, service: {}, sandbox_profile: {})",
                def.name, installed, def.service_name, def.sandbox_profile
            );
            Ok(CliResponseEnvelope::success(
                "package",
                "info",
                msg,
                Some(json!({
                    "package": def,
                    "lock_path": lock_path,
                    "installed": installed,
                })),
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
                format!("Package cancellation for '{}': {}", package, resp.output.trim()),
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
    let status_file = explicit_status_file
        .map(Path::to_path_buf)
        .or_else(|| {
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
        let opts = build_release_engine_options(cmd, global.dry_run)
            .expect("deploy/rollback always yields ReleaseOptions");
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
                    let req = build_self_update_runner_request(action_str, *channel)?;
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
                    let req = build_self_update_runner_request(action_str, *channel)?;
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
    Ok(CliResponseEnvelope::success("release", action, msg, Some(val)))
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
            let validated_db =
                af_models::validate_path_within_isolated_root(db, root, "--db-path")
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
        BackupCliCommand::RestoreDestructive { confirm_destructive_restore: false, .. } => None,
        BackupCliCommand::Create { backup_dir, operator_privileged, .. }
        | BackupCliCommand::RestoreDestructive { backup_dir, operator_privileged, .. }
        | BackupCliCommand::RecoverInterrupted { backup_dir, operator_privileged, .. }
        | BackupCliCommand::Delete { backup_dir, operator_privileged, .. }
        | BackupCliCommand::Prune { backup_dir, operator_privileged, .. }
        | BackupCliCommand::Chunk { backup_dir, operator_privileged, .. }
        | BackupCliCommand::Assemble { backup_dir, operator_privileged, .. } => {
            Some((backup_dir.as_deref(), *operator_privileged))
        }
        _ => None,
    };
    let _maintenance_lock = if global.dry_run {
        None
    } else if let Some((backup_dir, operator_privileged)) = mutating_backup_dir {
        let cfg = resolve_backup_config(global, backup_dir, None, "v4.0.0")?;
        require_backup_write_privilege(global, &cfg.backup_dir, operator_privileged, cmd.action_name())?;
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

            let sqlite_override_buf = if global.root.is_none()
                || global.root.as_deref() == Some(target_root.as_path())
            {
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
                let dummy_manifest = BackupManifest::new("v4.0.0", "aetherflow_placeholder.sqlite")?;
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
                sqlite_target_rel_path: trusted_sqlite_db_path
                    .as_deref()
                    .and_then(|db_p| af_models::derive_sqlite_target_rel_path(&resolved_target, db_p)),
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
                    format!("[DRY-RUN] Would delete backup artifacts for {}", target.display()),
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
    let root = global
        .root
        .clone()
        .unwrap_or_else(|| PathBuf::from("/"));
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
            let report = execute_provision_steps(
                &store,
                steps,
                false,
                true,
                *require_root,
                global.dry_run,
            )?;
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
