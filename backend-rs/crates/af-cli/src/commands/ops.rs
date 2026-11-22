use crate::cli::{
    build_hosts_runner_request, build_quota_runner_request, build_sandbox_runner_request,
    GlobalOptions, HostsCliCommand, MaintenanceCliCommand, QuotaCommand, SandboxCommand,
    ServiceCommand,
};
use crate::client::RunnerClientTransport;
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use af_host::{
    apply_network_tuning, clean_system_logs, inspect_home_disk_space,
    maintenance_helper_ownership_registry, sentinel_scan_auth_log,
};
use af_runner::{
    get_runner_package_definition, parse_quota_size_to_1k_blocks, render_systemd_sandbox_dropin,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) fn execute_hosts_command(
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

pub(crate) fn execute_maintenance_command(
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

pub(crate) fn execute_service_command(
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

pub(crate) fn execute_quota_command(
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

pub(crate) fn execute_sandbox_command(
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
