use super::package_discovery::{
    inspect_cli_package_receipts, inspect_cli_package_receipts_for_def,
    resolve_cli_package_definition, resolve_cli_package_port, resolve_cli_package_target_version,
    resolve_install_lock_dir, resolve_swizzin_lock_dir, validate_cli_package_target_policy,
};
use super::release::ensure_runner_release_dispatch_has_no_local_overrides;
use crate::cli::{
    build_package_runner_request, build_package_runner_request_with_target,
    build_sandbox_runner_request, build_self_update_runner_request, resolve_package_lock_name,
    GlobalOptions, PackageCommand,
};
use crate::client::RunnerClientTransport;
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use crate::PackageListEntry;
use af_runner::load_runner_package_definitions_in_root;
use serde_json::json;

pub(crate) fn execute_package_command(
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
                    let receipt = inspect_cli_package_receipts_for_def(global, pkg, def.as_ref())?;
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
                let resolved_target =
                    resolve_cli_package_target_version(global, pkg, target_version.as_deref())?;
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
            let mut definitions: Vec<_> =
                load_runner_package_definitions_in_root(global.root.as_deref())
                    .map_err(|err| CliError::PreflightOrIntegrity(err.to_string()))?
                    .collect();
            definitions.sort_by(|left, right| left.name.cmp(&right.name));
            definitions.dedup_by(|current, previous| current.name == previous.name);
            let mut entries = Vec::new();
            for def in definitions {
                let lock_name = resolve_package_lock_name(&def.name).to_string();
                let receipt = inspect_cli_package_receipts_for_def(global, &def.name, Some(&def))?;
                let installed = receipt.is_installed();
                if *installed_only && !installed {
                    continue;
                }
                let retained_lock_path = receipt
                    .retained_receipt_present
                    .then_some(receipt.retained_path);
                let legacy_lock_path = receipt
                    .legacy_receipt_present
                    .then_some(receipt.legacy_path)
                    .flatten();
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
            let explicit_lock =
                (!def.lock_file.trim().is_empty()).then_some(def.lock_file.as_str());
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
