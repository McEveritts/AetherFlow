use crate::cli::{GlobalOptions, ProvisionCliCommand};
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use crate::provision::{
    canonical_step_catalog, execute_provision_steps, run_provision_preflight,
    safe_overlay_config_file, ProvisionPaths, ProvisionStateStore, PROVISION_STATE_VERSION,
};
use serde_json::json;
use std::path::PathBuf;

fn resolve_provision_paths(global: &GlobalOptions) -> CliResult<ProvisionPaths> {
    let root = global.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    ProvisionPaths::for_root(root)
}

pub(crate) fn execute_provision_command(
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
