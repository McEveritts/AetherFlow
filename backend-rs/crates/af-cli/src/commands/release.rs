use crate::cli::{
    build_release_engine_options, build_self_update_runner_request, GlobalOptions,
    ReleaseCliCommand, ReleaseDispatchMode,
};
use crate::client::RunnerClientTransport;
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use af_models::SelfUpdateJobStatus;
use af_release::{ReleaseConfig, ReleaseEngine, ReleaseOutcome};
use af_runner::write_self_update_job_status_atomic;
use serde_json::json;
use std::path::{Path, PathBuf};

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

pub(crate) fn ensure_runner_release_dispatch_has_no_local_overrides(
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

pub(crate) fn execute_release_command(
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
