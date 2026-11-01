//! Administrative & Privileged Runner IPC Adapter (`af-runner` `/v1/self-update` and CLI entrypoint).
//!
//! Provides a stable, drop-in typed bridge between `af_models::SelfUpdateRequest` / `RunnerResponse`
//! and the `af-release` engine so the parent integrator can wire `af-runner` and `aetherflow-api`
//! without altering existing wire formats.

use crate::config::{ReleaseChannel, ReleaseCommand, ReleaseConfig, ReleaseOptions};
use crate::engine::{ReleaseEngine, ReleaseOutcome};
use crate::error::{ExitCode, ReleaseError, ReleaseResult};
use af_models::{RunnerResponse, SelfUpdateRequest};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Validated, strongly-typed self-update request parsed from `af_models::SelfUpdateRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSelfUpdateRequest {
    pub command: ReleaseCommand,
    pub channel: ReleaseChannel,
}

/// Validates an incoming `af_models::SelfUpdateRequest` from `/v1/self-update`.
///
/// Supports `"deploy"` and `"rollback"` commands, and `"stable"`, `"nightly"`, and `"experimental"`
/// channels (remediating the missing `"experimental"` channel check in `af-runner` while maintaining
/// exact error strings `"invalid self-update command"` and `"invalid update channel"`).
pub fn validate_self_update_request(
    req: &SelfUpdateRequest,
) -> Result<ValidatedSelfUpdateRequest, RunnerResponse> {
    let raw_cmd = req.command.trim();
    let command = match if raw_cmd.is_empty() { "deploy" } else { raw_cmd } {
        "deploy" => ReleaseCommand::Deploy,
        "rollback" => ReleaseCommand::Rollback,
        _ => {
            return Err(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid self-update command".to_string(),
            });
        }
    };

    let raw_channel = req.channel.trim();
    let channel = match if raw_channel.is_empty() {
        "stable"
    } else {
        raw_channel
    } {
        "stable" => ReleaseChannel::Stable,
        "nightly" => ReleaseChannel::Nightly,
        "experimental" => ReleaseChannel::Experimental,
        _ => {
            return Err(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid update channel".to_string(),
            });
        }
    };

    if let Err(err) = ReleaseChannel::from_str(channel.as_str()) {
        return Err(RunnerResponse {
            success: false,
            output: String::new(),
            error: err.to_string(),
        });
    }

    Ok(ValidatedSelfUpdateRequest { command, channel })
}

/// Resolves the default `release-manager.conf` path on the host if present.
pub fn resolve_release_manager_conf() -> Option<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/deploy/release-manager.conf"),
        PathBuf::from("/opt/AetherFlow/deploy/release-manager.conf"),
        PathBuf::from("deploy/release-manager.conf"),
        PathBuf::from("../deploy/release-manager.conf"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("deploy/release-manager.conf"));
            candidates.push(exe_dir.join("../deploy/release-manager.conf"));
        }
    }
    candidates.into_iter().find(|c| c.is_file())
}

/// Executes a validated `ValidatedSelfUpdateRequest` synchronously using a configured `ReleaseEngine`
/// and maps the result into an `af_models::RunnerResponse`.
pub fn execute_self_update_sync(
    req: &ValidatedSelfUpdateRequest,
    config: ReleaseConfig,
) -> (ExitCode, RunnerResponse) {
    let engine = ReleaseEngine::new_production(config);
    let opts = ReleaseOptions {
        command: req.command,
        channel: req.channel,
        dry_run: false,
        offline: false,
        from_source: false,
    };

    match engine.execute(&opts) {
        Ok(outcome) => {
            let summary = match outcome {
                ReleaseOutcome::Deploy(rep) => format!(
                    "Deployed release {} ({}) to {}",
                    rep.release_tag,
                    rep.channel,
                    rep.current_link.display()
                ),
                ReleaseOutcome::Rollback(rep) => {
                    format!("Rolled back to {}", rep.reverted_to.display())
                }
                ReleaseOutcome::Cleanup(rep) => {
                    format!("Pruned {} old releases", rep.pruned_releases.len())
                }
                ReleaseOutcome::MigrateSystemd(_) => {
                    "Migrated AetherFlow to systemd units".to_string()
                }
            };
            (
                ExitCode::Success,
                RunnerResponse {
                    success: true,
                    output: summary,
                    error: String::new(),
                },
            )
        }
        Err(err) => (
            err.exit_code(),
            RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            },
        ),
    }
}

/// CLI entrypoint helper matching `deploy/release-manager.sh` argument conventions.
/// Can be invoked from `aetherflow-api release <args...>` once wired by the parent crate.
pub fn run_cli_from_args<I, S>(
    args: I,
    conf_override: Option<&Path>,
) -> (ExitCode, ReleaseResult<ReleaseOutcome>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let default_conf = resolve_release_manager_conf();
    let conf_path = conf_override.or(default_conf.as_deref());

    let mut cfg = match ReleaseConfig::load_from_process_env(conf_path) {
        Ok(c) => c,
        Err(e) => return (e.exit_code(), Err(e)),
    };

    let mut opts = match ReleaseOptions::parse_args(args, cfg.release_channel) {
        Ok(o) => o,
        Err(e) => return (e.exit_code(), Err(e)),
    };

    if !opts.offline {
        if let Ok(env_offline) = std::env::var("AF_OFFLINE") {
            if matches!(
                env_offline.trim(),
                "1" | "true" | "TRUE" | "yes" | "YES"
            ) {
                opts.offline = true;
            }
        }
    }

    if let Err(e) = opts.validate() {
        return (e.exit_code(), Err(e));
    }

    cfg.release_channel = opts.channel;
    let engine = ReleaseEngine::new_production(cfg);
    match engine.execute(&opts) {
        Ok(outcome) => (ExitCode::Success, Ok(outcome)),
        Err(err) => (err.exit_code(), Err(err)),
    }
}

/// Returns whether the error indicates an unsupported feature (such as `--from-source`)
/// where callers may choose to fall back to `deploy/release-manager.sh` or surface exit code 4.
pub fn is_unsupported_error(err: &ReleaseError) -> bool {
    matches!(err, ReleaseError::Unsupported(_))
}
