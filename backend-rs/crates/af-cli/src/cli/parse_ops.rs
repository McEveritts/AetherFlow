use super::{MaintenanceCliCommand, ProvisionCliCommand};
use crate::error::{CliError, CliResult};
use std::path::PathBuf;

pub(super) fn parse_provision_subcommand(args: &[String]) -> CliResult<ProvisionCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af provision <preflight|status|list-steps|run|resume|repair|overlay-config|reset> [options]".to_string(),
        ));
    };
    let tail = &args[1..];

    match sub {
        "preflight" => {
            let mut os_release_path: Option<PathBuf> = None;
            let mut require_root = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--os-release" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--os-release requires a file path".to_string())
                        })?;
                        os_release_path = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--require-root" => {
                        require_root = true;
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision preflight': {}",
                            other
                        )));
                    }
                }
            }
            Ok(ProvisionCliCommand::Preflight {
                os_release_path,
                require_root,
            })
        }
        "status" => Ok(ProvisionCliCommand::Status),
        "list-steps" | "steps" => Ok(ProvisionCliCommand::ListSteps),
        "run" | "resume" => {
            let mut steps = Vec::new();
            let mut fresh = false;
            let mut require_root = true;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--fresh" => {
                        fresh = true;
                        i += 1;
                    }
                    "--resume" => {
                        fresh = false;
                        i += 1;
                    }
                    "--no-root-check" => {
                        require_root = false;
                        i += 1;
                    }
                    "--step" | "-s" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--step requires a canonical step ID".to_string())
                        })?;
                        steps.push(val.trim().to_string());
                        i += 2;
                    }
                    arg if !arg.starts_with('-') => {
                        steps.push(arg.trim().to_string());
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision {}': {}",
                            sub, other
                        )));
                    }
                }
            }
            Ok(ProvisionCliCommand::Run {
                steps,
                fresh,
                require_root,
            })
        }
        "repair" => {
            let mut steps = Vec::new();
            let mut require_root = true;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--no-root-check" => {
                        require_root = false;
                        i += 1;
                    }
                    "--step" | "-s" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--step requires a canonical step ID".to_string())
                        })?;
                        steps.push(val.trim().to_string());
                        i += 2;
                    }
                    arg if !arg.starts_with('-') => {
                        steps.push(arg.trim().to_string());
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision repair': {}",
                            other
                        )));
                    }
                }
            }
            if steps.is_empty() {
                return Err(CliError::Usage(
                    "usage: af provision repair <step1> [step2...]".to_string(),
                ));
            }
            Ok(ProvisionCliCommand::Repair {
                steps,
                require_root,
            })
        }
        "overlay-config" => {
            let mut source: Option<PathBuf> = None;
            let mut target: Option<PathBuf> = None;
            let mut force = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--source" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--source requires a file path".to_string())
                        })?;
                        source = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target requires a file path".to_string())
                        })?;
                        target = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--force" => {
                        force = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        if source.is_none() {
                            source = Some(PathBuf::from(arg));
                        } else if target.is_none() {
                            target = Some(PathBuf::from(arg));
                        } else {
                            return Err(CliError::Usage(format!(
                                "unexpected argument for 'af provision overlay-config': {}",
                                arg
                            )));
                        }
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision overlay-config': {}",
                            other
                        )));
                    }
                }
            }
            let source = source.ok_or_else(|| {
                CliError::Usage(
                    "usage: af provision overlay-config <source_path> <target_path> [--force]"
                        .to_string(),
                )
            })?;
            let target = target.ok_or_else(|| {
                CliError::Usage(
                    "usage: af provision overlay-config <source_path> <target_path> [--force]"
                        .to_string(),
                )
            })?;
            Ok(ProvisionCliCommand::OverlayConfig {
                source,
                target,
                force,
            })
        }
        "reset" => {
            let confirm = tail.iter().any(|a| a == "--confirm" || a == "--yes");
            Ok(ProvisionCliCommand::Reset { confirm })
        }
        other => Err(CliError::Usage(format!(
            "unknown provision subcommand {:?} (expected: preflight, status, list-steps, run, resume, repair, overlay-config, reset)",
            other
        ))),
    }
}

pub(super) fn parse_tune_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--dry-run" | "-n" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af tune': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Tune { root, dry_run })
}

pub(super) fn parse_sentinel_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut log_path: Option<PathBuf> = None;
    let mut threshold = af_host::DEFAULT_SENTINEL_THRESHOLD;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--log-path" | "--file" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--log-path requires a file path".to_string())
                })?;
                log_path = Some(PathBuf::from(val));
                i += 2;
            }
            "--threshold" => {
                let val = tail
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--threshold requires a number".to_string()))?;
                threshold = val
                    .parse::<usize>()
                    .map_err(|_| CliError::Usage(format!("invalid threshold {:?}", val)))?;
                i += 2;
            }
            arg if !arg.starts_with('-') && log_path.is_none() => {
                log_path = Some(PathBuf::from(arg));
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af sentinel': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Sentinel {
        log_path,
        threshold,
    })
}

pub(super) fn parse_clean_log_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut max_size_bytes: Option<u64> = None;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--max-size" | "--size" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--max-size requires a byte size (e.g. 10MB)".to_string())
                })?;
                max_size_bytes = Some(parse_byte_size_arg(val)?);
                i += 2;
            }
            "--dry-run" | "-n" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af clean-logs': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::CleanLogs {
        root,
        max_size_bytes,
        dry_run,
    })
}

pub(super) fn parse_showspace_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut user: Option<String> = None;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--user" => {
                let val = tail
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("--user requires a username".to_string()))?;
                user = Some(val.clone());
                i += 2;
            }
            arg if !arg.starts_with('-') && user.is_none() => {
                user = Some(arg.to_string());
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af showspace': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Showspace { root, user })
}

pub(super) fn parse_maintenance_subcommand(args: &[String]) -> CliResult<MaintenanceCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing maintenance subcommand (expected: tune, sentinel, clean-logs, showspace, ownership)".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "tune" => parse_tune_args(tail),
        "sentinel" => parse_sentinel_args(tail),
        "clean-log" | "clean-logs" => parse_clean_log_args(tail),
        "showspace" => parse_showspace_args(tail),
        "ownership" | "registry" => Ok(MaintenanceCliCommand::OwnershipRegistry),
        unknown => Err(CliError::Usage(format!(
            "unknown maintenance subcommand {:?}. Expected: tune, sentinel, clean-logs, showspace, ownership",
            unknown
        ))),
    }
}

/// Parses human-friendly byte size strings (`"512"`, `"64K"`, `"50M"`, `"2G"`) into `u64` bytes.
pub fn parse_byte_size_arg(raw: &str) -> CliResult<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::Validation(
            "size value must not be empty".to_string(),
        ));
    }
    let upper = trimmed.to_ascii_uppercase();
    let (num_part, mult) = if let Some(v) = upper.strip_suffix("KB") {
        (v, 1024u64)
    } else if let Some(v) = upper.strip_suffix('K') {
        (v, 1024u64)
    } else if let Some(v) = upper.strip_suffix("MB") {
        (v, 1024u64 * 1024)
    } else if let Some(v) = upper.strip_suffix('M') {
        (v, 1024u64 * 1024)
    } else if let Some(v) = upper.strip_suffix("GB") {
        (v, 1024u64 * 1024 * 1024)
    } else if let Some(v) = upper.strip_suffix('G') {
        (v, 1024u64 * 1024 * 1024)
    } else {
        (upper.as_str(), 1u64)
    };

    let base = num_part
        .trim()
        .parse::<u64>()
        .map_err(|_| CliError::Validation(format!("invalid byte size specification {:?}", raw)))?;
    let bytes = base
        .checked_mul(mult)
        .ok_or_else(|| CliError::Validation(format!("byte size overflow for {:?}", raw)))?;
    if bytes == 0 {
        return Err(CliError::Validation(
            "chunk/byte size must be greater than zero".to_string(),
        ));
    }
    Ok(bytes)
}
