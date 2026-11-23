use super::parse_backup::parse_backup_subcommand;
use super::parse_ops::{
    parse_clean_log_args, parse_maintenance_subcommand, parse_provision_subcommand,
    parse_sentinel_args, parse_showspace_args, parse_tune_args,
};
use super::requests::{
    build_hosts_runner_request, build_package_runner_request, build_quota_runner_request,
    build_sandbox_runner_request, build_self_update_runner_request, validate_service_request,
};
use super::{
    AfCommand, GlobalOptions, HelpTopic, HostsCliCommand, PackageCommand, ParsedInvocation,
    QuotaCommand, ReleaseCliCommand, ReleaseDispatchMode, SandboxCommand, ServiceCommand,
};
use crate::error::{CliError, CliResult};
use af_release::ReleaseChannel;
use af_runner::{parse_quota_size_to_1k_blocks, SAFE_QUOTA_SIZE, SAFE_USERNAME};
use std::path::PathBuf;
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────────────────────
// Manual CLI Parser Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Parses raw command-line arguments (excluding `argv[0]`) into a [`ParsedInvocation`].
///
/// If `raw_args` is empty, returns `CliError::Unsupported` explaining that the legacy interactive
/// `whiptail` TUI menu remains in `packages/system/af` while `af` (Rust) requires an explicit
/// subcommand or `--help`.
pub fn parse_cli_args<I, S>(raw_args: I) -> CliResult<ParsedInvocation>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let tokens: Vec<String> = raw_args
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();

    let mut global = GlobalOptions::default();
    let mut positional: Vec<String> = Vec::new();
    let mut help_requested = false;
    let mut version_requested = false;

    let mut idx = 0usize;
    while idx < tokens.len() {
        let arg = &tokens[idx];
        match arg.as_str() {
            "--json" => {
                global.json = true;
                idx += 1;
            }
            "--dry-run" | "-n" => {
                global.dry_run = true;
                idx += 1;
            }
            "--socket" => {
                let val = tokens.get(idx + 1).ok_or_else(|| {
                    CliError::Usage("--socket requires a Unix socket path".to_string())
                })?;
                if val.trim().is_empty() {
                    return Err(CliError::Usage(
                        "--socket path must not be empty".to_string(),
                    ));
                }
                global.socket_path = PathBuf::from(val);
                idx += 2;
            }
            s if s.starts_with("--socket=") => {
                let val = s.trim_start_matches("--socket=");
                if val.trim().is_empty() {
                    return Err(CliError::Usage(
                        "--socket path must not be empty".to_string(),
                    ));
                }
                global.socket_path = PathBuf::from(val);
                idx += 1;
            }
            "--root" => {
                let val = tokens.get(idx + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--root path must not be empty".to_string()));
                }
                global.root = Some(PathBuf::from(val));
                idx += 2;
            }
            s if s.starts_with("--root=") => {
                let val = s.trim_start_matches("--root=");
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--root path must not be empty".to_string()));
                }
                global.root = Some(PathBuf::from(val));
                idx += 1;
            }
            "-h" | "--help" => {
                help_requested = true;
                idx += 1;
            }
            "-V" | "--version" => {
                version_requested = true;
                idx += 1;
            }
            _ => {
                positional.push(arg.clone());
                idx += 1;
            }
        }
    }

    if version_requested && positional.is_empty() {
        return Ok(ParsedInvocation {
            global,
            command: AfCommand::Version,
        });
    }

    if help_requested {
        let topic = positional
            .first()
            .map(|s| parse_help_topic(s))
            .unwrap_or(HelpTopic::General);
        return Ok(ParsedInvocation {
            global,
            command: AfCommand::Help { topic },
        });
    }

    if positional.is_empty() {
        return Err(CliError::Unsupported {
            operation: "interactive-tui".to_string(),
            reason: "interactive whiptail menu is not supported in non-interactive Rust af-cli; pass a subcommand (e.g. 'af --help', 'af list', 'af package ...', 'af service ...', 'af release ...', 'af backup ...', 'af provision ...')".to_string(),
        });
    }

    let head = positional[0].as_str();
    let rest = &positional[1..];

    let command = match head {
        "help" => {
            let topic = rest
                .first()
                .map(|s| parse_help_topic(s))
                .unwrap_or(HelpTopic::General);
            AfCommand::Help { topic }
        }
        "version" => AfCommand::Version,
        "health" | "ping" | "status" => {
            if !rest.is_empty() {
                return Err(CliError::Usage(format!(
                    "unexpected arguments for 'af {head}': {}",
                    rest.join(" ")
                )));
            }
            AfCommand::Health
        }

        // Legacy `packages/system/af` top-level package shorthands:
        "install" => AfCommand::Package(parse_package_install_args(rest)?),
        "reinstall" => AfCommand::Package(parse_package_reinstall_args(rest)?),
        "remove" | "uninstall" => AfCommand::Package(parse_package_remove_args(rest)?),
        "list" => AfCommand::Package(parse_package_list_args(rest)?),
        "update" => AfCommand::Package(parse_package_update_args(rest)?),
        "upgrade" => AfCommand::Package(parse_package_upgrade_args(rest)?),

        // Structured domain subcommands:
        "package" | "pkg" => AfCommand::Package(parse_package_subcommand(rest)?),
        "service" | "svc" | "systemctl" => AfCommand::Service(parse_service_subcommand(rest)?),
        "quota" | "setdisk" => AfCommand::Quota(parse_quota_subcommand(head, rest)?),
        "sandbox" => AfCommand::Sandbox(parse_sandbox_subcommand(rest)?),
        "release" | "self-update" => AfCommand::Release(parse_release_subcommand(rest)?),
        "backup" => AfCommand::Backup(parse_backup_subcommand(rest, global.root.as_deref())?),
        "provision" | "setup" => AfCommand::Provision(parse_provision_subcommand(rest)?),
        "maintenance" => AfCommand::Maintenance(parse_maintenance_subcommand(rest)?),
        "tune" | "af-tune" => AfCommand::Maintenance(parse_tune_args(rest)?),
        "sentinel" | "af-sentinel" => AfCommand::Maintenance(parse_sentinel_args(rest)?),
        "clean-log" | "clean-logs" => AfCommand::Maintenance(parse_clean_log_args(rest)?),
        "showspace" => AfCommand::Maintenance(parse_showspace_args(rest)?),
        "hosts" | "dns" => AfCommand::Hosts(parse_hosts_subcommand(rest)?),

        unknown => {
            return Err(CliError::Usage(format!(
                "unknown command {:?}. Run 'af --help' for usage.",
                unknown
            )));
        }
    };

    Ok(ParsedInvocation { global, command })
}

pub(super) fn parse_help_topic(raw: &str) -> HelpTopic {
    match raw.trim().to_ascii_lowercase().as_str() {
        "package" | "pkg" | "install" | "reinstall" | "remove" | "list" => HelpTopic::Package,
        "update" => HelpTopic::Update,
        "service" | "svc" | "systemctl" => HelpTopic::Service,
        "quota" | "setdisk" => HelpTopic::Quota,
        "sandbox" => HelpTopic::Sandbox,
        "release" | "self-update" | "upgrade" => HelpTopic::Release,
        "backup" => HelpTopic::Backup,
        "provision" | "setup" => HelpTopic::Provision,
        "maintenance" | "tune" | "sentinel" | "clean-log" | "clean-logs" | "showspace" => {
            HelpTopic::Maintenance
        }
        "hosts" | "dns" => HelpTopic::Hosts,
        _ => HelpTopic::General,
    }
}

pub fn parse_hosts_subcommand(args: &[String]) -> CliResult<HostsCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing hosts subcommand (expected: update, remove, reconcile)".to_string(),
        ));
    };
    let tail = &args[1..];
    let cmd = match sub {
        "update" => {
            if tail.len() < 2 {
                return Err(CliError::Usage(
                    "usage: af hosts update <ip> <domain...>".to_string(),
                ));
            }
            HostsCliCommand::Update {
                ip: tail[0].clone(),
                domains: tail[1..].to_vec(),
            }
        }
        "remove" => {
            if tail.is_empty() {
                return Err(CliError::Usage(
                    "usage: af hosts remove <domain...>".to_string(),
                ));
            }
            HostsCliCommand::Remove {
                domains: tail.to_vec(),
            }
        }
        "reconcile" => {
            let ip = tail
                .first()
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let domains = if tail.len() > 1 {
                tail[1..].to_vec()
            } else {
                Vec::new()
            };
            HostsCliCommand::Reconcile { ip, domains }
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown hosts subcommand {:?} (expected: update, remove, reconcile)",
                other
            )));
        }
    };
    let _ = build_hosts_runner_request(&cmd)?;
    Ok(cmd)
}

fn parse_package_subcommand(args: &[String]) -> CliResult<PackageCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing package subcommand (expected: install, reinstall, remove, update, upgrade, list, info, cancel)"
                .to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "install" => parse_package_install_args(tail),
        "reinstall" => parse_package_reinstall_args(tail),
        "remove" | "uninstall" => parse_package_remove_args(tail),
        "update" => parse_package_update_args(tail),
        "upgrade" => parse_package_upgrade_args(tail),
        "list" => parse_package_list_args(tail),
        "info" | "inspect" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af package info <package>".to_string(),
                ));
            }
            let _ = build_package_runner_request("install", &tail[0], None)?;
            Ok(PackageCommand::Info {
                package: tail[0].trim().to_string(),
            })
        }
        "cancel" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af package cancel <package>".to_string(),
                ));
            }
            let _ = build_package_runner_request("install", &tail[0], None)?;
            Ok(PackageCommand::Cancel {
                package: tail[0].trim().to_string(),
            })
        }
        other => Err(CliError::Usage(format!(
            "unknown package subcommand {:?} (expected: install, reinstall, remove, update, upgrade, list, info, cancel)",
            other
        ))),
    }
}

fn parse_package_install_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut port: Option<i32> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let raw_port = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--port requires a numeric port value".to_string())
                })?;
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 2;
            }
            s if s.starts_with("--port=") => {
                let raw_port = s.trim_start_matches("--port=");
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!(
                        "unknown flag for package install: {}",
                        pkg
                    )));
                }
                let _ = build_package_runner_request("install", pkg, port)?;
                packages.push(pkg.trim().to_string());
                i += 1;
            }
        }
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] install <pkg1> [pkg2...] [--port <port>]".to_string(),
        ));
    }

    if packages.len() > 1 && port.is_some() {
        return Err(CliError::Usage(
            "--port may only be specified when installing a single package".to_string(),
        ));
    }

    Ok(PackageCommand::Install { packages, port })
}

fn parse_package_reinstall_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut port: Option<i32> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let raw_port = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--port requires a numeric port value".to_string())
                })?;
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 2;
            }
            s if s.starts_with("--port=") => {
                let raw_port = s.trim_start_matches("--port=");
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!(
                        "unknown flag for package reinstall: {}",
                        pkg
                    )));
                }
                let _ = build_package_runner_request("reinstall", pkg, port)?;
                packages.push(pkg.trim().to_string());
                i += 1;
            }
        }
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] reinstall <pkg1> [pkg2...] [--port <port>]".to_string(),
        ));
    }

    if packages.len() > 1 && port.is_some() {
        return Err(CliError::Usage(
            "--port may only be specified when reinstalling a single package".to_string(),
        ));
    }

    Ok(PackageCommand::Reinstall { packages, port })
}

fn parse_package_remove_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut purge = false;
    for arg in args {
        if arg == "--purge" {
            purge = true;
            continue;
        }
        if arg.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown flag for package remove: {}",
                arg
            )));
        }
        let _ = build_package_runner_request("remove", arg, None)?;
        packages.push(arg.trim().to_string());
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] remove <pkg1> [pkg2...]".to_string(),
        ));
    }

    Ok(PackageCommand::Remove { packages, purge })
}

fn parse_package_list_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut installed_only = false;
    for arg in args {
        match arg.as_str() {
            "--installed" => installed_only = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown argument for package list: {}",
                    other
                )));
            }
        }
    }
    Ok(PackageCommand::List { installed_only })
}

fn parse_package_update_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut package: Option<String> = None;
    let mut channel = ReleaseChannel::Stable;
    let mut target_version: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                let raw_ch = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--channel requires stable or nightly".to_string())
                })?;
                channel = ReleaseChannel::from_str(raw_ch)?;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                i += 1;
            }
            "--target-version" | "-t" => {
                let raw_target = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--target-version requires a version argument".to_string())
                })?;
                let trimmed = raw_target.trim();
                if !af_release::lifecycle::validate_target_version(trimmed) {
                    return Err(CliError::Validation(format!(
                        "invalid --target-version {:?} (must be a concrete version, commit SHA, or component manifest)",
                        raw_target
                    )));
                }
                target_version = Some(trimmed.to_string());
                i += 2;
            }
            s if s.starts_with("--target-version=") => {
                let raw_target = s.trim_start_matches("--target-version=");
                let trimmed = raw_target.trim();
                if !af_release::lifecycle::validate_target_version(trimmed) {
                    return Err(CliError::Validation(format!(
                        "invalid --target-version {:?} (must be a concrete version, commit SHA, or component manifest)",
                        raw_target
                    )));
                }
                target_version = Some(trimmed.to_string());
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!("unknown flag for update: {}", pkg)));
                }
                if package.is_some() {
                    return Err(CliError::Usage(
                        "usage: af [package] update [package_id] [--target-version <ver>] [--channel <channel>]".to_string(),
                    ));
                }
                let _ = build_package_runner_request("update", pkg, None)?;
                package = Some(pkg.trim().to_string());
                i += 1;
            }
        }
    }
    if package.is_none() && target_version.is_some() {
        return Err(CliError::Usage(
            "--target-version requires a package identifier (usage: af update <package> --target-version <ver>)".to_string(),
        ));
    }
    Ok(PackageCommand::Update {
        package,
        channel,
        target_version,
    })
}

fn parse_package_upgrade_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut channel = ReleaseChannel::Stable;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                let raw_ch = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--channel requires stable or nightly".to_string())
                })?;
                channel = ReleaseChannel::from_str(raw_ch)?;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for upgrade: {}",
                    other
                )));
            }
        }
    }
    Ok(PackageCommand::Upgrade { channel })
}

fn parse_service_subcommand(args: &[String]) -> CliResult<ServiceCommand> {
    if args.len() != 2 {
        return Err(CliError::Usage(
            "usage: af service <start|stop|restart|reload|enable|disable|status> <service_name>"
                .to_string(),
        ));
    }
    let req = validate_service_request(&args[1], &args[0])?;
    Ok(ServiceCommand {
        action: req.action,
        service: req.service,
    })
}

fn parse_quota_subcommand(head: &str, args: &[String]) -> CliResult<QuotaCommand> {
    // Support both `af setdisk <user> <size>` and `af quota set <user> <size>`
    if head == "setdisk" && args.len() == 2 {
        let (req, _) = build_quota_runner_request(&args[0], &args[1])?;
        return Ok(QuotaCommand::Set {
            username: req.username,
            size: req.size,
        });
    }

    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af quota <set|check-size> ...".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "set" => {
            if tail.len() != 2 {
                return Err(CliError::Usage(
                    "usage: af quota set <username> <size>".to_string(),
                ));
            }
            let (req, _) = build_quota_runner_request(&tail[0], &tail[1])?;
            Ok(QuotaCommand::Set {
                username: req.username,
                size: req.size,
            })
        }
        "check-size" | "parse" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af quota check-size <size>".to_string(),
                ));
            }
            let clean = tail[0].trim();
            if !SAFE_QUOTA_SIZE.is_match(clean) {
                return Err(CliError::Validation(format!(
                    "invalid quota size {:?}",
                    tail[0]
                )));
            }
            let _ = parse_quota_size_to_1k_blocks(clean)
                .ok_or_else(|| CliError::Validation(format!("invalid quota size {:?}", clean)))?;
            Ok(QuotaCommand::CheckSize {
                size: clean.to_string(),
            })
        }
        other => Err(CliError::Unsupported {
            operation: format!("quota {}", other),
            reason: "only 'af quota set <username> <size>' (runner /v1/quota) and 'af quota check-size <size>' are backed by verified af-runner contracts".to_string(),
        }),
    }
}

fn parse_sandbox_subcommand(args: &[String]) -> CliResult<SandboxCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af sandbox <apply|render> <package> [--user <username>]".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "apply" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af sandbox apply <package>".to_string(),
                ));
            }
            let req = build_sandbox_runner_request(&tail[0])?;
            Ok(SandboxCommand::Apply {
                package: req.package_id,
            })
        }
        "render" | "preview" => {
            if tail.is_empty() {
                return Err(CliError::Usage(
                    "usage: af sandbox render <package> [--user <username>]".to_string(),
                ));
            }
            let req = build_sandbox_runner_request(&tail[0])?;
            let mut username: Option<String> = None;
            let mut i = 1usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--user" | "-u" => {
                        let u = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--user requires a username".to_string())
                        })?;
                        if !SAFE_USERNAME.is_match(u.trim()) {
                            return Err(CliError::Validation(format!("invalid username {:?}", u)));
                        }
                        username = Some(u.trim().to_string());
                        i += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for sandbox render: {}",
                            other
                        )));
                    }
                }
            }
            Ok(SandboxCommand::Render {
                package: req.package_id,
                username,
            })
        }
        other => Err(CliError::Usage(format!(
            "unknown sandbox subcommand {:?} (expected: apply, render)",
            other
        ))),
    }
}

fn parse_release_subcommand(args: &[String]) -> CliResult<ReleaseCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af release <status|deploy|rollback|cleanup|migrate-systemd> [options]"
                .to_string(),
        ));
    };
    let tail = &args[1..];

    let mut channel = ReleaseChannel::Stable;
    let mut channel_explicit = false;
    let mut mode = ReleaseDispatchMode::RunnerSocket;
    let mut offline = false;
    let mut from_source = false;
    let mut keep_releases: Option<usize> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut job_status_file: Option<PathBuf> = None;
    let mut job_unit: Option<String> = None;

    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--channel" | "-c" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--channel requires stable or nightly".to_string())
                })?;
                channel = ReleaseChannel::from_str(val)?;
                channel_explicit = true;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                channel_explicit = true;
                i += 1;
            }
            "--local" | "--direct-engine" => {
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--via-runner" => {
                mode = ReleaseDispatchMode::RunnerSocket;
                i += 1;
            }
            "--offline" => {
                offline = true;
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--from-source" => {
                from_source = true;
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--keep-releases" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--keep-releases requires an integer >= 2".to_string())
                })?;
                let parsed = val.parse::<usize>().map_err(|_| {
                    CliError::Validation(format!("invalid --keep-releases count {:?}", val))
                })?;
                if parsed < 2 {
                    return Err(CliError::Validation(
                        "--keep-releases must be at least 2".to_string(),
                    ));
                }
                keep_releases = Some(parsed);
                i += 2;
            }
            "--config" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--config requires a path to release-manager.conf".to_string())
                })?;
                config_path = Some(PathBuf::from(val));
                i += 2;
            }
            s if s.starts_with("--config=") => {
                let val = s.trim_start_matches("--config=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--config requires a path to release-manager.conf".to_string(),
                    ));
                }
                config_path = Some(PathBuf::from(val));
                i += 1;
            }
            "--job-status-file" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage(
                        "--job-status-file requires a path to a status JSON file".to_string(),
                    )
                })?;
                job_status_file = Some(PathBuf::from(val));
                i += 2;
            }
            s if s.starts_with("--job-status-file=") => {
                let val = s.trim_start_matches("--job-status-file=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--job-status-file requires a path to a status JSON file".to_string(),
                    ));
                }
                job_status_file = Some(PathBuf::from(val));
                i += 1;
            }
            "--job-unit" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--job-unit requires a transient unit name".to_string())
                })?;
                job_unit = Some(val.clone());
                i += 2;
            }
            s if s.starts_with("--job-unit=") => {
                let val = s.trim_start_matches("--job-unit=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--job-unit requires a transient unit name".to_string(),
                    ));
                }
                job_unit = Some(val.to_string());
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown option for 'af release {}': {}",
                    sub, other
                )));
            }
        }
    }

    match sub {
        "status" => Ok(ReleaseCliCommand::Status { config_path }),
        "deploy" => {
            let _ = build_self_update_runner_request("deploy", channel)?;
            Ok(ReleaseCliCommand::Deploy {
                channel,
                channel_explicit,
                mode,
                offline,
                from_source,
                keep_releases,
                config_path,
                job_status_file,
                job_unit,
            })
        }
        "rollback" => {
            let _ = build_self_update_runner_request("rollback", channel)?;
            Ok(ReleaseCliCommand::Rollback {
                channel,
                channel_explicit,
                mode,
                config_path,
                job_status_file,
                job_unit,
            })
        }
        "cleanup" => Ok(ReleaseCliCommand::Cleanup {
            keep_releases,
            config_path,
        }),
        "migrate-systemd" => Ok(ReleaseCliCommand::MigrateSystemd { config_path }),
        other => Err(CliError::Usage(format!(
            "unknown release subcommand {:?} (expected: status, deploy, rollback, cleanup, migrate-systemd)",
            other
        ))),
    }
}
