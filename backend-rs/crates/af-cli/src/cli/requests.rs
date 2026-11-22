use super::{HostsCliCommand, ReleaseCliCommand, ALLOWED_SYSTEMCTL_ACTIONS};
use crate::error::{CliError, CliResult};
use af_models::{
    PackageRunnerRequest, QuotaRunnerRequest, SandboxRunnerRequest, SelfUpdateRequest,
    SystemctlRequest,
};
use af_release::{ReleaseChannel, ReleaseCommand, ReleaseOptions};
use af_runner::{
    get_runner_package_definition, parse_quota_size_to_1k_blocks, validate_hosts_domain,
    validate_hosts_ip, HostsUpdateRequest, SAFE_PKG_ID, SAFE_QUOTA_SIZE, SAFE_SERVICE_NAME,
    SAFE_USERNAME,
};

// ─────────────────────────────────────────────────────────────────────────────
// Typed Runner Request Builders & Validators
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the legacy `packages/system/af` lockfile name for a package identifier
/// (handling canonical aliases such as `autodl` -> `autodlirssi` and `transmission-daemon` -> `transmission`).
pub fn resolve_package_lock_name(pkg_id: &str) -> &str {
    af_models::resolve_package_lock_name(pkg_id)
}

/// Validates and builds a [`PackageRunnerRequest`] for `/v1/package` (`install`, `remove`, `update`).
pub fn build_package_runner_request(
    action: &str,
    pkg_id: &str,
    app_port: Option<i32>,
) -> CliResult<PackageRunnerRequest> {
    let clean_pkg = pkg_id.trim();
    if !SAFE_PKG_ID.is_match(clean_pkg) {
        return Err(CliError::Validation(format!(
            "invalid package identifier {:?} (must match ^[a-z0-9][a-z0-9_-]{{0,62}}$)",
            pkg_id
        )));
    }

    // Verify package exists in af-runner's allowlisted package registry (or canonical alias)
    let lookup_id = resolve_package_lock_name(clean_pkg);
    if get_runner_package_definition(lookup_id).is_none()
        && get_runner_package_definition(clean_pkg).is_none()
    {
        return Err(CliError::Validation(format!(
            "unknown or unallowlisted package {:?}",
            clean_pkg
        )));
    }

    let script_prefix = match action {
        "install" | "reinstall" => "installpackage-",
        "remove" => "removepackage-",
        "update" => "updatepackage-",
        other => {
            return Err(CliError::Validation(format!(
                "unsupported package action {:?} (expected install, reinstall, remove, or update)",
                other
            )));
        }
    };

    let port = app_port.unwrap_or(0);
    if !(0..=65535).contains(&port) {
        return Err(CliError::Validation(format!(
            "invalid application port {} (must be 0..=65535)",
            port
        )));
    }

    let mut secondary_port = 0;
    if clean_pkg == "rclone" && action != "remove" {
        if let Ok(raw) = std::env::var("RCLONE_API_PORT") {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                let parsed = af_runner::parse_rclone_port_value(trimmed).ok_or_else(|| {
                    CliError::Validation(format!(
                        "invalid RCLONE_API_PORT {:?} (must be 1..=65535)",
                        trimmed
                    ))
                })?;
                if port > 0 && parsed as i32 == port {
                    return Err(CliError::Validation(format!(
                        "RCLONE_API_PORT {} must differ from GUI port {}",
                        parsed, port
                    )));
                }
                secondary_port = parsed as i32;
            }
        }
    }

    let target = std::env::var("AF_TARGET_VERSION")
        .ok()
        .filter(|s| !s.trim().is_empty());

    Ok(PackageRunnerRequest {
        action: action.to_string(),
        package_id: clean_pkg.to_string(),
        script_name: format!("{}{}", script_prefix, clean_pkg),
        lifecycle_job_id: String::new(),
        app_port: port,
        secondary_port,
        delete_data: false,
        expected_target_version: target,
        ..Default::default()
    })
}

/// Validates and builds a [`PackageRunnerRequest`] with an explicit target version.
pub fn build_package_runner_request_with_target(
    action: &str,
    pkg_id: &str,
    app_port: Option<i32>,
    expected_target_version: Option<String>,
) -> CliResult<PackageRunnerRequest> {
    let mut req = build_package_runner_request(action, pkg_id, app_port)?;
    if let Some(target) = expected_target_version.filter(|s| !s.trim().is_empty()) {
        req.expected_target_version = Some(target.trim().to_string());
    }
    Ok(req)
}

/// Validates and builds a [`SystemctlRequest`] for `/v1/systemctl`.
pub fn validate_service_request(service: &str, action: &str) -> CliResult<SystemctlRequest> {
    let clean_action = action.trim().to_ascii_lowercase();
    if !ALLOWED_SYSTEMCTL_ACTIONS.contains(&clean_action.as_str()) {
        return Err(CliError::Validation(format!(
            "unsupported service action {:?} (allowed: {})",
            action,
            ALLOWED_SYSTEMCTL_ACTIONS.join(", ")
        )));
    }

    let clean_service = service.trim();
    if !SAFE_SERVICE_NAME.is_match(clean_service) {
        return Err(CliError::Validation(format!(
            "invalid systemd service name {:?}",
            service
        )));
    }

    Ok(SystemctlRequest {
        service: clean_service.to_string(),
        action: clean_action,
        lifecycle_job_id: String::new(),
    })
}

/// Validates and builds a [`QuotaRunnerRequest`] for `/v1/quota`, reusing
/// `af_runner::SAFE_USERNAME`, `af_runner::SAFE_QUOTA_SIZE`, and `af_runner::parse_quota_size_to_1k_blocks`.
pub fn build_quota_runner_request(
    username: &str,
    size: &str,
) -> CliResult<(QuotaRunnerRequest, u64)> {
    let clean_user = username.trim();
    if !SAFE_USERNAME.is_match(clean_user) {
        return Err(CliError::Validation(format!(
            "invalid username {:?} (must match ^[a-z_][a-z0-9_-]{{0,31}}$)",
            username
        )));
    }

    let clean_size = size.trim();
    if !SAFE_QUOTA_SIZE.is_match(clean_size) {
        return Err(CliError::Validation(format!(
            "invalid quota size {:?} (expected integer bytes or K/M/G/T suffix, e.g. 500G)",
            size
        )));
    }

    let (blocks_1k, _) = parse_quota_size_to_1k_blocks(clean_size)
        .ok_or_else(|| CliError::Validation(format!("invalid quota size {:?}", size)))?;

    Ok((
        QuotaRunnerRequest {
            username: clean_user.to_string(),
            size: clean_size.to_string(),
        },
        blocks_1k,
    ))
}

/// Validates and builds a [`SandboxRunnerRequest`] for `/v1/sandbox`, reusing `af_runner::SAFE_PKG_ID`.
pub fn build_sandbox_runner_request(package: &str) -> CliResult<SandboxRunnerRequest> {
    let clean_pkg = package.trim();
    if !SAFE_PKG_ID.is_match(clean_pkg) {
        return Err(CliError::Validation(format!(
            "invalid package identifier for sandbox: {:?}",
            package
        )));
    }

    Ok(SandboxRunnerRequest {
        package: clean_pkg.to_string(),
        package_id: clean_pkg.to_string(),
        lifecycle_job_id: String::new(),
    })
}

fn validate_hosts_domains(domains: &[String]) -> CliResult<Vec<String>> {
    let mut clean_domains = Vec::with_capacity(domains.len());
    for domain in domains {
        let valid =
            validate_hosts_domain(domain).map_err(|e| CliError::Validation(e.to_string()))?;
        clean_domains.push(valid);
    }
    Ok(clean_domains)
}

/// Validates and builds an [`af_runner::HostsUpdateRequest`] for `/v1/hosts`.
pub fn build_hosts_runner_request(cmd: &HostsCliCommand) -> CliResult<HostsUpdateRequest> {
    match cmd {
        HostsCliCommand::Update { ip, domains } => {
            if domains.is_empty() {
                return Err(CliError::Validation(
                    "hosts update requires at least one domain".to_string(),
                ));
            }
            validate_hosts_ip(ip)
                .map_err(|e| CliError::Validation(format!("invalid IP address {:?}: {}", ip, e)))?;
            Ok(HostsUpdateRequest {
                action: "update".to_string(),
                ip: ip.trim().to_string(),
                domains: validate_hosts_domains(domains)?,
                ..Default::default()
            })
        }
        HostsCliCommand::Remove { domains } => {
            if domains.is_empty() {
                return Err(CliError::Validation(
                    "hosts remove requires at least one domain".to_string(),
                ));
            }
            Ok(HostsUpdateRequest {
                action: "remove".to_string(),
                domains: validate_hosts_domains(domains)?,
                ..Default::default()
            })
        }
        HostsCliCommand::Reconcile { ip, domains } => {
            validate_hosts_ip(ip)
                .map_err(|e| CliError::Validation(format!("invalid IP address {:?}: {}", ip, e)))?;
            Ok(HostsUpdateRequest {
                action: "reconcile".to_string(),
                ip: ip.trim().to_string(),
                domains: validate_hosts_domains(domains)?,
                ..Default::default()
            })
        }
    }
}

/// Validates and builds a [`SelfUpdateRequest`] for `/v1/self-update` and validates it using
/// `af_release::validate_self_update_request`.
pub fn build_self_update_runner_request(
    command: &str,
    channel: ReleaseChannel,
) -> CliResult<SelfUpdateRequest> {
    let req = SelfUpdateRequest {
        command: command.to_string(),
        channel: channel.as_str().to_string(),
    };
    af_release::validate_self_update_request(&req)
        .map_err(|resp| CliError::Validation(resp.error))?;
    Ok(req)
}

/// Converts a [`ReleaseCliCommand`] into an [`af_release::ReleaseOptions`] struct for direct `ReleaseEngine` execution.
pub fn build_release_engine_options(
    cmd: &ReleaseCliCommand,
    dry_run: bool,
) -> Option<ReleaseOptions> {
    match cmd {
        ReleaseCliCommand::Status { .. } => None,
        ReleaseCliCommand::Deploy {
            channel,
            offline,
            from_source,
            ..
        } => Some(ReleaseOptions {
            command: ReleaseCommand::Deploy,
            channel: *channel,
            dry_run,
            offline: *offline,
            from_source: *from_source,
        }),
        ReleaseCliCommand::Rollback { channel, .. } => Some(ReleaseOptions {
            command: ReleaseCommand::Rollback,
            channel: *channel,
            dry_run,
            offline: false,
            from_source: false,
        }),
        ReleaseCliCommand::Cleanup { .. } => Some(ReleaseOptions {
            command: ReleaseCommand::Cleanup,
            channel: ReleaseChannel::Stable,
            dry_run,
            offline: false,
            from_source: false,
        }),
        ReleaseCliCommand::MigrateSystemd { .. } => Some(ReleaseOptions {
            command: ReleaseCommand::MigrateSystemd,
            channel: ReleaseChannel::Stable,
            dry_run,
            offline: false,
            from_source: false,
        }),
    }
}
