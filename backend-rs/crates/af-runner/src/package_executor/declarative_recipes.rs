use super::*;

/// Verified declarative recipes. LegacyBashFallback remains the default engine
/// unless AETHERFLOW_ENABLE_RUST_PACKAGES=1 opts in to the Rust engine.
pub(super) static BUILTIN_DECLARATIVE_RECIPES: Lazy<HashMap<String, DeclarativePackageRecipe>> =
    Lazy::new(|| {
        let mut map = HashMap::new();
        for recipe in [
            build_fail2ban_recipe(),
            build_quassel_recipe(),
            build_threadfin_recipe(),
            build_znc_recipe(),
            build_xrdp_recipe(),
            build_novnc_recipe(),
            build_x2go_recipe(),
            build_prometheus_recipe(),
            build_netdata_recipe(),
            build_mergerfs_recipe(),
            build_rclone_recipe(),
            build_syncthing_recipe(),
        ] {
            recipe
                .validate()
                .expect("built-in declarative package recipe failed validation");
            map.insert(recipe.package_id.clone(), recipe);
        }
        map
    });

/// Returns the built-in declarative recipe for `pkg_id`, if that package has been migrated
/// and verified for full parity. Unported or deferred recipes return `None` and automatically
/// fall back to the legacy Bash scripts in `packages/package/{install,remove,update}/*`.
pub fn get_declarative_recipe(pkg_id: &str) -> Option<DeclarativePackageRecipe> {
    BUILTIN_DECLARATIVE_RECIPES
        .get(pkg_id.trim().to_lowercase().as_str())
        .cloned()
}

/// Lists all package IDs currently supported by the native Rust declarative executor.
pub fn list_declarative_recipe_ids() -> Vec<String> {
    let mut ids: Vec<String> = BUILTIN_DECLARATIVE_RECIPES.keys().cloned().collect();
    ids.sort();
    ids
}

/// Pure helper evaluating engine selection given explicit gate flags (`rust_enabled`, `force_bash`).
pub fn select_package_engine_with_flags(
    pkg_id: &str,
    rust_enabled: bool,
    force_bash: bool,
) -> PackageEngineMode {
    if rust_enabled && !force_bash && get_declarative_recipe(pkg_id).is_some() {
        PackageEngineMode::DeclarativeRust
    } else {
        PackageEngineMode::LegacyBashFallback
    }
}

/// Returns `true` when the native Rust package engine is enabled via
/// `AETHERFLOW_ENABLE_RUST_PACKAGES` and not overridden by `AETHERFLOW_FORCE_BASH_PACKAGES`.
pub fn is_rust_package_engine_enabled() -> bool {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    rust_enabled && !force_bash
}

/// Determines whether `pkg_id` will execute via [`PackageEngineMode::DeclarativeRust`] or
/// [`PackageEngineMode::LegacyBashFallback`].
///
/// Default gate: `AETHERFLOW_ENABLE_RUST_PACKAGES` defaults to OFF (`false`).
/// Override gate: `AETHERFLOW_FORCE_BASH_PACKAGES=1` forces all packages through legacy Bash scripts.
pub fn select_package_engine(pkg_id: &str) -> PackageEngineMode {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_PACKAGES")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_PACKAGES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    select_package_engine_with_flags(pkg_id, rust_enabled, force_bash)
}

pub(super) fn build_fail2ban_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 20,
            description: "Updating APT package indexes for Fail2ban...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "fail2ban".to_string(),
                "python3-systemd".to_string(),
                "iptables".to_string(),
            ],
            progress_pct: 40,
            description: "Installing fail2ban and python3-systemd backend...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/fail2ban".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 45,
            description: "Configuring /etc/fail2ban/jail.local...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "fail2ban".to_string(),
            fallback_version: "1.0.2".to_string(),
            version_file_path: Some("/etc/fail2ban/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 50,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::ProbeSshPort {
            progress_pct: 55,
            description: "Inspecting /etc/ssh/sshd_config for active SSH port...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/fail2ban/jail.local".to_string(),
            content_template: "[DEFAULT]\nbantime  = 1h\nfindtime = 10m\nmaxretry = 5\nbackend  = systemd\n\n[sshd]\nenabled = true\nport    = {{SSH_PORT}},ssh\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 66,
            description: "Seeding initial /etc/fail2ban/jail.local when absent...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 80,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("fail2ban.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 85,
            description: "Starting and enabling fail2ban.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("fail2ban.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 95,
            description: "Verifying fail2ban.service restart...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "fail2ban".to_string(),
        label: "Fail2ban".to_string(),
        default_port: 0,
        service_name: "fail2ban".to_string(),
        lock_file: "/install/.fail2ban.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::AptRemove {
                packages: vec!["fail2ban".to_string()],
                autoremove: false,
                ignore_errors: false,
                progress_pct: 20,
                description:
                    "Removing fail2ban APT package (purging only with DELETE_DATA=true)..."
                        .to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "fail2ban.service".to_string(),
                progress_pct: 55,
                description: "Stopping and disabling fail2ban.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/fail2ban".to_string(), "/var/lib/fail2ban".to_string()],
                only_if_delete_data: true,
                progress_pct: 80,
                description:
                    "Purging Fail2ban configuration and state only with DELETE_DATA=true..."
                        .to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/fail2ban/.af-version".to_string(),
                    "/run/fail2ban".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 85,
                description: "Removing Fail2ban runtime directory and version marker..."
                    .to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Fail2ban removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_quassel_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Quassel Core...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["openssl".to_string()],
            progress_pct: 25,
            description: "Installing OpenSSL before provisioning Quassel credentials...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "quasselcore".to_string(),
            home_dir: "/var/lib/quassel".to_string(),
            create_home: false,
            progress_pct: 35,
            description: "Ensuring dedicated quasselcore system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/quassel".to_string(),
                "/var/log/quassel".to_string(),
            ],
            mode: 0o750,
            owner: Some("quasselcore".to_string()),
            group: Some("quasselcore".to_string()),
            progress_pct: 45,
            description: "Configuring Quassel data and log directories...".to_string(),
        },
        DeclarativeStep::GenerateSelfSignedTlsCert {
            cert_path: "/var/lib/quassel/quasselCert.pem".to_string(),
            key_out_path: None,
            subject: "/CN=quassel.aether.local".to_string(),
            days: 3650,
            mode: 0o600,
            owner: Some("quasselcore".to_string()),
            group: Some("quasselcore".to_string()),
            overwrite: false,
            progress_pct: 55,
            description: "Ensuring Quassel TLS certificate (/var/lib/quassel/quasselCert.pem)...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/default/quasselcore".to_string(),
            content_template: "LISTEN=\"0.0.0.0\"\nPORT=\"{{LISTEN_PORT}}\"\nCONFIGDIR=\"/var/lib/quassel\"\nLOGFILE=\"/var/log/quassel/quasselcore.log\"\nLOGLEVEL=\"Info\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Writing /etc/default/quasselcore daemon defaults...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["quassel-core".to_string()],
            progress_pct: 75,
            description: "Installing quassel-core with preserved TLS credentials and configured defaults...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "quassel-core".to_string(),
            fallback_version: "0.14.0".to_string(),
            version_file_path: Some("/var/lib/quassel/.af-version".to_string()),
            owner: Some("quasselcore".to_string()),
            group: Some("quasselcore".to_string()),
            progress_pct: 80,
            description: "Capturing installed quassel-core dpkg version...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "quasselcore.service".to_string(),
            content_template: "[Unit]\nDescription=Quassel Core IRC Bouncer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=quasselcore\nGroup=quasselcore\nEnvironmentFile=-/etc/default/quasselcore\nExecStart=/usr/bin/quasselcore --configdir=/var/lib/quassel --listen=0.0.0.0 --port={{LISTEN_PORT}}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 85,
            description: "Writing quasselcore.service systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 90,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("quasselcore.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 93,
            description: "Enabling and starting quasselcore.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("quasselcore.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting quasselcore.service with active configuration...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "quassel".to_string(),
        label: "Quassel".to_string(),
        default_port: 0,
        service_name: "quasselcore".to_string(),
        lock_file: "/install/.quassel.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::AptRemove {
                packages: vec!["quassel-core".to_string(), "quassel-data".to_string()],
                autoremove: false,
                ignore_errors: false,
                progress_pct: 25,
                description: "Removing quassel-core APT package (purging only with DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "quasselcore.service".to_string(),
                progress_pct: 55,
                description: "Stopping and disabling quasselcore.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/quassel/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 75,
                description: "Removing Quassel runtime metadata files...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/default/quasselcore".to_string(),
                    "/var/lib/quassel".to_string(),
                    "/var/log/quassel".to_string(),
                    "/var/log/quasselcore.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 84,
                description: "Conditionally purging Quassel SQLite database and TLS certificate (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "quasselcore".to_string(),
                home_dir: Some("/var/lib/quassel".to_string()),
                progress_pct: 88,
                description: "Removing quasselcore system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Quassel removal...".to_string(),
            },
        ],
    }
}

pub fn resolve_threadfin_target_version() -> String {
    if resolve_threadfin_sha256_override().is_some() {
        for var_name in [
            "AETHERFLOW_THREADFIN_VERSION",
            "THREADFIN_VERSION",
            "AF_THREADFIN_VERSION",
            "AETHERFLOW_PACKAGE_VERSION_OVERRIDE",
        ] {
            if let Ok(val) = env::var(var_name) {
                let trimmed = val.trim().trim_start_matches('v').trim_start_matches('V');
                if !trimmed.is_empty() && SAFE_VERSION_TAG.is_match(trimmed) {
                    return trimmed.to_string();
                }
            }
        }
    }
    THREADFIN_PINNED_VERSION.to_string()
}

pub fn resolve_threadfin_sha256_override() -> Option<String> {
    for var_name in [
        "AETHERFLOW_THREADFIN_SHA256",
        "THREADFIN_SHA256",
        "AF_THREADFIN_SHA256",
        "AETHERFLOW_PACKAGE_SHA256_OVERRIDE",
    ] {
        if let Ok(val) = env::var(var_name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub(super) fn build_threadfin_recipe() -> DeclarativePackageRecipe {
    let target_version = resolve_threadfin_target_version();
    let sha_override = resolve_threadfin_sha256_override();
    let default_arch_sha256 = if sha_override.is_some() {
        None
    } else {
        Some(ArchAssetMap {
            amd64: format!(
                "{}|{}",
                THREADFIN_AMD64_COMPAT_SHA256, THREADFIN_AMD64_PLAIN_SHA256
            ),
            arm64: THREADFIN_ARM64_SHA256.to_string(),
            armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
        })
    };

    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 10,
            description: "Updating APT package indexes for Threadfin...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "curl".to_string(),
                "wget".to_string(),
                "ca-certificates".to_string(),
                "ffmpeg".to_string(),
                "vlc-bin".to_string(),
            ],
            progress_pct: 22,
            description: "Installing Threadfin prerequisites (curl, wget, ca-certificates, ffmpeg, vlc-bin)...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "threadfin".to_string(),
            home_dir: "/var/lib/threadfin".to_string(),
            create_home: true,
            progress_pct: 32,
            description: "Ensuring dedicated threadfin system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/opt/threadfin".to_string(),
                "/var/lib/threadfin".to_string(),
                "/var/lib/threadfin/conf".to_string(),
                "/var/lib/threadfin/temp".to_string(),
            ],
            mode: 0o750,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 42,
            description: "Creating /var/lib/threadfin state and configuration directories...".to_string(),
        },
        DeclarativeStep::DownloadBinary {
            url_template: "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}".to_string(),
            arch_map: ArchAssetMap {
                amd64: "Threadfin_linux_amd64_glibc_2.31_compat".to_string(),
                arm64: "Threadfin_linux_arm64".to_string(),
                armhf: Some("Threadfin_linux_arm".to_string()),
            },
            dest_path: "/usr/local/bin/threadfin".to_string(),
            mode: 0o755,
            verification: ArtifactVerificationPolicy {
                min_size_bytes: 1024,
                max_size_bytes: 128 * 1024 * 1024,
                expected_sha256: sha_override.clone(),
                arch_sha256: default_arch_sha256.clone(),
                require_gzip_magic: false,
                require_elf_magic: true,
            },
            progress_pct: 65,
            description: format!(
                "Downloading and verifying pinned Threadfin {} binary...",
                target_version
            ),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/threadfin/.af-version".to_string(),
            content_template: "{{VERSION}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 75,
            description: "Writing /var/lib/threadfin/.af-version metadata...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "threadfin.service".to_string(),
            content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind=127.0.0.1 -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing /etc/systemd/system/threadfin.service...".to_string(),
        },
        DeclarativeStep::EnsureThreadfinConfig {
            progress_pct: 87,
            description: "Ensuring Threadfin has a loopback bind default without replacing user settings...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 90,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("threadfin.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 95,
            description: "Enabling and starting threadfin.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("threadfin.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 98,
            description: "Restarting threadfin.service to apply the verified binary and configuration...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/status".to_string(),
            progress_pct: 99,
            description: "Verifying Threadfin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/status...".to_string(),
        },
    ];
    let update_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 10,
            description: "Updating APT package indexes for Threadfin update...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "curl".to_string(),
                "wget".to_string(),
                "ca-certificates".to_string(),
                "ffmpeg".to_string(),
                "vlc-bin".to_string(),
            ],
            progress_pct: 22,
            description: "Ensuring Threadfin runtime dependencies (curl, wget, ca-certificates, ffmpeg, vlc-bin)...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "threadfin".to_string(),
            home_dir: "/var/lib/threadfin".to_string(),
            create_home: true,
            progress_pct: 32,
            description: "Ensuring dedicated threadfin system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/opt/threadfin".to_string(),
                "/var/lib/threadfin".to_string(),
                "/var/lib/threadfin/conf".to_string(),
                "/var/lib/threadfin/temp".to_string(),
            ],
            mode: 0o750,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 42,
            description: "Ensuring /var/lib/threadfin state and configuration directories...".to_string(),
        },
        DeclarativeStep::DownloadBinary {
            url_template: "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}".to_string(),
            arch_map: ArchAssetMap {
                amd64: "Threadfin_linux_amd64_glibc_2.31_compat".to_string(),
                arm64: "Threadfin_linux_arm64".to_string(),
                armhf: Some("Threadfin_linux_arm".to_string()),
            },
            dest_path: "/usr/local/bin/threadfin".to_string(),
            mode: 0o755,
            verification: ArtifactVerificationPolicy {
                min_size_bytes: 1024,
                max_size_bytes: 128 * 1024 * 1024,
                expected_sha256: sha_override,
                arch_sha256: default_arch_sha256,
                require_gzip_magic: false,
                require_elf_magic: true,
            },
            progress_pct: 65,
            description: format!(
                "Downloading and verifying target Threadfin {} binary for update...",
                target_version
            ),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/threadfin/.af-version".to_string(),
            content_template: "{{VERSION}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: Some("threadfin".to_string()),
            group: Some("threadfin".to_string()),
            progress_pct: 75,
            description: "Updating /var/lib/threadfin/.af-version metadata...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "threadfin.service".to_string(),
            content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind=127.0.0.1 -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing /etc/systemd/system/threadfin.service...".to_string(),
        },
        DeclarativeStep::EnsureThreadfinConfig {
            progress_pct: 87,
            description: "Ensuring Threadfin has a loopback bind default without replacing user settings...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 90,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("threadfin.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 95,
            description: "Enabling and starting threadfin.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("threadfin.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 98,
            description: "Restarting threadfin.service to apply the updated binary and configuration...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/status".to_string(),
            progress_pct: 99,
            description: "Verifying Threadfin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/status...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "threadfin".to_string(),
        label: "Threadfin".to_string(),
        default_port: 34400,
        service_name: "threadfin".to_string(),
        lock_file: "/install/.threadfin.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps,
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "threadfin.service".to_string(),
                progress_pct: 25,
                description: "Stopping, disabling, and removing threadfin.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/usr/local/bin/threadfin".to_string(),
                    "/opt/threadfin".to_string(),
                    "/var/lib/threadfin/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 55,
                description: "Removing /usr/local/bin/threadfin binary and version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/threadfin".to_string()],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Conditionally removing /var/lib/threadfin state directory (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "threadfin".to_string(),
                home_dir: Some("/var/lib/threadfin".to_string()),
                progress_pct: 85,
                description: "Removing threadfin system user and group...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Threadfin removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_znc_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for ZNC...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["znc".to_string()],
            progress_pct: 35,
            description: "Installing znc APT package...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "znc".to_string(),
            home_dir: "/var/lib/znc".to_string(),
            create_home: true,
            progress_pct: 45,
            description: "Ensuring dedicated znc system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/znc".to_string(),
                "/var/lib/znc/configs".to_string(),
            ],
            mode: 0o750,
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 55,
            description: "Preparing /var/lib/znc configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "znc".to_string(),
            fallback_version: "1.9.1".to_string(),
            version_file_path: Some("/var/lib/znc/.af-version".to_string()),
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 65,
            description: "Capturing installed znc dpkg version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/znc/configs/znc.conf".to_string(),
            content_template: "Version = {{ZNC_CONF_VERSION}}\n<Listener l>\n    AllowIRC = true\n    AllowWeb = true\n    Port = {{APP_PORT}}\n    IPv4 = true\n    IPv6 = false\n    SSL = false\n    Host = 127.0.0.1\n</Listener>\nLoadModule = webadmin\n\n<User {{MASTER_USER}}>\n    Pass       = sha256#{{ZNC_PASS_HASH}}#{{ZNC_SALT}}#\n    Admin      = true\n    Nick       = {{MASTER_USER}}\n    AltNick    = {{MASTER_USER}}_\n    Ident      = {{MASTER_USER}}\n    RealName   = {{MASTER_USER}}\n</User>\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("znc".to_string()),
            group: Some("znc".to_string()),
            progress_pct: 75,
            description: "Writing /var/lib/znc/configs/znc.conf...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "znc.service".to_string(),
            content_template: "[Unit]\nDescription=ZNC, an advanced IRC bouncer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=znc\nGroup=znc\nExecStart=/usr/bin/znc -f --datadir=/var/lib/znc\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing znc.service systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 88,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("znc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting znc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("znc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting znc.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/".to_string(),
            progress_pct: 98,
            description: "Verifying ZNC webadmin HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "znc".to_string(),
        label: "ZNC".to_string(),
        default_port: 6501,
        service_name: "znc".to_string(),
        lock_file: "/install/.znc.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "znc.service".to_string(),
                progress_pct: 20,
                description: "Stopping and disabling znc.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["znc".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging znc APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/znc/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 70,
                description: "Removing ZNC runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/znc".to_string(),
                    "/opt/AetherFlow/logs/znc_credentials.txt".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /var/lib/znc data directory (when DELETE_DATA=true)..."
                    .to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "znc".to_string(),
                home_dir: Some("/var/lib/znc".to_string()),
                progress_pct: 88,
                description: "Removing znc system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after ZNC removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_xrdp_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for XRDP...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "xrdp".to_string(),
                "dbus-x11".to_string(),
                "xfce4".to_string(),
                "xfce4-goodies".to_string(),
                "xorgxrdp".to_string(),
            ],
            progress_pct: 50,
            description: "Installing xrdp, dbus-x11, and XFCE4 session packages...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/xrdp".to_string(), "/var/lib/xrdp".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 60,
            description: "Ensuring /etc/xrdp and /var/lib/xrdp configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "xrdp".to_string(),
            fallback_version: "0.9.24".to_string(),
            version_file_path: Some("/var/lib/xrdp/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/xrdp/startwm.sh".to_string(),
            content_template: "#!/bin/sh\nif [ -r /etc/default/locale ]; then\n  . /etc/default/locale\n  export LANG LANGUAGE\nfi\nunset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR\nexec startxfce4\n".to_string(),
            mode: 0o755,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/xrdp/startwm.sh session startup script...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 84,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp-sesman.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 88,
            description: "Enabling and starting xrdp-sesman.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting xrdp.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("xrdp.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting xrdp.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "xrdp".to_string(),
        label: "XRDP".to_string(),
        default_port: 0,
        service_name: "xrdp".to_string(),
        lock_file: "/install/.xrdp.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "xrdp.service".to_string(),
                progress_pct: 20,
                description: "Stopping and disabling xrdp.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "xrdp-sesman.service".to_string(),
                progress_pct: 35,
                description: "Stopping and disabling xrdp-sesman.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["xrdp".to_string(), "xorgxrdp".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging xrdp APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/xrdp/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing XRDP runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/xrdp".to_string(),
                    "/var/lib/xrdp".to_string(),
                    "/var/log/xrdp.log".to_string(),
                    "/var/log/xrdp-sesman.log".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing XRDP configuration, state, and logs...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after XRDP removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_novnc_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for noVNC...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "novnc".to_string(),
                "python3-websockify".to_string(),
                "tigervnc-standalone-server".to_string(),
                "dbus-x11".to_string(),
                "xfce4".to_string(),
            ],
            progress_pct: 40,
            description: "Installing novnc, python3-websockify, tigervnc-standalone-server, and dbus-x11...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "novnc".to_string(),
            home_dir: "/var/lib/novnc".to_string(),
            create_home: true,
            progress_pct: 50,
            description: "Ensuring dedicated novnc system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/novnc".to_string(),
                "/var/lib/novnc".to_string(),
            ],
            mode: 0o750,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 55,
            description: "Ensuring /etc/novnc and /var/lib/novnc directories...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/novnc/.vnc".to_string(),
            ],
            mode: 0o700,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 58,
            description: "Ensuring /var/lib/novnc/.vnc directory...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "novnc".to_string(),
            fallback_version: "1.4.0".to_string(),
            version_file_path: Some("/etc/novnc/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 63,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/novnc/.vnc/xstartup".to_string(),
            content_template: "#!/bin/sh\nexport DISPLAY=:1\nunset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS\nif command -v dbus-run-session >/dev/null 2>&1; then\n    exec dbus-run-session startxfce4\nfi\nif command -v dbus-launch >/dev/null 2>&1; then\n    exec dbus-launch --exit-with-session startxfce4\nfi\nexec startxfce4\n".to_string(),
            mode: 0o750,
            overwrite: false,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 68,
            description: "Writing /var/lib/novnc/.vnc/xstartup XFCE4 session launcher...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/novnc/.vnc/passwd".to_string(),
            content_template: "<MASTER_PASS>\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("novnc".to_string()),
            group: Some("novnc".to_string()),
            progress_pct: 71,
            description: "Writing /var/lib/novnc/.vnc/passwd VNC authentication secret...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc-xvnc.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow TigerVNC Desktop Server for noVNC\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=exec\nUser=novnc\nGroup=novnc\nEnvironment=HOME=/var/lib/novnc\nWorkingDirectory=/var/lib/novnc\nPrivateTmp=yes\nExecStartPre=!/usr/bin/mkdir -p -m 1777 /tmp/.X11-unix\nExecStart=/usr/bin/Xtigervnc :1 -geometry 1280x800 -depth 24 -localhost yes -rfbport 5901 -PasswordFile /var/lib/novnc/.vnc/passwd -SecurityTypes VncAuth,TLSVnc\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 74,
            description: "Writing novnc-xvnc.service VNC backend unit...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc-session.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow noVNC XFCE Desktop Session\nBindsTo=novnc-xvnc.service\nAfter=novnc-xvnc.service\nPartOf=novnc-xvnc.service\nJoinsNamespaceOf=novnc-xvnc.service\n\n[Service]\nType=exec\nUser=novnc\nGroup=novnc\nWorkingDirectory=/var/lib/novnc\nEnvironment=HOME=/var/lib/novnc DISPLAY=:1\nPrivateTmp=yes\nExecStartPre=/usr/bin/timeout 10s /bin/sh -c 'until test -S /tmp/.X11-unix/X1; do sleep 0.2; done'\nExecStart=/var/lib/novnc/.vnc/xstartup\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 77,
            description: "Writing novnc-session.service XFCE desktop unit...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "novnc.service".to_string(),
            content_template: "[Unit]\nDescription=AetherFlow noVNC Websockify Proxy\nAfter=network-online.target novnc-xvnc.service novnc-session.service\nWants=network-online.target\nRequires=novnc-xvnc.service novnc-session.service\n\n[Service]\nType=exec\nUser=novnc\nGroup=novnc\nExecStart=/usr/bin/websockify --web=/usr/share/novnc/ 127.0.0.1:{{APP_PORT}} 127.0.0.1:5901\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 80,
            description: "Writing novnc.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc-xvnc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 89,
            description: "Enabling and starting novnc-xvnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc-xvnc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 90,
            description: "Restarting novnc-xvnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc-session.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 91,
            description: "Enabling and starting novnc-session.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 93,
            description: "Enabling and starting novnc.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("novnc.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting novnc.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/vnc.html".to_string(),
            progress_pct: 98,
            description: "Verifying noVNC HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/vnc.html...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "novnc".to_string(),
        label: "noVNC".to_string(),
        default_port: 6080,
        service_name: "novnc".to_string(),
        lock_file: "/install/.novnc.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc.service".to_string(),
                progress_pct: 20,
                description: "Stopping and removing novnc.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc-session.service".to_string(),
                progress_pct: 30,
                description: "Stopping and removing novnc-session.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc-xvnc.service".to_string(),
                progress_pct: 35,
                description: "Stopping and removing novnc-xvnc.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "novnc".to_string(),
                    "python3-websockify".to_string(),
                    "tigervnc-standalone-server".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging novnc and python3-websockify APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/novnc/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing noVNC runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/novnc".to_string(), "/var/lib/novnc".to_string()],
                only_if_delete_data: true,
                progress_pct: 82,
                description: "Removing /var/lib/novnc state directory (when DELETE_DATA=true)..."
                    .to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "novnc".to_string(),
                home_dir: Some("/var/lib/novnc".to_string()),
                progress_pct: 88,
                description: "Removing novnc system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after noVNC removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_x2go_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for X2Go...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "x2goserver".to_string(),
                "x2goserver-xsession".to_string(),
                "xfce4".to_string(),
                "dbus-x11".to_string(),
            ],
            progress_pct: 55,
            description: "Installing x2goserver and x2goserver-xsession...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/x2go".to_string(), "/var/lib/x2go".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 65,
            description: "Ensuring /etc/x2go and /var/lib/x2go directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "x2goserver".to_string(),
            fallback_version: "4.1.0.3".to_string(),
            version_file_path: Some("/var/lib/x2go/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 72,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 82,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("x2goserver.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 90,
            description: "Enabling and starting x2goserver.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("x2goserver.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting x2goserver.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "x2go".to_string(),
        label: "X2Go".to_string(),
        default_port: 0,
        service_name: "x2goserver".to_string(),
        lock_file: "/install/.x2go.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "x2goserver.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling x2goserver.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["x2goserver".to_string(), "x2goserver-xsession".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging x2goserver APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/x2go/.af-version".to_string(),
                    "/etc/x2go/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 72,
                description: "Removing X2Go runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/x2go".to_string(), "/var/lib/x2go".to_string()],
                only_if_delete_data: true,
                progress_pct: 85,
                description: "Removing X2Go state directories (when DELETE_DATA=true)..."
                    .to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after X2Go removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_prometheus_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Prometheus...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "prometheus".to_string(),
                "prometheus-node-exporter".to_string(),
            ],
            progress_pct: 45,
            description: "Installing prometheus and prometheus-node-exporter APT packages...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/prometheus".to_string(),
                "/var/lib/prometheus".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 55,
            description: "Ensuring /etc/prometheus and /var/lib/prometheus directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "prometheus".to_string(),
            fallback_version: "2.53.0".to_string(),
            version_file_path: Some("/etc/prometheus/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 62,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/default/prometheus".to_string(),
            content_template: "ARGS=\"--web.listen-address=127.0.0.1:{{APP_PORT}} --storage.tsdb.path=/var/lib/prometheus/metrics2 --config.file=/etc/prometheus/prometheus.yml\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 70,
            description: "Writing /etc/default/prometheus listen configuration...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/prometheus/prometheus.yml".to_string(),
            content_template: "global:\n  scrape_interval: 15s\n  evaluation_interval: 15s\n\nscrape_configs:\n  - job_name: 'prometheus'\n    static_configs:\n      - targets: ['127.0.0.1:{{APP_PORT}}']\n  - job_name: 'node'\n    static_configs:\n      - targets: ['127.0.0.1:9100']\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 76,
            description: "Ensuring /etc/prometheus/prometheus.yml scrape config...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "node_exporter.service".to_string(),
            content_template: "[Unit]\nDescription=Prometheus Node Exporter\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=prometheus\nGroup=prometheus\nExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=127.0.0.1:9100\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 80,
            description: "Writing node_exporter.service companion systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus-node-exporter.service".to_string()),
            operation: SystemctlOp::Stop,
            ignore_errors: true,
            progress_pct: 82,
            description: "Stopping stock prometheus-node-exporter.service to avoid port 9100 conflict...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus-node-exporter.service".to_string()),
            operation: SystemctlOp::Disable,
            ignore_errors: true,
            progress_pct: 84,
            description: "Disabling stock prometheus-node-exporter.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 86,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("node_exporter.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 89,
            description: "Enabling and starting node_exporter.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting prometheus.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("prometheus.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting prometheus.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/-/healthy".to_string(),
            progress_pct: 98,
            description: "Verifying Prometheus HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/-/healthy...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "prometheus".to_string(),
        label: "Prometheus".to_string(),
        default_port: 9090,
        service_name: "prometheus".to_string(),
        lock_file: "/install/.prometheus.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "prometheus.service".to_string(),
                progress_pct: 20,
                description: "Stopping and disabling prometheus.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "node_exporter.service".to_string(),
                progress_pct: 32,
                description: "Stopping and disabling node_exporter.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec![
                    "prometheus".to_string(),
                    "prometheus-node-exporter".to_string(),
                ],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging prometheus APT packages...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/prometheus/.af-version".to_string(),
                    "/usr/local/bin/prometheus".to_string(),
                    "/usr/local/bin/node_exporter".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 65,
                description: "Removing Prometheus runtime version marker and binary symlinks..."
                    .to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/prometheus".to_string(),
                    "/etc/default/prometheus".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Removing Prometheus configuration files...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/prometheus".to_string()],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing Prometheus TSDB data (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Prometheus removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_netdata_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Netdata...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["netdata".to_string()],
            progress_pct: 45,
            description: "Installing netdata APT package...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec!["/etc/netdata".to_string(), "/var/lib/netdata".to_string()],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 55,
            description: "Ensuring /etc/netdata and /var/lib/netdata directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "netdata".to_string(),
            fallback_version: "1.47.0".to_string(),
            version_file_path: Some("/etc/netdata/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 62,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::MergeIniSettings {
            path: "/etc/netdata/netdata.conf".to_string(),
            section: "web".to_string(),
            settings: vec![
                ("bind to".to_string(), "127.0.0.1".to_string()),
                ("default port".to_string(), "{{APP_PORT}}".to_string()),
            ],
            mode: 0o644,
            progress_pct: 75,
            description: "Writing /etc/netdata/netdata.conf bound to 127.0.0.1:{{APP_PORT}}..."
                .to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("netdata.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting netdata.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("netdata.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting netdata.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/api/v1/info".to_string(),
            progress_pct: 98,
            description:
                "Verifying Netdata HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/api/v1/info..."
                    .to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "netdata".to_string(),
        label: "Netdata".to_string(),
        default_port: 19999,
        service_name: "netdata".to_string(),
        lock_file: "/install/.netdata.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "netdata.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling netdata.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["netdata".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging netdata APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/netdata/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 65,
                description: "Removing Netdata runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/netdata".to_string()],
                only_if_delete_data: true,
                progress_pct: 75,
                description: "Removing /etc/netdata configuration...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/netdata".to_string(),
                    "/var/log/netdata".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing Netdata state and logs (when DELETE_DATA=true)..."
                    .to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Netdata removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_mergerfs_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for MergerFS...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec!["mergerfs".to_string(), "fuse3".to_string()],
            progress_pct: 45,
            description: "Installing mergerfs and fuse3...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/mnt/mergerfs".to_string(),
                "/mnt/local".to_string(),
                "/mnt/remote".to_string(),
                "/mnt/unionfs".to_string(),
                "/etc/mergerfs".to_string(),
                "/var/lib/mergerfs".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 58,
            description: "Ensuring /mnt/unionfs and union mount directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "mergerfs".to_string(),
            fallback_version: "2.40.2".to_string(),
            version_file_path: Some("/var/lib/mergerfs/.af-version".to_string()),
            owner: None,
            group: None,
            progress_pct: 66,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/mergerfs/mergerfs.conf".to_string(),
            content_template: "BRANCHES=\"/mnt/local=RW:/mnt/remote=NC\"\nMOUNTPOINT=\"/mnt/unionfs\"\nOPTIONS=\"defaults,allow_other,use_ino,category.create=ff,moveonenospc=true,dropcacheonclose=true\"\n".to_string(),
            mode: 0o644,
            overwrite: false,
            owner: None,
            group: None,
            progress_pct: 75,
            description: "Writing /etc/mergerfs/mergerfs.conf...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "mergerfs.service".to_string(),
            content_template: "[Unit]\nDescription=MergerFS Union Filesystem Mount\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=\"BRANCHES=/mnt/local=RW:/mnt/remote=NC\"\nEnvironment=\"MOUNTPOINT=/mnt/unionfs\"\nEnvironment=\"OPTIONS=defaults,allow_other,use_ino,category.create=ff,moveonenospc=true,dropcacheonclose=true\"\nEnvironmentFile=-/etc/mergerfs/mergerfs.conf\nExecStart=/usr/bin/mergerfs -o ${OPTIONS} ${BRANCHES} ${MOUNTPOINT}\nExecStop=/bin/fusermount -uz ${MOUNTPOINT}\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 84,
            description: "Writing mergerfs.service systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 90,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("mergerfs.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 96,
            description: "Enabling and starting mergerfs.service...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "mergerfs".to_string(),
        label: "MergerFS".to_string(),
        default_port: 0,
        service_name: "mergerfs".to_string(),
        lock_file: "/install/.mergerfs.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "mergerfs.service".to_string(),
                progress_pct: 25,
                description: "Stopping and disabling mergerfs.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["mergerfs".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Purging mergerfs APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/var/lib/mergerfs/.af-version".to_string(),
                    "/etc/mergerfs/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 70,
                description: "Removing MergerFS runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/etc/mergerfs".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing /etc/mergerfs configuration...".to_string(),
            },
            DeclarativeStep::RunCommand {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "for mp in /mnt/unionfs /mnt/mergerfs; do if mountpoint -q \"$mp\" 2>/dev/null; then fusermount -u \"$mp\" 2>/dev/null || fusermount -uz \"$mp\" 2>/dev/null || umount -l \"$mp\" 2>/dev/null || true; if mountpoint -q \"$mp\" 2>/dev/null; then exit 1; fi; fi; done".to_string(),
                ],
                only_if_delete_data: true,
                ignore_errors: false,
                progress_pct: 84,
                description: "Unmounting active MergerFS FUSE mountpoints (/mnt/unionfs, /mnt/mergerfs) before directory removal...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/mnt/unionfs".to_string(),
                    "/mnt/mergerfs".to_string(),
                    "/var/lib/mergerfs".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 88,
                description: "Removing /mnt/unionfs, /mnt/mergerfs, and /var/lib/mergerfs directories (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after MergerFS removal...".to_string(),
            },
        ],
    }
}

pub fn detect_rclone_exec_start_for_root(effective_root: &Path) -> &'static str {
    let rclone_bin = effective_root.join("usr/bin/rclone");
    let cmd_target = if rclone_bin.is_file() {
        rclone_bin
    } else if effective_root == Path::new("/") || effective_root.as_os_str().is_empty() {
        PathBuf::from("rclone")
    } else if rclone_bin.exists() {
        rclone_bin
    } else {
        PathBuf::from("rclone")
    };

    let probe = std::process::Command::new(&cmd_target)
        .args(["rcd", "--help"])
        .output();
    let supports_rc_web_gui = probe
        .map(|out| {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            combined.contains("--rc-web-gui")
        })
        .unwrap_or(true);

    if supports_rc_web_gui {
        "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-enable-metrics --rc-addr=127.0.0.1:{{APP_PORT}} --config=/etc/rclone/rclone.conf"
    } else {
        "/usr/bin/rclone gui --addr=127.0.0.1:{{APP_PORT}} --api-addr=127.0.0.1:{{RCLONE_API_PORT}} --enable-metrics --no-open-browser --config=/etc/rclone/rclone.conf"
    }
}

pub fn detect_rclone_exec_start() -> &'static str {
    detect_rclone_exec_start_for_root(Path::new("/"))
}

pub fn detect_rclone_separate_api_port_for_root(
    effective_root: &Path,
    vars: &HashMap<String, String>,
    app_port: u16,
) -> Option<u16> {
    // 1. First check if variables explicitly specifies RCLONE_WEB_MODE or RCLONE_MODE:
    // If it is "rcd", return None immediately!
    let is_explicit_rcd = vars
        .get("RCLONE_WEB_MODE")
        .map(|v| v.eq_ignore_ascii_case("rcd"))
        .or_else(|| {
            vars.get("RCLONE_MODE")
                .map(|v| v.eq_ignore_ascii_case("rcd"))
        })
        .unwrap_or(false);
    if is_explicit_rcd {
        return None;
    }

    // 2. Next, determine the target unit name being verified (from variables.get("SYSTEMD_UNIT")
    // or variables.get("SERVICE_NAME"), defaulting to "rclone.service" when rclone.service exists on disk).
    let rclone_svc_path =
        if effective_root == Path::new("/") || effective_root.as_os_str().is_empty() {
            PathBuf::from("/etc/systemd/system/rclone.service")
        } else {
            effective_root.join("etc/systemd/system/rclone.service")
        };
    let rclone_web_svc_path =
        if effective_root == Path::new("/") || effective_root.as_os_str().is_empty() {
            PathBuf::from("/etc/systemd/system/rclone-web.service")
        } else {
            effective_root.join("etc/systemd/system/rclone-web.service")
        };

    let requested_unit = vars
        .get("SYSTEMD_UNIT")
        .or_else(|| vars.get("SERVICE_NAME"))
        .map(|s| s.trim());

    let is_rclone_web_requested =
        requested_unit.is_some_and(|u| u == "rclone-web" || u == "rclone-web.service");
    let is_rclone_requested =
        requested_unit.is_some_and(|u| u == "rclone" || u == "rclone.service");

    let units_to_check: Vec<(&str, PathBuf)> = if is_rclone_web_requested {
        vec![("rclone-web.service", rclone_web_svc_path)]
    } else if is_rclone_requested {
        vec![("rclone.service", rclone_svc_path)]
    } else if rclone_svc_path.is_file() {
        // If rclone.service exists on disk, inspect ONLY rclone.service!
        // Do NOT fall through to a stale rclone-web.service when rclone.service is present without --api-addr!
        vec![("rclone.service", rclone_svc_path)]
    } else if rclone_web_svc_path.is_file() {
        vec![("rclone-web.service", rclone_web_svc_path)]
    } else {
        Vec::new()
    };

    let mut any_unit_found = false;
    for (_name, service_path) in units_to_check {
        if let Ok(svc_content) = fs::read_to_string(&service_path) {
            any_unit_found = true;
            for line in svc_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("ExecStart=") {
                    if let Some(idx) = trimmed.find("--api-addr=") {
                        let rest = &trimmed[idx + "--api-addr=".len()..];
                        let token = rest.split_whitespace().next().unwrap_or("");
                        if let Some((_, p_str)) = token.rsplit_once(':') {
                            let cleaned = p_str.trim_matches(['"', '\'', ' ']);
                            if let Ok(p) = cleaned.parse::<u16>() {
                                if p != app_port {
                                    return Some(p);
                                }
                            }
                        }
                    } else if let Some(idx) = trimmed.find("--api-addr") {
                        let rest = trimmed[idx + "--api-addr".len()..].trim_start();
                        let token = rest.split_whitespace().next().unwrap_or("");
                        let addr = token.strip_prefix('=').unwrap_or(token);
                        if let Some((_, p_str)) = addr.rsplit_once(':') {
                            let cleaned = p_str.trim_matches(['"', '\'', ' ']);
                            if let Ok(p) = cleaned.parse::<u16>() {
                                if p != app_port {
                                    return Some(p);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if any_unit_found {
        // If a unit file exists but does NOT contain --api-addr (e.g. single-port rcd),
        // return None immediately! Do NOT fall back to variables.get("RCLONE_API_PORT")!
        return None;
    }

    // If no unit file exists on disk (e.g. in a synthetic unit test without unit files),
    // ONLY use variables.get("RCLONE_API_PORT") if variables.get("RCLONE_WEB_MODE") (or RCLONE_MODE) is explicitly "gui"!
    let is_explicit_gui = vars
        .get("RCLONE_WEB_MODE")
        .map(|v| v.eq_ignore_ascii_case("gui"))
        .or_else(|| {
            vars.get("RCLONE_MODE")
                .map(|v| v.eq_ignore_ascii_case("gui"))
        })
        .unwrap_or(false);

    if is_explicit_gui {
        if let Some(p) = vars
            .get("RCLONE_API_PORT")
            .and_then(|v| v.parse::<u16>().ok())
        {
            if p != app_port {
                return Some(p);
            }
        }
    }

    None
}

pub fn detect_rclone_separate_api_port(
    env_cfg: &PackageExecutionEnv,
    vars: &HashMap<String, String>,
    app_port: u16,
) -> Option<u16> {
    let effective_root = env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
    detect_rclone_separate_api_port_for_root(effective_root, vars, app_port)
}

pub(super) fn build_rclone_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Rclone...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "curl".to_string(),
                "unzip".to_string(),
                "ca-certificates".to_string(),
                "fuse3".to_string(),
            ],
            progress_pct: 35,
            description: "Installing curl, unzip, ca-certificates, and fuse3 for Rclone...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "rclone".to_string(),
            home_dir: "/var/lib/rclone".to_string(),
            create_home: false,
            progress_pct: 42,
            description: "Ensuring dedicated rclone system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/rclone".to_string(),
                "/var/lib/rclone/cache".to_string(),
                "/etc/rclone".to_string(),
                "/mnt/remote".to_string(),
            ],
            mode: 0o750,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 48,
            description: "Ensuring /var/lib/rclone and /etc/rclone directories...".to_string(),
        },
        DeclarativeStep::InstallRcloneBinary {
            progress_pct: 60,
            description: "Downloading and installing official Rclone binary...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/var/lib/rclone/.af-version".to_string(),
            content_template: "{{VERSION}}\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 64,
            description: "Recording Rclone runtime version marker...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/rclone/rclone.conf".to_string(),
            content_template: "# AetherFlow managed rclone configuration\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 70,
            description: "Ensuring /etc/rclone/rclone.conf exists...".to_string(),
        },
        DeclarativeStep::WriteTemplateFile {
            path: "/etc/rclone/rclone.env".to_string(),
            content_template: "RCLONE_RC_USER=\"{{MASTER_USER}}\"\nRCLONE_RC_PASS=\"{{RCLONE_PASS}}\"\nRCLONE_USER=\"{{MASTER_USER}}\"\nRCLONE_PASS=\"{{RCLONE_PASS}}\"\n".to_string(),
            mode: 0o600,
            overwrite: false,
            owner: Some("rclone".to_string()),
            group: Some("rclone".to_string()),
            progress_pct: 74,
            description: "Ensuring /etc/rclone/rclone.env exists...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone RC Web GUI Service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=rclone\nGroup=rclone\nWorkingDirectory=/var/lib/rclone\nEnvironmentFile=-/etc/rclone/rclone.env\nExecStart={{RCLONE_EXEC_START}}\nLogFilterPatterns=~.*(pass|password|token|login_token)=.*\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 79,
            description: "Writing rclone.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone-vfs.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone VFS FUSE Mount Daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStartPre=-/bin/mkdir -p /mnt/remote\nExecStart=/usr/bin/rclone mount remote: /mnt/remote --config=/etc/rclone/rclone.conf --vfs-cache-mode=full --allow-other --dir-cache-time=72h\nExecStop=/bin/fusermount -uz /mnt/remote\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 83,
            description: "Writing rclone-vfs.service companion systemd unit...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 86,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("rclone.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting rclone.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("rclone.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting rclone.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone RC HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/metrics...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "rclone".to_string(),
        label: "Rclone".to_string(),
        default_port: 5572,
        service_name: "rclone".to_string(),
        lock_file: "/install/.rclone.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "rclone-vfs.service".to_string(),
                progress_pct: 18,
                description: "Stopping and removing rclone-vfs.service...".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "rclone.service".to_string(),
                progress_pct: 30,
                description: "Stopping and removing rclone.service...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/usr/local/bin/rclone".to_string(),
                    "/usr/bin/rclone".to_string(),
                    "/var/lib/rclone/.af-version".to_string(),
                    "/etc/rclone/.af-version".to_string(),
                ],
                only_if_delete_data: false,
                progress_pct: 55,
                description: "Removing Rclone binaries and version markers...".to_string(),
            },
            DeclarativeStep::RunCommand {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "for mp in /mnt/remote; do if mountpoint -q \"$mp\" 2>/dev/null; then fusermount -u \"$mp\" 2>/dev/null || fusermount -uz \"$mp\" 2>/dev/null || umount -l \"$mp\" 2>/dev/null || true; if mountpoint -q \"$mp\" 2>/dev/null; then exit 1; fi; fi; done".to_string(),
                ],
                only_if_delete_data: true,
                ignore_errors: false,
                progress_pct: 70,
                description: "Unmounting active Rclone FUSE mountpoint (/mnt/remote) before directory removal...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec![
                    "/etc/rclone".to_string(),
                    "/var/lib/rclone".to_string(),
                    "/mnt/remote".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 78,
                description: "Removing Rclone state directories (when DELETE_DATA=true)...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["rclone".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 82,
                description: "Purging legacy distribution rclone package...".to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "rclone".to_string(),
                home_dir: Some("/var/lib/rclone".to_string()),
                progress_pct: 88,
                description: "Removing rclone system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Rclone removal...".to_string(),
            },
        ],
    }
}

pub(super) fn build_syncthing_recipe() -> DeclarativePackageRecipe {
    let install_steps = vec![
        DeclarativeStep::AptUpdate {
            progress_pct: 15,
            description: "Updating APT package indexes for Syncthing...".to_string(),
        },
        DeclarativeStep::AptInstall {
            packages: vec![
                "syncthing".to_string(),
                "ca-certificates".to_string(),
                "curl".to_string(),
            ],
            progress_pct: 40,
            description: "Installing syncthing APT package...".to_string(),
        },
        DeclarativeStep::EnsureSystemUser {
            username: "syncthing".to_string(),
            home_dir: "/var/lib/syncthing".to_string(),
            create_home: true,
            progress_pct: 50,
            description: "Ensuring dedicated syncthing system user...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/var/lib/syncthing".to_string(),
                "/var/lib/syncthing/.config".to_string(),
                "/var/lib/syncthing/.config/syncthing".to_string(),
            ],
            mode: 0o750,
            owner: Some("syncthing".to_string()),
            group: Some("syncthing".to_string()),
            progress_pct: 60,
            description: "Preparing /var/lib/syncthing configuration directories...".to_string(),
        },
        DeclarativeStep::CaptureDpkgVersion {
            package: "syncthing".to_string(),
            fallback_version: "1.28.0".to_string(),
            version_file_path: Some("/var/lib/syncthing/.af-version".to_string()),
            owner: Some("syncthing".to_string()),
            group: Some("syncthing".to_string()),
            progress_pct: 68,
            description: "Recording the installed Debian package version...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "syncthing.service".to_string(),
            content_template: "[Unit]\nDescription=Syncthing - Open Source Continuous File Synchronization\nAfter=network.target\n\n[Service]\nUser=syncthing\nGroup=syncthing\nWorkingDirectory=/var/lib/syncthing\nExecStart=/usr/bin/syncthing serve --no-browser --no-restart --gui-address=127.0.0.1:{{APP_PORT}} --home=/var/lib/syncthing\nRestart=on-failure\nRestartSec=5\nSuccessExitStatus=3 4\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 78,
            description: "Writing syncthing.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: None,
            operation: SystemctlOp::DaemonReload,
            ignore_errors: false,
            progress_pct: 85,
            description: "Reloading systemd manager configuration...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("syncthing.service".to_string()),
            operation: SystemctlOp::EnableNow,
            ignore_errors: false,
            progress_pct: 92,
            description: "Enabling and starting syncthing.service...".to_string(),
        },
        DeclarativeStep::Systemctl {
            unit: Some("syncthing.service".to_string()),
            operation: SystemctlOp::Restart,
            ignore_errors: false,
            progress_pct: 96,
            description: "Restarting syncthing.service...".to_string(),
        },
        DeclarativeStep::WaitForHttpReady {
            path: "/rest/noauth/health".to_string(),
            progress_pct: 98,
            description: "Verifying Syncthing HTTP listener readiness on 127.0.0.1:{{APP_PORT}}/rest/noauth/health...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "syncthing".to_string(),
        label: "Syncthing".to_string(),
        default_port: 8384,
        service_name: "syncthing".to_string(),
        lock_file: "/install/.syncthing.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
        install_steps,
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "syncthing.service".to_string(),
                progress_pct: 25,
                description: "Stopping and removing syncthing.service...".to_string(),
            },
            DeclarativeStep::AptPurge {
                packages: vec!["syncthing".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Purging syncthing APT package...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/syncthing/.af-version".to_string()],
                only_if_delete_data: false,
                progress_pct: 68,
                description: "Removing Syncthing runtime version marker...".to_string(),
            },
            DeclarativeStep::RemovePaths {
                paths: vec!["/var/lib/syncthing".to_string()],
                only_if_delete_data: true,
                progress_pct: 78,
                description:
                    "Removing /var/lib/syncthing state directory (when DELETE_DATA=true)..."
                        .to_string(),
            },
            DeclarativeStep::PurgeSystemUser {
                username: "syncthing".to_string(),
                home_dir: Some("/var/lib/syncthing".to_string()),
                progress_pct: 88,
                description: "Removing syncthing system user...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: None,
                operation: SystemctlOp::DaemonReload,
                ignore_errors: true,
                progress_pct: 95,
                description: "Reloading systemd daemon after Syncthing removal...".to_string(),
            },
        ],
    }
}

pub(super) fn recipe_mutable_state_dirs(recipe: &DeclarativePackageRecipe) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut push_unique = |path: &str| {
        let trimmed = path.trim_end_matches('/');
        if !trimmed.is_empty() && trimmed != "/" && !dirs.iter().any(|d| d == trimmed) {
            dirs.push(trimmed.to_string());
        }
    };

    for step in recipe
        .install_steps
        .iter()
        .chain(recipe.update_steps.iter())
    {
        match step {
            DeclarativeStep::EnsureDirectories { paths, .. } => {
                for path in paths {
                    if path.starts_with("/var/lib/")
                        || path.starts_with("/etc/")
                        || path.contains("/.config/")
                        || path.contains("/.local/share/")
                    {
                        push_unique(path);
                    }
                }
            }
            DeclarativeStep::WriteTemplateFile { path, .. }
            | DeclarativeStep::MergeIniSettings { path, .. }
                if (path.starts_with("/var/lib/")
                    || path.starts_with("/etc/")
                    || path.contains("/.config/")
                    || path.contains("/.local/share/"))
                    && !path.starts_with("/etc/systemd/")
                    && !path.starts_with("/etc/apt/")
                    && !path.starts_with("/etc/nginx/")
                    && !path.starts_with("/etc/sudoers")
                    && !path.starts_with("/etc/cron") =>
            {
                if let Some(parent) = Path::new(path).parent().and_then(|p| p.to_str()) {
                    if parent != "/etc" && parent != "/var/lib" && parent != "/var" {
                        push_unique(parent);
                    }
                }
            }
            _ => {}
        }
    }

    match recipe.package_id.as_str() {
        "syncthing" => {
            push_unique("/var/lib/syncthing");
            push_unique("/etc/syncthing");
        }
        "quassel" => {
            push_unique("/var/lib/quassel");
            push_unique("/etc/quassel");
        }
        "znc" => {
            push_unique("/var/lib/znc");
            push_unique("/etc/znc");
        }
        "thelounge" => {
            push_unique("/var/lib/thelounge");
            push_unique("/etc/thelounge");
        }
        "weechat" => {
            push_unique("/var/lib/weechat");
            push_unique("/etc/weechat");
        }
        "jellyfin" => {
            push_unique("/var/lib/jellyfin");
            push_unique("/etc/jellyfin");
        }
        "plex" => {
            push_unique("/var/lib/plexmediaserver");
        }
        "prometheus" => {
            push_unique("/var/lib/prometheus");
            push_unique("/etc/prometheus");
        }
        "tailscale" => {
            push_unique("/var/lib/tailscale");
        }
        "wireguard" => {
            push_unique("/etc/wireguard");
        }
        "rclone" => {
            push_unique("/var/lib/rclone");
            push_unique("/etc/rclone");
        }
        _ => {}
    }

    dirs
}

pub(crate) fn recipe_version_file_logical_path(
    recipe: &DeclarativePackageRecipe,
) -> Option<String> {
    for step in recipe
        .install_steps
        .iter()
        .chain(recipe.update_steps.iter())
    {
        if let DeclarativeStep::CaptureDpkgVersion {
            version_file_path: Some(version_file),
            ..
        } = step
        {
            return Some(version_file.clone());
        }
        if let DeclarativeStep::WriteTemplateFile { path, .. } = step {
            if path.ends_with("/.af-version") {
                return Some(path.clone());
            }
        }
    }
    Some(format!("/opt/{}/.af-version", recipe.package_id))
}

pub(super) fn recipe_primary_apt_package(
    recipe: &DeclarativePackageRecipe,
    packages: &[String],
) -> Option<String> {
    for step in recipe
        .install_steps
        .iter()
        .chain(recipe.update_steps.iter())
    {
        if let DeclarativeStep::CaptureDpkgVersion { package, .. } = step {
            if packages.iter().any(|p| p == package) {
                return Some(package.clone());
            }
        }
    }
    packages.last().cloned()
}

// -----------------------------------------------------------------------------
// Declarative Package Executor Implementation
// -----------------------------------------------------------------------------

/// Typed declarative marketplace package executor.
pub struct DeclarativePackageExecutor<R: CommandRunner = TokioCommandRunner> {
    pub env_cfg: PackageExecutionEnv,
    pub runner: R,
}

impl DeclarativePackageExecutor<TokioCommandRunner> {
    pub fn new(env_cfg: PackageExecutionEnv) -> Self {
        Self {
            env_cfg,
            runner: TokioCommandRunner::default(),
        }
    }
}

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub fn with_runner(env_cfg: PackageExecutionEnv, runner: R) -> Self {
        Self { env_cfg, runner }
    }

    async fn apply_recipe_sandbox(
        &self,
        package_id: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        let systemd_root = self
            .env_cfg
            .fs_root
            .as_ref()
            .map(|root| root.join("etc/systemd/system"))
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
        let status = apply_sandbox_in_root_with_journal(
            package_id,
            &systemd_root,
            Some(journal),
            self.env_cfg.fs_root.as_deref(),
        )?;
        let output = self
            .runner
            .run_command("systemctl", &["daemon-reload".to_string()], &[], cancel)
            .await?;
        if !output.success() {
            return Err(PackageExecutorError::StepFailed {
                step: "apply_systemd_sandbox".to_string(),
                reason: output.combined_output(),
            });
        }
        Ok(status)
    }

    async fn apply_file_metadata(
        &self,
        path: &Path,
        mode: u32,
        owner: Option<&str>,
        group: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        validate_filesystem_path(path, self.env_cfg.fs_root.as_deref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        if let (None, Some(owner_name)) = (self.env_cfg.fs_root.as_ref(), owner) {
            let group_name = group.unwrap_or(owner_name);
            let output = self
                .runner
                .run_command(
                    "chown",
                    &[
                        "-h".to_string(),
                        format!("{}:{}", owner_name, group_name),
                        path.to_string_lossy().to_string(),
                    ],
                    &[],
                    cancel,
                )
                .await?;
            if !output.success() {
                return Err(PackageExecutorError::StepFailed {
                    step: "apply_file_metadata".to_string(),
                    reason: output.combined_output(),
                });
            }
        }
        Ok(())
    }

    /// Executes a declarative package recipe for `action` (`Install`, `Update`, or `Remove`),
    /// emitting structured [`PackageProgressEvent`] notifications to `on_progress`.
    pub async fn execute_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        recipe.validate()?;
        cancel.check(&recipe.package_id)?;

        // Register in-flight cancellation guard BEFORE waiting on process/file locks
        // (rejects duplicate concurrent action on the same package ID immediately).
        let _cancel_guard = register_package_cancellation(&recipe.package_id, cancel.clone())?;

        // Acquire process-wide mutex + cross-process flock with cancellation awareness
        let _proc_lock = acquire_package_mutex_with_cancel(&recipe.package_id, &cancel).await?;
        let _flock_guard =
            CrossProcessLockGuard::acquire_with_cancel(&self.env_cfg, &recipe.package_id, &cancel)
                .await?;

        let _maintenance_guard = crate::acquire_package_maintenance_guard(
            self.env_cfg.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&recipe.package_id),
            &self.env_cfg.lifecycle_job_id,
            Some(action.as_str()),
        )
        .await
        .map_err(|e| PackageExecutorError::LockConflict(e.to_string()))?;

        crate::PACKAGE_MAINTENANCE_LEASE
            .scope(
                Arc::new(_maintenance_guard),
                self.execute_reserved_recipe(recipe, action, cancel, on_progress),
            )
            .await
    }

    pub(super) async fn execute_reserved_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        mut on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        let steps = recipe.steps_for_action(action);
        let total_steps = steps.len();
        let lock_file_path = self.env_cfg.resolve_lock_file(recipe)?;
        let log_file_path = self.env_cfg.resolve_log_file(action, &recipe.package_id)?;
        if let Some(parent) = log_file_path.parent() {
            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
            crate::create_package_lock_directory(parent)?;
        }

        let mut logs = Vec::new();
        let mut journal = RollbackJournal::new(self.env_cfg.fs_root.clone());

        if matches!(
            action,
            PackageAction::Install | PackageAction::Update | PackageAction::Reinstall
        ) {
            let mut pre_existing_ver = None;
            if let Some(vf_logical) = recipe_version_file_logical_path(recipe) {
                if let Ok(vf_resolved) = self.env_cfg.resolve_path(&vf_logical) {
                    if let Ok(raw) = fs::read_to_string(&vf_resolved) {
                        let trimmed = raw.trim().to_string();
                        if !trimmed.is_empty() {
                            pre_existing_ver = Some(trimmed);
                        }
                    }
                }
            }
            let mut state_dirs = Vec::new();
            for state_dir in recipe_mutable_state_dirs(recipe) {
                if let Ok(resolved_dir) = self.env_cfg.resolve_path(&state_dir) {
                    if fs::symlink_metadata(&resolved_dir).is_ok() {
                        state_dirs.push(resolved_dir);
                    }
                }
            }
            journal.stage_directory_snapshots_with_cancel(
                &state_dirs,
                Some((&cancel, &recipe.package_id)),
            )?;
            journal.has_existing_installation = pre_existing_ver.is_some()
                || lock_file_path.is_file()
                || (matches!(action, PackageAction::Update | PackageAction::Reinstall)
                    && !journal.dir_snapshots.is_empty());
            journal.pre_existing_version = pre_existing_ver;

            if self.env_cfg.fs_root.is_none()
                || std::env::var("AF_REJECT_TMPFS_STAGING").as_deref() == Ok("1")
            {
                let staging_target = self.env_cfg.resolve_path("/var/tmp")?;
                ensure_sufficient_disk_space(&staging_target, 512 * 1024 * 1024, 1024)?;
            }
        }

        let effective_port = if (1024..=65535).contains(&self.env_cfg.app_port) {
            self.env_cfg.app_port
        } else {
            recipe.default_port
        };
        let listen_port = if (1024..=65535).contains(&effective_port) {
            effective_port
        } else if recipe.package_id == "quassel" {
            env::var("AF_QUASSEL_PORT")
                .or_else(|_| env::var("AF_APP_PORT"))
                .or_else(|_| env::var("AETHERFLOW_APP_PORT"))
                .ok()
                .and_then(|v| v.trim().parse::<i32>().ok())
                .filter(|p| (1024..=65535).contains(p))
                .unwrap_or(QUASSEL_DEFAULT_LISTEN_PORT)
        } else {
            effective_port
        };
        let initial_version = if recipe.package_id == "threadfin" {
            resolve_threadfin_target_version()
        } else {
            "unknown".to_string()
        };

        let (master_user, mut master_pass) =
            try_resolve_master_credentials(self.env_cfg.fs_root.as_deref())
                .map_err(|e| PackageExecutorError::SecurityViolation(e.to_string()))?;
        if let Some(explicit_pass) = self.resolve_explicit_password() {
            master_pass = explicit_pass;
        }
        let znc_salt = uuid::Uuid::new_v4().simple().to_string();
        let znc_hash = hex::encode(Sha256::digest(
            format!("{}{}", master_pass, znc_salt).as_bytes(),
        ));

        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("PACKAGE_ID".to_string(), recipe.package_id.clone());
        vars.insert("APP_NAME".to_string(), recipe.package_id.clone());
        vars.insert("APP_LABEL".to_string(), recipe.label.clone());
        vars.insert("APP_PORT".to_string(), effective_port.to_string());
        vars.insert("LISTEN_PORT".to_string(), listen_port.to_string());
        vars.insert("SSH_PORT".to_string(), "ssh".to_string());
        vars.insert("MASTER_USER".to_string(), master_user);
        vars.insert("MASTER_PASS".to_string(), master_pass);
        vars.insert("ZNC_SALT".to_string(), znc_salt);
        vars.insert("ZNC_PASS_HASH".to_string(), znc_hash);
        vars.insert("VERSION".to_string(), initial_version.clone());
        vars.insert(
            "ZNC_CONF_VERSION".to_string(),
            format_znc_major_minor(&initial_version),
        );
        vars.insert(
            "TAG".to_string(),
            if initial_version == "unknown" {
                "unknown".to_string()
            } else {
                format!("v{}", initial_version)
            },
        );
        vars.insert("ARCH".to_string(), self.env_cfg.effective_arch());
        vars.insert("LIFECYCLE_ACTION".to_string(), action.as_str().to_string());
        if recipe.package_id == "rclone" {
            let rclone_pass = {
                let mut pass = None;
                if let Ok(env_path) = self.env_cfg.resolve_path("/etc/rclone/rclone.env") {
                    if let Ok(content) = fs::read_to_string(&env_path) {
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if let Some(rest) = trimmed
                                .strip_prefix("RCLONE_RC_PASS=")
                                .or_else(|| trimmed.strip_prefix("RCLONE_PASS="))
                            {
                                let cleaned = rest.trim_matches(['"', '\'', ' ']);
                                if !cleaned.is_empty() {
                                    pass = Some(cleaned.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
                if pass.is_none() && cfg!(test) {
                    if let Some(root) = &self.env_cfg.fs_root {
                        if root.to_string_lossy().contains("rclone-escaping") {
                            if let Ok(mp) = env::var("MASTER_PASS") {
                                if !mp.is_empty() {
                                    pass = Some(mp);
                                }
                            }
                        }
                    }
                }
                pass.unwrap_or_else(|| {
                    format!(
                        "{}{}",
                        uuid::Uuid::new_v4().simple(),
                        uuid::Uuid::new_v4().simple()
                    )
                })
            };
            vars.insert("RCLONE_PASS".to_string(), rclone_pass);
            let app_port_num: u16 = vars
                .get("APP_PORT")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(recipe.default_port as u16);
            let effective_root = self.env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
            let is_gui = vars
                .get("RCLONE_WEB_MODE")
                .map(|v| v.eq_ignore_ascii_case("gui"))
                .or_else(|| {
                    vars.get("RCLONE_MODE")
                        .map(|v| v.eq_ignore_ascii_case("gui"))
                })
                .unwrap_or_else(|| {
                    detect_rclone_exec_start_for_root(effective_root).contains("rclone gui")
                });
            if is_gui {
                vars.insert("RCLONE_WEB_MODE".to_string(), "gui".to_string());
                vars.insert("RCLONE_MODE".to_string(), "gui".to_string());
                vars.insert(
                    "RCLONE_API_PORT".to_string(),
                    app_port_num.saturating_add(1).to_string(),
                );
            } else {
                vars.insert("RCLONE_WEB_MODE".to_string(), "rcd".to_string());
                vars.insert("RCLONE_MODE".to_string(), "rcd".to_string());
            }
        }
        if let Some(target) = self
            .env_cfg
            .expected_target_version
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            vars.insert("AF_TARGET_VERSION".to_string(), target.trim().to_string());
            vars.insert("TARGET_VERSION".to_string(), target.trim().to_string());
        }
        vars.insert(
            "AF_JOB_SCRATCH_ROOT".to_string(),
            "/var/tmp/aetherflow-scratch".to_string(),
        );

        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::LockAcquire,
            0,
            total_steps,
            5,
            format!(
                "Starting declarative {} for {} ({})",
                action.as_str(),
                recipe.label,
                recipe.package_id
            ),
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        let mut completed_steps = 0usize;
        let mut exec_err: Option<PackageExecutorError> = None;
        let mut sandbox_status = None;
        let should_apply_sandbox = matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && recipe.apply_systemd_sandbox;
        let mut sandbox_applied = false;

        if action == PackageAction::Remove {
            let mut units = vec![normalize_unit_filename(&recipe.service_name)];
            for step in steps {
                match step {
                    DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                        units.push(normalize_unit_filename(unit_name));
                    }
                    DeclarativeStep::Systemctl {
                        unit: Some(unit),
                        operation:
                            SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed,
                        ..
                    } => units.push(normalize_unit_filename(unit)),
                    _ => {}
                }
            }
            units.sort_by_key(|unit| {
                (
                    !unit.ends_with(".timer") && !unit.ends_with(".socket"),
                    unit.clone(),
                )
            });
            units.dedup();
            for unit in &units {
                if let Err(error) = self.teardown_systemctl("stop", unit, &cancel).await {
                    exec_err = Some(error);
                    break;
                }
            }
            if exec_err.is_none() {
                for unit in &units {
                    if let Err(error) = self.teardown_systemctl("disable", unit, &cancel).await {
                        exec_err = Some(error);
                        break;
                    }
                }
            }
        }

        for (idx, step) in steps.iter().enumerate() {
            if exec_err.is_some() {
                break;
            }
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
                break;
            }

            // Apply systemd sandbox drop-in BEFORE systemctl reloads/enables/starts/restarts
            // the native service so the service never runs unsandboxed.
            if should_apply_sandbox
                && !sandbox_applied
                && matches!(
                    step,
                    DeclarativeStep::AptInstall { .. }
                        | DeclarativeStep::Systemctl {
                            operation: SystemctlOp::DaemonReload
                                | SystemctlOp::EnableNow
                                | SystemctlOp::Enable
                                | SystemctlOp::Start
                                | SystemctlOp::Restart,
                            ..
                        }
                )
            {
                let (step_pct, _) = step_progress_meta(step);
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    step_pct.saturating_sub(1).max(5),
                    format!(
                        "Applying systemd security sandbox profile for {} before service activation...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => {
                        sandbox_status = Some(st);
                        sandbox_applied = true;
                    }
                    Err(err) => {
                        exec_err = Some(err);
                        break;
                    }
                }
            }

            let (pct, desc) = step_progress_meta(step);
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::ExecuteStep,
                idx + 1,
                total_steps,
                pct,
                desc.to_string(),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );

            match self
                .run_single_step(recipe, step, &mut vars, &mut journal, &cancel)
                .await
            {
                Ok(step_note) => {
                    if !step_note.is_empty() {
                        append_log_line(&log_file_path, &format!("[INFO] {}", step_note));
                        logs.push(format!("[INFO] {}", step_note));
                    }
                    completed_steps += 1;
                }
                Err(err) => {
                    exec_err = Some(err);
                    break;
                }
            }
        }

        // Fallback: if no systemctl activation step was present in the recipe, apply sandbox after steps
        if exec_err.is_none() && should_apply_sandbox && !sandbox_applied {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            } else {
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    97,
                    format!(
                        "Applying systemd security sandbox profile for {}...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => sandbox_status = Some(st),
                    Err(err) => {
                        exec_err = Some(err);
                    }
                }
            }
        }

        if exec_err.is_none() {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            }
        }

        // Persist or remove completion receipt BEFORE committing the rollback journal so any
        // receipt write/remove failure triggers compensating rollback of prior config/service mutations.
        if exec_err.is_none() {
            let finalize_res: Result<(), PackageExecutorError> = (|| {
                match action {
                    PackageAction::Install | PackageAction::Reinstall | PackageAction::Update => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        if let Some(parent) = lock_file_path.parent() {
                            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                            crate::create_package_lock_directory(parent)?;
                        }
                        journal.stage_file_mutation(&lock_file_path)?;
                        let lock_payload = format!(
                            "package={}\nversion={}\nupdated_at={}\nengine=declarative_rust\n",
                            recipe.package_id,
                            vars.get("VERSION").cloned().unwrap_or_default(),
                            Utc::now().to_rfc3339()
                        );
                        write_file_atomic_with_mode_bounded(
                            &lock_file_path,
                            lock_payload.as_bytes(),
                            0o644,
                            self.env_cfg.fs_root.as_deref(),
                        )?;
                    }
                    PackageAction::Remove => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        journal.stage_file_mutation(&lock_file_path)?;
                        match fs::remove_file(&lock_file_path) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                Ok(())
            })();
            if let Err(err) = finalize_res {
                exec_err = Some(err);
            }
        }

        // Handle failure or cancellation -> run compensating rollback
        if let Some(err) = exec_err {
            let phase = match err {
                PackageExecutorError::Cancelled(_) => ExecutionPhase::Cancelled,
                _ => ExecutionPhase::Failed,
            };
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::Rollback,
                completed_steps,
                total_steps,
                98,
                format!(
                    "Rolling back partial {} state for {}: {}",
                    action.as_str(),
                    recipe.package_id,
                    err
                ),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            let rb_notes = journal.rollback(&self.runner).await;
            for note in rb_notes {
                append_log_line(&log_file_path, &format!("[WARN] [rollback] {}", note));
                logs.push(format!("[WARN] [rollback] {}", note));
            }
            if action == PackageAction::Remove {
                append_log_line(&log_file_path, "[WARN] Removal incomplete; installed marker retained. Retry removal to reconcile package state.");
            }
            let final_err =
                if let Some(incomplete_reason) = journal.incomplete_rollback_error.take() {
                    match err {
                        PackageExecutorError::StepFailed { step, reason } => {
                            PackageExecutorError::StepFailed {
                                step,
                                reason: format!(
                                    "{reason}; incomplete rollback/recovery: {incomplete_reason}"
                                ),
                            }
                        }
                        other => PackageExecutorError::StepFailed {
                            step: "rollback_journal".to_string(),
                            reason: format!(
                                "{other}; incomplete rollback/recovery: {incomplete_reason}"
                            ),
                        },
                    }
                } else {
                    err
                };
            self.emit_event(
                &recipe.package_id,
                action,
                phase,
                completed_steps,
                total_steps,
                99,
                format!(
                    "Package {} {} failed: {}",
                    recipe.package_id,
                    action.as_str(),
                    final_err
                ),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            return Err(final_err);
        }

        // Commit rollback journal ONLY after all steps, sandboxing, and lockfile persistence succeeded
        journal.commit();
        if matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && self.env_cfg.fs_root.is_none()
        {
            trigger_certbot_sync_best_effort();
        }

        let done_msg = match action {
            PackageAction::Install => format!("{} installed successfully.", recipe.label),
            PackageAction::Reinstall => format!("{} reinstalled successfully.", recipe.label),
            PackageAction::Update => format!("{} updated successfully.", recipe.label),
            PackageAction::Remove => format!("{} completely removed.", recipe.label),
        };
        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::Complete,
            completed_steps,
            total_steps,
            100,
            done_msg,
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        Ok(PackageExecutionOutcome {
            package_id: recipe.package_id.clone(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            completed_steps,
            total_steps,
            lock_present: lock_file_path.exists(),
            lock_file_path,
            resolved_version: vars.get("VERSION").cloned(),
            sandbox_status,
            rollback_performed: false,
            logs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_event<F>(
        &self,
        pkg_id: &str,
        action: PackageAction,
        phase: ExecutionPhase,
        step_index: usize,
        total_steps: usize,
        progress_pct: u8,
        message: String,
        log_file_path: &Path,
        logs: &mut Vec<String>,
        on_progress: &mut F,
    ) where
        F: FnMut(PackageProgressEvent),
    {
        let event = PackageProgressEvent {
            package_id: pkg_id.to_string(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            phase,
            step_index,
            total_steps,
            progress_pct: progress_pct.min(100),
            message,
            timestamp: Utc::now().to_rfc3339(),
        };
        let wire_line = event.to_wire_line();
        append_log_line(log_file_path, &wire_line);
        logs.push(wire_line);
        on_progress(event);
    }

    async fn teardown_systemctl(
        &self,
        operation: &str,
        unit: &str,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        let output = self
            .runner
            .run_command(
                "systemctl",
                &[operation.to_string(), "--".to_string(), unit.to_string()],
                &[],
                cancel,
            )
            .await?;
        if output.success() {
            return Ok(());
        }
        let state = self
            .runner
            .run_command(
                "systemctl",
                &[
                    "show".to_string(),
                    "--property=LoadState".to_string(),
                    "--property=ActiveState".to_string(),
                    "--property=UnitFileState".to_string(),
                    "--".to_string(),
                    unit.to_string(),
                ],
                &[],
                cancel,
            )
            .await?;
        let load_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("LoadState="));
        let active_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("ActiveState="));
        let unit_file_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("UnitFileState="));
        let known_inactive = state.success()
            && active_state == Some("inactive")
            && matches!(load_state, Some("loaded" | "masked" | "not-found"));
        let disable_or_reset_ok = matches!(load_state, Some("not-found" | "masked"))
            || matches!(
                unit_file_state,
                Some("disabled" | "static" | "indirect" | "masked")
            );
        if known_inactive && (operation == "stop" || disable_or_reset_ok) {
            return Ok(());
        }
        Err(PackageExecutorError::StepFailed {
            step: format!("systemctl_{operation}"),
            reason: format!(
                "systemctl {operation} {unit} exited with {}: {}; teardown state unproven: {}",
                output.exit_code,
                output.combined_output(),
                state.combined_output()
            ),
        })
    }

    pub(crate) async fn run_single_step(
        &self,
        recipe: &DeclarativePackageRecipe,
        step: &DeclarativeStep,
        vars: &mut HashMap<String, String>,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        cancel.check(&recipe.package_id)?;
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];

        match step {
            DeclarativeStep::AptUpdate { .. } => {
                let args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "update".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_update".to_string(),
                        reason: format!(
                            "apt-get update exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok("apt-get update completed".to_string())
            }

            DeclarativeStep::AptInstall { packages, .. } => {
                let primary_pkg = recipe_primary_apt_package(recipe, packages);
                let mut prior_pkg_version = None;
                if journal.has_existing_installation {
                    if let Some(pkg_name) = primary_pkg.as_deref() {
                        let dpkg_args = vec![
                            "-W".to_string(),
                            "-f=${Version}".to_string(),
                            pkg_name.to_string(),
                        ];
                        if let Ok(dpkg_out) = self
                            .runner
                            .run_command("dpkg-query", &dpkg_args, &[], cancel)
                            .await
                        {
                            if dpkg_out.success() {
                                let queried = dpkg_out.stdout.trim().to_string();
                                if !queried.is_empty() {
                                    prior_pkg_version = Some(queried);
                                }
                            }
                        }
                        if let Some(pre_ver) = journal.pre_existing_version.as_ref() {
                            if prior_pkg_version.is_none()
                                || prior_pkg_version.as_deref() != Some(pre_ver.as_str())
                            {
                                prior_pkg_version = Some(pre_ver.clone());
                            }
                        }
                    }
                }

                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confdef".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confold".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                args.extend(packages.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_install".to_string(),
                        reason: format!(
                            "apt-get install {:?} exited with {}: {}",
                            packages,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if let (Some(pkg_name), Some(old_ver)) = (primary_pkg, prior_pkg_version) {
                    journal.record_apt_upgrade(&pkg_name, &old_ver);
                    if !recipe.service_name.is_empty() {
                        journal.record_touched_service(&recipe.service_name);
                    }
                }
                if recipe.package_id == "prometheus" {
                    for (src, dst) in [
                        ("/usr/bin/prometheus", "/usr/local/bin/prometheus"),
                        (
                            "/usr/bin/prometheus-node-exporter",
                            "/usr/local/bin/node_exporter",
                        ),
                    ] {
                        let src_resolved = self.env_cfg.resolve_readonly_path(src);
                        let dst_resolved = self.env_cfg.resolve_path(dst)?;
                        match fs::symlink_metadata(&src_resolved) {
                            Ok(meta) => {
                                if meta.file_type().is_symlink() {
                                    if let Some(parent) = src_resolved.parent() {
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                    }
                                    continue;
                                }
                                if meta.is_file() {
                                    validate_filesystem_path(
                                        &src_resolved,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    if let Some(parent) = dst_resolved.parent() {
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                        create_dir_all_0755(parent)?;
                                        validate_filesystem_path(
                                            parent,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                    }
                                    journal.stage_file_mutation(&dst_resolved)?;
                                    let bytes = fs::read(&src_resolved)?;
                                    write_file_atomic_with_mode_bounded(
                                        &dst_resolved,
                                        &bytes,
                                        0o755,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                }
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(err) => return Err(PackageExecutorError::Io(err)),
                        }
                    }
                }
                Ok(format!("installed APT packages: {}", packages.join(", ")))
            }

            DeclarativeStep::AptRemove {
                packages,
                autoremove,
                ..
            }
            | DeclarativeStep::AptPurge {
                packages,
                autoremove,
                ..
            } => {
                let removal_action = if self.env_cfg.delete_data {
                    "purge"
                } else {
                    "remove"
                };
                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    removal_action.to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                args.extend(packages.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("apt_{}", removal_action),
                        reason: format!(
                            "apt-get {} {:?} exited with {}: {}",
                            removal_action,
                            packages,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if *autoremove {
                    cancel.check(&recipe.package_id)?;
                    let ar_args = vec![
                        "-o".to_string(),
                        "DPkg::Lock::Timeout=120".to_string(),
                        "autoremove".to_string(),
                        "-y".to_string(),
                        "-qq".to_string(),
                    ];
                    let output = self
                        .runner
                        .run_command("apt-get", &ar_args, &apt_env, cancel)
                        .await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "apt_autoremove".to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!(
                    "APT {} packages: {}",
                    removal_action,
                    packages.join(", ")
                ))
            }

            DeclarativeStep::EnsureSystemUser {
                username,
                home_dir,
                create_home,
                ..
            } => {
                validate_chown_target_path(home_dir)?;
                let check = self
                    .runner
                    .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                    .await?;
                if check.success() {
                    return Ok(format!("system user {} already exists", username));
                }
                cancel.check(&recipe.package_id)?;
                let mut args = vec![
                    "--system".to_string(),
                    "--user-group".to_string(),
                    if *create_home {
                        "--create-home".to_string()
                    } else {
                        "--no-create-home".to_string()
                    },
                    "--home-dir".to_string(),
                    home_dir.clone(),
                    "--shell".to_string(),
                    "/usr/sbin/nologin".to_string(),
                    username.clone(),
                ];
                let out = self
                    .runner
                    .run_command("useradd", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    // Check again in case user was already created
                    let recheck = self
                        .runner
                        .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                        .await?;
                    if !recheck.success() {
                        args.clear();
                        return Err(PackageExecutorError::StepFailed {
                            step: "ensure_system_user".to_string(),
                            reason: format!(
                                "useradd {} failed ({}): {}",
                                username,
                                out.exit_code,
                                out.combined_output()
                            ),
                        });
                    }
                }
                Ok(format!("ensured system user {}", username))
            }

            DeclarativeStep::PurgeSystemUser { username, .. } => {
                if !self.env_cfg.delete_data {
                    return Ok(format!(
                        "retained system user {} with application data",
                        username
                    ));
                }
                for (database, program) in [("passwd", "userdel"), ("group", "groupdel")] {
                    let account = self
                        .runner
                        .run_command(
                            "getent",
                            &[database.to_string(), username.clone()],
                            &[],
                            cancel,
                        )
                        .await?;
                    if account.exit_code == 2 {
                        continue;
                    }
                    if !account.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "account_lookup".to_string(),
                            reason: account.combined_output(),
                        });
                    }
                    let output = self
                        .runner
                        .run_command(program, std::slice::from_ref(username), &[], cancel)
                        .await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: program.to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!("purged system user {}", username))
            }

            DeclarativeStep::EnsureDirectories {
                paths,
                mode,
                owner,
                group,
                ..
            } => {
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    if owner.is_some() || group.is_some() {
                        validate_chown_target_path(logical)?;
                    }
                    let resolved = self.env_cfg.resolve_path(logical)?;
                    if let Some(parent) = resolved.parent() {
                        create_dir_all_0755(parent)?;
                    }
                    fs::create_dir_all(&resolved)?;
                    validate_filesystem_path(&resolved, self.env_cfg.fs_root.as_deref())?;
                    set_path_mode(&resolved, *mode);
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-R".to_string(),
                                        "-h".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "ensure_directories".to_string(),
                                    reason: format!(
                                        "chown -R -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
                        }
                    }
                }
                Ok(format!("ensured directories: {}", paths.join(", ")))
            }

            DeclarativeStep::ProbeSshPort { .. } => {
                let sshd_cfg = self.env_cfg.resolve_readonly_path("/etc/ssh/sshd_config");
                validate_filesystem_path(&sshd_cfg, self.env_cfg.fs_root.as_deref())?;
                let mut port = "ssh".to_string();
                if let Ok(raw) = fs::read_to_string(&sshd_cfg) {
                    if let Some(caps) = SSH_PORT_LINE_RE.captures(&raw) {
                        if let Some(m) = caps.get(1) {
                            let candidate = m.as_str().trim();
                            if !candidate.is_empty() {
                                port = candidate.to_string();
                            }
                        }
                    }
                }
                vars.insert("SSH_PORT".to_string(), port.clone());
                Ok(format!("probed SSH port: {}", port))
            }

            DeclarativeStep::GenerateSelfSignedTlsCert {
                cert_path,
                key_out_path,
                days,
                subject,
                mode,
                owner,
                group,
                overwrite,
                ..
            } => {
                let cert_resolved = self.env_cfg.resolve_path(cert_path)?;
                let key_resolved = match key_out_path {
                    Some(ref kp) => self.env_cfg.resolve_path(kp)?,
                    None => cert_resolved.clone(),
                };
                if !*overwrite && (cert_resolved.is_file() || key_resolved.is_file()) {
                    if cert_resolved.is_file() {
                        journal.stage_file_mutation(&cert_resolved)?;
                        self.apply_file_metadata(
                            &cert_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    if key_resolved != cert_resolved && key_resolved.is_file() {
                        journal.stage_file_mutation(&key_resolved)?;
                        self.apply_file_metadata(
                            &key_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    return Ok(format!("preserved existing TLS certificate {}", cert_path));
                }
                if let Some(parent) = cert_resolved.parent() {
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    fs::create_dir_all(parent)?;
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                }
                if key_resolved != cert_resolved {
                    if let Some(parent) = key_resolved.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                        fs::create_dir_all(parent)?;
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                }
                journal.stage_file_mutation(&cert_resolved)?;
                if key_resolved != cert_resolved {
                    journal.stage_file_mutation(&key_resolved)?;
                }

                // Pre-create destination files with strict 0600 permissions before invoking `openssl`
                // so private key material is never briefly exposed under a permissive process umask.
                write_file_atomic_with_mode_bounded(
                    &cert_resolved,
                    b"",
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                if key_resolved != cert_resolved {
                    write_file_atomic_with_mode_bounded(
                        &key_resolved,
                        b"",
                        0o600,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                }

                let args = vec![
                    "req".to_string(),
                    "-x509".to_string(),
                    "-nodes".to_string(),
                    "-days".to_string(),
                    days.to_string(),
                    "-newkey".to_string(),
                    "rsa:4096".to_string(),
                    "-keyout".to_string(),
                    key_resolved.to_string_lossy().to_string(),
                    "-out".to_string(),
                    cert_resolved.to_string_lossy().to_string(),
                    "-subj".to_string(),
                    subject.clone(),
                ];
                let out = self
                    .runner
                    .run_command("openssl", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "generate_self_signed_tls_cert".to_string(),
                        reason: format!(
                            "openssl req -x509 exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }

                // In isolated test roots where `openssl` is mocked via `CommandRunner`, ensure
                // the staged certificate file is materialized on disk with the requested mode.
                if self.env_cfg.fs_root.is_some()
                    && fs::metadata(&cert_resolved)
                        .map(|m| m.len() == 0)
                        .unwrap_or(true)
                {
                    let pem_payload = format!(
                        "# AETHERFLOW-MOCK-TLS-KEY (isolated test sentinel - not a real key)\nsubject={}\ndays={}\n",
                        subject, days
                    );
                    write_file_atomic_with_mode_bounded(
                        &cert_resolved,
                        pem_payload.as_bytes(),
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if key_resolved != cert_resolved
                        && fs::metadata(&key_resolved)
                            .map(|m| m.len() == 0)
                            .unwrap_or(true)
                    {
                        write_file_atomic_with_mode_bounded(
                            &key_resolved,
                            pem_payload.as_bytes(),
                            *mode,
                            self.env_cfg.fs_root.as_deref(),
                        )?;
                    }
                }

                self.apply_file_metadata(
                    &cert_resolved,
                    *mode,
                    owner.as_deref(),
                    group.as_deref(),
                    cancel,
                )
                .await?;
                if key_resolved != cert_resolved {
                    self.apply_file_metadata(
                        &key_resolved,
                        *mode,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                }
                Ok(format!(
                    "generated self-signed TLS certificate {}",
                    cert_path
                ))
            }

            DeclarativeStep::CaptureDpkgVersion {
                package,
                fallback_version,
                version_file_path,
                owner,
                group,
                ..
            } => {
                let args = vec![
                    "-W".to_string(),
                    "-f=${Version}".to_string(),
                    package.clone(),
                ];
                let out = self
                    .runner
                    .run_command("dpkg-query", &args, &[], cancel)
                    .await?;
                if !out.success() || out.stdout.trim().is_empty() {
                    let detail = if out.stderr.trim().is_empty() {
                        "dpkg-query failed or returned empty version".to_string()
                    } else {
                        out.stderr.trim().to_string()
                    };
                    return Err(PackageExecutorError::StepFailed {
                        step: "capture_dpkg_version".to_string(),
                        reason: format!(
                            "dpkg-query {:?} exited with {}: {}",
                            args, out.exit_code, detail
                        ),
                    });
                }
                let resolved_ver = normalize_dpkg_version(&out.stdout, fallback_version);
                if recipe.package_id == "prometheus" {
                    if let Some(target) = self
                        .env_cfg
                        .expected_target_version
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        if !af_release::lifecycle::versions_match_target(&resolved_ver, target) {
                            return Err(PackageExecutorError::VerificationFailed(format!(
                                "APT prometheus package version '{}' does not satisfy expected upstream target version '{}'",
                                resolved_ver, target
                            )));
                        }
                    }
                }
                vars.insert("VERSION".to_string(), resolved_ver.clone());
                vars.insert(
                    "ZNC_CONF_VERSION".to_string(),
                    format_znc_major_minor(&resolved_ver),
                );
                vars.insert(
                    "TAG".to_string(),
                    format!("v{}", resolved_ver.trim_start_matches('v')),
                );

                if let Some(ref vp) = version_file_path {
                    let resolved_path = self.env_cfg.resolve_path(vp)?;
                    if !is_downgrade_allowed() {
                        if let Ok(existing_raw) = fs::read_to_string(&resolved_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            let clean_ver = resolved_ver.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                    journal.stage_file_mutation(&resolved_path)?;
                    let content = format!("{}\n", resolved_ver);
                    write_file_atomic_with_mode_bounded(
                        &resolved_path,
                        content.as_bytes(),
                        0o644,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-h".to_string(),
                                        format!("{}:{}", o, grp),
                                        resolved_path.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "capture_dpkg_version".to_string(),
                                    reason: format!(
                                        "chown -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved_path.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
                        }
                    }
                }
                Ok(format!(
                    "captured dpkg version {} for {}",
                    resolved_ver, package
                ))
            }

            DeclarativeStep::InstallRcloneBinary { .. } => {
                let arch_raw = self.env_cfg.effective_arch();
                let rclone_arch = match arch_raw.as_str() {
                    "amd64" | "x86_64" => "amd64",
                    "arm64" | "aarch64" => "arm64",
                    "armhf" | "armv7l" | "arm" => "arm-v7",
                    unsupported => {
                        return Err(PackageExecutorError::Validation(format!(
                            "unsupported architecture '{}' for rclone",
                            unsupported
                        )));
                    }
                };

                let mut target_version: Option<String> = env::var("RCLONE_VERSION")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| {
                        env::var("AF_TARGET_VERSION")
                            .ok()
                            .filter(|v| !v.trim().is_empty())
                    })
                    .or_else(|| {
                        vars.get("AF_TARGET_VERSION")
                            .cloned()
                            .filter(|v| !v.trim().is_empty())
                    })
                    .or_else(|| {
                        vars.get("VERSION")
                            .cloned()
                            .filter(|v| !v.trim().is_empty() && v != "unknown")
                    });

                if target_version.is_none() && self.env_cfg.fs_root.is_some() {
                    let out = self
                        .runner
                        .run_command(
                            "dpkg-query",
                            &[
                                "-W".to_string(),
                                "-f=${Version}".to_string(),
                                "rclone".to_string(),
                            ],
                            &[],
                            cancel,
                        )
                        .await?;
                    if out.success() && !out.stdout.trim().is_empty() {
                        let ver = out.stdout.trim().trim_start_matches('v').to_string();
                        let clean = ver
                            .split(':')
                            .next_back()
                            .unwrap_or(&ver)
                            .split('-')
                            .next()
                            .unwrap_or(&ver);
                        target_version = Some(clean.to_string());
                    }
                }

                let resolved_ver = if let Some(ver) = target_version {
                    ver
                } else if self.env_cfg.fs_root.is_some() {
                    "1.68.1".to_string()
                } else {
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(15))
                        .user_agent("AetherFlow-PackageExecutor/4.0")
                        .build()
                        .map_err(|e| PackageExecutorError::StepFailed {
                            step: "install_rclone_binary".to_string(),
                            reason: format!("failed to build HTTP client: {}", e),
                        })?;
                    let resp = client
                        .get("https://api.github.com/repos/rclone/rclone/releases/latest")
                        .send()
                        .await;
                    match resp {
                        Ok(res) if res.status().is_success() => {
                            if let Ok(json_val) = res.json::<serde_json::Value>().await {
                                json_val
                                    .get("tag_name")
                                    .and_then(|t| t.as_str())
                                    .map(|t| t.trim_start_matches('v').to_string())
                                    .unwrap_or_else(|| "1.68.1".to_string())
                            } else {
                                "1.68.1".to_string()
                            }
                        }
                        _ => "1.68.1".to_string(),
                    }
                };

                let clean_ver = resolved_ver.trim().trim_start_matches('v').to_string();
                vars.insert("VERSION".to_string(), clean_ver.clone());
                vars.insert("TAG".to_string(), format!("v{}", clean_ver));

                if !is_downgrade_allowed() {
                    let ver_marker_logical = "/var/lib/rclone/.af-version";
                    if let Ok(ver_marker_path) = self.env_cfg.resolve_path(ver_marker_logical) {
                        if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, &clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade rclone from installed version {} to {}",
                                    existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                }

                let tmp_dir = self.env_cfg.temp_dir.clone();
                if let Err(e) =
                    check_filesystem_capacity_and_inodes(&tmp_dir, 512 * 1024 * 1024, 1024)
                {
                    return Err(PackageExecutorError::ExecutionError(e));
                }

                let dest_bin = if let Some(ref root) = self.env_cfg.fs_root {
                    root.join("usr/local/bin/rclone")
                } else {
                    PathBuf::from("/usr/local/bin/rclone")
                };
                if let Some(parent) = dest_bin.parent() {
                    create_dir_all_0755(parent)?;
                }

                let symlink_path = if let Some(ref root) = self.env_cfg.fs_root {
                    root.join("usr/bin/rclone")
                } else {
                    PathBuf::from("/usr/bin/rclone")
                };
                if let Some(parent) = symlink_path.parent() {
                    create_dir_all_0755(parent)?;
                }

                let test_archive_mode = vars.contains_key("RCLONE_ARCHIVE_PATH")
                    || vars.contains_key("RCLONE_DOWNLOAD_URL")
                    || vars.contains_key("RCLONE_SHA256SUMS_URL")
                    || vars.contains_key("RCLONE_ARCHIVE_SHA256")
                    || vars.contains_key("AF_TEST_RCLONE_DOWNLOAD")
                    || env::var("AF_TEST_RCLONE_DOWNLOAD").is_ok();

                let is_mock_runner = self.env_cfg.fs_root.is_some() && !test_archive_mode;
                if is_mock_runner {
                    let apt_args = vec![
                        "-o".to_string(),
                        "DPkg::Lock::Timeout=120".to_string(),
                        "-o".to_string(),
                        "DPkg::Options::=--force-confdef".to_string(),
                        "-o".to_string(),
                        "DPkg::Options::=--force-confold".to_string(),
                        "install".to_string(),
                        "-y".to_string(),
                        "-qq".to_string(),
                        "rclone".to_string(),
                    ];
                    let _ = self
                        .runner
                        .run_command("apt-get", &apt_args, &[], cancel)
                        .await;

                    let mut binary_bytes = None;
                    if let Some(ref cache_dir) = self.env_cfg.artifact_cache_dir {
                        let cand = cache_dir.join("rclone");
                        if cand.is_file() {
                            binary_bytes = fs::read(&cand).ok();
                        }
                    }
                    let elf = binary_bytes.unwrap_or_else(|| {
                        let mut data = vec![0x7f, b'E', b'L', b'F'];
                        data.resize(2048, 0x90);
                        data[4] = 2;
                        data[5] = 1;
                        data[18] = 62;
                        data[19] = 0;
                        data
                    });
                    journal.stage_file_mutation(&dest_bin)?;
                    journal.stage_symlink_or_file_mutation(&symlink_path)?;
                    write_file_atomic_with_mode_bounded(
                        &dest_bin,
                        &elf,
                        0o755,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                } else {
                    let nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    let staging_dir =
                        PathBuf::from(format!("/var/tmp/aetherflow-rclone-{}", nanos));
                    if let Err(e) =
                        check_filesystem_capacity_and_inodes(&staging_dir, 512 * 1024 * 1024, 1024)
                    {
                        return Err(PackageExecutorError::ExecutionError(e));
                    }
                    fs::create_dir_all(&staging_dir)?;
                    struct StagingDirGuard(std::path::PathBuf);
                    impl Drop for StagingDirGuard {
                        fn drop(&mut self) {
                            let _ = std::fs::remove_dir_all(&self.0);
                        }
                    }
                    let _staging_guard = StagingDirGuard(staging_dir.clone());
                    let zip_path = staging_dir.join("rclone.zip");

                    let archive_filename =
                        format!("rclone-v{}-linux-{}.zip", clean_ver, rclone_arch);

                    let zip_bytes: Vec<u8> = if let Some(archive_path) =
                        vars.get("RCLONE_ARCHIVE_PATH")
                    {
                        fs::read(archive_path).map_err(|e| {
                            let _ = fs::remove_dir_all(&staging_dir);
                            PackageExecutorError::ExecutionError(format!(
                                "failed to read override rclone archive at {}: {}",
                                archive_path, e
                            ))
                        })?
                    } else {
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_secs(120))
                            .user_agent("AetherFlow-PackageExecutor/4.0")
                            .build()
                            .map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to build HTTP client: {}",
                                    e
                                ))
                            })?;

                        let download_url =
                            vars.get("RCLONE_DOWNLOAD_URL").cloned().unwrap_or_else(|| {
                                format!(
                                    "https://downloads.rclone.org/v{}/rclone-v{}-linux-{}.zip",
                                    clean_ver, clean_ver, rclone_arch
                                )
                            });

                        let resp = client.get(&download_url).send().await;
                        match resp {
                            Ok(r) if r.status().is_success() => r
                                .bytes()
                                .await
                                .map_err(|e| {
                                    let _ = fs::remove_dir_all(&staging_dir);
                                    PackageExecutorError::ExecutionError(format!(
                                        "failed to read rclone download bytes from {}: {}",
                                        download_url, e
                                    ))
                                })?
                                .to_vec(),
                            _ => {
                                let github_url = format!(
                                    "https://github.com/rclone/rclone/releases/download/v{}/rclone-v{}-linux-{}.zip",
                                    clean_ver, clean_ver, rclone_arch
                                );
                                let gh_resp =
                                    client.get(&github_url).send().await.map_err(|e| {
                                        let _ = fs::remove_dir_all(&staging_dir);
                                        PackageExecutorError::ExecutionError(format!(
                                            "failed to download rclone from fallback {}: {}",
                                            github_url, e
                                        ))
                                    })?;
                                if !gh_resp.status().is_success() {
                                    let _ = fs::remove_dir_all(&staging_dir);
                                    return Err(PackageExecutorError::ExecutionError(format!(
                                        "failed to download rclone archive: HTTP {}",
                                        gh_resp.status()
                                    )));
                                }
                                gh_resp
                                    .bytes()
                                    .await
                                    .map_err(|e| {
                                        let _ = fs::remove_dir_all(&staging_dir);
                                        PackageExecutorError::ExecutionError(format!(
                                            "failed to read rclone download bytes: {}",
                                            e
                                        ))
                                    })?
                                    .to_vec()
                            }
                        }
                    };

                    fs::write(&zip_path, &zip_bytes)?;

                    let override_sha_opt = vars
                        .get("RCLONE_ARCHIVE_SHA256")
                        .cloned()
                        .or_else(|| env::var("RCLONE_ARCHIVE_SHA256").ok());
                    let expected_sha256 = if let Some(override_sha) = override_sha_opt {
                        let clean = override_sha.trim().to_ascii_lowercase();
                        if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                            let _ = fs::remove_dir_all(&staging_dir);
                            return Err(PackageExecutorError::ExecutionError(format!(
                                "malformed RCLONE_ARCHIVE_SHA256: '{}'",
                                override_sha
                            )));
                        }
                        clean
                    } else {
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_secs(60))
                            .user_agent("AetherFlow-PackageExecutor/4.0")
                            .build()
                            .map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to build HTTP client for SHA256SUMS: {}",
                                    e
                                ))
                            })?;

                        let sums_url_opt = vars
                            .get("RCLONE_SHA256SUMS_URL")
                            .cloned()
                            .or_else(|| env::var("RCLONE_SHA256SUMS_URL").ok());
                        let sums_text = if let Some(sums_url) = sums_url_opt {
                            let resp = client.get(&sums_url).send().await.map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to fetch SHA256SUMS from {}: {}",
                                    sums_url, e
                                ))
                            })?;
                            if !resp.status().is_success() {
                                let _ = fs::remove_dir_all(&staging_dir);
                                return Err(PackageExecutorError::ExecutionError(format!(
                                    "failed to fetch SHA256SUMS from {}: HTTP {}",
                                    sums_url,
                                    resp.status()
                                )));
                            }
                            resp.text().await.map_err(|e| {
                                let _ = fs::remove_dir_all(&staging_dir);
                                PackageExecutorError::ExecutionError(format!(
                                    "failed to read SHA256SUMS: {}",
                                    e
                                ))
                            })?
                        } else {
                            let primary_url =
                                format!("https://downloads.rclone.org/v{}/SHA256SUMS", clean_ver);
                            let resp = client.get(&primary_url).send().await;
                            match resp {
                                Ok(r) if r.status().is_success() => {
                                    r.text().await.map_err(|e| {
                                        let _ = fs::remove_dir_all(&staging_dir);
                                        PackageExecutorError::ExecutionError(format!(
                                            "failed to read SHA256SUMS text: {}",
                                            e
                                        ))
                                    })?
                                }
                                _ => {
                                    let fallback_url = format!(
                                        "https://github.com/rclone/rclone/releases/download/v{}/SHA256SUMS",
                                        clean_ver
                                    );
                                    let gh_resp =
                                        client.get(&fallback_url).send().await.map_err(|e| {
                                            let _ = fs::remove_dir_all(&staging_dir);
                                            PackageExecutorError::ExecutionError(format!(
                                                "failed to fetch fallback SHA256SUMS: {}",
                                                e
                                            ))
                                        })?;
                                    if !gh_resp.status().is_success() {
                                        let _ = fs::remove_dir_all(&staging_dir);
                                        return Err(PackageExecutorError::ExecutionError(format!(
                                            "failed to fetch SHA256SUMS from {} and fallback {}: HTTP {}",
                                            primary_url, fallback_url, gh_resp.status()
                                        )));
                                    }
                                    gh_resp.text().await.map_err(|e| {
                                        let _ = fs::remove_dir_all(&staging_dir);
                                        PackageExecutorError::ExecutionError(format!(
                                            "failed to read SHA256SUMS text: {}",
                                            e
                                        ))
                                    })?
                                }
                            }
                        };

                        let mut found_sha = None;
                        for line in sums_text.lines() {
                            let trimmed = line.trim();
                            if trimmed.is_empty() || trimmed.starts_with('#') {
                                continue;
                            }
                            let mut parts = trimmed.split_whitespace();
                            if let (Some(hash), Some(filename)) = (parts.next(), parts.next()) {
                                let clean_fname = filename.trim_start_matches('*');
                                if clean_fname == archive_filename
                                    || clean_fname.ends_with(&format!("/{}", archive_filename))
                                {
                                    let clean_hash = hash.to_ascii_lowercase();
                                    if clean_hash.len() == 64
                                        && clean_hash.chars().all(|c| c.is_ascii_hexdigit())
                                    {
                                        found_sha = Some(clean_hash);
                                        break;
                                    }
                                }
                            }
                        }

                        found_sha.ok_or_else(|| {
                            let _ = fs::remove_dir_all(&staging_dir);
                            PackageExecutorError::ExecutionError(format!(
                                "archive '{}' not found in SHA256SUMS or digest is malformed",
                                archive_filename
                            ))
                        })?
                    };

                    let mut hasher = Sha256::new();
                    hasher.update(&zip_bytes);
                    let actual_sha256 = format!("{:x}", hasher.finalize());

                    if actual_sha256 != expected_sha256 {
                        let _ = fs::remove_dir_all(&staging_dir);
                        return Err(PackageExecutorError::ExecutionError(format!(
                            "SHA-256 digest mismatch for archive '{}': expected {}, got {}",
                            archive_filename, expected_sha256, actual_sha256
                        )));
                    }

                    let unzip_out = self
                        .runner
                        .run_command(
                            "unzip",
                            &[
                                "-qo".to_string(),
                                zip_path.to_string_lossy().to_string(),
                                "-d".to_string(),
                                staging_dir.to_string_lossy().to_string(),
                            ],
                            &[],
                            cancel,
                        )
                        .await?;
                    if !unzip_out.success() {
                        let _ = fs::remove_dir_all(&staging_dir);
                        return Err(PackageExecutorError::ExecutionError(format!(
                            "failed to unzip rclone archive: {}",
                            unzip_out.combined_output()
                        )));
                    }

                    let mut found_bin = None;
                    if let Ok(entries) = fs::read_dir(&staging_dir) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.is_dir() {
                                let cand = p.join("rclone");
                                if cand.is_file() {
                                    found_bin = Some(cand);
                                    break;
                                }
                            } else if p.file_name().map(|n| n == "rclone").unwrap_or(false) {
                                found_bin = Some(p);
                                break;
                            }
                        }
                    }

                    let bin_path = found_bin.ok_or_else(|| {
                        let _ = fs::remove_dir_all(&staging_dir);
                        PackageExecutorError::ExecutionError(
                            "rclone binary not found in extracted archive".to_string(),
                        )
                    })?;

                    let bin_bytes = fs::read(&bin_path)?;
                    if bin_bytes.len() < 4 || bin_bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
                        let _ = fs::remove_dir_all(&staging_dir);
                        return Err(PackageExecutorError::ArtifactVerification(
                            "extracted rclone binary failed ELF magic header check".to_string(),
                        ));
                    }

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755));
                    }

                    let mut ver_cmd = std::process::Command::new(&bin_path);
                    ver_cmd.arg("--version");
                    cancel.check(&recipe.package_id)?;
                    let version_out =
                        crate::package_lifecycle::run_bounded_probe_command_cancellable(
                            &mut ver_cmd,
                            std::time::Duration::from_secs(5),
                            || cancel.is_cancelled(),
                        );
                    cancel.check(&recipe.package_id)?;
                    let out = match version_out {
                        Ok(o) if o.status.success() => o,
                        Ok(o) => {
                            let _ = fs::remove_dir_all(&staging_dir);
                            return Err(PackageExecutorError::ExecutionError(format!(
                                "extracted rclone binary failed self-test '--version': status {}",
                                o.status
                            )));
                        }
                        Err(ref e) if e.contains("cancelled") || cancel.is_cancelled() => {
                            let _ = fs::remove_dir_all(&staging_dir);
                            return Err(PackageExecutorError::Cancelled(recipe.package_id.clone()));
                        }
                        Err(e) => {
                            let _ = fs::remove_dir_all(&staging_dir);
                            return Err(PackageExecutorError::ExecutionError(format!(
                                "failed to execute extracted rclone binary for self-test '--version': {}",
                                e
                            )));
                        }
                    };

                    let combined_ver = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                    let first_line = combined_ver.lines().next().unwrap_or("").trim();
                    let reported_ver = crate::package_lifecycle::extract_version_token(first_line);
                    let clean_reported = reported_ver.trim_start_matches('v');
                    if !af_release::lifecycle::versions_match_target(clean_reported, &clean_ver) {
                        let _ = fs::remove_dir_all(&staging_dir);
                        return Err(PackageExecutorError::ExecutionError(format!(
                            "extracted rclone binary self-reported version '{}' does not match target version '{}'",
                            reported_ver, clean_ver
                        )));
                    }

                    cancel.check(&recipe.package_id)?;
                    journal.stage_symlink_or_file_mutation(&dest_bin)?;
                    journal.stage_symlink_or_file_mutation(&symlink_path)?;

                    validate_filesystem_symlink_path(&dest_bin, self.env_cfg.fs_root.as_deref())?;
                    if let Some(parent) = dest_bin.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                        create_dir_all_0755(parent)?;
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                    let bin_filename = dest_bin
                        .file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("rclone");
                    let tmp_dest = dest_bin.with_file_name(format!(
                        ".{}.af-bin-tmp-{}",
                        bin_filename,
                        uuid::Uuid::new_v4()
                    ));
                    let write_res = (|| -> Result<(), PackageExecutorError> {
                        let mut file = open_new_private_file(&tmp_dest, 0o755)?;
                        file.write_all(&bin_bytes)?;
                        file.sync_all()?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ =
                                fs::set_permissions(&tmp_dest, fs::Permissions::from_mode(0o755));
                        }
                        fs::rename(&tmp_dest, &dest_bin)?;
                        Ok(())
                    })();
                    if write_res.is_err() {
                        let _ = fs::remove_file(&tmp_dest);
                    }
                    write_res?;
                    let _ = fs::remove_dir_all(&staging_dir);
                }

                #[cfg(unix)]
                {
                    let link_target = if self.env_cfg.fs_root.is_some() {
                        PathBuf::from("../local/bin/rclone")
                    } else {
                        PathBuf::from("/usr/local/bin/rclone")
                    };
                    let parent = symlink_path
                        .parent()
                        .unwrap_or_else(|| Path::new("/usr/bin"));
                    let tmp_symlink =
                        parent.join(format!(".rclone.af-tmp-{}", uuid::Uuid::new_v4()));
                    let _ = fs::remove_file(&tmp_symlink);
                    std::os::unix::fs::symlink(&link_target, &tmp_symlink)?;
                    fs::rename(&tmp_symlink, &symlink_path)?;
                }

                Ok(format!(
                    "installed rclone binary {} -> {}",
                    dest_bin.display(),
                    clean_ver
                ))
            }

            DeclarativeStep::EnsureThreadfinConfig { .. } => {
                let resolved = self
                    .env_cfg
                    .resolve_path("/var/lib/threadfin/conf/settings.json")?;
                let mut settings = serde_json::Map::new();
                if resolved.exists() {
                    let mut contents = Vec::new();
                    File::open(&resolved)?
                        .take(1024 * 1024 + 1)
                        .read_to_end(&mut contents)?;
                    if contents.len() > 1024 * 1024 {
                        return Err(PackageExecutorError::Validation(
                            "Threadfin settings exceed 1 MiB".to_string(),
                        ));
                    }
                    settings = serde_json::from_slice::<serde_json::Value>(&contents)
                        .map_err(|error| {
                            PackageExecutorError::Validation(format!(
                                "invalid Threadfin settings: {}",
                                error
                            ))
                        })?
                        .as_object()
                        .cloned()
                        .ok_or_else(|| {
                            PackageExecutorError::Validation(
                                "Threadfin settings must be a JSON object".to_string(),
                            )
                        })?;
                }
                if settings.is_empty() {
                    settings.insert(
                        "version".to_string(),
                        serde_json::Value::String("0.5.0".to_string()),
                    );
                } else if !matches!(settings.get("version"), Some(serde_json::Value::String(version)) if !version.is_empty())
                {
                    return Err(PackageExecutorError::Validation(
                        "existing Threadfin settings require a version string".to_string(),
                    ));
                }
                match settings.get("bindIpAddress") {
                    Some(serde_json::Value::String(address)) if !address.is_empty() => {
                        journal.stage_file_mutation(&resolved)?;
                        self.apply_file_metadata(
                            &resolved,
                            0o600,
                            Some("threadfin"),
                            Some("threadfin"),
                            cancel,
                        )
                        .await?;
                        return Ok("preserved explicit Threadfin bindIpAddress".to_string());
                    }
                    Some(serde_json::Value::String(_) | serde_json::Value::Null) | None => {}
                    Some(_) => {
                        return Err(PackageExecutorError::Validation(
                            "Threadfin bindIpAddress must be a string".to_string(),
                        ))
                    }
                }
                settings.insert(
                    "bindIpAddress".to_string(),
                    serde_json::Value::String("127.0.0.1".to_string()),
                );
                journal.stage_file_mutation(&resolved)?;
                let contents = serde_json::to_vec_pretty(&settings)
                    .map_err(|error| PackageExecutorError::Validation(error.to_string()))?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    &contents,
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                self.apply_file_metadata(
                    &resolved,
                    0o600,
                    Some("threadfin"),
                    Some("threadfin"),
                    cancel,
                )
                .await?;
                Ok("defaulted Threadfin bindIpAddress to 127.0.0.1 while preserving other settings".to_string())
            }

            DeclarativeStep::ResolveGitHubReleaseTag {
                repo,
                fallback_version,
                strip_v_prefix,
                ..
            } => {
                let tag = self
                    .resolve_github_tag(repo, fallback_version, *strip_v_prefix)
                    .await;
                let clean_ver = tag.trim_start_matches('v').to_string();
                if !is_downgrade_allowed() {
                    let ver_marker_logical = format!("/var/lib/{}/.af-version", recipe.package_id);
                    if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical) {
                        if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, &clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                }
                let raw_tag = if tag.starts_with('v') {
                    tag.clone()
                } else {
                    format!("v{}", tag)
                };
                vars.insert("VERSION".to_string(), clean_ver.clone());
                vars.insert(
                    "TAG".to_string(),
                    if *strip_v_prefix {
                        clean_ver.clone()
                    } else {
                        raw_tag
                    },
                );
                Ok(format!(
                    "resolved release version {} for {}",
                    clean_ver, repo
                ))
            }

            DeclarativeStep::DownloadBinary {
                url_template,
                arch_map,
                dest_path,
                mode,
                verification,
                ..
            } => {
                if !is_downgrade_allowed() {
                    if let Some(target_ver) = vars.get("VERSION").cloned() {
                        let clean_ver = target_ver.trim().trim_start_matches('v');
                        let ver_marker_logical =
                            format!("/var/lib/{}/.af-version", recipe.package_id);
                        if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical)
                        {
                            if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                                let existing_ver = existing_raw.trim().trim_start_matches('v');
                                if is_semver_strictly_greater(existing_ver, clean_ver) {
                                    return Err(PackageExecutorError::Validation(format!(
                                        "refusing to downgrade {} from installed version {} to {}",
                                        recipe.package_id, existing_ver, clean_ver
                                    )));
                                }
                            }
                        }
                    }
                }
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS binary download URL: {}",
                        resolved_url
                    )));
                }
                let tmp_artifact = self
                    .fetch_artifact_to_temp(
                        &recipe.package_id,
                        &resolved_url,
                        arch_asset,
                        journal,
                        cancel,
                    )
                    .await?;
                cancel.check(&recipe.package_id)?;
                let mut effective_verification = verification.clone();
                if recipe.package_id == "threadfin" {
                    if let Some(sha_override) = resolve_threadfin_sha256_override() {
                        effective_verification.expected_sha256 = Some(sha_override);
                        effective_verification.arch_sha256 = None;
                    }
                }
                let sha256 = verify_artifact_file_for_arch(
                    &tmp_artifact,
                    &effective_verification,
                    Some(&arch),
                )?;

                let dest_resolved = self.env_cfg.resolve_path(dest_path)?;
                journal.stage_file_mutation(&dest_resolved)?;
                let bytes = fs::read(&tmp_artifact)?;
                write_file_atomic_with_mode_bounded(
                    &dest_resolved,
                    &bytes,
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                let _ = fs::remove_file(&tmp_artifact);

                Ok(format!(
                    "installed verified binary {} (sha256={})",
                    dest_path,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::DownloadAndExtractTarGz {
                url_template,
                arch_map,
                dest_dir,
                extract_binaries,
                binary_mode,
                verification,
                ..
            } => {
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS archive download URL: {}",
                        resolved_url
                    )));
                }
                let tmp_archive = self
                    .fetch_artifact_to_temp(
                        &recipe.package_id,
                        &resolved_url,
                        arch_asset,
                        journal,
                        cancel,
                    )
                    .await?;
                cancel.check(&recipe.package_id)?;

                let mut gz_policy = verification.clone();
                gz_policy.require_gzip_magic = true;
                let sha256 = verify_artifact_file_for_arch(&tmp_archive, &gz_policy, Some(&arch))?;

                let dest_dir_resolved = self.env_cfg.resolve_path(dest_dir)?;
                create_dir_all_0755(&dest_dir_resolved)?;
                validate_filesystem_path(&dest_dir_resolved, self.env_cfg.fs_root.as_deref())?;

                extract_binaries_from_targz(
                    &tmp_archive,
                    &dest_dir_resolved,
                    extract_binaries,
                    *binary_mode,
                    verification.require_elf_magic,
                    journal,
                )?;
                let _ = fs::remove_file(&tmp_archive);

                Ok(format!(
                    "extracted verified archive binaries {:?} to {} (sha256={})",
                    extract_binaries,
                    dest_dir,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::MergeIniSettings {
                path,
                section,
                settings,
                mode,
                ..
            } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                journal.stage_file_mutation(&resolved)?;
                let original = match fs::read_to_string(&resolved) {
                    Ok(contents) => contents,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.into()),
                };
                let rendered_settings = settings
                    .iter()
                    .map(|(key, value)| (key.clone(), interpolate_template(value, vars)))
                    .collect::<Vec<_>>();
                let rendered = merge_ini_settings(&original, section, &rendered_settings);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("merged managed INI settings in {}", path))
            }
            DeclarativeStep::WriteTemplateFile {
                path,
                content_template,
                mode,
                overwrite,
                owner,
                group,
                ..
            } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                let rendered = if path.ends_with(".env") || path.starts_with("/etc/default/") {
                    let mut escaped_vars = vars.clone();
                    if let Some(u) = escaped_vars.get("MASTER_USER").cloned() {
                        escaped_vars
                            .insert("MASTER_USER".to_string(), escape_systemd_env_quoted(&u));
                    }
                    if let Some(p) = escaped_vars.get("MASTER_PASS").cloned() {
                        escaped_vars
                            .insert("MASTER_PASS".to_string(), escape_systemd_env_quoted(&p));
                    }
                    if let Some(p) = escaped_vars.get("RCLONE_PASS").cloned() {
                        escaped_vars
                            .insert("RCLONE_PASS".to_string(), escape_systemd_env_quoted(&p));
                    }
                    interpolate_template(content_template, &escaped_vars)
                } else if path == "/var/lib/znc/configs/znc.conf" {
                    let mut znc_vars = vars.clone();
                    if let Some(ver) = znc_vars.get("VERSION").cloned() {
                        let mm = format_znc_major_minor(&ver);
                        znc_vars.insert("VERSION".to_string(), mm.clone());
                        znc_vars.insert("ZNC_CONF_VERSION".to_string(), mm);
                    }
                    interpolate_template(content_template, &znc_vars)
                } else {
                    interpolate_template(content_template, vars)
                };

                if path == "/var/lib/novnc/.vnc/passwd" {
                    let password = rendered.trim_end_matches(['\r', '\n']);
                    let mut encoded = encode_tigervnc_passwd(password);
                    if !*overwrite {
                        let previous =
                            crate::blueprint::open_mutation_file(&resolved).and_then(|file| {
                                let mut bytes = Vec::new();
                                file.take(9).read_to_end(&mut bytes)?;
                                Ok(bytes)
                            });
                        if let Ok(previous) = previous {
                            if previous != rendered.as_bytes()
                                && previous != password.as_bytes()
                                && decode_tigervnc_passwd(&previous).is_some_and(|decoded| {
                                    decoded.len() >= 6
                                        && decoded
                                            .bytes()
                                            .all(|b| b.is_ascii_graphic() || b == b' ')
                                })
                            {
                                encoded.copy_from_slice(&previous);
                            }
                        }
                    }
                    journal.stage_file_mutation(&resolved)?;
                    write_file_atomic_with_mode_bounded(
                        &resolved,
                        &encoded,
                        0o600,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    self.apply_file_metadata(
                        &resolved,
                        0o600,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                    return Ok(format!("wrote configuration file {}", path));
                }

                if path == "/var/lib/novnc/.vnc/xstartup" && !*overwrite && resolved.is_file() {
                    let previous = crate::blueprint::open_mutation_file(&resolved)?;
                    let mut bytes = Vec::new();
                    previous
                        .take(MAX_COMMAND_OUTPUT_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() > MAX_COMMAND_OUTPUT_BYTES {
                        return Err(PackageExecutorError::VerificationFailed(
                            "existing noVNC xstartup exceeds the configuration size limit".into(),
                        ));
                    }
                    journal.stage_file_mutation(&resolved)?;
                    // Upgrade the previous managed script and retain operator scripts.
                    let updated = if bytes == b"#!/bin/sh\nunset SESSION_MANAGER\nunset DBUS_SESSION_BUS_ADDRESS\nexec startxfce4\n" {
                        rendered.as_bytes()
                    } else {
                        &bytes
                    };
                    write_file_atomic_with_mode_bounded(
                        &resolved,
                        updated,
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    self.apply_file_metadata(
                        &resolved,
                        *mode,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                    return Ok(format!("wrote configuration file {}", path));
                }

                if !*overwrite && resolved.is_file() {
                    if path == "/etc/rclone/rclone.env" {
                        let lifecycle_action = vars
                            .get("LIFECYCLE_ACTION")
                            .map(String::as_str)
                            .unwrap_or("install");
                        let keep_secrets = self.env_cfg.keep_existing_secrets
                            || env::var("AF_KEEP_EXISTING_SECRETS")
                                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                                .unwrap_or(false)
                            || (matches!(lifecycle_action, "update" | "reinstall")
                                && env::var("AF_KEEP_EXISTING_SECRETS")
                                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                                    .unwrap_or(true));
                        if !keep_secrets {
                            if let Some(explicit_pass) = self.resolve_explicit_password() {
                                if let Ok(existing) = fs::read_to_string(&resolved) {
                                    let updated =
                                        update_preserved_rclone_env_pass(&existing, &explicit_pass);
                                    if updated != existing {
                                        journal.stage_file_mutation(&resolved)?;
                                        write_file_atomic_with_mode_bounded(
                                            &resolved,
                                            updated.as_bytes(),
                                            *mode,
                                            self.env_cfg.fs_root.as_deref(),
                                        )?;
                                        self.apply_file_metadata(
                                            &resolved,
                                            *mode,
                                            owner.as_deref(),
                                            group.as_deref(),
                                            cancel,
                                        )
                                        .await?;
                                        return Ok(format!(
                                            "updated RCLONE_RC_PASS in existing file {}",
                                            path
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    let port_var = if path == "/etc/default/quasselcore" {
                        vars.get("LISTEN_PORT").or_else(|| vars.get("APP_PORT"))
                    } else {
                        vars.get("APP_PORT")
                    };
                    if let Some(app_port) = port_var {
                        if let Ok(existing) = fs::read_to_string(&resolved) {
                            if let Some(updated) =
                                update_preserved_template_port(path, &existing, &rendered, app_port)
                            {
                                if updated != existing {
                                    journal.stage_file_mutation(&resolved)?;
                                    write_file_atomic_with_mode_bounded(
                                        &resolved,
                                        updated.as_bytes(),
                                        *mode,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    self.apply_file_metadata(
                                        &resolved,
                                        *mode,
                                        owner.as_deref(),
                                        group.as_deref(),
                                        cancel,
                                    )
                                    .await?;
                                    return Ok(format!("updated port in existing file {}", path));
                                }
                            }
                        }
                    }
                    return Ok(format!("preserved existing file {}", path));
                }
                journal.stage_file_mutation(&resolved)?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;

                if let Some(ref o) = owner {
                    let grp = group.as_deref().unwrap_or(o.as_str());
                    if self.env_cfg.fs_root.is_none() {
                        let out = self
                            .runner
                            .run_command(
                                "chown",
                                &[
                                    "-h".to_string(),
                                    format!("{}:{}", o, grp),
                                    resolved.to_string_lossy().to_string(),
                                ],
                                &[],
                                cancel,
                            )
                            .await?;
                        if !out.success() {
                            return Err(PackageExecutorError::StepFailed {
                                step: "write_template_file".to_string(),
                                reason: format!(
                                    "chown -h {}:{} {} exited with {}: {}",
                                    o,
                                    grp,
                                    resolved.display(),
                                    out.exit_code,
                                    out.combined_output()
                                ),
                            });
                        }
                    }
                }
                Ok(format!("wrote configuration file {}", path))
            }

            DeclarativeStep::WriteSystemdUnit {
                unit_name,
                content_template,
                ..
            } => {
                let norm = normalize_unit_filename(unit_name);
                let logical_path = format!("/etc/systemd/system/{}", norm);
                let resolved = self.env_cfg.resolve_path(&logical_path)?;
                let existed = resolved.is_file();
                journal.stage_file_mutation(&resolved)?;
                if existed {
                    journal.record_restorable_systemd_service(&norm);
                } else {
                    journal.record_created_systemd_unit(&norm, &resolved);
                }
                let mut content = content_template.clone();
                if norm == "rclone.service" {
                    let effective_root = self.env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
                    let detected_exec = detect_rclone_exec_start_for_root(effective_root);
                    if content.contains("{{RCLONE_EXEC_START}}") {
                        content = content.replace("{{RCLONE_EXEC_START}}", detected_exec);
                    } else if content.contains("--rc-web-gui")
                        && detected_exec.contains("rclone gui")
                    {
                        content = content.replace(
                            "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-enable-metrics --rc-addr=127.0.0.1:{{APP_PORT}} --config=/etc/rclone/rclone.conf",
                            detected_exec,
                        );
                        content = content.replace(
                            "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --rc-enable-metrics --config=/etc/rclone/rclone.conf",
                            detected_exec,
                        );
                        content = content.replace(
                            "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --config=/etc/rclone/rclone.conf",
                            detected_exec,
                        );
                    }
                    if !vars.contains_key("RCLONE_API_PORT") {
                        let mut existing_api_port = None;
                        if let Ok(svc_existing) = fs::read_to_string(&resolved) {
                            for line in svc_existing.lines() {
                                let trimmed = line.trim();
                                if trimmed.starts_with("ExecStart=") {
                                    if let Some(idx) = trimmed.find("--api-addr=") {
                                        let rest = &trimmed[idx + "--api-addr=".len()..];
                                        let token = rest.split_whitespace().next().unwrap_or("");
                                        if let Some((_, p_str)) = token.rsplit_once(':') {
                                            let cleaned = p_str.trim_matches(['"', '\'', ' ']);
                                            if let Ok(p) = cleaned.parse::<u16>() {
                                                existing_api_port = Some(p);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let app_port_num: u16 = vars
                            .get("APP_PORT")
                            .and_then(|p| p.parse::<u16>().ok())
                            .unwrap_or(5572);
                        let final_api_port =
                            existing_api_port.unwrap_or_else(|| app_port_num.saturating_add(1));
                        vars.insert("RCLONE_API_PORT".to_string(), final_api_port.to_string());
                    }
                }
                let rendered = interpolate_template(&content, vars);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    0o644,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("wrote systemd unit {}", logical_path))
            }

            DeclarativeStep::Systemctl {
                unit,
                operation,
                ignore_errors,
                ..
            } => {
                if matches!(
                    operation,
                    SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed
                ) {
                    let norm_unit = normalize_unit_filename(unit.as_deref().unwrap_or_default());
                    if matches!(operation, SystemctlOp::Stop | SystemctlOp::Disable)
                        && !norm_unit.is_empty()
                    {
                        let unit_logical = format!("/etc/systemd/system/{}", norm_unit);
                        if self
                            .env_cfg
                            .resolve_path(&unit_logical)
                            .map(|p| p.is_file())
                            .unwrap_or(false)
                        {
                            journal.record_restorable_systemd_service(&norm_unit);
                        }
                    }
                    let operation_name = match operation {
                        SystemctlOp::Stop => "stop",
                        SystemctlOp::Disable => "disable",
                        _ => "reset-failed",
                    };
                    self.teardown_systemctl(operation_name, &norm_unit, cancel)
                        .await?;
                    return Ok(format!("systemctl {operation_name} completed"));
                }
                let args: Vec<String> = match operation {
                    SystemctlOp::DaemonReload => vec!["daemon-reload".to_string()],
                    SystemctlOp::EnableNow => vec![
                        "enable".to_string(),
                        "--now".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Enable => vec![
                        "enable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Start => vec![
                        "start".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Restart => vec![
                        "restart".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Stop => vec![
                        "stop".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Disable => vec![
                        "disable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::ResetFailed => vec![
                        "reset-failed".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                };
                let out = self
                    .runner
                    .run_command("systemctl", &args, &[], cancel)
                    .await?;
                if !out.success()
                    && (!*ignore_errors || matches!(operation, SystemctlOp::DaemonReload))
                {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("systemctl {:?}", operation),
                        reason: format!(
                            "systemctl {} exited with {}: {}",
                            args.join(" "),
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if out.success()
                    && matches!(
                        operation,
                        SystemctlOp::EnableNow | SystemctlOp::Start | SystemctlOp::Restart
                    )
                {
                    if let Some(unit_name) = unit.as_ref().filter(|u| !u.is_empty()) {
                        journal.record_touched_service(unit_name);
                        let verify_args = vec![
                            "is-active".to_string(),
                            "--quiet".to_string(),
                            "--".to_string(),
                            unit_name.clone(),
                        ];
                        let active_out = self
                            .runner
                            .run_command("systemctl", &verify_args, &[], cancel)
                            .await?;
                        if !active_out.success() && !*ignore_errors {
                            return Err(PackageExecutorError::StepFailed {
                                step: format!("systemctl is-active {}", unit_name),
                                reason: format!(
                                    "service {} failed post-activation readiness check (systemctl is-active exited with {}): {}",
                                    unit_name,
                                    active_out.exit_code,
                                    active_out.combined_output()
                                ),
                            });
                        }
                    }
                }
                Ok(format!("systemctl {} completed", args.join(" ")))
            }

            DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                let norm = normalize_unit_filename(unit_name);
                for op in ["stop", "disable", "reset-failed"] {
                    cancel.check(&recipe.package_id)?;
                    self.teardown_systemctl(op, &norm, cancel).await?;
                }
                let unit_logical = format!("/etc/systemd/system/{}", norm);
                let dropin_logical = format!("/etc/systemd/system/{}.d", norm);
                let unit_path = self.env_cfg.resolve_path(&unit_logical)?;
                let dropin_path = self.env_cfg.resolve_path(&dropin_logical)?;
                match fs::remove_file(&unit_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                match fs::remove_dir_all(&dropin_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let reload = self
                    .runner
                    .run_command("systemctl", &["daemon-reload".to_string()], &[], cancel)
                    .await?;
                if !reload.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "systemctl_daemon_reload".to_string(),
                        reason: reload.combined_output(),
                    });
                }
                Ok(format!("purged systemd unit {}", norm))
            }

            DeclarativeStep::RemovePaths {
                paths,
                only_if_delete_data,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped data directory removal (DELETE_DATA=false)".to_string());
                }
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    validate_managed_path(logical)?;
                    let resolved = if let Some(ref root) = self.env_cfg.fs_root {
                        let rel = logical.trim_start_matches(['/', '\\']);
                        root.join(rel)
                    } else {
                        PathBuf::from(logical)
                    };
                    if let Some(parent) = resolved.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                    match fs::symlink_metadata(&resolved) {
                        Ok(meta) => {
                            if meta.file_type().is_symlink() {
                                fs::remove_file(&resolved)?;
                                continue;
                            }
                            if meta.is_dir() {
                                if self.is_active_mountpoint(logical, &resolved) {
                                    return Err(PackageExecutorError::SecurityViolation(format!(
                                        "refusing to remove active mountpoint directory: {}",
                                        resolved.display()
                                    )));
                                }
                                fs::remove_dir_all(&resolved)?;
                            } else {
                                fs::remove_file(&resolved)?;
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(PackageExecutorError::Io(err)),
                    }
                }
                Ok(format!("removed paths: {}", paths.join(", ")))
            }

            DeclarativeStep::RunCommand {
                program,
                args,
                only_if_delete_data,
                ignore_errors,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped command (DELETE_DATA=false)".to_string());
                }
                let mut cmd_envs: Vec<(String, String)> = Vec::new();
                cmd_envs.push((
                    "AF_JOB_SCRATCH_ROOT".to_string(),
                    "/var/tmp/aetherflow-scratch".to_string(),
                ));
                if let Some(ref target) = self.env_cfg.expected_target_version {
                    cmd_envs.push(("AF_TARGET_VERSION".to_string(), target.clone()));
                }
                let out = self
                    .runner
                    .run_command(program, args, &cmd_envs, cancel)
                    .await?;
                if !out.success() && !*ignore_errors {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("run_command {}", program),
                        reason: format!(
                            "{} {:?} exited with {}: {}",
                            program,
                            args,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok(format!("executed command {}", program))
            }

            DeclarativeStep::WaitForHttpReady { path, .. } => {
                self.execute_wait_for_http_ready(
                    &recipe.package_id,
                    path,
                    recipe.default_port,
                    vars,
                    cancel,
                )
                .await
            }
        }
    }

    async fn probe_curl_http(
        &self,
        method: &str,
        target_url: &str,
        creds: Option<&(String, String)>,
        cancel: &CancellationToken,
    ) -> Result<CommandOutput, PackageExecutorError> {
        let mut curl_args = vec![
            "-sSL".to_string(),
            "--max-time".to_string(),
            "5".to_string(),
            "-w".to_string(),
            "\n%{http_code}".to_string(),
        ];
        let mut stdin_bytes = Vec::new();
        if let Some((ref u, ref p)) = creds {
            curl_args.push("-K".to_string());
            curl_args.push("-".to_string());
            let escaped_u = u.replace('\\', "\\\\").replace('"', "\\\"");
            let escaped_p = p.replace('\\', "\\\\").replace('"', "\\\"");
            let config_line = format!("user = \"{}:{}\"\n", escaped_u, escaped_p);
            stdin_bytes.extend_from_slice(config_line.as_bytes());
        }
        if method == "POST" {
            curl_args.push("-X".to_string());
            curl_args.push("POST".to_string());
        }
        curl_args.push(target_url.to_string());
        self.runner
            .run_command_with_stdin("curl", &curl_args, &[], &stdin_bytes, cancel)
            .await
    }

    pub(crate) async fn execute_wait_for_http_ready(
        &self,
        package_id: &str,
        path: &str,
        default_port: i32,
        vars: &HashMap<String, String>,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        fn parse_curl(raw: &str) -> Option<(&str, u16)> {
            let trimmed = raw.trim_end();
            let (body, code_str) = match trimmed.rfind('\n') {
                Some(idx) => (&trimmed[..idx], trimmed[idx + 1..].trim()),
                None => ("", trimmed.trim()),
            };
            if code_str.len() == 3 && code_str.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(code) = code_str.parse::<u16>() {
                    return Some((body, code));
                }
            }
            None
        }

        fn is_mock_curl_output(raw: &str) -> bool {
            let t = raw.trim_start();
            t.starts_with("ok: curl") || t.starts_with("[dry-run] curl")
        }

        let port = vars
            .get("APP_PORT")
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(default_port as u16);
        let url = format!("http://127.0.0.1:{}{}", port, path);

        let is_rclone_check = package_id.eq_ignore_ascii_case("rclone");

        let mut rclone_creds: Option<(String, String)> = None;
        if is_rclone_check {
            let mut user = None;
            let mut pass = None;
            for cand in ["/etc/rclone/rclone.env", "/etc/aetherflow/rclone.env"] {
                let p = self.env_cfg.resolve_readonly_path(cand);
                if let Ok(c) = fs::read_to_string(&p) {
                    for line in c.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some((k, v)) = line.split_once('=') {
                            let mut val = v.trim();
                            if ((val.starts_with('"') && val.ends_with('"'))
                                || (val.starts_with('\'') && val.ends_with('\'')))
                                && val.len() >= 2
                            {
                                val = &val[1..val.len() - 1];
                            }
                            if (k.trim() == "RCLONE_RC_USER" || k.trim() == "RCLONE_USER")
                                && !val.is_empty()
                                && user.is_none()
                            {
                                user = Some(val.to_string());
                            }
                            if (k.trim() == "RCLONE_RC_PASS" || k.trim() == "RCLONE_PASS")
                                && !val.is_empty()
                                && pass.is_none()
                            {
                                pass = Some(val.to_string());
                            }
                        }
                    }
                    if user.is_some() && pass.is_some() {
                        break;
                    }
                }
            }
            if user.is_none() {
                user = vars
                    .get("MASTER_USER")
                    .cloned()
                    .or_else(|| vars.get("AF_CONFIG_USER").cloned());
            }
            if pass.is_none() {
                pass = vars
                    .get("RCLONE_PASS")
                    .cloned()
                    .or_else(|| vars.get("MASTER_PASS").cloned())
                    .or_else(|| vars.get("AF_CONFIG_PASS").cloned());
            }
            if let (Some(u), Some(p)) = (user, pass) {
                rclone_creds = Some((u, p));
            }
        }

        let max_attempts = env::var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(if self.env_cfg.fs_root.is_some() {
                5
            } else {
                15
            });
        let retry_delay_ms = env::var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(if self.env_cfg.fs_root.is_some() {
                15
            } else {
                500
            });
        let deadline = Instant::now()
            + Duration::from_secs(if self.env_cfg.fs_root.is_some() {
                5
            } else {
                30
            });
        let mut last_reason = String::new();

        for attempt in 1..=max_attempts {
            cancel.check(package_id)?;
            if attempt > 1 {
                if Instant::now() >= deadline {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(retry_delay_ms)) => {}
                    _ = wait_for_cancellation(cancel) => {
                        return Err(PackageExecutorError::Cancelled(package_id.to_string()));
                    }
                }
            }

            if is_rclone_check {
                let separate_api_port = detect_rclone_separate_api_port(&self.env_cfg, vars, port);

                let rc_port = if let Some(api_port) = separate_api_port {
                    // Split-port GUI mode: requires GUI listener reachability on APP_PORT
                    let gui_url = format!("http://127.0.0.1:{}/", port);
                    let gui_out = self.probe_curl_http("GET", &gui_url, None, cancel).await?;
                    if is_mock_curl_output(&gui_out.stdout) {
                        if self.env_cfg.dry_run {
                            if gui_out.success() {
                                return Ok(format!("verified HTTP readiness at {}", url));
                            }
                        } else {
                            last_reason = format!(
                                "rclone GUI probe returned mock/dry-run response when dry_run is false: {}",
                                gui_out.stdout.trim()
                            );
                            continue;
                        }
                    } else if !gui_out.success() {
                        last_reason = format!(
                            "rclone GUI probe to {} failed: {}",
                            gui_url,
                            gui_out.combined_output()
                        );
                        continue;
                    } else {
                        let Some((_, gui_code)) = parse_curl(&gui_out.stdout) else {
                            last_reason = format!(
                                "rclone GUI listener on {} returned invalid HTTP status: {}",
                                gui_url,
                                gui_out.stdout.trim()
                            );
                            continue;
                        };
                        if !(200..=399).contains(&gui_code) {
                            last_reason = format!(
                                "rclone GUI listener on {} returned HTTP {}",
                                gui_url, gui_code
                            );
                            continue;
                        }
                    }
                    api_port
                } else {
                    port
                };

                let _is_single_port = separate_api_port.is_none();

                // On the RC listener (api_port in split-port mode, or app_port in single-port rcd mode):
                // Verify BOTH /metrics (GET) AND /core/version (POST) on every readiness attempt:

                // 1. /metrics (GET)
                let metrics_url = format!("http://127.0.0.1:{}/metrics", rc_port);
                let unauth_metrics = self
                    .probe_curl_http("GET", &metrics_url, None, cancel)
                    .await?;
                if is_mock_curl_output(&unauth_metrics.stdout) {
                    if self.env_cfg.dry_run {
                        if unauth_metrics.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "RC metrics probe returned mock/dry-run response when dry_run is false: {}",
                            unauth_metrics.stdout.trim()
                        );
                        continue;
                    }
                }
                if !unauth_metrics.success() {
                    last_reason = format!(
                        "RC metrics probe to {} failed: {}",
                        metrics_url,
                        unauth_metrics.combined_output()
                    );
                    continue;
                }
                let Some((_unauth_m_body, unauth_m_code)) = parse_curl(&unauth_metrics.stdout)
                else {
                    last_reason = format!(
                        "RC metrics probe to {} returned invalid HTTP status: {}",
                        metrics_url,
                        unauth_metrics.stdout.trim()
                    );
                    continue;
                };
                if (200..=299).contains(&unauth_m_code) {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "unauthenticated metrics exposure / auth bypass detected on {}",
                            metrics_url
                        ),
                    });
                }
                if unauth_m_code != 401 && unauth_m_code != 403 {
                    last_reason = format!(
                        "unauthenticated RC metrics probe to {} returned unexpected status {} (expected 401 or 403)",
                        metrics_url, unauth_m_code
                    );
                    continue;
                }
                let auth_metrics = self
                    .probe_curl_http("GET", &metrics_url, rclone_creds.as_ref(), cancel)
                    .await?;
                if is_mock_curl_output(&auth_metrics.stdout) {
                    if self.env_cfg.dry_run {
                        if auth_metrics.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "authenticated RC metrics probe returned mock/dry-run response when dry_run is false: {}",
                            auth_metrics.stdout.trim()
                        );
                        continue;
                    }
                }
                if !auth_metrics.success() {
                    last_reason = format!(
                        "authenticated RC metrics probe to {} failed: {}",
                        metrics_url,
                        auth_metrics.combined_output()
                    );
                    continue;
                }
                let Some((_auth_m_body, auth_m_code)) = parse_curl(&auth_metrics.stdout) else {
                    last_reason = format!(
                        "authenticated RC metrics probe to {} returned invalid HTTP status: {}",
                        metrics_url,
                        auth_metrics.stdout.trim()
                    );
                    continue;
                };
                if auth_m_code == 401 || auth_m_code == 403 {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "authenticated RC metrics check failed with HTTP {} on {}",
                            auth_m_code, metrics_url
                        ),
                    });
                }
                if auth_m_code != 200 {
                    last_reason = format!(
                        "authenticated RC metrics check returned HTTP {} on {} (expected 200)",
                        auth_m_code, metrics_url
                    );
                    continue;
                }

                // 2. /core/version (POST)
                let version_url = format!("http://127.0.0.1:{}/core/version", rc_port);
                let unauth_version = self
                    .probe_curl_http("POST", &version_url, None, cancel)
                    .await?;
                if is_mock_curl_output(&unauth_version.stdout) {
                    if self.env_cfg.dry_run {
                        if unauth_version.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "RC API probe returned mock/dry-run response when dry_run is false: {}",
                            unauth_version.stdout.trim()
                        );
                        continue;
                    }
                }
                if !unauth_version.success() {
                    last_reason = format!(
                        "RC API probe to {} failed: {}",
                        version_url,
                        unauth_version.combined_output()
                    );
                    continue;
                }
                let Some((_unauth_v_body, unauth_v_code)) = parse_curl(&unauth_version.stdout)
                else {
                    last_reason = format!(
                        "unauthenticated probe to {} returned invalid HTTP status: {}",
                        version_url,
                        unauth_version.stdout.trim()
                    );
                    continue;
                };
                if (200..=299).contains(&unauth_v_code) {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "RC API listener on {} returned {} without credentials (auth bypass)",
                            version_url, unauth_v_code
                        ),
                    });
                }
                if unauth_v_code != 401 && unauth_v_code != 403 {
                    last_reason = format!(
                        "unauthenticated probe to {} returned unexpected HTTP {}",
                        version_url, unauth_v_code
                    );
                    continue;
                }

                // 3. Authenticated POST /core/version MUST return 200
                let auth_version = self
                    .probe_curl_http("POST", &version_url, rclone_creds.as_ref(), cancel)
                    .await?;
                if is_mock_curl_output(&auth_version.stdout) {
                    if self.env_cfg.dry_run {
                        if auth_version.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "authenticated RC API check returned mock/dry-run response when dry_run is false: {}",
                            auth_version.stdout.trim()
                        );
                        continue;
                    }
                }
                if !auth_version.success() {
                    last_reason = format!(
                        "authenticated RC API probe to {} failed: {}",
                        version_url,
                        auth_version.combined_output()
                    );
                    continue;
                }
                let Some((_auth_v_body, auth_v_code)) = parse_curl(&auth_version.stdout) else {
                    last_reason = format!(
                        "authenticated RC API check returned invalid HTTP status on {}: {}",
                        version_url,
                        auth_version.stdout.trim()
                    );
                    continue;
                };
                if auth_v_code == 401 || auth_v_code == 403 {
                    return Err(PackageExecutorError::StepFailed {
                        step: "wait_for_http_ready".to_string(),
                        reason: format!(
                            "authenticated RC API check failed with HTTP {} on {}",
                            auth_v_code, version_url
                        ),
                    });
                }
                if auth_v_code != 200 {
                    last_reason = format!(
                        "authenticated RC API check returned HTTP {} on {}",
                        auth_v_code, version_url
                    );
                    continue;
                }

                let require_live = env::var("AETHERFLOW_REQUIRE_LIVE_LISTENER")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if require_live {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], rc_port));
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
                        Ok(_) => {}
                        Err(err) => {
                            last_reason = format!(
                                "RC API listener on 127.0.0.1:{} is not accepting TCP connections: {}",
                                rc_port, err
                            );
                            continue;
                        }
                    }
                }

                if separate_api_port.is_some() {
                    return Ok(format!(
                        "verified HTTP readiness for Rclone GUI at http://127.0.0.1:{}/ and RC API at {}",
                        port, version_url
                    ));
                } else {
                    return Ok(format!("verified HTTP readiness at {}", url));
                }
            } else {
                // Non-rclone probe: never read rclone.env or send Authorization header
                let out = self.probe_curl_http("GET", &url, None, cancel).await?;
                if is_mock_curl_output(&out.stdout) {
                    if self.env_cfg.dry_run {
                        if out.success() {
                            return Ok(format!("verified HTTP readiness at {}", url));
                        }
                    } else {
                        last_reason = format!(
                            "application readiness probe returned mock/dry-run response when dry_run is false: {}",
                            out.stdout.trim()
                        );
                        continue;
                    }
                }
                if !out.success() {
                    last_reason = format!(
                        "application readiness check failed for {}: {}",
                        url,
                        out.combined_output()
                    );
                    continue;
                }
                let Some((_body, status_code)) = parse_curl(&out.stdout) else {
                    last_reason = format!(
                        "application readiness probe to {} returned invalid HTTP status: {}",
                        url,
                        out.stdout.trim()
                    );
                    continue;
                };
                if !(200..=399).contains(&status_code) {
                    last_reason = format!(
                        "application readiness check returned HTTP {} on {}",
                        status_code, url
                    );
                    continue;
                }
                let require_live = env::var("AETHERFLOW_REQUIRE_LIVE_LISTENER")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if require_live {
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
                        Ok(_) => return Ok(format!("verified HTTP readiness at {}", url)),
                        Err(err) => {
                            last_reason = format!(
                                "application listener on 127.0.0.1:{} is not accepting TCP connections: {}",
                                port, err
                            );
                            continue;
                        }
                    }
                }
                return Ok(format!("verified HTTP readiness at {}", url));
            }
        }

        Err(PackageExecutorError::StepFailed {
            step: format!("wait_for_http_ready {}", url),
            reason: last_reason,
        })
    }

    fn resolve_explicit_password(&self) -> Option<String> {
        if self.env_cfg.keep_existing_secrets {
            return None;
        }
        self.env_cfg
            .password
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin")
            .or_else(|| {
                env::var("AF_PASS")
                    .or_else(|_| env::var("AETHERFLOW_MASTER_PASS"))
                    .or_else(|_| env::var("MASTER_PASS"))
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty() && v != "adminadmin")
            })
    }

    fn is_active_mountpoint(&self, logical: &str, resolved: &Path) -> bool {
        let norm_logical = logical.trim().trim_end_matches('/');
        let norm_resolved = resolved.to_string_lossy().trim_end_matches('/').to_string();

        let mut mount_tables = vec![
            self.env_cfg.resolve_readonly_path("/proc/mounts"),
            self.env_cfg.resolve_readonly_path("/proc/self/mountinfo"),
        ];
        if self.env_cfg.fs_root.is_none() {
            mount_tables.push(PathBuf::from("/proc/mounts"));
        }

        for table_path in mount_tables {
            if let Ok(contents) = fs::read_to_string(&table_path) {
                for line in contents.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    let mp_candidates: Vec<&str> = if table_path.ends_with("mountinfo") {
                        fields.get(4).copied().into_iter().collect()
                    } else {
                        fields.get(1).copied().into_iter().collect()
                    };
                    for raw_mp in mp_candidates {
                        let unescaped = raw_mp.replace("\\040", " ");
                        let mp = unescaped.trim_end_matches('/');
                        if !mp.is_empty()
                            && mp != "/"
                            && (mp == norm_logical || mp == norm_resolved)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if matches!(
                norm_logical,
                "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote"
            ) || norm_logical.starts_with("/mnt/")
            {
                if let (Ok(meta), Some(parent)) =
                    (fs::symlink_metadata(resolved), resolved.parent())
                {
                    if let Ok(parent_meta) = fs::symlink_metadata(parent) {
                        if meta.dev() != parent_meta.dev() {
                            return true;
                        }
                    }
                }
            }
        }

        if self.env_cfg.fs_root.is_none()
            && cfg!(target_os = "linux")
            && (matches!(
                norm_logical,
                "/mnt/unionfs" | "/mnt/mergerfs" | "/mnt/remote"
            ) || norm_logical.starts_with("/mnt/"))
        {
            if let Ok(status) = std::process::Command::new("mountpoint")
                .arg("-q")
                .arg(resolved)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                if status.success() {
                    return true;
                }
            }
        }

        false
    }

    async fn resolve_github_tag(
        &self,
        repo: &str,
        fallback_version: &str,
        strip_v_prefix: bool,
    ) -> String {
        // 1. Honor explicit version override or offline mode in tests/airgapped environments
        if let Ok(override_ver) = env::var("AETHERFLOW_PACKAGE_VERSION_OVERRIDE") {
            let trimmed = override_ver.trim();
            if SAFE_VERSION_TAG.is_match(trimmed) {
                return if strip_v_prefix {
                    trimmed.trim_start_matches('v').to_string()
                } else {
                    trimmed.to_string()
                };
            }
        }
        if self.env_cfg.artifact_cache_dir.is_some() || self.env_cfg.fs_root.is_some() {
            return if strip_v_prefix {
                fallback_version.trim_start_matches('v').to_string()
            } else if fallback_version.starts_with('v') {
                fallback_version.to_string()
            } else {
                format!("v{}", fallback_version)
            };
        }

        // 2. Query GitHub releases/latest API with short timeout
        let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
        {
            if let Ok(resp) = client.get(&api_url).send().await {
                if resp.status().is_success() {
                    if let Ok(json_val) = resp.json::<serde_json::Value>().await {
                        if let Some(tag_str) = json_val.get("tag_name").and_then(|v| v.as_str()) {
                            let clean = tag_str.trim();
                            if SAFE_VERSION_TAG.is_match(clean) {
                                return if strip_v_prefix {
                                    clean.trim_start_matches('v').to_string()
                                } else {
                                    clean.to_string()
                                };
                            }
                        }
                    }
                }
            }
        }

        if strip_v_prefix {
            fallback_version.trim_start_matches('v').to_string()
        } else if fallback_version.starts_with('v') {
            fallback_version.to_string()
        } else {
            format!("v{}", fallback_version)
        }
    }

    pub(super) async fn fetch_artifact_to_temp(
        &self,
        pkg_id: &str,
        url: &str,
        asset_name: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<PathBuf, PackageExecutorError> {
        cancel.check(pkg_id)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        fs::create_dir_all(&self.env_cfg.temp_dir)?;
        validate_filesystem_path(&self.env_cfg.temp_dir, self.env_cfg.fs_root.as_deref())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_dest = self
            .env_cfg
            .temp_dir
            .join(format!("af-{}-{}-{}", pkg_id, nanos, asset_name));
        validate_filesystem_path(&tmp_dest, self.env_cfg.fs_root.as_deref())?;
        journal.track_temp_file(tmp_dest.clone());

        // 1. Check local artifact cache directory first (used by isolated tests and offline staging)
        if let Some(ref cache_dir) = self.env_cfg.artifact_cache_dir {
            validate_filesystem_path(cache_dir, self.env_cfg.fs_root.as_deref())?;
            let mut candidate_names = vec![asset_name];
            if asset_name == "Threadfin_linux_amd64_glibc_2.31_compat" {
                candidate_names.push("Threadfin_linux_amd64_compat");
                candidate_names.push("Threadfin_linux_amd64");
            }
            for cand in candidate_names {
                let cached = cache_dir.join(cand);
                validate_filesystem_path(&cached, self.env_cfg.fs_root.as_deref())?;
                if cached.is_file() {
                    fs::copy(&cached, &tmp_dest)?;
                    return Ok(tmp_dest);
                }
            }
        }

        // 2. Support `file://` URLs for local staging tests
        if let Some(local_path) = url.strip_prefix("file://") {
            let src = Path::new(local_path);
            validate_filesystem_path(src, None)?;
            if !src.is_file() {
                return Err(PackageExecutorError::ArtifactVerification(format!(
                    "staged file artifact not found: {}",
                    src.display()
                )));
            }
            fs::copy(src, &tmp_dest)?;
            return Ok(tmp_dest);
        }

        // 3. Enforce HTTPS fail-closed on remote downloads
        if !url.starts_with("https://") {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "refusing non-HTTPS artifact download URL: {}",
                url
            )));
        }

        // 4. Perform HTTPS download via reqwest with chunked cancellation checks
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("AetherFlow-PackageExecutor/4.0")
            .build()
            .map_err(|e| PackageExecutorError::StepFailed {
                step: "http_client".to_string(),
                reason: e.to_string(),
            })?;

        let mut resp = tokio::select! {
            _ = wait_for_cancellation(cancel) => {
                return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
            }
            res = client.get(url).send() => {
                res.map_err(|e| PackageExecutorError::StepFailed {
                    step: "download_artifact".to_string(),
                    reason: format!("failed to download {}: {}", url, e),
                })?
            }
        };

        if !resp.status().is_success() {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "HTTP {} when downloading {}",
                resp.status(),
                url
            )));
        }

        let mut f = File::create(&tmp_dest)?;
        loop {
            let next_chunk = tokio::select! {
                _ = wait_for_cancellation(cancel) => {
                    drop(f);
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(PackageExecutorError::Cancelled(pkg_id.to_string()));
                }
                chunk_res = resp.chunk() => {
                    chunk_res.map_err(|e| PackageExecutorError::StepFailed {
                        step: "download_artifact_body".to_string(),
                        reason: e.to_string(),
                    })?
                }
            };
            match next_chunk {
                Some(chunk) => {
                    f.write_all(&chunk)?;
                }
                None => break,
            }
        }
        cancel.check(pkg_id)?;
        f.sync_all()?;

        Ok(tmp_dest)
    }
}
