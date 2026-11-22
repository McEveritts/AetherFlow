use super::*;

pub(in crate::package_executor) fn build_fail2ban_recipe() -> DeclarativePackageRecipe {
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

pub(in crate::package_executor) fn build_quassel_recipe() -> DeclarativePackageRecipe {
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
            if is_valid_sha256_hex(trimmed) {
                return Some(trimmed.to_ascii_lowercase());
            }
        }
    }
    None
}

pub(in crate::package_executor) fn build_threadfin_recipe() -> DeclarativePackageRecipe {
    let target_version = resolve_threadfin_target_version();
    let sha_override = resolve_threadfin_sha256_override();
    let default_arch_sha256 = if sha_override.is_some() {
        None
    } else {
        Some(ArchAssetMap {
            amd64: THREADFIN_AMD64_COMPAT_SHA256.to_string(),
            arm64: THREADFIN_ARM64_SHA256.to_string(),
            armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
        })
    };

    let state_directory = DeclarativeStep::EnsureDirectories {
        paths: vec!["/var/lib/threadfin".to_string()],
        // The installed-version reader opens ancestor directories with
        // O_RDONLY | O_DIRECTORY | O_NOFOLLOW; 0755 lets it read .af-version
        // while /var/lib/threadfin/conf stays private (0750).
        mode: 0o755,
        owner: Some("threadfin".to_string()),
        group: Some("threadfin".to_string()),
        progress_pct: 40,
        description: "Creating the Threadfin state directory...".to_string(),
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
        state_directory.clone(),
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/opt/threadfin".to_string(),
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
            content_template: "[Unit]\nDescription=Threadfin M3U and HDHomeRun IPTV Proxy\nAfter=syslog.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=threadfin\nGroup=threadfin\nEnvironment=HOME=/var/lib/threadfin\nWorkingDirectory=/var/lib/threadfin\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}} -bind={{BIND_ADDRESS}} -config=/var/lib/threadfin/conf\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
            description: "Verifying Threadfin HTTP listener readiness on {{BIND_ADDRESS}}:{{APP_PORT}}/status...".to_string(),
        },
    ];
    DeclarativePackageRecipe {
        package_id: "threadfin".to_string(),
        label: "Threadfin".to_string(),
        default_port: 34400,
        service_name: "threadfin".to_string(),
        lock_file: "/install/.threadfin.lock".to_string(),
        apply_systemd_sandbox: true,
        update_steps: install_steps.clone(),
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

pub(in crate::package_executor) fn build_znc_recipe() -> DeclarativePackageRecipe {
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
            content_template: "Version = {{ZNC_CONF_VERSION}}\n<Listener l>\n    AllowIRC = true\n    AllowWeb = true\n    Port = {{APP_PORT}}\n    IPv4 = true\n    IPv6 = false\n    SSL = false\n    Host = {{BIND_ADDRESS}}\n</Listener>\nLoadModule = webadmin\n\n<User {{MASTER_USER}}>\n    Pass       = sha256#{{ZNC_PASS_HASH}}#{{ZNC_SALT}}#\n    Admin      = true\n    Nick       = {{MASTER_USER}}\n    AltNick    = {{MASTER_USER}}_\n    Ident      = {{MASTER_USER}}\n    RealName   = {{MASTER_USER}}\n</User>\n".to_string(),
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
            description: "Verifying ZNC webadmin HTTP listener readiness on {{BIND_ADDRESS}}:{{APP_PORT}}/...".to_string(),
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
            DeclarativeStep::AptRemove {
                packages: vec!["znc".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Removing znc APT package (purging only with DELETE_DATA=true)..."
                    .to_string(),
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

pub(in crate::package_executor) fn build_xrdp_recipe() -> DeclarativePackageRecipe {
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
            DeclarativeStep::AptRemove {
                packages: vec!["xrdp".to_string(), "xorgxrdp".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description: "Removing xrdp APT packages (purging only with DELETE_DATA=true)..."
                    .to_string(),
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

pub(in crate::package_executor) fn build_x2go_recipe() -> DeclarativePackageRecipe {
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
            DeclarativeStep::AptRemove {
                packages: vec!["x2goserver".to_string(), "x2goserver-xsession".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description:
                    "Removing x2goserver APT packages (purging only with DELETE_DATA=true)..."
                        .to_string(),
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

pub(in crate::package_executor) fn build_netdata_recipe() -> DeclarativePackageRecipe {
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
                ("bind to".to_string(), "{{BIND_ADDRESS}}".to_string()),
                ("default port".to_string(), "{{APP_PORT}}".to_string()),
            ],
            mode: 0o644,
            progress_pct: 75,
            description:
                "Writing /etc/netdata/netdata.conf bound to {{BIND_ADDRESS}}:{{APP_PORT}}..."
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
                "Verifying Netdata HTTP listener readiness on {{BIND_ADDRESS}}:{{APP_PORT}}/api/v1/info..."
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
            DeclarativeStep::AptRemove {
                packages: vec!["netdata".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 55,
                description: "Removing netdata APT package (purging only with DELETE_DATA=true)..."
                    .to_string(),
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

pub(in crate::package_executor) fn build_mergerfs_recipe() -> DeclarativePackageRecipe {
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
            ],
            mode: 0o775,
            owner: None,
            group: None,
            progress_pct: 55,
            description: "Ensuring /mnt/unionfs and union mount directories (0775)...".to_string(),
        },
        DeclarativeStep::EnsureDirectories {
            paths: vec![
                "/etc/mergerfs".to_string(),
                "/var/lib/mergerfs".to_string(),
            ],
            mode: 0o755,
            owner: None,
            group: None,
            progress_pct: 58,
            description: "Ensuring /etc/mergerfs and /var/lib/mergerfs state directories..."
                .to_string(),
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
            DeclarativeStep::UnmountPaths {
                paths: vec!["/mnt/unionfs".to_string(), "/mnt/mergerfs".to_string()],
                progress_pct: 40,
                description: "Unmounting active MergerFS mountpoints (/mnt/unionfs, /mnt/mergerfs)..."
                    .to_string(),
            },
            DeclarativeStep::AptRemove {
                packages: vec!["mergerfs".to_string()],
                autoremove: true,
                ignore_errors: true,
                progress_pct: 60,
                description:
                    "Removing mergerfs APT package (purging only with DELETE_DATA=true)..."
                        .to_string(),
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
                paths: vec![
                    "/etc/mergerfs".to_string(),
                    "/etc/default/mergerfs".to_string(),
                    "/var/lib/mergerfs".to_string(),
                ],
                only_if_delete_data: true,
                progress_pct: 84,
                description: "Removing MergerFS configuration and state directories (when DELETE_DATA=true; preserving /mnt/unionfs and /mnt/mergerfs)...".to_string(),
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

pub(in crate::package_executor) fn build_rclone_recipe() -> DeclarativePackageRecipe {
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
            path: RCLONE_ENV.to_string(),
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
            content_template: "[Unit]\nDescription=Rclone RC Web GUI Service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=rclone\nGroup=rclone\nWorkingDirectory=/var/lib/rclone\nEnvironmentFile=/etc/rclone/rclone.env\nExecStart={{RCLONE_EXEC_START}}\nLogFilterPatterns=~.*(pass|password|token|login_token)=.*\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
            progress_pct: 79,
            description: "Writing rclone.service systemd unit on port {{APP_PORT}}...".to_string(),
        },
        DeclarativeStep::WriteSystemdUnit {
            unit_name: "rclone-vfs.service".to_string(),
            content_template: "[Unit]\nDescription=Rclone VFS FUSE Mount Daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStartPre=-/bin/mkdir -p /mnt/remote\nExecStart={{RCLONE_BIN}} mount remote: /mnt/remote --config=/etc/rclone/rclone.conf --vfs-cache-mode=full --allow-other --dir-cache-time=72h\nExecStop=/bin/fusermount -uz /mnt/remote\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n".to_string(),
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
        DeclarativeStep::Systemctl {
            unit: Some("rclone-vfs.service".to_string()),
            operation: SystemctlOp::TryRestart,
            ignore_errors: false,
            progress_pct: 97,
            description: "Restarting the Rclone VFS companion if it is active...".to_string(),
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
            DeclarativeStep::RemoveRcloneFiles {
                progress_pct: 78,
                description: "Removing the managed runtime and, when requested, Rclone data...".to_string(),
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

pub(in crate::package_executor) fn recipe_mutable_state_dirs(
    recipe: &DeclarativePackageRecipe,
) -> Vec<String> {
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

    let extra_dirs: &[&str] = match recipe.package_id.as_str() {
        "quassel" => &["/var/lib/quassel", "/etc/quassel"],
        "znc" => &["/var/lib/znc", "/etc/znc"],
        "rclone" => &["/var/lib/rclone", "/etc/rclone"],
        _ => &[],
    };
    for path in extra_dirs {
        push_unique(path);
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

pub(in crate::package_executor) fn recipe_primary_apt_package(
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
    None
}
