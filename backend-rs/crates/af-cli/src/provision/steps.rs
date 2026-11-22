use super::apache_htpasswd::provision_apache_htpasswd_if_configured;
use super::fs_helpers::{
    enforce_root_private_file_perms, ensure_dir_no_symlinks, ensure_install_dir_secure,
    ensure_no_symlink_ancestors, write_file_atomic_exclusive,
};
use super::lock::ProvisionLockGuard;
use super::preflight::{is_effective_root_user, parse_and_validate_os_release};
use super::state::ProvisionStateStore;
use super::{
    canonical_step_catalog, validate_step_id, ProvisionStepDescriptor, ProvisionStepTier,
    PROVISION_STATE_VERSION, STATE_VERSION_HEADER,
};
use crate::error::{CliError, CliResult};
use af_host::{apply_network_tuning, reject_if_symlink};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::Path;
use uuid::Uuid;

/// Execution outcome for an individual provisioning step during `af provision run` or `repair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionStatus {
    /// Step was already recorded as completed in `.aetherflow.state` and skipped (`--resume`).
    SkippedAlreadyDone,
    /// Step was validated in `--dry-run` mode without mutating disk state.
    DryRunPlanned,
    /// Step executed and was persisted as completed in `.aetherflow.state`.
    Completed,
    /// Step is a `RetainedShellBootstrap` step that must be run via `setup/AetherFlow-Setup`.
    DeferredToShellBootstrap,
}

/// Detailed record for a single step processed during a provisioning run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecutionRecord {
    pub step_id: String,
    pub tier: ProvisionStepTier,
    pub status: StepExecutionStatus,
    pub detail: String,
}

/// Summary report returned by [`execute_provision_steps`] (`af provision run` / `repair`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionRunReport {
    pub mode: String,
    pub dry_run: bool,
    pub fresh: bool,
    pub cleared_for_repair: Vec<String>,
    pub records: Vec<StepExecutionRecord>,
    pub completed_steps_after: Vec<String>,
}

/// Executes or resumes a bounded list of provisioning steps (or the default Rust-native foundation
/// steps when `requested_steps` is empty).
///
/// If `is_repair` is `true`, first clears completion state for `requested_steps` so they are
/// guaranteed to re-run.
pub fn execute_provision_steps(
    store: &ProvisionStateStore,
    requested_steps: &[String],
    fresh: bool,
    is_repair: bool,
    require_root: bool,
    dry_run: bool,
) -> CliResult<ProvisionRunReport> {
    let paths = store.paths();
    ensure_no_symlink_ancestors(&paths.fs_root, "provision fs_root")?;

    // Enforce root privilege unless running against an isolated non-root test directory or dry-run
    if require_root && !dry_run && paths.fs_root == Path::new("/") && !is_effective_root_user() {
        return Err(CliError::PrivilegeRequired(
            "provisioning live '/' root requires root privileges (UID 0)".to_string(),
        ));
    }

    // Default to the 6 Rust-native foundation steps when no explicit step list is passed
    let target_steps: Vec<String> = if requested_steps.is_empty() {
        vec![
            "checkroot".to_string(),
            "logcheck".to_string(),
            "checkkernel".to_string(),
            "makedirs".to_string(),
            "boot".to_string(),
            "harden_perms".to_string(),
        ]
    } else {
        let mut out = Vec::with_capacity(requested_steps.len());
        for s in requested_steps {
            out.push(validate_step_id(s)?);
        }
        out
    };

    let _lock = if !dry_run {
        Some(ProvisionLockGuard::acquire(&paths.lock_file)?)
    } else {
        None
    };

    if !dry_run {
        store.ensure_initialized(fresh)?;
    }

    let cleared_for_repair = if is_repair && !dry_run {
        store.clear_steps_for_repair(&target_steps)?
    } else if is_repair {
        target_steps.clone()
    } else {
        Vec::new()
    };

    let catalog_map: BTreeMap<&str, ProvisionStepDescriptor> = canonical_step_catalog()
        .into_iter()
        .map(|d| (d.step_id, d))
        .collect();

    let mut records = Vec::with_capacity(target_steps.len());

    for step_id in &target_steps {
        let desc = catalog_map
            .get(step_id.as_str())
            .ok_or_else(|| CliError::Validation(format!("unknown canonical step {:?}", step_id)))?;

        if !dry_run && !is_repair && store.is_step_done(step_id)? {
            records.push(StepExecutionRecord {
                step_id: step_id.clone(),
                tier: desc.tier,
                status: StepExecutionStatus::SkippedAlreadyDone,
                detail: "already recorded in .aetherflow.state (# STATE_VERSION=2)".to_string(),
            });
            continue;
        }

        match desc.tier {
            ProvisionStepTier::RetainedShellBootstrap => {
                records.push(StepExecutionRecord {
                    step_id: step_id.clone(),
                    tier: desc.tier,
                    status: StepExecutionStatus::DeferredToShellBootstrap,
                    detail: format!(
                        "step '{}' is owned by setup/AetherFlow-Setup shell bootstrap; state marker ready for shell resume/repair",
                        step_id
                    ),
                });
            }
            ProvisionStepTier::RustNativeFoundation => {
                if dry_run {
                    records.push(StepExecutionRecord {
                        step_id: step_id.clone(),
                        tier: desc.tier,
                        status: StepExecutionStatus::DryRunPlanned,
                        detail: format!(
                            "would execute Rust-native foundation step: {}",
                            desc.summary
                        ),
                    });
                    continue;
                }

                let detail = execute_single_rust_step(store, step_id, require_root)?;
                store.mark_step_done(step_id)?;
                records.push(StepExecutionRecord {
                    step_id: step_id.clone(),
                    tier: desc.tier,
                    status: StepExecutionStatus::Completed,
                    detail,
                });
            }
        }
    }

    let (_, completed_steps_after) = if dry_run {
        store
            .read_state()
            .unwrap_or((Some(PROVISION_STATE_VERSION), Vec::new()))
    } else {
        store.read_state()?
    };

    Ok(ProvisionRunReport {
        mode: if is_repair {
            "repair".to_string()
        } else {
            "run".to_string()
        },
        dry_run,
        fresh,
        cleared_for_repair,
        records,
        completed_steps_after,
    })
}

pub(super) fn generate_crypto_secret(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // 248 is the largest multiple of 62 <= 256 (62 * 4 = 248); rejection sampling eliminates modulo bias.
    if let Ok(mut f) = File::open("/dev/urandom") {
        use std::io::Read;
        let mut s = String::with_capacity(len);
        let mut buf = [0u8; 64];
        while s.len() < len {
            if f.read_exact(&mut buf).is_err() {
                break;
            }
            for &b in &buf {
                if b < 248 {
                    s.push(CHARSET[(b as usize) % CHARSET.len()] as char);
                    if s.len() == len {
                        return s;
                    }
                }
            }
        }
    }
    // Fallback if /dev/urandom is unavailable on non-Unix platforms
    let mut s = String::with_capacity(len);
    while s.len() < len {
        for &b in Uuid::new_v4().as_bytes() {
            if b < 248 {
                s.push(CHARSET[(b as usize) % CHARSET.len()] as char);
                if s.len() == len {
                    break;
                }
            }
        }
    }
    s
}

fn execute_single_rust_step(
    store: &ProvisionStateStore,
    step_id: &str,
    require_root: bool,
) -> CliResult<String> {
    let paths = store.paths();
    match step_id {
        "bashrc" => {
            let root_dir = paths.fs_root.join("root");
            ensure_dir_no_symlinks(&paths.fs_root, &root_dir, 0o700, "root home dir")?;
            let bashrc_path = root_dir.join(".bashrc");
            ensure_no_symlink_ancestors(&bashrc_path, "root .bashrc")?;
            let export_line = "export PATH=\"/usr/local/bin:$PATH\"\n";
            if !bashrc_path.exists() {
                write_file_atomic_exclusive(
                    &bashrc_path,
                    export_line.as_bytes(),
                    0o640,
                    "root .bashrc",
                )?;
            } else {
                reject_if_symlink(&bashrc_path, "root .bashrc")?;
                let content = fs::read_to_string(&bashrc_path)
                    .map_err(|e| CliError::io(format!("reading {}", bashrc_path.display()), e))?;
                if !content.contains("/usr/local/bin") {
                    let mut updated = content;
                    if !updated.ends_with('\n') {
                        updated.push('\n');
                    }
                    updated.push_str(export_line);
                    write_file_atomic_exclusive(
                        &bashrc_path,
                        updated.as_bytes(),
                        0o640,
                        "root .bashrc",
                    )?;
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&bashrc_path, fs::Permissions::from_mode(0o640))
                            .map_err(|e| {
                                CliError::io(
                                    format!("setting permissions on {}", bashrc_path.display()),
                                    e,
                                )
                            })?;
                    }
                }
            }
            Ok(
                "ensured root/.bashrc exists with mode 0640 and /usr/local/bin PATH export"
                    .to_string(),
            )
        }
        "checkroot" => {
            if require_root && paths.fs_root == Path::new("/") && !is_effective_root_user() {
                return Err(CliError::PrivilegeRequired(
                    "checkroot failed: effective UID is not 0".to_string(),
                ));
            }
            Ok("verified operator privilege and lockfile ownership".to_string())
        }
        "logcheck" => {
            store.ensure_initialized(false)?;
            store.save_config_value("PROVISION_ENGINE", "af-cli-v4")?;
            Ok(format!(
                "initialized state and log under {}",
                paths.install_dir.display()
            ))
        }
        "checkkernel" => {
            ensure_no_symlink_ancestors(&paths.os_release_file, "os-release file")?;
            if paths.os_release_file.is_file() {
                let raw = fs::read_to_string(&paths.os_release_file).map_err(|e| {
                    CliError::io(format!("reading {}", paths.os_release_file.display()), e)
                })?;
                let info = parse_and_validate_os_release(&raw);
                if !info.supported {
                    return Err(CliError::PreflightOrIntegrity(info.support_reason));
                }
                store.save_config_value("DISTRO_ID", &info.distro_id)?;
                store.save_config_value("DISTRO_VERSION_ID", &info.version_id)?;
                Ok(info.support_reason)
            } else {
                Ok(
                    "no /etc/os-release in isolated root; skipped kernel/distro rejection"
                        .to_string(),
                )
            }
        }
        "hostname" => {
            let config_map = store.read_config_map()?;
            let hostname_val = config_map
                .get("hostname_value")
                .or_else(|| config_map.get("domain"))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("localhost")
                .to_string();

            let etc_dir = paths.fs_root.join("etc");
            ensure_dir_no_symlinks(&paths.fs_root, &etc_dir, 0o755, "etc dir")?;
            let etc_hostname = etc_dir.join("hostname");
            ensure_no_symlink_ancestors(&etc_hostname, "etc hostname")?;
            write_file_atomic_exclusive(
                &etc_hostname,
                format!("{}\n", hostname_val).as_bytes(),
                0o644,
                "etc hostname",
            )?;

            store.save_config_value("HOSTNAME_CONFIGURED", "true")?;
            Ok(format!(
                "configured hostname '{}' and recorded HOSTNAME_CONFIGURED=true",
                hostname_val
            ))
        }
        "locale" => {
            let etc_default = paths.fs_root.join("etc/default");
            ensure_dir_no_symlinks(&paths.fs_root, &etc_default, 0o755, "etc default dir")?;
            let locale_file = etc_default.join("locale");
            ensure_no_symlink_ancestors(&locale_file, "etc/default/locale")?;
            let body = b"LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\n";
            write_file_atomic_exclusive(&locale_file, body, 0o644, "etc/default/locale")?;
            Ok(
                "wrote etc/default/locale with LANG=en_US.UTF-8 and LC_ALL=en_US.UTF-8 (0644)"
                    .to_string(),
            )
        }
        "skel" => {
            let skel_subdirs = [
                paths.fs_root.join("etc/skel/Media"),
                paths.fs_root.join("etc/skel/torrents/rtorrent"),
                paths.fs_root.join("etc/skel/torrents/deluge"),
                paths.fs_root.join("etc/skel/torrents/qbittorrent"),
            ];
            for dir in &skel_subdirs {
                ensure_dir_no_symlinks(&paths.fs_root, dir, 0o750, "user skel directory")?;
            }
            Ok("created canonical user skeleton directories under etc/skel".to_string())
        }
        "apachesudo" => {
            let sudoers_d = paths.fs_root.join("etc/sudoers.d");
            ensure_no_symlink_ancestors(&sudoers_d, "etc/sudoers.d")?;
            if sudoers_d.is_dir() {
                let entries = fs::read_dir(&sudoers_d).map_err(|e| {
                    CliError::io(format!("reading directory {}", sudoers_d.display()), e)
                })?;
                for entry in entries {
                    let entry = entry.map_err(|e| {
                        CliError::io(format!("reading entry in {}", sudoers_d.display()), e)
                    })?;
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if name_str.starts_with("aether") {
                        let target = entry.path();
                        ensure_no_symlink_ancestors(&target, "legacy sudoers file")?;
                        if target.is_file() || target.is_symlink() {
                            fs::remove_file(&target).map_err(|e| {
                                CliError::io(
                                    format!("removing legacy sudoers file {}", target.display()),
                                    e,
                                )
                            })?;
                        }
                    }
                }
            }
            provision_apache_htpasswd_if_configured(store)?;
            store.save_config_value("SUDOERS_HARDENED", "true")?;
            Ok(
                "purged legacy /etc/sudoers.d/aether* files and recorded SUDOERS_HARDENED=true"
                    .to_string(),
            )
        }
        "build_modern" => {
            let env_path = paths.fs_root.join("etc/aetherflow/aetherflow.env");
            ensure_no_symlink_ancestors(&env_path, "etc/aetherflow/aetherflow.env")?;
            if env_path.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).map_err(
                        |e| {
                            CliError::io(
                                format!("setting permissions on {}", env_path.display()),
                                e,
                            )
                        },
                    )?;
                }
                Ok("preserved existing /etc/aetherflow/aetherflow.env with 0600 mode".to_string())
            } else {
                let etc_af = paths.fs_root.join("etc/aetherflow");
                ensure_dir_no_symlinks(&paths.fs_root, &etc_af, 0o750, "etc aetherflow dir")?;

                let aes_key = generate_crypto_secret(32);
                let jwt_secret = generate_crypto_secret(64);

                let env_content = format!(
                    "AES_MASTER_KEY={aes_key}\n\
                     JWT_SECRET={jwt_secret}\n\
                     PORT=8080\n\
                     BIND_ADDR=0.0.0.0\n\
                     ALLOWED_HOSTS=localhost,127.0.0.1\n\
                     ALLOWED_CORS_ORIGIN=http://localhost:8080,http://127.0.0.1:8080\n\
                     AF_DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\n\
                     DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\n\
                     AETHERFLOW_DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\n\
                     AETHERFLOW_RUNNER_SOCK=/run/aetherflow/runner.sock\n\
                     PRIVILEGED_RUNNER_ENABLED=true\n\
                     COOKIE_SECURE=false\n\
                     AETHERFLOW_ENV=production\n"
                );

                write_file_atomic_exclusive(
                    &env_path,
                    env_content.as_bytes(),
                    0o600,
                    "etc/aetherflow/aetherflow.env",
                )?;
                Ok("generated /etc/aetherflow/aetherflow.env with cryptographic keys and 0600 mode".to_string())
            }
        }
        "makedirs" => {
            ensure_install_dir_secure(&paths.fs_root, &paths.install_dir)?;
            let dirs = [
                &paths.etc_aetherflow,
                &paths.etc_legacy_aetherflow,
                &paths.var_lib_aetherflow,
                &paths.var_lib_backups,
                &paths.var_log_aetherflow,
            ];
            for dir in dirs {
                ensure_dir_no_symlinks(&paths.fs_root, dir, 0o750, "FHS directory")?;
            }
            for dir in [
                &paths.opt_aetherflow,
                &paths.opt_releases,
                &paths.etc_systemd_system,
            ] {
                ensure_dir_no_symlinks(
                    &paths.fs_root,
                    dir,
                    0o755,
                    "executable or shared FHS directory",
                )?;
            }
            Ok("created canonical bare-metal FHS directories".to_string())
        }
        "boot" => {
            ensure_dir_no_symlinks(
                &paths.fs_root,
                &paths.etc_systemd_system,
                0o755,
                "systemd unit dir",
            )?;
            // `aetherflow-api.service` owns its tailored sandboxing (GPU DeviceAllow, ProtectProc=default,
            // ProcSubset=all, UMask=0027) and is exempt from `10-aetherflow-sandbox.conf`.
            // Clean up any stale drop-in left behind by an older provisioner before reloading systemd.
            let dropin_dir = paths.etc_systemd_system.join("aetherflow-api.service.d");
            ensure_no_symlink_ancestors(&dropin_dir, "systemd dropin dir")?;
            let mut removed_stale = false;
            if dropin_dir.is_dir() {
                let stale_dropin = dropin_dir.join("10-aetherflow-sandbox.conf");
                if fs::symlink_metadata(&stale_dropin).is_ok() {
                    fs::remove_file(&stale_dropin).map_err(|e| {
                        CliError::io(
                            format!("removing stale sandbox drop-in {}", stale_dropin.display()),
                            e,
                        )
                    })?;
                    removed_stale = true;
                }
                let stale_sidecar = dropin_dir.join("10-aetherflow-sandbox.conf.aetherflow-sha256");
                if fs::symlink_metadata(&stale_sidecar).is_ok() {
                    let _ = fs::remove_file(&stale_sidecar);
                }
            }
            if paths.fs_root == Path::new("/") && Path::new("/run/systemd/system").is_dir() {
                let output = std::process::Command::new("systemctl")
                    .arg("daemon-reload")
                    .output()
                    .map_err(|e| CliError::io("running systemctl daemon-reload", e))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    return Err(CliError::Execution(format!(
                        "systemctl daemon-reload failed ({}): {}",
                        output.status, stderr
                    )));
                }
            }
            if removed_stale {
                Ok(format!(
                    "verified {} and removed stale aetherflow-api.service.d/10-aetherflow-sandbox.conf",
                    paths.etc_systemd_system.display()
                ))
            } else {
                Ok(format!(
                    "verified systemd unit directory {} (aetherflow-api.service exempt from 10-aetherflow-sandbox.conf)",
                    paths.etc_systemd_system.display()
                ))
            }
        }
        "harden_perms" => {
            if paths.install_dir.is_dir() {
                ensure_install_dir_secure(&paths.fs_root, &paths.install_dir)?;
            }
            provision_apache_htpasswd_if_configured(store)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for (dir, mode) in [
                    (&paths.etc_aetherflow, 0o750u32),
                    (&paths.var_lib_aetherflow, 0o750u32),
                    (&paths.var_lib_backups, 0o750u32),
                    (&paths.var_log_aetherflow, 0o750u32),
                ] {
                    if dir.is_dir() {
                        ensure_no_symlink_ancestors(dir, "harden_perms directory")?;
                        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
                    }
                }
                for file in [&paths.state_file, &paths.config_file, &paths.install_log] {
                    if file.is_file() {
                        ensure_no_symlink_ancestors(file, "harden_perms file")?;
                        enforce_root_private_file_perms(file);
                    }
                }
            }
            // Write a deterministic sha256 verification stamp of the state header
            let mut hasher = Sha256::new();
            hasher.update(STATE_VERSION_HEADER.as_bytes());
            let stamp = hex::encode(hasher.finalize());
            store.save_config_value("HARDEN_PERMS_STAMP", &stamp[..16])?;
            Ok("applied directory and state file permission hardening".to_string())
        }
        "perms" => {
            let env_path = paths.fs_root.join("etc/aetherflow/aetherflow.env");
            if env_path.is_file() {
                ensure_no_symlink_ancestors(&env_path, "etc/aetherflow/aetherflow.env")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).map_err(
                        |e| {
                            CliError::io(
                                format!("setting permissions on {}", env_path.display()),
                                e,
                            )
                        },
                    )?;
                }
            }
            let var_lib = paths.fs_root.join("var/lib/aetherflow");
            if var_lib.exists() {
                ensure_no_symlink_ancestors(&var_lib, "var_lib_aetherflow")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&var_lib, fs::Permissions::from_mode(0o700)).map_err(
                        |e| {
                            CliError::io(format!("setting permissions on {}", var_lib.display()), e)
                        },
                    )?;
                }
            } else {
                ensure_dir_no_symlinks(&paths.fs_root, &var_lib, 0o700, "var_lib_aetherflow")?;
            }
            Ok("normalized permissions on /etc/aetherflow/aetherflow.env (0600) and /var/lib/aetherflow (0700)".to_string())
        }
        "bbr" => {
            let tuning_report = apply_network_tuning(&paths.fs_root, false)?;
            Ok(format!(
                "applied sysctl network tuning to {}",
                tuning_report.config_path.display()
            ))
        }
        other => Err(CliError::Unsupported {
            operation: format!("provision step {}", other),
            reason: "step is retained in setup/AetherFlow-Setup shell bootstrap".to_string(),
        }),
    }
}
