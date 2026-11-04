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
/// Supports deploy/rollback on stable/nightly; legacy experimental requests migrate to nightly.
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
        "nightly" | "experimental" => ReleaseChannel::Nightly,
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

/// Resolves the default `release-manager.conf` path on the host (or inside `explicit_root` /
/// `AETHERFLOW_RELEASE_ROOT` when an isolated root is active).
pub fn resolve_release_manager_conf_for_root(explicit_root: Option<&Path>) -> Option<PathBuf> {
    if let Ok(explicit_env) = std::env::var("AETHERFLOW_RELEASE_CONF") {
        let trimmed = explicit_env.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    let env_root = std::env::var("AETHERFLOW_RELEASE_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    if let Some(root) = explicit_root
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or(env_root)
    {
        let rooted_candidates = [
            root.join("etc/aetherflow/release-manager.conf"),
            root.join("opt/AetherFlow/current/deploy/release-manager.conf"),
            root.join("opt/AetherFlow/deploy/release-manager.conf"),
            root.join("deploy/release-manager.conf"),
        ];
        return rooted_candidates.into_iter().find(|c| c.is_file());
    }

    let mut candidates = vec![
        PathBuf::from("/etc/aetherflow/release-manager.conf"),
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

pub fn resolve_release_manager_conf() -> Option<PathBuf> {
    resolve_release_manager_conf_for_root(None)
}

fn map_default_release_lock_parent(
    parent_dir: &Path,
    isolated_root: Option<&Path>,
) -> PathBuf {
    if let Some(iso) = isolated_root {
        let iso_var_lib = iso.join("var/lib/aetherflow");
        if parent_dir == iso_var_lib {
            let iso_run = iso.join("run/aetherflow");
            if iso_run.is_dir() {
                return iso_run;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let (Ok(root_meta), Ok(var_meta)) = (
                    std::fs::symlink_metadata(iso),
                    std::fs::symlink_metadata(&iso_var_lib),
                ) {
                    if root_meta.uid() == 0 && var_meta.uid() != 0 {
                        return iso_run;
                    }
                }
            }
        }
        return parent_dir.to_path_buf();
    }
    if parent_dir == Path::new("/var/lib/aetherflow") {
        return PathBuf::from("/run/aetherflow");
    }
    parent_dir.to_path_buf()
}

pub fn resolve_maintenance_lock_path_for_config(cfg: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    let resolved_db = crate::config::try_resolve_db_path(cfg, None)?;
    let candidate_lock = match std::env::var("AETHERFLOW_MAINTENANCE_LOCK_PATH")
        .ok()
        .map(|raw_val| raw_val.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
    {
        Some(explicit_lock) => PathBuf::from(explicit_lock),
        None => {
            if let Some(db_parent) = resolved_db
                .path
                .parent()
                .filter(|parent_val| !parent_val.as_os_str().is_empty())
            {
                map_default_release_lock_parent(db_parent, cfg.isolated_root.as_deref())
                    .join(".snapshot.lock")
            } else {
                map_default_release_lock_parent(&cfg.data_dir, cfg.isolated_root.as_deref())
                    .join(".snapshot.lock")
            }
        }
    };

    crate::config::validate_no_parent_traversal(&candidate_lock, "maintenance lock path")?;
    if let Some(ref root_path) = cfg.isolated_root {
        if !crate::config::path_is_within_root(&candidate_lock, root_path) {
            return Err(ReleaseError::Config(format!(
                "maintenance lock path '{}' escapes isolated release root '{}'",
                candidate_lock.display(),
                root_path.display()
            )));
        }
    }
    Ok(candidate_lock)
}

pub fn resolve_self_update_jobs_dir_for_config(cfg: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    let jobs_dir = cfg.data_dir.join(".self-update-jobs");
    crate::config::validate_no_parent_traversal(&jobs_dir, "self-update jobs directory")?;
    if let Some(ref root_path) = cfg.isolated_root {
        if !crate::config::path_is_within_root(&jobs_dir, root_path) {
            return Err(ReleaseError::Config(format!(
                "self-update jobs directory '{}' escapes isolated release root '{}'",
                jobs_dir.display(),
                root_path.display()
            )));
        }
    }
    Ok(jobs_dir)
}

pub fn resolve_self_update_jobs_dir_from_process_env(
    explicit_root: Option<&Path>,
    conf_override: Option<&Path>,
) -> ReleaseResult<PathBuf> {
    let resolved_conf = conf_override
        .map(Path::to_path_buf)
        .or_else(|| resolve_release_manager_conf_for_root(explicit_root));
    let cfg = ReleaseConfig::load_for_root_from_process_env(explicit_root, resolved_conf.as_deref())?;
    resolve_self_update_jobs_dir_for_config(&cfg)
}

pub fn ensure_interoperable_maintenance_lock_file(cfg: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    let shared_lock_path = resolve_maintenance_lock_path_for_config(cfg)?;
    crate::fs_security::ensure_no_symlink_ancestors(&shared_lock_path)?;

    let is_runtime_anchor = shared_lock_path
        .parent()
        .map(|parent_dir| {
            parent_dir == Path::new("/run/aetherflow")
                || cfg
                    .isolated_root
                    .as_ref()
                    .map(|iso| parent_dir == iso.join("run/aetherflow"))
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    if let Some(parent) = shared_lock_path.parent() {
        if !parent.as_os_str().is_empty() {
            let parent_mode = if is_runtime_anchor { 0o1770 } else { 0o750 };
            crate::fs_security::create_dir_all_no_symlinks(parent, parent_mode)?;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let euid = unsafe { libc::geteuid() };
        let mut target_owner: Option<(libc::uid_t, libc::gid_t)> = None;
        if euid == 0 {
            let uid_env = std::env::var("AETHERFLOW_SERVICE_UID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            let gid_env = std::env::var("AETHERFLOW_SERVICE_GID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            if let (Some(uid_val), Some(gid_val)) = (uid_env, gid_env) {
                target_owner = Some((uid_val as libc::uid_t, gid_val as libc::gid_t));
            }
            if target_owner.is_none() {
                if let Some(parent) = shared_lock_path.parent() {
                    if let Ok(parent_file) = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
                        .open(parent)
                    {
                        let mut pst: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(parent_file.as_raw_fd(), &mut pst) } == 0
                            && pst.st_uid != 0
                            && (pst.st_mode & libc::S_ISVTX) == 0
                        {
                            target_owner = Some((pst.st_uid, pst.st_gid));
                        }
                    }
                }
            }
            if target_owner.is_none() {
                let user_name = std::env::var("AETHERFLOW_SERVICE_USER")
                    .ok()
                    .map(|val| val.trim().to_string())
                    .filter(|val| !val.is_empty())
                    .unwrap_or_else(|| "aetherflow".to_string());
                if let Ok(user_c) = std::ffi::CString::new(user_name) {
                    unsafe {
                        let mut pwd: libc::passwd = std::mem::zeroed();
                        let mut res: *mut libc::passwd = std::ptr::null_mut();
                        let mut buf = vec![0u8; 4096];
                        if libc::getpwnam_r(
                            user_c.as_ptr(),
                            &mut pwd,
                            buf.as_mut_ptr() as *mut libc::c_char,
                            buf.len(),
                            &mut res,
                        ) == 0
                            && !res.is_null()
                        {
                            target_owner = Some((
                                uid_env.unwrap_or(pwd.pw_uid) as libc::uid_t,
                                gid_env.unwrap_or(pwd.pw_gid) as libc::gid_t,
                            ));
                        }
                    }
                }
            }
            if is_runtime_anchor {
                if let Some(parent) = shared_lock_path.parent() {
                    if let Ok(parent_file) = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
                        .open(parent)
                    {
                        let pfd = parent_file.as_raw_fd();
                        if let Some((_, target_gid)) = target_owner {
                            let _ = unsafe { libc::fchown(pfd, 0, target_gid) };
                        }
                        let _ = unsafe { libc::fchmod(pfd, 0o1770) };
                    }
                }
            }
        }

        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&shared_lock_path)
        {
            Ok(existing) => existing,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o660)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&shared_lock_path)
                .map_err(|create_err| {
                    ReleaseError::io(
                        format!(
                            "initializing shared maintenance lockfile {}",
                            shared_lock_path.display()
                        ),
                        create_err,
                    )
                })?,
            Err(err) => {
                return Err(ReleaseError::io(
                    format!(
                        "initializing shared maintenance lockfile {}",
                        shared_lock_path.display()
                    ),
                    err,
                ));
            }
        };

        let fd = file.as_raw_fd();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(ReleaseError::io(
                format!("fstat maintenance lockfile {}", shared_lock_path.display()),
                std::io::Error::last_os_error(),
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(ReleaseError::PathValidation {
                path: shared_lock_path,
                reason: "maintenance lockfile is not a regular file".to_string(),
            });
        }
        if st.st_nlink > 1 {
            return Err(ReleaseError::PathValidation {
                path: shared_lock_path,
                reason: "maintenance lockfile must not have multiple hard links".to_string(),
            });
        }

        if euid == 0 {
            if let Some((target_uid, target_gid)) = target_owner {
                let desired_uid = if is_runtime_anchor { 0 } else { target_uid };
                if unsafe { libc::fchown(fd, desired_uid, target_gid) } != 0 {
                    return Err(ReleaseError::io(
                        format!(
                            "fchown({}:{}) on maintenance lockfile {}",
                            desired_uid,
                            target_gid,
                            shared_lock_path.display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
            }
            if unsafe { libc::fchmod(fd, 0o660) } != 0 {
                return Err(ReleaseError::io(
                    format!(
                        "fchmod(0660) on maintenance lockfile {}",
                        shared_lock_path.display()
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
        } else if st.st_uid == euid
            && (st.st_mode & 0o777) != 0o660
            && unsafe { libc::fchmod(fd, 0o660) } != 0
        {
            return Err(ReleaseError::io(
                format!(
                    "fchmod(0660) on maintenance lockfile {}",
                    shared_lock_path.display()
                ),
                std::io::Error::last_os_error(),
            ));
        }
    }

    Ok(shared_lock_path)
}

/// Executes a validated `ValidatedSelfUpdateRequest` synchronously using a configured `ReleaseEngine`
/// and maps the result into an `af_models::RunnerResponse`.
pub fn execute_self_update_sync(
    req: &ValidatedSelfUpdateRequest,
    config: ReleaseConfig,
) -> (ExitCode, RunnerResponse) {
    if let Err(err) = ensure_interoperable_maintenance_lock_file(&config) {
        return (
            err.exit_code(),
            RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            },
        );
    }
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
    let effective_for_lock = cfg.with_dry_run(opts.dry_run);
    if let Err(e) = ensure_interoperable_maintenance_lock_file(&effective_for_lock) {
        return (e.exit_code(), Err(e));
    }
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
