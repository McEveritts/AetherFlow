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
    let command = match if raw_cmd.is_empty() {
        "deploy"
    } else {
        raw_cmd
    } {
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
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("deploy/release-manager.conf"));
            candidates.push(exe_dir.join("../deploy/release-manager.conf"));
        }
    }
    #[cfg(unix)]
    let allow_relative_cwd = unsafe { libc::geteuid() != 0 };
    #[cfg(not(unix))]
    let allow_relative_cwd = true;
    if allow_relative_cwd {
        candidates.push(PathBuf::from("deploy/release-manager.conf"));
        candidates.push(PathBuf::from("../deploy/release-manager.conf"));
    }
    candidates.into_iter().find(|c| c.is_file())
}

pub fn resolve_release_manager_conf() -> Option<PathBuf> {
    resolve_release_manager_conf_for_root(None)
}

fn map_default_release_lock_parent(parent_dir: &Path, isolated_root: Option<&Path>) -> PathBuf {
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
    resolve_maintenance_lock_path_for_config_with_env(cfg, None)
}

pub fn resolve_maintenance_lock_path_for_config_with_env(
    cfg: &ReleaseConfig,
    systemd_env_blob: Option<&str>,
) -> ReleaseResult<PathBuf> {
    let candidate_lock = match std::env::var("AETHERFLOW_MAINTENANCE_LOCK_PATH")
        .ok()
        .map(|raw_val| raw_val.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
    {
        Some(explicit_lock) => PathBuf::from(explicit_lock),
        None if cfg.is_dry_run_config() => cfg.data_dir.join(".snapshot.lock"),
        None => {
            let resolved_db = crate::config::try_resolve_db_path(cfg, systemd_env_blob)?;
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
    let jobs_parent = map_default_release_lock_parent(&cfg.data_dir, cfg.isolated_root.as_deref());
    let jobs_dir = jobs_parent.join(".self-update-jobs");
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
    let cfg =
        ReleaseConfig::load_for_root_from_process_env(explicit_root, resolved_conf.as_deref())?;
    resolve_self_update_jobs_dir_for_config(&cfg)
}

pub fn ensure_interoperable_maintenance_lock_file(cfg: &ReleaseConfig) -> ReleaseResult<PathBuf> {
    ensure_interoperable_maintenance_lock_file_with_env(cfg, None)
}

pub fn ensure_interoperable_maintenance_lock_file_with_env(
    cfg: &ReleaseConfig,
    systemd_env_blob: Option<&str>,
) -> ReleaseResult<PathBuf> {
    let shared_lock_path =
        resolve_maintenance_lock_path_for_config_with_env(cfg, systemd_env_blob)?;
    crate::fs_security::ensure_no_symlink_ancestors(&shared_lock_path)?;

    let parent = shared_lock_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| ReleaseError::PathValidation {
            path: shared_lock_path.clone(),
            reason: "maintenance lock path has no parent directory".to_string(),
        })?;
    let leaf = shared_lock_path
        .file_name()
        .ok_or_else(|| ReleaseError::PathValidation {
            path: shared_lock_path.clone(),
            reason: "maintenance lock path has no filename".to_string(),
        })?;

    let is_runtime_anchor = parent == Path::new("/run/aetherflow")
        || cfg
            .isolated_root
            .as_ref()
            .map(|iso| parent == iso.join("run/aetherflow"))
            .unwrap_or(false);

    #[cfg(not(unix))]
    {
        let _ = (leaf, is_runtime_anchor);
        crate::fs_security::create_dir_all_no_symlinks(parent, 0o750)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        // Pin the parent directory once via component-wise `O_DIRECTORY | O_NOFOLLOW` so every
        // subsequent inspection, ownership update, and lockfile open/create executes strictly via
        // `openat(parent_dfd, leaf)` with zero path-based TOCTOU window.
        let parent_dir = crate::fs_security::open_or_create_dir_nofollow(parent, 0o750)?;
        let parent_dfd = parent_dir.as_raw_fd();
        let leaf_c =
            std::ffi::CString::new(leaf.as_bytes()).map_err(|_| ReleaseError::PathValidation {
                path: shared_lock_path.clone(),
                reason: "maintenance lock filename contains NUL byte".to_string(),
            })?;

        let euid = unsafe { libc::geteuid() };
        let mut parent_uid: libc::uid_t = 0;
        let mut parent_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(parent_dfd, &mut parent_st) } == 0 {
            parent_uid = parent_st.st_uid;
        }
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
            if target_owner.is_none()
                && parent_st.st_uid != 0
                && (parent_st.st_mode & libc::S_ISVTX) == 0
            {
                target_owner = Some((parent_st.st_uid, parent_st.st_gid));
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
                if let Some((_, target_gid)) = target_owner {
                    let _ = unsafe { libc::fchown(parent_dfd, 0, target_gid) };
                }
                let _ = unsafe { libc::fchmod(parent_dfd, 0o750) };
            }
        }

        let open_existing = || unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };

        let (raw_fd, created_fresh) = {
            let mut created = false;
            let mut fd = open_existing();
            if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                fd = unsafe {
                    libc::openat(
                        parent_dfd,
                        leaf_c.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_NONBLOCK
                            | libc::O_CLOEXEC,
                        0o660 as libc::c_uint,
                    )
                };
                if fd >= 0 {
                    created = true;
                } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                    fd = open_existing();
                }
            }
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ELOOP) {
                    return Err(ReleaseError::PathValidation {
                        path: shared_lock_path,
                        reason: "maintenance lockfile is a symbolic link".to_string(),
                    });
                }
                return Err(ReleaseError::io(
                    format!(
                        "initializing shared maintenance lockfile {}",
                        shared_lock_path.display()
                    ),
                    err,
                ));
            }
            (fd, created)
        };
        let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };

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
            if !is_runtime_anchor && parent_uid != 0 && !created_fresh {
                let expected_uid = target_owner.map(|(uid, _)| uid).unwrap_or(parent_uid);
                if st.st_uid == 0 || st.st_uid != expected_uid {
                    return Err(ReleaseError::PathValidation {
                        path: shared_lock_path,
                        reason: format!(
                            "refusing to chown pre-existing file (uid={}) at maintenance lock path inside non-root directory (uid={parent_uid})",
                            st.st_uid
                        ),
                    });
                }
            }
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
            if matches!(env_offline.trim(), "1" | "true" | "TRUE" | "yes" | "YES") {
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

/// Called under the shared maintenance lock by both the launcher and local
/// release engine. API orchestration also covers pre-stop and post-script work;
/// the runner's script lock alone cannot protect those phases.
pub fn ensure_no_active_package_lifecycle_jobs(
    cfg: &ReleaseConfig,
    command: ReleaseCommand,
) -> ReleaseResult<()> {
    ensure_no_active_package_lifecycle_jobs_with_env(cfg, command, None)
}

pub fn ensure_no_active_package_lifecycle_jobs_with_env(
    cfg: &ReleaseConfig,
    command: ReleaseCommand,
    systemd_env_blob: Option<&str>,
) -> ReleaseResult<()> {
    let path = crate::config::try_resolve_db_path(cfg, systemd_env_blob)?.path;
    let mut file = match crate::fs_security::validate_sqlite_file_and_sidecars_nofollow(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(()),
        Err(err) => {
            if command == ReleaseCommand::Rollback {
                return Ok(());
            }
            return Err(err);
        }
    };
    // Reject a corrupt header before opening SQLite: even a read-only WAL
    // connection can rebuild -shm. Explicit recovery must preserve those files
    // until the rollback engine validates its snapshot and quiesces writers.
    let mut header = [0u8; 16];
    use std::io::Read;
    let count = file
        .read(&mut header)
        .map_err(|e| ReleaseError::io("reading lifecycle database header", e))?;
    if count == 0 {
        return Ok(());
    }
    if count != 16 || &header != b"SQLite format 3\0" {
        if command == ReleaseCommand::Rollback {
            return Ok(());
        }
        return Err(ReleaseError::Config(
            "Cannot verify application lifecycle journal: invalid SQLite header".into(),
        ));
    }

    // When `root` inspects a database inside an unprivileged directory (e.g. `aetherflow`-owned
    // `/var/lib/aetherflow`), `open_sqlite_isolated_for_reconcile` copies pinned `O_NOFOLLOW` FDs
    // into a private `0700` root scratch replica (`is_scratch == true`) so `reconcile_jobs_with_options`
    // evaluates real `.lifecycle-owners` locks and checks active rows strictly in-scratch without
    // `root` ever opening live SQLite sidecars (`-wal`/`-shm`/`-journal`) in `/var/lib/aetherflow`.
    let active = (|| -> Result<bool, ReleaseError> {
        let (conn, is_scratch) = crate::fs_security::open_sqlite_isolated_for_reconcile(&path)?;
        let table: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ReleaseError::Snapshot {
                db_path: path.clone(),
                reason: e.to_string(),
            })?;
        if !table {
            return Ok(false);
        }
        crate::lifecycle::reconcile_jobs_with_options(&conn, &path, !is_scratch).map_err(
            |error| ReleaseError::Snapshot {
                db_path: path.clone(),
                reason: error.to_string(),
            },
        )?;
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted'))",
            [],
            |r| r.get(0),
        )
        .map_err(|e| ReleaseError::Snapshot {
            db_path: path.clone(),
            reason: e.to_string(),
        })
    })();
    let active = match active {
        Ok(active) => active,
        Err(ReleaseError::Snapshot { ref reason, .. })
            if command == ReleaseCommand::Rollback
                && (reason.contains("database disk image is malformed")
                    || reason.contains("file is not a database")
                    || reason.contains("DatabaseCorrupt")
                    || reason.contains("NotADatabase")) =>
        {
            false
        }
        Err(ReleaseError::PathValidation { .. }) if command == ReleaseCommand::Rollback => false,
        Err(ReleaseError::Config(msg)) => return Err(ReleaseError::Config(msg)),
        Err(error) => {
            return Err(ReleaseError::Config(format!(
                "Cannot verify application lifecycle journal: {}",
                error
            )));
        }
    };
    if active {
        return Err(ReleaseError::LockBusy {
            lock_path: path,
            reason: "Application lifecycle orchestration is active".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod package_admission_tests {
    use super::*;
    #[test]
    fn durable_api_jobs_block_updates_in_pre_stop_and_post_script_phases() {
        let root = std::env::temp_dir().join(format!("af-api-admission-{}", uuid::Uuid::new_v4()));
        let cfg = ReleaseConfig::for_root(&root);
        let path = crate::config::try_resolve_db_path(&cfg, None).unwrap().path;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE package_lifecycle_jobs(status TEXT); INSERT INTO package_lifecycle_jobs VALUES ('updating');").unwrap();
        assert!(ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Deploy).is_err());
        conn.execute("UPDATE package_lifecycle_jobs SET status='failed'", [])
            .unwrap();
        assert!(ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Deploy).is_ok());
        conn.execute("UPDATE package_lifecycle_jobs SET status='interrupted'", [])
            .unwrap();
        assert!(ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Deploy).is_ok());
        drop(conn);
        std::fs::write(&path, b"corrupt database fixture").unwrap();
        assert!(ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Deploy).is_err());
        assert!(ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Rollback).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
