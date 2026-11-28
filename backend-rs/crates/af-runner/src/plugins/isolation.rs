use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use uuid::Uuid;

use crate::{lookup_passwd_uid_reentrant, RunnerPeerCred};

use super::manifest::{
    validate_plugin_token, validate_systemd_path_value, ResolvedPluginStart, VerifiedPluginSpec,
};
use super::{
    using_custom_systemd_run_override, PluginRunnerError, PLUGIN_APP_MOUNT_POINT,
    PLUGIN_TOKEN_FILE_IN_SANDBOX, PLUGIN_TOKEN_MOUNT_POINT,
};

#[cfg(unix)]
fn ensure_private_root_dir(dir: &Path, mode: u32) -> Result<(), PluginRunnerError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                PluginRunnerError::Runtime(format!(
                    "Failed to create parent directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }
    match fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to create directory '{}': {}",
                dir.display(),
                err
            )));
        }
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| {
        PluginRunnerError::Runtime(format!("Failed to stat '{}': {}", dir.display(), e))
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(PluginRunnerError::Runtime(format!(
            "Unsafe non-directory or symlink at '{}'",
            dir.display()
        )));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(PluginRunnerError::Runtime(format!(
            "Directory '{}' is owned by uid={}, expected runner uid={}",
            dir.display(),
            meta.uid(),
            euid
        )));
    }
    if (meta.mode() & 0o777) != mode {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|e| {
            PluginRunnerError::Runtime(format!(
                "Failed to enforce mode {:o} on '{}': {}",
                mode,
                dir.display(),
                e
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_root_dir(_dir: &Path, _mode: u32) -> Result<(), PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(
        "Managed plugin token isolation requires Unix".to_string(),
    ))
}

#[cfg(unix)]
pub(super) fn write_staged_plugin_token(
    tokens_root: &Path,
    plugin_id: &str,
    runtime_id: &str,
    token: &str,
    must_exist: bool,
) -> Result<PathBuf, PluginRunnerError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    validate_plugin_token(token)?;
    ensure_private_root_dir(tokens_root, 0o700)?;
    let plugin_dir = tokens_root.join(plugin_id);
    ensure_private_root_dir(&plugin_dir, 0o700)?;

    // Prune stale runtime directories when launching a fresh runtime instance.
    if !must_exist {
        if let Ok(entries) = fs::read_dir(&plugin_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_str() != Some(runtime_id) {
                    let path = entry.path();
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        if meta.is_dir() && !meta.file_type().is_symlink() {
                            let _ = fs::remove_dir_all(&path);
                        } else {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
        }
    }

    let runtime_dir = plugin_dir.join(runtime_id);
    if must_exist {
        let meta = fs::symlink_metadata(&runtime_dir).map_err(|_| {
            PluginRunnerError::InvalidRequest(
                "Active plugin runtime token directory does not exist".to_string(),
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(PluginRunnerError::Runtime(
                "Unsafe plugin runtime token directory".to_string(),
            ));
        }
    }
    ensure_private_root_dir(&runtime_dir, 0o755)?;

    let token_path = runtime_dir.join("runtime.token");
    let temp_path = runtime_dir.join(format!(".runtime-{}.tmp", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| {
            PluginRunnerError::Runtime(format!("Failed to stage plugin token file: {}", e))
        })?;
    let write_res = file
        .write_all(token.as_bytes())
        .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o444)))
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temp_path, &token_path));
    if let Err(err) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(PluginRunnerError::Runtime(format!(
            "Failed to publish plugin token file: {}",
            err
        )));
    }
    Ok(runtime_dir)
}

#[cfg(not(unix))]
pub(super) fn write_staged_plugin_token(
    _tokens_root: &Path,
    _plugin_id: &str,
    _runtime_id: &str,
    _token: &str,
    _must_exist: bool,
) -> Result<PathBuf, PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(
        "Managed plugin token isolation requires Unix".to_string(),
    ))
}

pub(super) fn cleanup_plugin_tokens(tokens_root: &Path, plugin_id: &str) {
    let plugin_dir = tokens_root.join(plugin_id);
    if let Ok(meta) = fs::symlink_metadata(&plugin_dir) {
        if !meta.file_type().is_symlink() && meta.is_dir() {
            let _ = fs::remove_dir_all(&plugin_dir);
        }
    }
}

pub(super) fn ensure_host_mountpoints() -> Result<(), PluginRunnerError> {
    if using_custom_systemd_run_override() {
        return Ok(());
    }
    ensure_private_root_dir(Path::new(PLUGIN_APP_MOUNT_POINT), 0o555)?;
    ensure_private_root_dir(Path::new(PLUGIN_TOKEN_MOUNT_POINT), 0o555)?;
    Ok(())
}

fn is_critical_os_root(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "/" | "/bin"
                | "/dev"
                | "/etc"
                | "/lib"
                | "/lib64"
                | "/opt"
                | "/proc"
                | "/run"
                | "/sbin"
                | "/sys"
                | "/tmp"
                | "/usr"
                | "/var"
                | "/var/lib"
                | "/var/log"
                | "/var/tmp"
        )
    )
}

pub(super) fn collect_transcode_runtime_paths_in(run_dir: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from(crate::peer_transcode::DEFAULT_DISPATCHER_RUNTIME_DIR),
        PathBuf::from(crate::peer_transcode::DEFAULT_WORKER_RUNTIME_DIR),
    ];
    // systemd `InaccessiblePaths=` does not expand shell globs, so mask both
    // canonical transcode runtime directories plus any live `/run/aetherflow-transcode*`
    // sibling entries present under `run_dir` (`SEC-09`).
    if let Ok(entries) = fs::read_dir(run_dir) {
        for entry in entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("aetherflow-transcode"))
            })
            .take(64)
        {
            let path = entry.path();
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    paths
}

pub(super) fn collect_control_plane_inaccessible_paths(
    canon_plugin_dir: &Path,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Vec<String> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/var/lib/aetherflow"),
        PathBuf::from("/etc/aetherflow"),
        PathBuf::from("/etc/AetherFlow"),
        PathBuf::from("/run/aetherflow"),
        PathBuf::from("/var/log/aetherflow"),
        PathBuf::from("/opt/AetherFlow/backend"),
        PathBuf::from("/opt/AetherFlow/current/backend"),
    ];
    candidates.extend(collect_transcode_runtime_paths_in(Path::new("/run")));

    for key in [
        "DATA_DIR",
        "AETHERFLOW_BACKUP_DIR",
        "AF_BACKUP_DIR",
        "BACKUP_DIR",
    ] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                candidates.push(PathBuf::from(trimmed));
            }
        }
    }

    for key in [
        "DB_PATH",
        "AETHERFLOW_DB_PATH",
        "AF_DB_PATH",
        "AETHERFLOW_RUNNER_SOCK",
        "AETHERFLOW_ENV_FILE",
        "AF_TRANSCODE_SOCKET",
        "AF_TRANSCODE_WORKER_SOCKET",
    ] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                if let Some(parent) = p.parent() {
                    if !is_critical_os_root(parent) {
                        candidates.push(parent.to_path_buf());
                    } else {
                        candidates.push(p);
                    }
                }
            }
        }
    }

    let mut result = BTreeSet::new();
    // Mask the host token staging root when it sorts strictly after the token mount
    // destination (avoiding systemd mount-order collisions) while keeping host 0700 DAC.
    let canon_tokens_root =
        fs::canonicalize(tokens_root).unwrap_or_else(|_| tokens_root.to_path_buf());
    if !is_critical_os_root(&canon_tokens_root)
        && !canon_plugin_dir.starts_with(&canon_tokens_root)
        && canon_tokens_root
            .to_str()
            .is_some_and(|s| s > PLUGIN_TOKEN_MOUNT_POINT)
    {
        if let Ok(validated) = validate_systemd_path_value(&canon_tokens_root, "tokens root") {
            result.insert(validated);
        }
    }
    for raw in candidates {
        let candidate = fs::canonicalize(&raw).unwrap_or(raw);
        if is_critical_os_root(&candidate) {
            continue;
        }
        let overlaps_plugin = canon_plugin_dir.starts_with(&candidate);
        let overlaps_token = runtime_token_dir.is_some_and(|td| td.starts_with(&candidate));
        if overlaps_plugin || overlaps_token {
            // If an operator staged data and plugins under the same parent, still mask
            // specific control-plane subpaths that cannot contain this plugin.
            for child in [
                "aetherflow.sqlite",
                "aetherflow.sqlite-wal",
                "aetherflow.sqlite-shm",
                "mcbrowser",
                "backups",
                "plugin-tokens",
                "aetherflow.env",
            ] {
                let sub = candidate.join(child);
                if !canon_plugin_dir.starts_with(&sub)
                    && !runtime_token_dir.is_some_and(|td| td.starts_with(&sub))
                {
                    if let Ok(validated) = validate_systemd_path_value(&sub, "inaccessible path") {
                        result.insert(validated);
                    }
                }
            }
            continue;
        }
        if let Ok(validated) = validate_systemd_path_value(&candidate, "inaccessible path") {
            result.insert(validated);
        }
    }

    // Also mask sibling plugin directories inside the same plugins root so a managed
    // plugin cannot inspect other plugins' static assets.
    if let Some(plugins_root) = canon_plugin_dir.parent() {
        if let Ok(entries) = fs::read_dir(plugins_root) {
            for entry in entries.flatten().take(64) {
                let sibling = entry.path();
                if sibling == canon_plugin_dir {
                    continue;
                }
                if let Ok(meta) = fs::symlink_metadata(&sibling) {
                    if !meta.file_type().is_symlink() && meta.is_dir() {
                        if let Ok(validated) =
                            validate_systemd_path_value(&sibling, "sibling plugin path")
                        {
                            result.insert(validated);
                        }
                    }
                }
            }
        }
    }

    result.into_iter().collect()
}

fn push_common_isolation_properties(
    args: &mut Vec<String>,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: Option<&str>,
    api_base_url: &str,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Result<(), PluginRunnerError> {
    let plugin_dir_str = validate_systemd_path_value(&spec.plugin_dir, "plugin directory")?;
    let state_dir_name = format!("aetherflow-plugin-{}", spec.id);
    let state_dir_path = format!("/var/lib/{state_dir_name}");

    args.extend([
        "--property=DynamicUser=yes".to_string(),
        "--property=SupplementaryGroups=".to_string(),
        "--property=UMask=0077".to_string(),
        "--property=NoNewPrivileges=yes".to_string(),
        "--property=CapabilityBoundingSet=".to_string(),
        "--property=AmbientCapabilities=".to_string(),
        "--property=ProtectSystem=strict".to_string(),
        "--property=ProtectHome=yes".to_string(),
        "--property=PrivateTmp=yes".to_string(),
        "--property=PrivateDevices=yes".to_string(),
        "--property=ProtectClock=yes".to_string(),
        "--property=ProtectControlGroups=yes".to_string(),
        "--property=ProtectKernelLogs=yes".to_string(),
        "--property=ProtectKernelModules=yes".to_string(),
        "--property=ProtectKernelTunables=yes".to_string(),
        "--property=ProtectProc=invisible".to_string(),
        "--property=ProcSubset=all".to_string(),
        "--property=RemoveIPC=yes".to_string(),
        "--property=LockPersonality=yes".to_string(),
        "--property=RestrictNamespaces=yes".to_string(),
        "--property=RestrictRealtime=yes".to_string(),
        "--property=RestrictSUIDSGID=yes".to_string(),
        "--property=SystemCallArchitectures=native".to_string(),
        "--property=SystemCallFilter=@system-service".to_string(),
        "--property=SystemCallFilter=~@privileged @mount @debug @obsolete @cpu-emulation"
            .to_string(),
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_string(),
        "--property=SocketBindDeny=any".to_string(),
        format!("--property=SocketBindAllow=ipv4:tcp:{port}"),
        "--property=IPAddressDeny=any".to_string(),
        "--property=IPAddressAllow=localhost".to_string(),
        "--property=StandardInput=null".to_string(),
        "--property=StandardOutput=null".to_string(),
        "--property=StandardError=null".to_string(),
        format!("--property=SyslogIdentifier=aetherflow-plugin-{}", spec.id),
        format!("--property=StateDirectory={state_dir_name}"),
        "--property=StateDirectoryMode=0700".to_string(),
        format!("--property=BindReadOnlyPaths={plugin_dir_str}:{PLUGIN_APP_MOUNT_POINT}"),
        format!("--property=WorkingDirectory={PLUGIN_APP_MOUNT_POINT}"),
    ]);

    if let Some(token_dir) = runtime_token_dir {
        let token_dir_str = validate_systemd_path_value(token_dir, "plugin token directory")?;
        args.push(format!(
            "--property=BindReadOnlyPaths={token_dir_str}:{PLUGIN_TOKEN_MOUNT_POINT}"
        ));
    }

    for inaccessible in
        collect_control_plane_inaccessible_paths(&spec.plugin_dir, runtime_token_dir, tokens_root)
    {
        args.push(format!("--property=InaccessiblePaths=-{inaccessible}"));
    }

    // Explicitly pass only sanitized non-secret environment variables.
    args.extend([
        "--setenv=PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
        format!("--setenv=PLUGIN_ID={}", spec.id),
        format!("--setenv=PLUGIN_NAME={}", spec.name),
        format!("--setenv=PLUGIN_VERSION={}", spec.version),
        "--setenv=PLUGIN_BIND_ADDR=127.0.0.1".to_string(),
        format!("--setenv=PLUGIN_PORT={port}"),
        format!("--setenv=PORT={port}"),
        format!("--setenv=AETHERFLOW_API_BASE_URL={api_base_url}"),
        format!("--setenv=PLUGIN_STATE_DIR={state_dir_path}"),
        format!("--setenv=AETHERFLOW_PLUGIN_STATE_DIR={state_dir_path}"),
        format!("--setenv=HOME={state_dir_path}"),
        "--setenv=TMPDIR=/tmp".to_string(),
    ]);
    if let Some(rid) = runtime_id {
        args.push(format!("--setenv=AETHERFLOW_PLUGIN_RUNTIME_ID={rid}"));
    }
    if runtime_token_dir.is_some() {
        args.push(format!(
            "--setenv=AETHERFLOW_PLUGIN_TOKEN_FILE={PLUGIN_TOKEN_FILE_IN_SANDBOX}"
        ));
    }

    Ok(())
}

pub(super) fn build_plugin_start_systemd_run_args(
    unit_name: &str,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: &str,
    api_base_url: &str,
    runtime_token_dir: &Path,
    tokens_root: &Path,
) -> Result<Vec<String>, PluginRunnerError> {
    let start_target = spec.start_target.as_ref().ok_or_else(|| {
        PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no managed backend executable or on_start hook",
            spec.id
        ))
    })?;

    let mut args = vec![
        "--no-ask-password".to_string(),
        format!("--unit={unit_name}"),
        format!(
            "--description=AetherFlow Isolated Plugin Backend ({})",
            spec.id
        ),
        "--collect".to_string(),
        "--quiet".to_string(),
        "--property=Type=exec".to_string(),
        "--property=Restart=no".to_string(),
        "--property=KillMode=control-group".to_string(),
        "--property=KillSignal=SIGTERM".to_string(),
        "--property=TimeoutStopSec=10s".to_string(),
    ];

    push_common_isolation_properties(
        &mut args,
        spec,
        port,
        Some(runtime_id),
        api_base_url,
        Some(runtime_token_dir),
        tokens_root,
    )?;

    if let Some(stop_rel) = &spec.stop_hook_rel {
        args.push(format!(
            "--property=ExecStop=/bin/bash {PLUGIN_APP_MOUNT_POINT}/{stop_rel}"
        ));
    }

    args.push("--".to_string());
    match start_target {
        ResolvedPluginStart::Binary(rel) => {
            args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{rel}"));
        }
        ResolvedPluginStart::BashHook(rel) => {
            args.push("/bin/bash".to_string());
            args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{rel}"));
        }
    }

    Ok(args)
}

pub(super) fn build_plugin_stop_hook_systemd_run_args(
    stop_unit_name: &str,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: Option<&str>,
    api_base_url: &str,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Result<Vec<String>, PluginRunnerError> {
    let stop_rel = spec.stop_hook_rel.as_ref().ok_or_else(|| {
        PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no lifecycle_hooks.on_stop hook",
            spec.id
        ))
    })?;

    let mut args = vec![
        "--no-ask-password".to_string(),
        format!("--unit={stop_unit_name}"),
        format!(
            "--description=AetherFlow Isolated Plugin Stop Hook ({})",
            spec.id
        ),
        "--wait".to_string(),
        "--collect".to_string(),
        "--quiet".to_string(),
        "--property=Type=oneshot".to_string(),
        "--property=Restart=no".to_string(),
        "--property=KillMode=control-group".to_string(),
        "--property=KillSignal=SIGTERM".to_string(),
        "--property=TimeoutStartSec=5s".to_string(),
        "--property=TimeoutStopSec=5s".to_string(),
    ];

    push_common_isolation_properties(
        &mut args,
        spec,
        port,
        runtime_id,
        api_base_url,
        runtime_token_dir,
        tokens_root,
    )?;

    args.push("--".to_string());
    args.push("/bin/bash".to_string());
    args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{stop_rel}"));
    Ok(args)
}

#[derive(Debug, Default)]
pub(super) struct UnitShowProps {
    pub(super) active_state: String,
    pub(super) sub_state: String,
    pub(super) main_pid: Option<u32>,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
}

fn parse_optional_u32(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "[not set]" {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "linux")]
fn read_proc_uid_gid(pid: u32) -> (Option<u32>, Option<u32>) {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (None, None);
    };
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .nth(1)
                .or_else(|| rest.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest
                .split_whitespace()
                .nth(1)
                .or_else(|| rest.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok());
        }
    }
    (uid, gid)
}

#[cfg(not(target_os = "linux"))]
fn read_proc_uid_gid(_pid: u32) -> (Option<u32>, Option<u32>) {
    (None, None)
}

#[cfg(unix)]
fn lookup_group_gid_reentrant(group_name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(group_name).ok()?;
    let mut buf_len = 1024usize;
    const MAX_BUF_LEN: usize = 16 * 1024;
    while buf_len <= MAX_BUF_LEN {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; buf_len];
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() {
                return None;
            }
            return Some(grp.gr_gid as u32);
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

pub(super) async fn query_unit_properties(
    systemctl: &Path,
    unit_name: &str,
) -> Result<UnitShowProps, PluginRunnerError> {
    let mut cmd = Command::new(systemctl);
    cmd.args([
        "show",
        "--property=ActiveState",
        "--property=SubState",
        "--property=MainPID",
        "--property=UID",
        "--property=GID",
        unit_name,
    ]);
    let out = crate::bounded_command::output(cmd, Duration::from_secs(5), 64 * 1024)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                PluginRunnerError::Runtime(format!(
                    "systemctl show timed out for plugin unit '{unit_name}'"
                ))
            } else {
                PluginRunnerError::Runtime(format!(
                    "Failed to execute systemctl show for '{unit_name}': {e}"
                ))
            }
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(PluginRunnerError::Runtime(format!(
            "systemctl show failed for '{unit_name}': {}",
            stderr.trim()
        )));
    }
    let mut props = UnitShowProps::default();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "ActiveState" => props.active_state = value.trim().to_string(),
                "SubState" => props.sub_state = value.trim().to_string(),
                "MainPID" => props.main_pid = parse_optional_u32(value).filter(|&p| p > 0),
                "UID" => props.uid = parse_optional_u32(value),
                "GID" => props.gid = parse_optional_u32(value),
                _ => {}
            }
        }
    }
    if (props.uid.is_none() || props.gid.is_none()) && props.main_pid.is_some() {
        if let Some(pid) = props.main_pid {
            let (proc_uid, proc_gid) = read_proc_uid_gid(pid);
            if props.uid.is_none() {
                props.uid = proc_uid;
            }
            if props.gid.is_none() {
                props.gid = proc_gid;
            }
        }
    }
    Ok(props)
}

pub(super) fn verify_isolated_identity(
    props: &UnitShowProps,
    peer: Option<RunnerPeerCred>,
    strict_required: bool,
) -> Result<(), PluginRunnerError> {
    let Some(uid) = props.uid else {
        if strict_required {
            return Err(PluginRunnerError::Runtime(
                "Refusing managed plugin start: isolated systemd unit did not report a verified non-root UID"
                    .to_string(),
            ));
        }
        return Ok(());
    };
    let Some(gid) = props.gid else {
        if strict_required {
            return Err(PluginRunnerError::Runtime(
                "Refusing managed plugin start: isolated systemd unit did not report a verified non-root GID"
                    .to_string(),
            ));
        }
        return Ok(());
    };

    if uid == 0 || gid == 0 {
        return Err(PluginRunnerError::Runtime(format!(
            "Refusing managed plugin start: isolated unit resolved privileged root identity uid={uid} gid={gid}"
        )));
    }

    #[cfg(unix)]
    {
        if let Some(api_uid) = lookup_passwd_uid_reentrant("aetherflow") {
            if uid == api_uid {
                return Err(PluginRunnerError::Runtime(format!(
                    "Refusing managed plugin start: isolated unit uid={uid} matches aetherflow API user"
                )));
            }
        }
        if let Some(api_gid) = lookup_group_gid_reentrant("aetherflow") {
            if gid == api_gid {
                return Err(PluginRunnerError::Runtime(format!(
                    "Refusing managed plugin start: isolated unit gid={gid} matches aetherflow API group"
                )));
            }
        }
    }

    if let Some(cred) = peer {
        if cred.uid != 0 && uid == cred.uid {
            return Err(PluginRunnerError::Runtime(format!(
                "Refusing managed plugin start: isolated unit uid={uid} matches API caller OS uid={}",
                cred.uid
            )));
        }
        if cred.gid != 0 && gid == cred.gid {
            return Err(PluginRunnerError::Runtime(format!(
                "Refusing managed plugin start: isolated unit gid={gid} matches API caller OS gid={}",
                cred.gid
            )));
        }
    }

    Ok(())
}

pub(super) async fn stop_and_reset_unit(
    systemctl: &Path,
    unit_name: &str,
) -> Result<(), PluginRunnerError> {
    let mut stop_cmd = Command::new(systemctl);
    stop_cmd.args(["stop", unit_name]);
    let stop_out = crate::bounded_command::output(stop_cmd, Duration::from_secs(20), 64 * 1024)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                PluginRunnerError::Runtime(format!(
                    "systemctl stop timed out for plugin unit '{unit_name}'"
                ))
            } else {
                PluginRunnerError::Runtime(format!(
                    "Failed to execute systemctl stop for '{unit_name}': {e}"
                ))
            }
        })?;
    if !stop_out.status.success() {
        let stderr = String::from_utf8_lossy(&stop_out.stderr);
        let lower = stderr.to_ascii_lowercase();
        if !lower.contains("not loaded") && !lower.contains("could not be found") {
            return Err(PluginRunnerError::Runtime(format!(
                "systemctl stop failed for '{unit_name}': {}",
                stderr.trim()
            )));
        }
    }
    let mut reset_cmd = Command::new(systemctl);
    reset_cmd.args(["reset-failed", unit_name]);
    let _ = crate::bounded_command::output(reset_cmd, Duration::from_secs(5), 64 * 1024).await;
    Ok(())
}

#[cfg(test)]
mod sec09_tests {
    use super::*;

    #[test]
    fn inaccessible_paths_mask_transcode_runtime_directories() {
        let tmp = env::temp_dir().join(format!("af-plugin-sec09-{}", Uuid::new_v4()));
        let plugin_dir = tmp.join("plugins/demo");
        let token_dir = tmp.join("tokens/demo/rt-1");
        let run_dir = tmp.join("run");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::create_dir_all(&token_dir).unwrap();
        fs::create_dir_all(run_dir.join("aetherflow-transcode-custom")).unwrap();
        fs::create_dir_all(run_dir.join("unrelated-service")).unwrap();

        let paths = collect_control_plane_inaccessible_paths(
            &plugin_dir,
            Some(&token_dir),
            &tmp.join("tokens"),
        );
        assert!(
            paths.iter().any(|p| p == "/run/aetherflow-transcode"),
            "expected /run/aetherflow-transcode in InaccessiblePaths: {paths:?}"
        );
        assert!(
            paths
                .iter()
                .any(|p| p == "/run/aetherflow-transcode-worker"),
            "expected /run/aetherflow-transcode-worker in InaccessiblePaths: {paths:?}"
        );

        let discovered = collect_transcode_runtime_paths_in(&run_dir);
        assert!(discovered.contains(&PathBuf::from("/run/aetherflow-transcode")));
        assert!(discovered.contains(&PathBuf::from("/run/aetherflow-transcode-worker")));
        assert!(discovered.contains(&run_dir.join("aetherflow-transcode-custom")));
        assert!(!discovered.contains(&run_dir.join("unrelated-service")));

        let _ = fs::remove_dir_all(&tmp);
    }
}
