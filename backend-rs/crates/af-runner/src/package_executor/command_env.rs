use super::*;

// -----------------------------------------------------------------------------
// Pluggable Command Runner (Production OS Commands vs Isolated Test Mock)
// -----------------------------------------------------------------------------

/// Output of an external system command (`apt-get`, `systemctl`, `useradd`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn combined_output(&self) -> String {
        match (self.stdout.trim().is_empty(), self.stderr.trim().is_empty()) {
            (true, true) => String::new(),
            (false, true) => self.stdout.trim().to_string(),
            (true, false) => self.stderr.trim().to_string(),
            (false, false) => format!("{}\n{}", self.stdout.trim(), self.stderr.trim()),
        }
    }
}

/// Recorded command invocation for audit and test verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Abstraction over privileged command execution so tests can run deterministically
/// without mutating the host operating system.
pub trait CommandRunner: Send + Sync {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    >;

    fn run_command_with_stdin<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        stdin_data: &'a [u8],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        let _ = stdin_data;
        self.run_command(program, args, env_vars, cancel)
    }
}

/// Reads from an async pipe up to `max_bytes`, draining any remaining bytes to EOF
/// so the child process never blocks on a full pipe buffer.
async fn read_pipe_bounded<R: tokio::io::AsyncRead + Unpin>(
    mut reader: Option<R>,
    max_bytes: usize,
) -> String {
    use tokio::io::AsyncReadExt;
    let Some(ref mut r) = reader else {
        return String::new();
    };
    let mut retained = Vec::new();
    let mut truncated = false;
    let mut scratch = [0u8; 4096];
    loop {
        match r.read(&mut scratch).await {
            Ok(0) => break,
            Ok(n) => {
                let remaining = max_bytes.saturating_sub(retained.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    retained.extend_from_slice(&scratch[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    let mut out = String::from_utf8_lossy(&retained).into_owned();
    if truncated {
        out.push_str("\n...[output truncated]");
    }
    out
}

/// Terminates a spawned child and its entire Unix process group (`-pgid`), then reaps the child.
/// Polls `child.try_wait()` up to a bounded grace window (default `2500ms`, configurable via
/// `AETHERFLOW_ROLLBACK_GRACE_MS`) after `SIGTERM` so `trap ... TERM EXIT` rollback handlers
/// can restore state cleanly without being cut short by `SIGKILL`.
pub(crate) async fn terminate_child_process_group(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        if pid > 0 {
            let pgid = -(pid as libc::pid_t);
            let grace_ms = env::var("AETHERFLOW_ROLLBACK_GRACE_MS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(2500);
            unsafe {
                let _ = libc::kill(pgid, libc::SIGTERM);
                let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            let deadline = tokio::time::Instant::now() + Duration::from_millis(grace_ms);
            loop {
                if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
                    unsafe {
                        let _ = libc::kill(pgid, libc::SIGKILL);
                    }
                    return;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            unsafe {
                let _ = libc::kill(pgid, libc::SIGKILL);
            }
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

/// Production command runner using `tokio::process::Command` with dedicated process group
/// isolation (`process_group(0)`), bounded output retention, and group-wide cancellation termination.
#[derive(Debug, Clone)]
pub struct TokioCommandRunner {
    pub respect_dry_run_env: bool,
}

impl Default for TokioCommandRunner {
    fn default() -> Self {
        Self {
            respect_dry_run_env: true,
        }
    }
}

#[allow(non_upper_case_globals)]
pub const TokioCommandRunner: TokioCommandRunner = TokioCommandRunner {
    respect_dry_run_env: true,
};

impl CommandRunner for TokioCommandRunner {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        self.run_command_with_stdin(program, args, env_vars, &[], cancel)
    }

    fn run_command_with_stdin<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        env_vars: &'a [(String, String)],
        stdin_data: &'a [u8],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        let stdin_bytes = stdin_data.to_vec();
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(PackageExecutorError::Cancelled(program.to_string()));
            }

            let force_real = env::var("AETHERFLOW_TEST_REAL_COMMAND_RUNNER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let dry_run = self.respect_dry_run_env
                && env::var("AETHERFLOW_PACKAGE_DRY_RUN")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            if (dry_run || !cfg!(target_os = "linux")) && !force_real {
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("[dry-run] {} {}", program, args.join(" ")),
                    stderr: String::new(),
                });
            }

            let mut cmd = Command::new(program);
            cmd.args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            if stdin_bytes.is_empty() {
                cmd.stdin(Stdio::null());
            } else {
                cmd.stdin(Stdio::piped());
            }

            #[cfg(unix)]
            cmd.process_group(0);
            for (k, v) in env_vars {
                cmd.env(k, v);
            }

            #[cfg(unix)]
            if let Ok(result) = crate::PACKAGE_MAINTENANCE_LEASE
                .try_with(|guard| guard.preserve_in_child(cmd.as_std_mut()))
            {
                result.map_err(PackageExecutorError::Io)?;
            }

            let mut child = cmd.spawn().map_err(|e| PackageExecutorError::StepFailed {
                step: program.to_string(),
                reason: format!("failed to spawn {}: {}", program, e),
            })?;

            if !stdin_bytes.is_empty() {
                if let Some(mut stdin_pipe) = child.stdin.take() {
                    let to_write = stdin_bytes.clone();
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let _ = stdin_pipe.write_all(&to_write).await;
                        let _ = stdin_pipe.flush().await;
                        drop(stdin_pipe);
                    });
                }
            }

            #[cfg(unix)]
            let child_pgid = child.id();

            let stdout_pipe = child.stdout.take();
            let stderr_pipe = child.stderr.take();

            let mut out_task = tokio::spawn(async move {
                read_pipe_bounded(stdout_pipe, MAX_COMMAND_OUTPUT_BYTES).await
            });
            let mut err_task = tokio::spawn(async move {
                read_pipe_bounded(stderr_pipe, MAX_COMMAND_OUTPUT_BYTES).await
            });

            loop {
                tokio::select! {
                    status_res = child.wait() => {
                        let status = status_res.map_err(|e| PackageExecutorError::StepFailed {
                            step: program.to_string(),
                            reason: e.to_string(),
                        })?;
                        // Ensure any background descendants in the process group holding pipes open are reaped
                        let stdout = match tokio::time::timeout(Duration::from_millis(250), &mut out_task).await {
                            Ok(res) => res.unwrap_or_default(),
                            Err(_) => {
                                #[cfg(unix)]
                                if let Some(pid) = child_pgid {
                                    if pid > 0 {
                                        unsafe {
                                            let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                                        }
                                    }
                                }
                                out_task.abort();
                                String::new()
                            }
                        };
                        let stderr = match tokio::time::timeout(Duration::from_millis(250), &mut err_task).await {
                            Ok(res) => res.unwrap_or_default(),
                            Err(_) => {
                                err_task.abort();
                                String::new()
                            }
                        };
                        return Ok(CommandOutput {
                            exit_code: status.code().unwrap_or(if status.success() { 0 } else { 1 }),
                            stdout,
                            stderr,
                        });
                    }
                    _ = tokio::time::sleep(Duration::from_millis(30)) => {
                        if cancel.is_cancelled() {
                            terminate_child_process_group(&mut child).await;
                            out_task.abort();
                            err_task.abort();
                            let _ = out_task.await;
                            let _ = err_task.await;
                            return Err(PackageExecutorError::Cancelled(program.to_string()));
                        }
                    }
                }
            }
        })
    }
}

// -----------------------------------------------------------------------------
// Execution Environment & Path Sandboxing
// -----------------------------------------------------------------------------

/// Trusted persistent recovery root for privileged root-run marketplace updates.
/// Kept outside `/tmp` and `/var/tmp` so rollback material remains accessible to
/// operators and survives systemd `PrivateTmp=yes` restarts.
pub const DEFAULT_PRIVILEGED_RECOVERY_ROOT: &str = "/var/backups/aetherflow-recovery";

/// Execution context and filesystem root configuration for [`DeclarativePackageExecutor`].
#[derive(Debug, Clone)]
pub struct PackageExecutionEnv {
    pub lifecycle_job_id: String,
    /// Optional root prefix for isolated testing (`AETHERFLOW_FS_ROOT`). Empty/`/` in production.
    pub fs_root: Option<PathBuf>,
    /// Directory for package lock files (`/install` by default).
    pub lock_dir: PathBuf,
    /// Directory for package installer logs (`/var/log/aetherflow` by default).
    pub log_dir: PathBuf,
    /// Disposable download/staging directory (`/var/tmp` or `TMPDIR` by default).
    pub temp_dir: PathBuf,
    /// Optional persistent recovery backup root (`AETHERFLOW_RECOVERY_ROOT` / `AF_RECOVERY_ROOT`).
    /// Distinct from disposable download/staging (`temp_dir`, `scratch_root`).
    pub recovery_root: Option<PathBuf>,
    /// Override architecture (`amd64`, `arm64`, `armhf`) or auto-detected at runtime.
    pub arch_override: Option<String>,
    /// Allocated application port (`1024..=65535` or `0`).
    pub app_port: i32,
    /// Optional explicit Rclone RC API secondary port override (`1..=65535`).
    pub rclone_api_port: Option<u16>,
    /// Optional explicit password override (`AF_PASS`) supplied for install/reinstall.
    pub password: Option<String>,
    /// Whether `DELETE_DATA=true` is enabled during `remove`.
    pub delete_data: bool,
    /// Whether `AF_KEEP_EXISTING_SECRETS=1` was explicitly requested via environment.
    pub keep_existing_secrets: bool,
    /// Optional local artifact override directory (`AETHERFLOW_ARTIFACT_CACHE_DIR`) for offline/airgapped or test runs.
    pub artifact_cache_dir: Option<PathBuf>,
    /// Expected target version (`AF_TARGET_VERSION`) for declarative jobs.
    pub expected_target_version: Option<String>,
    /// Disposable scratch root (`AF_JOB_SCRATCH_ROOT`) for declarative jobs.
    pub scratch_root: Option<PathBuf>,
    /// Whether dry-run mode is active for this execution context.
    pub dry_run: bool,
}

impl Default for PackageExecutionEnv {
    fn default() -> Self {
        let fs_root = crate::package_fs_root_override();
        let lock_dir = env::var("LOCK_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/install"));
        let log_dir = PathBuf::from("/var/log/aetherflow");
        let temp_dir = env::var("AETHERFLOW_RUNNER_TEMP_DIR")
            .or_else(|_| env::var("AF_RUNNER_TEMP_DIR"))
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let var_tmp = Path::new("/var/tmp");
                if var_tmp.is_dir() {
                    var_tmp.to_path_buf()
                } else {
                    env::temp_dir()
                }
            });
        let recovery_root = env::var("AETHERFLOW_RECOVERY_ROOT")
            .or_else(|_| env::var("AF_RECOVERY_ROOT"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let password = env::var("AF_PASS")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "adminadmin");
        let delete_data = env::var("DELETE_DATA")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let keep_existing_secrets = env::var("AF_KEEP_EXISTING_SECRETS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let artifact_cache_dir = env::var("AETHERFLOW_ARTIFACT_CACHE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);
        let dry_run = env::var("AETHERFLOW_PACKAGE_DRY_RUN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            lifecycle_job_id: crate::current_package_job_id(),
            fs_root,
            lock_dir,
            log_dir,
            temp_dir,
            recovery_root,
            arch_override: None,
            app_port: 0,
            rclone_api_port: None,
            password,
            delete_data,
            keep_existing_secrets,
            artifact_cache_dir,
            expected_target_version: env::var("AF_TARGET_VERSION")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            scratch_root: Some(PathBuf::from("/var/tmp/aetherflow-scratch")),
            dry_run,
        }
    }
}

impl PackageExecutionEnv {
    /// Creates an isolated execution environment rooted inside `root` (for unit/integration tests).
    pub fn isolated(root: &Path) -> Self {
        Self {
            lifecycle_job_id: String::new(),
            fs_root: Some(root.to_path_buf()),
            lock_dir: PathBuf::from("/install"),
            log_dir: PathBuf::from("/var/log/aetherflow"),
            temp_dir: root.join("tmp"),
            recovery_root: Some(root.join("var/backups/aetherflow-recovery")),
            arch_override: Some("amd64".to_string()),
            app_port: 0,
            rclone_api_port: None,
            password: None,
            delete_data: false,
            keep_existing_secrets: false,
            artifact_cache_dir: Some(root.join("artifacts")),
            expected_target_version: env::var("AF_TARGET_VERSION")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            scratch_root: Some(root.join("var/tmp/aetherflow-scratch")),
            dry_run: false,
        }
    }

    /// Resolves a managed logical path (`/etc/fail2ban/jail.local`) into a concrete host/test path,
    /// verifying all existing ancestor components with `lstat` to reject symlink traversal.
    pub fn resolve_path(&self, logical_path: &str) -> Result<PathBuf, PackageExecutorError> {
        validate_managed_path(logical_path)?;
        let resolved = if let Some(ref root) = self.fs_root {
            let rel = logical_path.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical_path)
        };
        validate_filesystem_path(&resolved, self.env_cfg_fs_root())?;
        Ok(resolved)
    }

    fn env_cfg_fs_root(&self) -> Option<&Path> {
        self.fs_root.as_deref()
    }

    /// Resolves a read-only system path (such as `/etc/ssh/sshd_config`) respecting `fs_root`.
    pub fn resolve_readonly_path(&self, logical_path: &str) -> PathBuf {
        if let Some(ref root) = self.fs_root {
            let rel = logical_path.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical_path)
        }
    }

    /// Resolves the package completion lockfile (`/install/.<pkg>.lock`).
    pub fn resolve_lock_file(
        &self,
        recipe: &DeclarativePackageRecipe,
    ) -> Result<PathBuf, PackageExecutorError> {
        if !recipe.lock_file.trim().is_empty() {
            self.resolve_path(&recipe.lock_file)
        } else {
            let lock_logical = format!(
                "{}/.{}.lock",
                self.lock_dir.to_string_lossy().trim_end_matches('/'),
                recipe.package_id
            );
            self.resolve_path(&lock_logical)
        }
    }

    /// Resolves the per-operation log file (`/var/log/aetherflow/<action>-<pkg>.log`).
    pub fn resolve_log_file(
        &self,
        action: PackageAction,
        pkg_id: &str,
    ) -> Result<PathBuf, PackageExecutorError> {
        let prefix = match action {
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update => "install",
            PackageAction::Remove => "remove",
        };
        let logical = format!(
            "{}/{}-{}.log",
            self.log_dir.to_string_lossy().trim_end_matches('/'),
            prefix,
            pkg_id
        );
        self.resolve_path(&logical)
    }

    pub fn effective_arch(&self) -> String {
        if let Some(ref a) = self.arch_override {
            return a.clone();
        }
        match env::consts::ARCH {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            "arm" => "armhf".to_string(),
            other => other.to_string(),
        }
    }
}

