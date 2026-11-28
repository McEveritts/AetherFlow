//! Transcode worker Unix-socket server (`af-transcode worker`).
//!
//! Security & reliability invariants:
//! - Restricted Unix socket permissions (default `0660`, world bits forbidden) are set inside a
//!   private staging directory. Publishing the socket cannot replace an existing path.
//! - Safe parent directory & stale-socket checks: rejects symlinked or shared-writable parent dirs,
//!   refuses to unlink non-socket paths or another user's socket, probes for a live listener before
//!   treating an existing socket as stale, and unlinks only its own `(dev, ino)` on shutdown.
//! - Concurrency cap (`max_concurrent_jobs`), bounded Start-frame and frame-write timeouts, and
//!   64-frame channel backpressure.
//! - Strict validation of `Start` (`args`, `cwd`, narrow `env_subset` allowlist); child environment
//!   is cleared (`env_clear`) and populated only from safe worker-local baseline + validated subset.
//! - Defense-in-depth SSRF & confinement: rejects network/socket FFmpeg protocols and caller
//!   attempts to widen `-protocol_whitelist`, enforces `-protocol_whitelist file,pipe,fd,crypto,data,subfile`
//!   on every input, and clamps child `current_dir` to a validated safe restricted directory.
//! - Vendor-aware render-node selection via `af_hardware::detect_render_nodes()` and exact
//!   token-boundary rewriting.
//! - Every child runs in its own process group (`process_group(0)`), receiving forwarded signals
//!   via `killpg` and immediate `SIGKILL` process-group cleanup whenever the socket closes without
//!   a clean `Exit` or the worker shuts down.

use crate::argv;
use crate::capabilities;
use crate::config::{
    configured_real_ffmpeg_path, configured_worker_max_jobs, configured_worker_socket_mode,
    configured_worker_socket_path, resolve_worker_child_cwd, validate_absolute_clean_path,
    validate_real_ffmpeg_path, validate_socket_mode, validate_start_request, ConfigError,
    DEFAULT_FRAME_WRITE_TIMEOUT, DEFAULT_JELLYFIN_CACHE_DIR, DEFAULT_WORKER_MAX_JOBS,
    DEFAULT_WORKER_SOCKET_MODE, DEFAULT_WORKER_START_FRAME_TIMEOUT, MAX_UNIX_SOCKET_PATH_BYTES,
    MAX_WORKER_MAX_JOBS, WORKER_BASELINE_ENV_KEYS,
};
use crate::protocol::{
    bounded_frame_channel, encode_framed, read_frame, write_frame, ErrorKind, Frame, ProtocolError,
    FRAME_CHANNEL_CAPACITY, MAX_ERROR_MESSAGE_BYTES, MAX_IO_CHUNK_BYTES,
};
use af_hardware::RenderNode;
use anyhow::Context;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use std::env;
use std::fs;
use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

static TEMP_SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Runtime configuration for `af-transcode worker`.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub socket_path: PathBuf,
    pub real_ffmpeg: PathBuf,
    pub socket_mode: u32,
    pub max_concurrent_jobs: usize,
    pub start_frame_timeout: Duration,
    pub frame_write_timeout: Duration,
    pub render_nodes_override: Option<Vec<RenderNode>>,
    pub allowed_peer_uids: Option<Vec<u32>>,
    /// Explicit restricted directory used as the fallback `current_dir` for spawned `ffmpeg`
    /// children when a caller's `Start.cwd` lies outside `allowed_cwd_roots`.
    /// Defaults to the validated parent directory of `socket_path`.
    pub safe_cwd: Option<PathBuf>,
    /// Optional explicit allowlist of canonicalized directory roots permitted for child `cwd`.
    /// Defaults to `[safe_cwd, /var/cache/jellyfin]`.
    pub allowed_cwd_roots: Option<Vec<PathBuf>>,
}

impl WorkerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            socket_path: configured_worker_socket_path(),
            real_ffmpeg: configured_real_ffmpeg_path(),
            socket_mode: configured_worker_socket_mode()?,
            max_concurrent_jobs: configured_worker_max_jobs(),
            start_frame_timeout: DEFAULT_WORKER_START_FRAME_TIMEOUT,
            frame_write_timeout: DEFAULT_FRAME_WRITE_TIMEOUT,
            render_nodes_override: None,
            allowed_peer_uids: configured_allowed_peer_uids()?,
            safe_cwd: None,
            allowed_cwd_roots: None,
        })
    }

    /// Creates a fixture-friendly config with safe defaults and explicit socket/ffmpeg paths.
    pub fn for_paths(socket_path: PathBuf, real_ffmpeg: PathBuf) -> Self {
        Self {
            socket_path,
            real_ffmpeg,
            socket_mode: DEFAULT_WORKER_SOCKET_MODE,
            max_concurrent_jobs: DEFAULT_WORKER_MAX_JOBS,
            start_frame_timeout: DEFAULT_WORKER_START_FRAME_TIMEOUT,
            frame_write_timeout: DEFAULT_FRAME_WRITE_TIMEOUT,
            render_nodes_override: None,
            allowed_peer_uids: None,
            safe_cwd: None,
            allowed_cwd_roots: None,
        }
    }
}

/// Owned listening Unix socket with inode-verified cleanup on drop.
pub struct BoundWorkerSocket {
    listener: UnixListener,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl BoundWorkerSocket {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl Drop for BoundWorkerSocket {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_socket() && meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// `SO_PEERCRED` UID allowlist for the worker socket (`SEC-09`).
///
/// Comma- and/or whitespace-separated numeric UIDs or user names, e.g. `jellyfin,aetherflow,0`.
/// `*` or `any` explicitly disables the UID check (socket file permissions still apply). When
/// unset or empty, [`default_allowed_peer_uids`] is used. Unknown names or malformed entries make
/// `WorkerConfig::from_env` fail closed.
pub const ENV_WORKER_ALLOWED_PEER_UIDS: &str = "AF_TRANSCODE_ALLOWED_PEER_UIDS";

/// Service account of `aetherflow-api.service`, which reaches the worker socket via
/// `SupplementaryGroups=jellyfin` to run peer-offloaded transcode jobs.
pub const DEFAULT_API_SERVICE_USER: &str = "aetherflow";

/// Default peer UID allowlist, matching the current deployment: the worker's own UID (the
/// `jellyfin` service and its `af-transcode` shim), `root` (the privileged runner), and the
/// `aetherflow` API service account when it exists on this host.
pub fn default_allowed_peer_uids(
    worker_euid: u32,
    resolve_user: impl Fn(&str) -> Option<u32>,
) -> Vec<u32> {
    let mut uids = vec![worker_euid, 0];
    uids.extend(resolve_user(DEFAULT_API_SERVICE_USER));
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// Parses an `AF_TRANSCODE_ALLOWED_PEER_UIDS` value.
///
/// Returns `Ok(None)` when the UID check is explicitly disabled (`*` / `any`),
/// `Ok(Some(default))` when the value is empty, and `Err(entry)` naming the first entry that is
/// neither a numeric UID nor a resolvable user name.
pub fn parse_allowed_peer_uids(
    raw: &str,
    worker_euid: u32,
    resolve_user: impl Fn(&str) -> Option<u32>,
) -> Result<Option<Vec<u32>>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Some(default_allowed_peer_uids(worker_euid, resolve_user)));
    }
    if trimmed == "*" || trimmed.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    let mut uids = Vec::new();
    for entry in trimmed
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
    {
        let uid = if entry.bytes().all(|b| b.is_ascii_digit()) {
            entry.parse::<u32>().map_err(|_| entry.to_string())?
        } else if entry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            resolve_user(entry).ok_or_else(|| entry.to_string())?
        } else {
            return Err(entry.to_string());
        };
        uids.push(uid);
    }
    uids.sort_unstable();
    uids.dedup();
    Ok(Some(uids))
}

/// Resolves a local user name to its UID via `getpwnam_r(3)`.
fn lookup_user_uid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `passwd` is a plain C struct; an all-zero value is a valid "empty" record that
    // `getpwnam_r` fully overwrites on success.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live, properly sized storage owned by this frame, and
    // `buf.len()` is the exact length of `buf`.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    (rc == 0 && !result.is_null()).then_some(pwd.pw_uid)
}

/// Resolves the effective peer UID allowlist from [`ENV_WORKER_ALLOWED_PEER_UIDS`].
pub fn configured_allowed_peer_uids() -> Result<Option<Vec<u32>>, ConfigError> {
    let raw = env::var(ENV_WORKER_ALLOWED_PEER_UIDS).unwrap_or_default();
    let parsed = parse_allowed_peer_uids(&raw, current_euid(), lookup_user_uid).map_err(|entry| {
        ConfigError::Io {
            path: ENV_WORKER_ALLOWED_PEER_UIDS.to_string(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid peer UID allowlist entry '{entry}' (expected a numeric UID or existing user name)"),
            ),
        }
    })?;
    if parsed.is_none() {
        tracing::warn!(
            "{ENV_WORKER_ALLOWED_PEER_UIDS} disables SO_PEERCRED UID checks; relying on socket permissions only"
        );
    }
    Ok(parsed)
}

/// Returns whether a connecting peer passes the `SO_PEERCRED` UID allowlist. A missing allowlist
/// (`None`) admits every peer that the socket permissions admit; a peer whose credentials cannot
/// be read is always rejected when an allowlist is configured.
pub fn peer_uid_allowed(allowed: Option<&[u32]>, peer_uid: Option<u32>) -> bool {
    match allowed {
        None => true,
        Some(list) => peer_uid.is_some_and(|uid| list.contains(&uid)),
    }
}

/// A private directory for the unpublished socket. It is never shared by competing workers.
struct SocketStagingDir(PathBuf);

impl Drop for SocketStagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("s"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn stale_worker_socket(path: &Path) -> io::Result<bool> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let max_sun_path = addr.sun_path.len() - 1;
    if path_bytes.is_empty() || path_bytes.len() > max_sun_path || path_bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path length",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (idx, &byte) in path_bytes.iter().enumerate() {
        addr.sun_path[idx] = byte as libc::c_char;
    }

    // SAFETY: Creates a fresh non-blocking cloexec Unix stream socket fd.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw_fd is a newly opened, owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let addr_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1)
        as libc::socklen_t;

    // SAFETY: addr is a valid initialized sockaddr_un whose length includes the trailing NUL.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::ConnectionRefused {
        Ok(true)
    } else if err.kind() == io::ErrorKind::WouldBlock
        || err.raw_os_error() == Some(libc::EINPROGRESS)
    {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Binds in a private staging directory and publishes the socket without replacing a competing entry.
pub fn bind_worker_socket(config: &WorkerConfig) -> anyhow::Result<BoundWorkerSocket> {
    validate_socket_mode(config.socket_mode)?;
    validate_absolute_clean_path(&config.socket_path)?;

    let path_bytes = config.socket_path.as_os_str().as_encoded_bytes().len();
    if path_bytes > MAX_UNIX_SOCKET_PATH_BYTES {
        anyhow::bail!(
            "worker socket path '{}' ({path_bytes} bytes) exceeds Linux sun_path limit ({MAX_UNIX_SOCKET_PATH_BYTES})",
            config.socket_path.display()
        );
    }

    let parent = config
        .socket_path
        .parent()
        .context("worker socket has no parent")?;
    let parent_dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .with_context(|| format!("open worker socket directory '{}'", parent.display()))?;
    let metadata = parent_dir.metadata()?;
    let euid = current_euid();

    anyhow::ensure!(
        (metadata.uid() == euid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0,
        "worker socket directory '{}' must belong to the service user or root and forbid group or world writes",
        parent.display()
    );

    // Hold the directory lock across stale detection and publication. The descriptor remains open
    // for the entire operation, and a concurrent starter fails promptly.
    // SAFETY: parent_dir is a live Linux directory descriptor.
    if unsafe { libc::flock(parent_dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error()).context("lock worker socket directory");
    }

    match fs::symlink_metadata(&config.socket_path) {
        Ok(existing) => {
            anyhow::ensure!(
                existing.file_type().is_socket() && (existing.uid() == euid || euid == 0),
                "refusing to replace unmanaged worker socket path '{}'",
                config.socket_path.display()
            );
            anyhow::ensure!(
                stale_worker_socket(&config.socket_path).context("probe existing worker socket")?,
                "worker socket '{}' is already served by a live process",
                config.socket_path.display()
            );
            fs::remove_file(&config.socket_path).context("remove stale worker socket")?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspect worker socket path"),
    }

    let seq = TEMP_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging_path = parent.join(format!(".af-worker-{}-{seq}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging_path)
        .context("create private worker socket staging directory")?;
    let staging = SocketStagingDir(staging_path);
    let staged = staging.0.join("s");

    // Linux resolves the directory descriptor alias within bind(2), keeping sun_path short
    // even when the final path is too long to append a staging component.
    let stage_fd = fs::File::open(&staging.0).context("open worker socket staging directory")?;
    let bind_path = format!("/proc/self/fd/{}/s", stage_fd.as_raw_fd());
    let listener = UnixListener::bind(&bind_path).context("bind private worker socket")?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(config.socket_mode))
        .context("set worker socket permissions")?;
    let bound_meta = fs::symlink_metadata(&staged).context("inspect private worker socket")?;

    // A Unix filesystem socket can be published by linking its inode on Linux. Unlike rename,
    // this operation fails if the final name was taken. The staging guard removes the other name.
    fs::hard_link(&staged, &config.socket_path).context("publish worker socket")?;

    Ok(BoundWorkerSocket {
        listener,
        path: config.socket_path.clone(),
        dev: bound_meta.dev(),
        ino: bound_meta.ino(),
    })
}

/// RAII process-group terminator: guarantees no child or grandchild survives abnormal teardown.
struct ProcessGroupGuard {
    pgid: Option<Pid>,
}

impl ProcessGroupGuard {
    fn new(pgid: Pid) -> Self {
        Self { pgid: Some(pgid) }
    }

    fn kill_now(&self, sig: Signal) {
        if let Some(pgid) = self.pgid {
            let _ = killpg(pgid, sig);
        }
    }

    fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            let _ = killpg(pgid, Signal::SIGKILL);
        }
    }
}

fn peer_socket_disconnected(fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: pfd points to a single valid pollfd struct for a live socket descriptor.
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc < 0 {
        return io::Error::last_os_error().kind() != io::ErrorKind::Interrupted;
    }
    (pfd.revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

fn exit_status_to_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

/// Runs the worker server until `shutdown` resolves, then terminates any remaining jobs cleanly.
pub async fn run_worker(
    config: WorkerConfig,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let real_ffmpeg = validate_real_ffmpeg_path(&config.real_ffmpeg)
        .with_context(|| format!("invalid real ffmpeg '{}'", config.real_ffmpeg.display()))?;
    let bound = bind_worker_socket(&config)?;
    serve_worker_listener(bound, config, real_ffmpeg, shutdown).await
}

/// Serves an already-bound worker socket until `shutdown` resolves.
///
/// Exposed so tests can bind synchronously, know the exact ready socket path with zero race,
/// and drive the worker with an explicit shutdown channel.
pub async fn serve_worker_listener(
    bound: BoundWorkerSocket,
    config: WorkerConfig,
    validated_real_ffmpeg: PathBuf,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let max_jobs = config.max_concurrent_jobs.clamp(1, MAX_WORKER_MAX_JOBS);
    let job_semaphore = Arc::new(Semaphore::new(max_jobs));
    // Bound pending pre-Start connections so silent sockets cannot exhaust file descriptors.
    let pending_semaphore = Arc::new(Semaphore::new(max_jobs.saturating_mul(2).max(4)));
    let shared_cfg = Arc::new(config);
    let real_ffmpeg = Arc::new(validated_real_ffmpeg);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();

    tracing::info!(
        socket = %bound.path().display(),
        max_concurrent_jobs = max_jobs,
        "af-transcode worker listening"
    );

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(true);
                break;
            }
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    tracing::warn!(error = %err, "worker connection task failed");
                }
            }
            accept_res = bound.listener().accept() => {
                let (stream, _) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "worker accept failed");
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        continue;
                    }
                };

                // SO_PEERCRED UID allowlist (`AF_TRANSCODE_ALLOWED_PEER_UIDS`, SEC-09).
                if let Some(ref allowed) = shared_cfg.allowed_peer_uids {
                    let peer_uid = stream.peer_cred().ok().map(|cred| cred.uid());
                    if !peer_uid_allowed(Some(allowed), peer_uid) {
                        tracing::warn!(
                            peer_uid = ?peer_uid,
                            "rejecting worker connection from unauthorized peer uid"
                        );
                        drop(stream);
                        continue;
                    }
                }

                let Ok(pending_permit) = pending_semaphore.clone().try_acquire_owned() else {
                    if let Ok(error) = encode_framed(&Frame::Error {
                        kind: ErrorKind::Busy,
                        message: "worker connection queue full".to_string(),
                    }) {
                        let _ = stream.try_write(&error);
                    }
                    continue;
                };

                let cfg = Arc::clone(&shared_cfg);
                let ffmpeg = Arc::clone(&real_ffmpeg);
                let jobs = Arc::clone(&job_semaphore);
                let conn_shutdown = shutdown_rx.clone();

                connections.spawn(async move {
                    let _pending = pending_permit;
                    handle_connection(stream, cfg, ffmpeg, jobs, conn_shutdown).await;
                });
            }
        }
    }

    // Drain active job tasks so every running ffmpeg process group is killed and reaped.
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !connections.is_empty() {
        match tokio::time::timeout_at(drain_deadline, connections.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                break;
            }
        }
    }

    drop(bound);
    Ok(())
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

async fn send_error_and_close(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    kind: ErrorKind,
    message: String,
    timeout: Duration,
) {
    let truncated = truncate_utf8_bytes(&message, MAX_ERROR_MESSAGE_BYTES);
    let _ = tokio::time::timeout(
        timeout,
        write_frame(
            writer,
            &Frame::Error {
                kind,
                message: truncated,
            },
        ),
    )
    .await;
}

async fn handle_connection(
    stream: UnixStream,
    config: Arc<WorkerConfig>,
    real_ffmpeg: Arc<PathBuf>,
    job_semaphore: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let (mut reader, mut writer) = stream.into_split();

    // Wait for initial Frame::Start within bounded timeout BEFORE acquiring an execution
    // job permit so idle/slow pre-Start connections cannot starve active transcode slots.
    let first_frame = tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout(config.start_frame_timeout, read_frame(&mut reader)) => res,
    };

    let start_req = match first_frame {
        Ok(Ok(Some(Frame::Start(req)))) => req,
        Ok(Ok(Some(other))) => {
            send_error_and_close(
                &mut writer,
                ErrorKind::ProtocolViolation,
                format!("expected Start as first frame, got {other:?}"),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
        Ok(Ok(None)) => return,
        Ok(Err(err)) => {
            let kind = match err {
                ProtocolError::FrameTooLarge { .. }
                | ProtocolError::AllocationLimitExceeded(_)
                | ProtocolError::EmptyFrame
                | ProtocolError::TrailingBytes
                | ProtocolError::InvalidWireFormat(_) => ErrorKind::ProtocolViolation,
                ProtocolError::TruncatedFrame { .. }
                | ProtocolError::EncodeFailed(_)
                | ProtocolError::Io(_) => ErrorKind::Internal,
            };
            send_error_and_close(
                &mut writer,
                kind,
                format!("invalid initial frame: {err}"),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
        Err(_) => {
            send_error_and_close(
                &mut writer,
                ErrorKind::ProtocolViolation,
                format!(
                    "timed out waiting for Start frame after {} ms",
                    config.start_frame_timeout.as_millis()
                ),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
    };

    // Acquire execution concurrency permit only after receiving Start.
    let Ok(job_permit) = job_semaphore.try_acquire_owned() else {
        send_error_and_close(
            &mut writer,
            ErrorKind::Busy,
            format!(
                "worker reached max concurrent jobs ({})",
                config.max_concurrent_jobs
            ),
            config.frame_write_timeout,
        )
        .await;
        return;
    };

    // Validate received Start (`args`, `cwd`, narrow `env_subset` allowlist).
    let validated_cwd = match validate_start_request(&start_req) {
        Ok(dir) => dir,
        Err(err) => {
            send_error_and_close(
                &mut writer,
                ErrorKind::InvalidRequest,
                err.to_string(),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
    };

    // Defense-in-depth SSRF & local-only protocol check: refuse network/socket inputs or
    // caller attempts to widen `-protocol_whitelist` even if worker is invoked directly.
    if let Err(reason) = argv::validate_worker_args(&start_req.args) {
        send_error_and_close(
            &mut writer,
            ErrorKind::InvalidRequest,
            reason,
            config.frame_write_timeout,
        )
        .await;
        return;
    }

    // Clamp child `current_dir` to a validated safe restricted directory (never inheriting
    // arbitrary process cwd or letting caller-supplied / symlinked `cwd` escape allowed roots).
    let fallback_safe_cwd = match config
        .safe_cwd
        .as_deref()
        .or_else(|| config.socket_path.parent())
    {
        Some(dir) => dir.to_path_buf(),
        None => {
            send_error_and_close(
                &mut writer,
                ErrorKind::Internal,
                "worker has no safe working directory configured".to_string(),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
    };
    let allowed_cwd_roots = match &config.allowed_cwd_roots {
        Some(roots) => roots.clone(),
        None => vec![
            fallback_safe_cwd.clone(),
            PathBuf::from(DEFAULT_JELLYFIN_CACHE_DIR),
        ],
    };
    let child_cwd =
        match resolve_worker_child_cwd(&validated_cwd, &fallback_safe_cwd, &allowed_cwd_roots) {
            Ok(dir) => dir,
            Err(err) => {
                send_error_and_close(
                    &mut writer,
                    ErrorKind::Internal,
                    format!("worker safe working directory unavailable: {err}"),
                    config.frame_write_timeout,
                )
                .await;
                return;
            }
        };
    if fs::canonicalize(&validated_cwd).ok().as_deref() != Some(child_cwd.as_path()) {
        tracing::debug!(
            requested_cwd = %validated_cwd.display(),
            clamped_cwd = %child_cwd.display(),
            "clamped worker child cwd to restricted safe directory"
        );
    }

    // Infer required hardware capability and rewrite DRM render node if args reference one.
    let capability = argv::required_capability(&start_req.args);
    let rewritten_args = if !capability.render_nodes.is_empty() {
        let detected_nodes = match &config.render_nodes_override {
            Some(nodes) => nodes.clone(),
            None => af_hardware::detect_render_nodes(),
        };
        let Some(selected_node) = capabilities::select_render_node(&capability, &detected_nodes)
        else {
            send_error_and_close(
                &mut writer,
                ErrorKind::DeviceUnavailable,
                format!(
                    "no suitable DRM render node available on worker for {:?}",
                    capability.hwaccel
                ),
                config.frame_write_timeout,
            )
            .await;
            return;
        };
        let Some(selected_str) = selected_node.to_str() else {
            send_error_and_close(
                &mut writer,
                ErrorKind::DeviceUnavailable,
                "selected render node path is not valid UTF-8".to_string(),
                config.frame_write_timeout,
            )
            .await;
            return;
        };
        argv::rewrite_any_render_node(&start_req.args, selected_str)
    } else {
        start_req.args.clone()
    };

    // Enforce local-only `-protocol_whitelist` on every input before spawning real `ffmpeg`.
    let final_args = argv::inject_local_protocol_whitelist(&rewritten_args);

    // Construct real ffmpeg process with clean environment (worker baseline + validated subset).
    let mut cmd = Command::new(real_ffmpeg.as_ref());
    cmd.args(&final_args)
        .current_dir(&child_cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);

    for &key in WORKER_BASELINE_ENV_KEYS {
        if let Some(val) = env::var_os(key) {
            cmd.env(key, val);
        }
    }
    for (key, value) in &start_req.env_subset {
        cmd.env(key, value);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            send_error_and_close(
                &mut writer,
                ErrorKind::SpawnFailed,
                format!("failed to spawn real ffmpeg: {err}"),
                config.frame_write_timeout,
            )
            .await;
            return;
        }
    };

    let Some(raw_pid) = child.id() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        send_error_and_close(
            &mut writer,
            ErrorKind::SpawnFailed,
            "spawned ffmpeg child has no PID".to_string(),
            config.frame_write_timeout,
        )
        .await;
        return;
    };
    let pgid = Pid::from_raw(raw_pid as i32);
    let mut pg_guard = ProcessGroupGuard::new(pgid);

    // Send Frame::Started before pumping stdio.
    if tokio::time::timeout(
        config.frame_write_timeout,
        write_frame(&mut writer, &Frame::Started),
    )
    .await
    .map_or(true, |res| res.is_err())
    {
        pg_guard.kill_now(Signal::SIGKILL);
        reap_or_defer_killed_child(child, pg_guard, job_permit).await;
        return;
    }

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Bounded 64-frame channel for outbound Stdout/Stderr/Exit frames.
    let (outbound_tx, mut outbound_rx) = bounded_frame_channel();
    let (writer_failed_tx, mut writer_failed_rx) = watch::channel(false);

    let write_timeout = config.frame_write_timeout;
    let mut writer_task = tokio::spawn(async move {
        while let Some(frame) = outbound_rx.recv().await {
            match tokio::time::timeout(write_timeout, write_frame(&mut writer, &frame)).await {
                Ok(Ok(())) => {}
                _ => {
                    let _ = writer_failed_tx.send(true);
                    break;
                }
            }
        }
        drop(writer);
    });

    // Child stdout pump -> outbound 64-frame channel.
    let mut output_tasks = JoinSet::new();
    let stdout_tx = outbound_tx.clone();
    output_tasks.spawn(async move {
        let Some(mut out) = child_stdout else {
            return;
        };
        let mut buf = vec![0u8; MAX_IO_CHUNK_BYTES];
        loop {
            match out.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout_tx
                        .send(Frame::Stdout(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // Child stderr pump -> outbound 64-frame channel.
    let stderr_tx = outbound_tx.clone();
    output_tasks.spawn(async move {
        let Some(mut err_stream) = child_stderr else {
            return;
        };
        let mut buf = vec![0u8; MAX_IO_CHUNK_BYTES];
        loop {
            match err_stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stderr_tx
                        .send(Frame::Stderr(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // Dedicated bounded 64-frame child stdin writer so slow/non-reading ffmpeg cannot block Signal handling.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(FRAME_CHANNEL_CAPACITY);
    let stdin_task = tokio::spawn(async move {
        let Some(mut child_in) = child_stdin else {
            return;
        };
        while let Some(bytes) = stdin_rx.recv().await {
            if child_in.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = child_in.shutdown().await;
    });

    // Main supervision loop: forward Stdin/StdinEof/Signal, detect socket disconnect, wait for child exit.
    let mut stdin_tx_opt = Some(stdin_tx);
    let mut pending_stdin: Option<Vec<u8>> = None;
    let mut stdin_stall_deadline: Option<tokio::time::Instant> = None;
    let mut clean_exit_code: Option<i32> = None;

    loop {
        if let (Some(_), Some(tx)) = (pending_stdin.as_ref(), stdin_tx_opt.as_ref()) {
            if peer_socket_disconnected(reader.as_ref().as_raw_fd()) {
                pg_guard.kill_now(Signal::SIGKILL);
                break;
            }
            let deadline = stdin_stall_deadline
                .unwrap_or_else(|| tokio::time::Instant::now() + config.frame_write_timeout);
            let mut clear_stdin = false;
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    pg_guard.kill_now(Signal::SIGKILL);
                    break;
                }
                _ = writer_failed_rx.changed() => {
                    pg_guard.kill_now(Signal::SIGKILL);
                    break;
                }
                wait_res = child.wait() => {
                    clean_exit_code = Some(match wait_res {
                        Ok(status) => exit_status_to_code(status),
                        Err(_) => 1,
                    });
                    pg_guard.disarm();
                    break;
                }
                permit_res = tx.reserve() => {
                    match permit_res {
                        Ok(permit) => {
                            if let Some(bytes) = pending_stdin.take() {
                                permit.send(bytes);
                            }
                            stdin_stall_deadline = None;
                        }
                        Err(_) => {
                            clear_stdin = true;
                            pending_stdin = None;
                            stdin_stall_deadline = None;
                        }
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = outbound_tx.try_send(Frame::Error {
                        kind: ErrorKind::WorkerFailed,
                        message: "ffmpeg stopped reading stdin".to_string(),
                    });
                    pg_guard.kill_now(Signal::SIGKILL);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
            if clear_stdin {
                stdin_tx_opt = None;
            }
            continue;
        }

        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                pg_guard.kill_now(Signal::SIGKILL);
                break;
            }
            _ = writer_failed_rx.changed() => {
                pg_guard.kill_now(Signal::SIGKILL);
                break;
            }
            wait_res = child.wait() => {
                clean_exit_code = Some(match wait_res {
                    Ok(status) => exit_status_to_code(status),
                    Err(_) => 1,
                });
                pg_guard.disarm();
                break;
            }
            frame_res = read_frame(&mut reader) => {
                match frame_res {
                    Ok(Some(Frame::Stdin(bytes))) => {
                        if bytes.is_empty() {
                            stdin_tx_opt = None;
                        } else if let Some(ref tx) = stdin_tx_opt {
                            match tx.try_send(bytes) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => stdin_tx_opt = None,
                                Err(mpsc::error::TrySendError::Full(bytes)) => {
                                    pending_stdin = Some(bytes);
                                    stdin_stall_deadline =
                                        Some(tokio::time::Instant::now() + config.frame_write_timeout);
                                }
                            }
                        }
                    }
                    Ok(Some(Frame::StdinEof)) => stdin_tx_opt = None,
                    Ok(Some(Frame::Signal(sig))) => {
                        pg_guard.kill_now(sig.to_nix());
                    }
                    Ok(Some(_unexpected)) => {
                        let _ = outbound_tx.try_send(Frame::Error {
                            kind: ErrorKind::ProtocolViolation,
                            message: "unexpected frame received during active job".to_string(),
                        });
                        pg_guard.kill_now(Signal::SIGKILL);
                        break;
                    }
                    Ok(None) | Err(_) => {
                        // Peer socket closed or errored before clean Exit -> kill entire process group!
                        pg_guard.kill_now(Signal::SIGKILL);
                        break;
                    }
                }
            }
        }
    }

    // Close stdin task immediately.
    drop(stdin_tx_opt);
    stdin_task.abort();
    let _ = stdin_task.await;

    let mut permit_opt = Some(job_permit);
    if let Some(code) = clean_exit_code {
        // Give both pipes time to finish before reporting success. A timed-out drain must
        // abort the pumps, otherwise they can keep outbound senders and the socket alive.
        let terminal_frame = match tokio::time::timeout(Duration::from_secs(5), async {
            while output_tasks.join_next().await.is_some() {}
        })
        .await
        {
            Ok(()) => Frame::Exit(code),
            Err(_) => {
                output_tasks.shutdown().await;
                Frame::Error {
                    kind: ErrorKind::WorkerFailed,
                    message: "ffmpeg output did not finish draining".to_string(),
                }
            }
        };
        let _ = tokio::time::timeout(config.frame_write_timeout, outbound_tx.send(terminal_frame))
            .await;
    } else {
        // Abnormal teardown: kill process group BEFORE waiting so PGID cannot be reused, then reap.
        pg_guard.kill_now(Signal::SIGKILL);
        output_tasks.shutdown().await;
        if let Some(permit) = permit_opt.take() {
            reap_or_defer_killed_child(child, pg_guard, permit).await;
        }
    }

    drop(outbound_tx);
    let writer_timeout = if clean_exit_code.is_some() {
        config.frame_write_timeout
    } else {
        Duration::from_millis(250)
    };
    if tokio::time::timeout(writer_timeout, &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
        let _ = writer_task.await;
    }
    drop(permit_opt);
}

async fn reap_or_defer_killed_child(
    mut child: tokio::process::Child,
    mut pg_guard: ProcessGroupGuard,
    job_permit: tokio::sync::OwnedSemaphorePermit,
) {
    match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
        Ok(_) => {
            pg_guard.disarm();
            drop(job_permit);
        }
        Err(_) => {
            // Retain the concurrency permit until an uninterruptible (e.g., D-state NFS) child exits.
            tokio::spawn(async move {
                let _ = child.wait().await;
                pg_guard.disarm();
                drop(job_permit);
            });
        }
    }
}

#[cfg(test)]
mod peer_uid_allowlist_tests {
    use super::*;

    fn resolver(name: &str) -> Option<u32> {
        match name {
            "aetherflow" => Some(998),
            "jellyfin" => Some(997),
            _ => None,
        }
    }

    #[test]
    fn sec09_default_allowlist_is_worker_root_and_api_service() {
        assert_eq!(default_allowed_peer_uids(997, resolver), vec![0, 997, 998]);
        assert_eq!(default_allowed_peer_uids(0, |_| None), vec![0]);
        assert_eq!(
            parse_allowed_peer_uids("", 997, resolver),
            Ok(Some(vec![0, 997, 998]))
        );
        assert_eq!(
            parse_allowed_peer_uids("  \t ", 1000, |_| None),
            Ok(Some(vec![0, 1000]))
        );
    }

    #[test]
    fn sec09_parses_numeric_uids_and_user_names() {
        assert_eq!(
            parse_allowed_peer_uids("jellyfin, aetherflow 0,1000,1000", 5, resolver),
            Ok(Some(vec![0, 997, 998, 1000]))
        );
        assert_eq!(parse_allowed_peer_uids("*", 5, resolver), Ok(None));
        assert_eq!(parse_allowed_peer_uids("ANY", 5, resolver), Ok(None));
    }

    #[test]
    fn sec09_rejects_unknown_or_malformed_entries() {
        assert_eq!(
            parse_allowed_peer_uids("jellyfin,nobody-here", 5, resolver),
            Err("nobody-here".to_string())
        );
        assert_eq!(
            parse_allowed_peer_uids("99999999999", 5, resolver),
            Err("99999999999".to_string())
        );
        assert_eq!(
            parse_allowed_peer_uids("-1", 5, resolver),
            Err("-1".to_string())
        );
        assert_eq!(
            parse_allowed_peer_uids("root;id", 5, resolver),
            Err("root;id".to_string())
        );
    }

    #[test]
    fn sec09_peer_uid_policy() {
        assert!(peer_uid_allowed(None, None));
        assert!(peer_uid_allowed(None, Some(4242)));
        assert!(peer_uid_allowed(Some(&[0, 997]), Some(997)));
        assert!(!peer_uid_allowed(Some(&[0, 997]), Some(4242)));
        assert!(
            !peer_uid_allowed(Some(&[0, 997]), None),
            "unreadable credentials must be rejected"
        );
        assert!(!peer_uid_allowed(Some(&[]), Some(0)));
    }

    #[test]
    fn sec09_root_user_resolves_via_getpwnam() {
        assert_eq!(lookup_user_uid("root"), Some(0));
        assert_eq!(lookup_user_uid("af-no-such-user-xyz"), None);
        assert_eq!(lookup_user_uid("bad\0name"), None);
    }

    #[tokio::test]
    async fn sec09_so_peercred_allowlist_admits_own_uid_and_rejects_others() {
        let euid = current_euid();
        let (_client, server) = UnixStream::pair().unwrap();
        let peer_uid = server.peer_cred().ok().map(|cred| cred.uid());
        assert_eq!(peer_uid, Some(euid));
        let defaults = default_allowed_peer_uids(euid, lookup_user_uid);
        assert!(peer_uid_allowed(Some(&defaults), peer_uid));
        let other = euid.wrapping_add(4242);
        assert!(!peer_uid_allowed(Some(&[other]), peer_uid));
    }

    #[tokio::test]
    async fn sec09_worker_drops_connections_from_disallowed_peer_uids() {
        let dir = env::temp_dir().join(format!(
            "af-transcode-peercred-{}-{}",
            std::process::id(),
            TEMP_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let socket = dir.join("w.sock");
        let mut cfg = WorkerConfig::for_paths(socket.clone(), PathBuf::from("/bin/true"));
        cfg.allowed_peer_uids = Some(vec![current_euid().wrapping_add(4242)]);
        let bound = bind_worker_socket(&cfg).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_worker_listener(
            bound,
            cfg,
            PathBuf::from("/bin/true"),
            async move {
                let _ = rx.await;
            },
        ));
        let mut client = UnixStream::connect(&socket).await.unwrap();
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("disallowed peer must be disconnected promptly");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "disallowed peer must receive EOF without any frame: {read:?}"
        );
        let _ = tx.send(());
        server.await.unwrap().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
