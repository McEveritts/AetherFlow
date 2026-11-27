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

use crate::argv::{self, AdaptedTargetBackend, Capability, HwAccel};
use crate::capabilities::{
    self, CapabilitiesConfig, TranscodeCapabilities, PCI_VENDOR_AMD, PCI_VENDOR_INTEL,
    PCI_VENDOR_NVIDIA,
};
use crate::config::{
    configured_real_ffmpeg_path, configured_worker_adapt_backend, configured_worker_ffmpeg_threads,
    configured_worker_max_jobs, configured_worker_optimize_vulkan_tonemap,
    configured_worker_socket_mode, configured_worker_socket_path, configured_worker_vulkan_compute,
    configured_worker_vulkan_video, resolve_worker_child_cwd, validate_absolute_clean_path,
    validate_real_ffmpeg_path, validate_safe_dir, validate_socket_mode, validate_start_request,
    BackendAdaptMode, ConfigError, DEFAULT_FRAME_WRITE_TIMEOUT, DEFAULT_JELLYFIN_CACHE_DIR,
    DEFAULT_PROBE_TIMEOUT, DEFAULT_WORKER_MAX_JOBS, DEFAULT_WORKER_SOCKET_MODE,
    DEFAULT_WORKER_START_FRAME_TIMEOUT, MAX_UNIX_SOCKET_PATH_BYTES, MAX_WORKER_MAX_JOBS,
    WORKER_BASELINE_ENV_KEYS,
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
use std::path::{Component, Path, PathBuf};
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
    /// Optional per-job `ffmpeg` thread cap applied to `-threads`, `-filter_threads`, and
    /// `-filter_complex_threads`.
    pub ffmpeg_max_threads: Option<usize>,
    /// Backend adaptation policy (`Off`, `Gpu`, `PreferQsv`, `All`).
    pub adapt_backend_mode: BackendAdaptMode,
    /// When `true`, pre-scales linear VA-API -> Vulkan `libplacebo` tonemapping graphs on VA-API.
    pub optimize_vulkan_tonemap: bool,
    /// When `true`, worker permits Vulkan Compute filters (`libplacebo`, `*_vulkan` filters).
    pub vulkan_compute: bool,
    /// When `true`, worker permits Vulkan Video hardware decode/encode (`-hwaccel vulkan`, `*_vulkan` codecs).
    pub vulkan_video: bool,
    /// Optional explicit worker capabilities override (primarily for tests/fixtures).
    /// When `None`, the worker probes capabilities once at startup.
    pub capabilities_override: Option<TranscodeCapabilities>,
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
            allowed_peer_uids: None,
            safe_cwd: None,
            allowed_cwd_roots: None,
            ffmpeg_max_threads: configured_worker_ffmpeg_threads(),
            adapt_backend_mode: configured_worker_adapt_backend(),
            optimize_vulkan_tonemap: configured_worker_optimize_vulkan_tonemap(),
            vulkan_compute: configured_worker_vulkan_compute(),
            vulkan_video: configured_worker_vulkan_video(),
            capabilities_override: None,
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
            ffmpeg_max_threads: None,
            adapt_backend_mode: BackendAdaptMode::Off,
            optimize_vulkan_tonemap: false,
            vulkan_compute: true,
            vulkan_video: false,
            capabilities_override: None,
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

const MAX_MESA_SHADER_CACHE_DIR_BYTES: usize = 4096;

/// Safely validates and creates `MESA_SHADER_CACHE_DIR` without following symlinks on any
/// existing path component, enforcing a 4096-byte length bound and forbidding `/`.
fn ensure_safe_mesa_shader_cache_dir(path: &Path) -> anyhow::Result<PathBuf> {
    validate_absolute_clean_path(path)?;
    let path_bytes = path.as_os_str().as_encoded_bytes().len();
    anyhow::ensure!(
        path_bytes <= MAX_MESA_SHADER_CACHE_DIR_BYTES,
        "MESA_SHADER_CACHE_DIR path ({path_bytes} bytes) exceeds {MAX_MESA_SHADER_CACHE_DIR_BYTES} bytes"
    );
    anyhow::ensure!(
        path != Path::new("/"),
        "MESA_SHADER_CACHE_DIR must not be '/'"
    );

    let mut segments = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(seg) => segments.push(seg),
            Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("MESA_SHADER_CACHE_DIR contains invalid path component");
            }
        }
    }
    anyhow::ensure!(
        !segments.is_empty(),
        "MESA_SHADER_CACHE_DIR must not be '/'"
    );

    let mut prefix = PathBuf::from("/");
    for seg in segments {
        prefix.push(seg);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing symlink component '{}' in MESA_SHADER_CACHE_DIR",
                        prefix.display()
                    );
                }
                if !meta.file_type().is_dir() {
                    anyhow::bail!(
                        "non-directory component '{}' in MESA_SHADER_CACHE_DIR",
                        prefix.display()
                    );
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => match fs::create_dir(&prefix) {
                Ok(()) => {}
                Err(create_err) if create_err.kind() == io::ErrorKind::AlreadyExists => {
                    let meta = fs::symlink_metadata(&prefix).with_context(|| {
                        format!(
                            "inspect MESA_SHADER_CACHE_DIR component '{}'",
                            prefix.display()
                        )
                    })?;
                    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                        anyhow::bail!(
                            "refusing symlink or non-directory component '{}' in MESA_SHADER_CACHE_DIR",
                            prefix.display()
                        );
                    }
                }
                Err(create_err) => {
                    return Err(create_err).with_context(|| {
                        format!(
                            "create MESA_SHADER_CACHE_DIR component '{}'",
                            prefix.display()
                        )
                    });
                }
            },
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "inspect MESA_SHADER_CACHE_DIR component '{}'",
                        prefix.display()
                    )
                });
            }
        }
    }

    validate_safe_dir(&prefix)
        .with_context(|| format!("validate MESA_SHADER_CACHE_DIR '{}'", path.display()))
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
    // Best-effort, symlink-safe creation of worker-local MESA_SHADER_CACHE_DIR once at startup.
    if let Some(cache_dir) = env::var_os("MESA_SHADER_CACHE_DIR") {
        let cache_path = Path::new(&cache_dir);
        if let Err(err) = ensure_safe_mesa_shader_cache_dir(cache_path) {
            tracing::debug!(
                path = %cache_path.display(),
                error = %err,
                "skipping unsafe or unavailable MESA_SHADER_CACHE_DIR creation"
            );
        }
    }

    // Probe or load worker capabilities once at startup regardless of `adapt_backend_mode` so
    // worker-side Vulkan checks and `plan_backend_adaptation` decisions match the controller.
    let worker_capabilities: Arc<Option<TranscodeCapabilities>> = Arc::new(
        if let Some(override_caps) = config.capabilities_override.clone() {
            Some(override_caps)
        } else {
            let probe_cfg = CapabilitiesConfig {
                real_ffmpeg: validated_real_ffmpeg.clone(),
                dpkg_query_path: None,
                vainfo_path: CapabilitiesConfig::from_env().vainfo_path,
                render_nodes_override: config.render_nodes_override.clone(),
                probe_timeout: DEFAULT_PROBE_TIMEOUT,
                vulkan_compute_override: Some(config.vulkan_compute),
                vulkan_video_override: Some(config.vulkan_video),
            };
            match capabilities::probe_capabilities(&probe_cfg).await {
                Ok(caps) => {
                    if caps.encoders.is_empty() {
                        tracing::debug!(
                            ffmpeg = %validated_real_ffmpeg.display(),
                            "worker capability probe returned no video encoders; retaining probed Vulkan metadata with fallback encoder synthesis"
                        );
                    }
                    Some(caps)
                }
                Err(err) => {
                    tracing::warn!(
                        ffmpeg = %validated_real_ffmpeg.display(),
                        error = %err,
                        "worker capability probe failed; falling back to node-derived capability synthesis"
                    );
                    None
                }
            }
        },
    );

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

                // Optional SO_PEERCRED UID restriction.
                if let Some(ref allowed) = shared_cfg.allowed_peer_uids {
                    let allowed_peer = stream
                        .peer_cred()
                        .ok()
                        .is_some_and(|cred| allowed.contains(&cred.uid()));
                    if !allowed_peer {
                        tracing::warn!("rejecting worker connection from unauthorized peer uid");
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
                let caps = Arc::clone(&worker_capabilities);
                let jobs = Arc::clone(&job_semaphore);
                let conn_shutdown = shutdown_rx.clone();

                connections.spawn(async move {
                    let _pending = pending_permit;
                    handle_connection(stream, cfg, ffmpeg, caps, jobs, conn_shutdown).await;
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

fn select_intel_node(nodes: &[RenderNode]) -> Option<&Path> {
    nodes
        .iter()
        .find(|n| {
            n.vendor_id
                .as_deref()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case(PCI_VENDOR_INTEL))
        })
        .map(|n| n.path.as_path())
}

fn resolve_worker_render_nodes(config: &WorkerConfig) -> Vec<RenderNode> {
    if let Some(nodes) = &config.render_nodes_override {
        return nodes.clone();
    }
    if let Some(caps) = &config.capabilities_override {
        return caps
            .render_nodes
            .iter()
            .map(|n| RenderNode {
                path: PathBuf::from(&n.path),
                vendor_id: n.vendor_id.clone(),
            })
            .collect();
    }
    af_hardware::detect_render_nodes()
}

fn synthesize_fallback_encoders(
    nodes: &[RenderNode],
    capability: &Capability,
    vulkan_video_enabled: bool,
) -> Vec<String> {
    let mut encoders = vec!["libx264".to_string(), "libx265".to_string()];

    let has_vaapi = nodes.iter().any(|n| {
        let vendor = n
            .vendor_id
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty());
        matches!(
            vendor.as_deref(),
            Some(PCI_VENDOR_INTEL | PCI_VENDOR_AMD) | None
        )
    });
    let has_intel_or_unknown = nodes.iter().any(|n| {
        n.vendor_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none_or(|v| v.eq_ignore_ascii_case(PCI_VENDOR_INTEL))
    });
    let has_nvidia_or_unknown = nodes.iter().any(|n| {
        n.vendor_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none_or(|v| v.eq_ignore_ascii_case(PCI_VENDOR_NVIDIA))
    });

    if has_vaapi {
        for enc in [
            "h264_vaapi",
            "hevc_vaapi",
            "av1_vaapi",
            "vp9_vaapi",
            "mjpeg_vaapi",
            "mpeg2_vaapi",
        ] {
            encoders.push(enc.to_string());
        }
    }
    if has_intel_or_unknown {
        for enc in [
            "h264_qsv",
            "hevc_qsv",
            "av1_qsv",
            "vp9_qsv",
            "mjpeg_qsv",
            "mpeg2_qsv",
        ] {
            encoders.push(enc.to_string());
        }
    }
    if has_nvidia_or_unknown {
        for enc in ["h264_nvenc", "hevc_nvenc", "av1_nvenc"] {
            encoders.push(enc.to_string());
        }
    }
    if vulkan_video_enabled && !nodes.is_empty() {
        for enc in ["h264_vulkan", "hevc_vulkan", "av1_vulkan"] {
            encoders.push(enc.to_string());
        }
    }
    if !capability.requires_hardware() {
        if let Some(enc) = capability.required_encoder() {
            if !encoders.iter().any(|e| e.eq_ignore_ascii_case(enc)) {
                encoders.push(enc.to_string());
            }
        }
    }

    encoders
}

fn effective_worker_vulkan_capabilities<'a>(
    config: &WorkerConfig,
    worker_capabilities: Option<&'a TranscodeCapabilities>,
) -> argv::WorkerVulkanCapabilities<'a> {
    let vulkan_compute = if !config.vulkan_compute {
        Some(false)
    } else {
        worker_capabilities.and_then(|c| c.vulkan_compute)
    };

    let (vulkan_video, decode_codecs, encode_codecs) = if !config.vulkan_video {
        (Some(false), &[][..], &[][..])
    } else if let Some(caps) = worker_capabilities {
        (
            caps.vulkan_video,
            caps.vulkan_video_decode_codecs.as_slice(),
            caps.vulkan_video_encode_codecs.as_slice(),
        )
    } else {
        (None, &[][..], &[][..])
    };

    argv::WorkerVulkanCapabilities {
        vulkan_compute,
        vulkan_video,
        vulkan_video_decode_codecs: decode_codecs,
        vulkan_video_encode_codecs: encode_codecs,
    }
}

fn validate_worker_vulkan_requirements(
    capability: &Capability,
    vulkan: &argv::WorkerVulkanCapabilities<'_>,
) -> Result<(), String> {
    if capability.requires_vulkan_compute && vulkan.vulkan_compute == Some(false) {
        return Err("Vulkan Compute is disabled or unavailable on this worker".to_string());
    }
    if capability.requires_vulkan_video {
        if vulkan.vulkan_video == Some(false) {
            return Err("Vulkan Video is disabled or unavailable on this worker".to_string());
        }
        if capability.requires_vulkan_video_decode
            && (vulkan.vulkan_video == Some(true) || !vulkan.vulkan_video_decode_codecs.is_empty())
        {
            if vulkan.vulkan_video_decode_codecs.is_empty() {
                return Err("worker does not support Vulkan Video hardware decode".to_string());
            }
            if let Some(req_dec) = capability.required_hw_decoder() {
                if !vulkan
                    .vulkan_video_decode_codecs
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(req_dec))
                {
                    return Err(format!(
                        "worker does not support Vulkan Video decode for codec '{req_dec}'"
                    ));
                }
            } else if let Some(raw_dec) = capability.decoder.as_deref() {
                return Err(format!(
                    "worker does not support Vulkan Video decode for decoder '{raw_dec}'"
                ));
            }
        }
        if (vulkan.vulkan_video == Some(true) || !vulkan.vulkan_video_encode_codecs.is_empty())
            && capability
                .required_encoder()
                .is_some_and(|e| e.to_ascii_lowercase().ends_with("_vulkan"))
        {
            if let Some(enc) = capability.required_encoder() {
                let lower = enc.to_ascii_lowercase();
                let mapped = match lower.strip_suffix("_vulkan") {
                    Some("h264") => Some("h264"),
                    Some("hevc") => Some("hevc"),
                    Some("av1") => Some("av1"),
                    _ => None,
                };
                let supported = mapped.is_some_and(|codec| {
                    vulkan
                        .vulkan_video_encode_codecs
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(codec))
                });
                if !supported {
                    return Err(format!(
                        "worker does not support Vulkan Video encoder '{enc}'"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn adapt_worker_args(
    args: &[String],
    capability: &Capability,
    config: &WorkerConfig,
    worker_capabilities: Option<&TranscodeCapabilities>,
    detected_nodes: &[RenderNode],
) -> Result<Vec<String>, String> {
    let mode = config.adapt_backend_mode;
    let fallback_encoders;
    let (worker_encoders, worker_hw_decoders): (&[String], &[String]) =
        if let Some(caps) = worker_capabilities.filter(|c| !c.encoders.is_empty()) {
            (&caps.encoders, &caps.hw_decoders)
        } else {
            fallback_encoders =
                synthesize_fallback_encoders(detected_nodes, capability, config.vulkan_video);
            (&fallback_encoders, &[])
        };
    let vulkan_caps = effective_worker_vulkan_capabilities(config, worker_capabilities);

    match argv::plan_backend_adaptation_with_vulkan(
        args,
        capability,
        mode,
        worker_encoders,
        worker_hw_decoders,
        detected_nodes,
        &vulkan_caps,
    ) {
        Some(AdaptedTargetBackend::Native) => {
            if !capability.render_nodes.is_empty() {
                let Some(selected_node) =
                    capabilities::select_render_node(capability, detected_nodes)
                else {
                    return Err(format!(
                        "no suitable DRM render node available on worker for {:?}",
                        capability.hwaccel
                    ));
                };
                let Some(selected_str) = selected_node.to_str() else {
                    return Err("selected render node path is not valid UTF-8".to_string());
                };
                Ok(argv::rewrite_any_render_node(args, selected_str))
            } else {
                Ok(args.to_vec())
            }
        }
        Some(AdaptedTargetBackend::Vaapi) => {
            let vaapi_cap = Capability {
                hwaccel: Some(HwAccel::Vaapi),
                required_hwaccels: vec![HwAccel::Vaapi],
                requires_vaapi_tonemap: capability.requires_vaapi_tonemap,
                ..Default::default()
            };
            let Some(vaapi_node) = capabilities::select_render_node(&vaapi_cap, detected_nodes)
            else {
                return Err(format!(
                    "no suitable VA-API DRM render node available on worker (adaptation mode {})",
                    mode.as_str()
                ));
            };
            let Some(node_str) = vaapi_node.to_str() else {
                return Err("selected VA-API render node path is not valid UTF-8".to_string());
            };
            argv::adapt_args_for_backend(args, AdaptedTargetBackend::Vaapi, Some(node_str))
        }
        Some(AdaptedTargetBackend::Qsv) => {
            let Some(intel_node) = select_intel_node(detected_nodes) else {
                return Err(format!(
                    "no suitable Intel QSV DRM render node available on worker (adaptation mode {})",
                    mode.as_str()
                ));
            };
            let Some(node_str) = intel_node.to_str() else {
                return Err("selected Intel QSV render node path is not valid UTF-8".to_string());
            };
            argv::adapt_args_for_backend(args, AdaptedTargetBackend::Qsv, Some(node_str))
        }
        Some(AdaptedTargetBackend::Cpu) => {
            argv::adapt_args_for_backend(args, AdaptedTargetBackend::Cpu, None)
        }
        None => Err(format!(
            "no suitable worker backend available for {:?} (adaptation mode {})",
            capability.hwaccel,
            mode.as_str()
        )),
    }
}

async fn handle_connection(
    stream: UnixStream,
    config: Arc<WorkerConfig>,
    real_ffmpeg: Arc<PathBuf>,
    worker_capabilities: Arc<Option<TranscodeCapabilities>>,
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

    // Infer required hardware capability, apply optional backend adaptation, and rewrite DRM render node.
    let capability = argv::required_capability(&start_req.args);
    let rewritten_args = if config.adapt_backend_mode == BackendAdaptMode::Off {
        let vulkan_caps =
            effective_worker_vulkan_capabilities(&config, worker_capabilities.as_ref().as_ref());
        if let Err(reason) = validate_worker_vulkan_requirements(&capability, &vulkan_caps) {
            send_error_and_close(
                &mut writer,
                ErrorKind::DeviceUnavailable,
                reason,
                config.frame_write_timeout,
            )
            .await;
            return;
        }
        if capability.requires_hardware() {
            let detected_nodes = resolve_worker_render_nodes(&config);
            let Some(selected_node) =
                capabilities::select_render_node(&capability, &detected_nodes)
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
            if !capability.render_nodes.is_empty() {
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
            }
        } else {
            start_req.args.clone()
        }
    } else {
        let detected_nodes = resolve_worker_render_nodes(&config);
        match adapt_worker_args(
            &start_req.args,
            &capability,
            &config,
            worker_capabilities.as_ref().as_ref(),
            &detected_nodes,
        ) {
            Ok(args) => args,
            Err(reason) => {
                send_error_and_close(
                    &mut writer,
                    ErrorKind::DeviceUnavailable,
                    reason,
                    config.frame_write_timeout,
                )
                .await;
                return;
            }
        }
    };

    // Optional Vulkan libplacebo scale-before-tonemap optimization.
    let rewritten_args = if config.optimize_vulkan_tonemap && config.vulkan_compute {
        argv::optimize_vulkan_tonemap_args(&rewritten_args)
    } else {
        rewritten_args
    };

    // Optional worker-local FFmpeg thread cap.
    let rewritten_args = if let Some(max_threads) = config.ffmpeg_max_threads {
        argv::apply_ffmpeg_thread_cap(&rewritten_args, max_threads)
    } else {
        rewritten_args
    };

    // Defense-in-depth re-validation after argument rewrites.
    if let Err(reason) = argv::validate_worker_args(&rewritten_args) {
        send_error_and_close(
            &mut writer,
            ErrorKind::InvalidRequest,
            format!("adapted worker arguments failed safety validation: {reason}"),
            config.frame_write_timeout,
        )
        .await;
        return;
    }

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
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        pg_guard.disarm();
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
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        pg_guard.disarm();
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
    drop(job_permit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn unique_worker_test_dir(tag: &str) -> PathBuf {
        let seq = TEMP_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(format!("/tmp/af-wtest-{tag}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .expect("create test dir");
        dir
    }

    #[test]
    fn ensure_safe_mesa_shader_cache_dir_creates_clean_dir_and_refuses_symlinks_and_bounds() {
        let dir = unique_worker_test_dir("mesa-cache");

        // 1. Clean nested path is created and validated.
        let clean = dir.join("nested/shader/cache");
        let canonical = ensure_safe_mesa_shader_cache_dir(&clean).expect("create clean cache dir");
        assert!(clean.is_dir());
        assert_eq!(canonical, fs::canonicalize(&clean).unwrap());

        // 2. Symlinked leaf path is refused.
        let target_dir = dir.join("real-target");
        fs::create_dir(&target_dir).unwrap();
        let symlink_leaf = dir.join("sym-leaf");
        symlink(&target_dir, &symlink_leaf).unwrap();
        assert!(
            ensure_safe_mesa_shader_cache_dir(&symlink_leaf).is_err(),
            "symlinked leaf cache path must be refused"
        );

        // 3. Symlinked ancestor parent is refused and MUST NOT create child dirs through the symlink.
        let symlink_child = symlink_leaf.join("should-not-exist/deep");
        assert!(
            ensure_safe_mesa_shader_cache_dir(&symlink_child).is_err(),
            "symlinked parent component must be refused"
        );
        assert!(
            !target_dir.join("should-not-exist").exists(),
            "must never create directories through a symlinked parent"
        );

        // 4. Root `/`, relative paths, `..` traversal, regular file component, and >4096-byte paths are refused.
        assert!(ensure_safe_mesa_shader_cache_dir(Path::new("/")).is_err());
        assert!(ensure_safe_mesa_shader_cache_dir(Path::new("relative/cache")).is_err());
        assert!(ensure_safe_mesa_shader_cache_dir(&dir.join("../escape")).is_err());

        let regular_file = dir.join("not-a-dir");
        fs::write(&regular_file, b"x").unwrap();
        assert!(ensure_safe_mesa_shader_cache_dir(&regular_file.join("sub")).is_err());

        let long_path = PathBuf::from(format!("/{}", "a".repeat(MAX_MESA_SHADER_CACHE_DIR_BYTES)));
        assert!(ensure_safe_mesa_shader_cache_dir(&long_path).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_worker_vulkan_requirements_fails_closed_on_unrecognized_vulkan_decoders() {
        let decode_codecs = vec!["h264".to_string(), "hevc".to_string(), "av1".to_string()];
        let encode_codecs = vec!["h264".to_string()];
        let vk_caps = argv::WorkerVulkanCapabilities {
            vulkan_compute: Some(true),
            vulkan_video: Some(true),
            vulkan_video_decode_codecs: &decode_codecs,
            vulkan_video_encode_codecs: &encode_codecs,
        };

        for bad_dec in ["ffv1_vulkan", "prores_vulkan", "mpeg4"] {
            let cap = argv::required_capability(&[
                "-init_hw_device",
                "vulkan=vk",
                "-hwaccel",
                "vulkan",
                "-c:v",
                bad_dec,
                "-i",
                "/srv/media/in.mkv",
                "-c:v",
                "h264_vulkan",
                "out.m3u8",
            ]);
            assert!(
                validate_worker_vulkan_requirements(&cap, &vk_caps).is_err(),
                "unrecognized Vulkan Video decoder '{bad_dec}' must fail closed"
            );
        }

        let valid_cap = argv::required_capability(&[
            "-init_hw_device",
            "vulkan=vk",
            "-hwaccel",
            "vulkan",
            "-c:v",
            "av1",
            "-i",
            "/srv/media/in.mkv",
            "-c:v",
            "h264_vulkan",
            "out.m3u8",
        ]);
        assert!(validate_worker_vulkan_requirements(&valid_cap, &vk_caps).is_ok());
    }

    #[test]
    fn synthesize_fallback_encoders_includes_av1_vulkan_and_adapt_honors_probed_vulkan_with_empty_encoders(
    ) {
        let amd_nodes = vec![RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some(PCI_VENDOR_AMD.to_string()),
        }];
        let cap_av1 = argv::required_capability(&[
            "-init_hw_device",
            "vulkan=vk",
            "-i",
            "/srv/media/in.mkv",
            "-c:v",
            "av1_vulkan",
            "out.m3u8",
        ]);

        let encs_enabled = synthesize_fallback_encoders(&amd_nodes, &cap_av1, true);
        assert!(encs_enabled.iter().any(|e| e == "h264_vulkan"));
        assert!(encs_enabled.iter().any(|e| e == "hevc_vulkan"));
        assert!(encs_enabled.iter().any(|e| e == "av1_vulkan"));

        let encs_disabled = synthesize_fallback_encoders(&amd_nodes, &cap_av1, false);
        assert!(!encs_disabled.iter().any(|e| e.ends_with("_vulkan")));

        // When probed `TranscodeCapabilities` has empty `encoders` (minimal mock ffmpeg) but valid
        // probed Vulkan fields, `adapt_worker_args` falls back to synthesized encoders while still
        // enforcing probed Vulkan Video codecs and Vulkan Compute availability.
        let mut cfg = WorkerConfig::for_paths(
            PathBuf::from("/tmp/unused.sock"),
            PathBuf::from("/usr/bin/true"),
        );
        cfg.adapt_backend_mode = BackendAdaptMode::Gpu;
        cfg.vulkan_compute = true;
        cfg.vulkan_video = true;

        let probed_empty_encoders = TranscodeCapabilities {
            encoders: Vec::new(),
            vulkan_compute: Some(false),
            vulkan_video: Some(true),
            vulkan_video_decode_codecs: vec!["h264".into()],
            vulkan_video_encode_codecs: vec!["av1".into()],
            ..Default::default()
        };

        let av1_args: Vec<String> = [
            "-init_hw_device",
            "vulkan=vk",
            "-i",
            "/srv/media/in.mkv",
            "-c:v",
            "av1_vulkan",
            "out.m3u8",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert!(
            adapt_worker_args(
                &av1_args,
                &cap_av1,
                &cfg,
                Some(&probed_empty_encoders),
                &amd_nodes,
            )
            .is_ok(),
            "av1_vulkan should be synthesized in fallback encoders and accepted when probed encode codecs contain av1"
        );

        let placebo_args: Vec<String> = [
            "-init_hw_device",
            "vulkan=vk",
            "-i",
            "/srv/media/in.mkv",
            "-vf",
            "format=p010,hwupload,libplacebo=tonemapping=bt.2390:format=nv12,hwdownload,format=nv12",
            "-c:v",
            "libx264",
            "out.m3u8",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let cap_placebo = argv::required_capability(&placebo_args);
        assert!(
            adapt_worker_args(
                &placebo_args,
                &cap_placebo,
                &cfg,
                Some(&probed_empty_encoders),
                &amd_nodes,
            )
            .is_err(),
            "probed vulkan_compute=Some(false) must still be enforced when caps.encoders is empty"
        );
    }
}
