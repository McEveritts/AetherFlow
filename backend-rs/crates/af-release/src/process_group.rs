//! Bounded subprocess execution with supervised process-group cleanup (`SEC-02`).
//!
//! This is the crate-DAG-lowest home of the `tokio` + `libc` process-group
//! supervisor (`af-runner -> af-release -> af-models`), so `af-release` itself
//! and every crate above it share one implementation.
//!
//! Guarantees:
//! - Every child is spawned as the leader of a fresh process group
//!   (`process_group(0)`) with `kill_on_drop(true)`.
//! - stdout and stderr are captured with a hard byte cap; exceeding it is an
//!   error (`InvalidData`), never silent truncation of a "successful" result.
//! - A timeout is never success (`TimedOut`; resulting state is unconfirmed).
//! - When the command finishes, times out, is cancelled by its caller, or the
//!   owning [`SupervisorRegistry`] shuts down, the whole group is `SIGKILL`ed
//!   (`kill(-pgid)`) and the supervisor keeps the [`Command`] (including any
//!   inherited-lock clone captured by a `pre_exec` closure) and any caller
//!   guard alive until no live member of the group remains.
//! - Supervisors outlive a cancelled caller, but are *tracked*: a daemon can
//!   [`SupervisorRegistry::shutdown`] to cancel all of them and await every
//!   `-pgid` reap before exiting.

use af_models::secret_zeroize::SecretBytes;
use std::future::Future;
use std::io;
use std::process::{ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

const GROUP_REAP_POLL: Duration = Duration::from_millis(25);
/// How long a supervisor withholds its result waiting for the group to die
/// before reporting and continuing cleanup detached (but still tracked).
const GROUP_REAP_GRACE: Duration = Duration::from_millis(500);
/// Upper bound [`output_blocking`] waits for detached group cleanup before
/// returning while leaving the supervisor running on the shared blocking runtime.
const BLOCKING_REAP_CEILING: Duration = Duration::from_secs(5);

fn blocking_supervisor_runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    static INIT_LOCK: Mutex<()> = Mutex::new(());
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("af-process-group")
        .enable_all()
        .build()?;
    let _ = RUNTIME.set(rt);
    Ok(RUNTIME
        .get()
        .expect("blocking supervisor runtime initialized"))
}

// ---------------------------------------------------------------------------
// Supervisor registry
// ---------------------------------------------------------------------------

/// Tracks live process supervisors so shutdown can cancel and await them.
///
/// Cloning yields another handle to the same registry.
#[derive(Clone)]
pub struct SupervisorRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    state: Mutex<RegistryState>,
    idle: Notify,
    cancel: watch::Sender<bool>,
}

#[derive(Default)]
struct RegistryState {
    active: usize,
    shutting_down: bool,
}

/// Outcome of [`SupervisorRegistry::shutdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// `true` when every tracked supervisor finished (all groups reaped)
    /// before the deadline.
    pub drained: bool,
    /// Supervisors still running when `shutdown` returned.
    pub remaining: usize,
}

impl Default for SupervisorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SupervisorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorRegistry")
            .field("active", &self.active())
            .field("shutting_down", &self.is_shutting_down())
            .finish()
    }
}

impl SupervisorRegistry {
    /// Creates an independent (scoped) registry.
    pub fn new() -> Self {
        let (cancel, _) = watch::channel(false);
        Self {
            inner: Arc::new(RegistryInner {
                state: Mutex::new(RegistryState::default()),
                idle: Notify::new(),
                cancel,
            }),
        }
    }

    /// Number of supervisors currently tracked (including detached cleanup).
    pub fn active(&self) -> usize {
        self.inner.lock_state().active
    }

    pub fn is_shutting_down(&self) -> bool {
        self.inner.lock_state().shutting_down
    }

    /// Stops admitting new supervisors, signals every tracked supervisor to
    /// cancel (killing its process group), and waits up to `deadline` for all
    /// of them to finish reaping.
    pub async fn shutdown(&self, deadline: Duration) -> ShutdownReport {
        self.inner.lock_state().shutting_down = true;
        self.inner.cancel.send_replace(true);
        let drained = tokio::time::timeout(deadline, self.wait_idle())
            .await
            .is_ok();
        ShutdownReport {
            drained,
            remaining: self.active(),
        }
    }

    async fn wait_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Spawns a detached, tracked task. `task` receives a [`ShutdownSignal`]
    /// that resolves when the registry begins shutting down; the registry's
    /// [`shutdown`](Self::shutdown) awaits the task's completion.
    pub fn spawn_tracked<F, Fut>(&self, task: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce(ShutdownSignal) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let ticket = self.register()?;
        let signal = ShutdownSignal {
            receiver: ticket.cancel.clone(),
        };
        let fut = task(signal);
        Ok(tokio::spawn(async move {
            let _ticket = ticket;
            fut.await;
        }))
    }

    fn register(&self) -> io::Result<SupervisorTicket> {
        let mut state = self.inner.lock_state();
        if state.shutting_down {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "process supervisor registry is shutting down; refusing to spawn",
            ));
        }
        state.active += 1;
        drop(state);
        Ok(SupervisorTicket {
            registry: Arc::clone(&self.inner),
            cancel: self.inner.cancel.subscribe(),
        })
    }
}

impl RegistryInner {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Process-wide registry used by the non-`_in` entry points. Daemons call
/// `global_registry().shutdown(..)` before exit.
pub fn global_registry() -> &'static SupervisorRegistry {
    static GLOBAL: OnceLock<SupervisorRegistry> = OnceLock::new();
    GLOBAL.get_or_init(SupervisorRegistry::new)
}

/// Resolves once the owning registry starts shutting down.
#[derive(Clone)]
pub struct ShutdownSignal {
    receiver: watch::Receiver<bool>,
}

impl ShutdownSignal {
    pub fn is_shutting_down(&self) -> bool {
        *self.receiver.borrow()
    }

    pub async fn cancelled(&mut self) {
        if self.receiver.wait_for(|value| *value).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

struct SupervisorTicket {
    registry: Arc<RegistryInner>,
    cancel: watch::Receiver<bool>,
}

impl SupervisorTicket {
    async fn cancelled(&mut self) {
        if self.cancel.wait_for(|value| *value).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for SupervisorTicket {
    fn drop(&mut self) {
        let mut state = self.registry.lock_state();
        state.active = state.active.saturating_sub(1);
        let idle = state.active == 0;
        drop(state);
        if idle {
            self.registry.idle.notify_waiters();
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded capture
// ---------------------------------------------------------------------------

/// Runs `command` to completion with captured stdout/stderr bounded to
/// `byte_limit` each, within `budget`, tracked by [`global_registry`].
///
/// stdin is `/dev/null`. The whole process group is killed and reaped before
/// this returns (or, for an unkillable task, cleanup continues detached while
/// still tracked).
pub async fn output(command: Command, budget: Duration, byte_limit: usize) -> io::Result<Output> {
    output_in(global_registry(), command, budget, byte_limit).await
}

/// [`output`] tracked by an explicit `registry`.
pub async fn output_in(
    registry: &SupervisorRegistry,
    command: Command,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<Output> {
    let (receive, _join) = spawn_capture(registry, command, None, budget, byte_limit)?;
    receive_outcome(receive).await
}

/// Like [`output`], but writes `stdin` to the child (then closes the pipe)
/// concurrently with output capture. The stdin buffer is zeroized after use,
/// so it may carry credentials that must not appear in argv or the
/// environment. Non-`BrokenPipe` stdin write failures return an error, while
/// `BrokenPipe` (child exited early) preserves the child's exit status and stderr.
pub async fn output_with_stdin(
    command: Command,
    stdin: Vec<u8>,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<Output> {
    output_with_stdin_in(global_registry(), command, stdin, budget, byte_limit).await
}

/// [`output_with_stdin`] tracked by an explicit `registry`.
pub async fn output_with_stdin_in(
    registry: &SupervisorRegistry,
    command: Command,
    stdin: Vec<u8>,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<Output> {
    let stdin = SecretBytes::new(stdin);
    let (receive, _join) = spawn_capture(registry, command, Some(stdin), budget, byte_limit)?;
    receive_outcome(receive).await
}

/// Synchronous [`output`] / [`output_with_stdin`] for blocking call sites.
///
/// Safe to call from any thread, including inside a Tokio runtime: the
/// supervisor runs on a persistent shared Tokio runtime tracked by
/// [`global_registry`]. Waits up to an additional 5 s for detached group
/// cleanup after the result is known, and keeps any still-wedged `'D'`-state
/// reaper alive, tracked, and reaping on the persistent runtime after return.
pub fn output_blocking(
    command: Command,
    stdin: Option<Vec<u8>>,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<Output> {
    let runtime = blocking_supervisor_runtime()?;
    let registry = global_registry().clone();
    let (res_tx, res_rx) = std::sync::mpsc::sync_channel::<io::Result<Output>>(1);
    let (reap_tx, reap_rx) = std::sync::mpsc::sync_channel::<()>(1);
    runtime.spawn(async move {
        let stdin = stdin.map(SecretBytes::new);
        let (receive, join) = match spawn_capture(&registry, command, stdin, budget, byte_limit) {
            Ok(handles) => handles,
            Err(err) => {
                let _ = res_tx.send(Err(err));
                let _ = reap_tx.send(());
                return;
            }
        };
        let result = receive_outcome(receive).await;
        let _ = res_tx.send(result);
        let _ = join.await;
        let _ = reap_tx.send(());
    });
    let result = res_rx.recv().map_err(|_| {
        io::Error::other("process-group supervisor task stopped before reporting an outcome")
    })?;
    let _ = reap_rx.recv_timeout(BLOCKING_REAP_CEILING);
    result
}

async fn receive_outcome<T>(receive: oneshot::Receiver<io::Result<T>>) -> io::Result<T> {
    receive
        .await
        .map_err(|_| io::Error::other("command supervisor stopped before reporting an outcome"))?
}

fn budget_exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "command execution budget exhausted",
    )
}

fn spawn_group_leader(command: &mut Command) -> io::Result<(Child, Option<u32>)> {
    command.kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn()?;
    let group = child.id();
    Ok((child, group))
}

type CaptureHandles = (oneshot::Receiver<io::Result<Output>>, JoinHandle<()>);

fn spawn_capture(
    registry: &SupervisorRegistry,
    mut command: Command,
    stdin: Option<SecretBytes>,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<CaptureHandles> {
    if budget.is_zero() {
        return Err(budget_exhausted());
    }
    let mut ticket = registry.register()?;
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (mut child, group) = spawn_group_leader(&mut command)?;
    #[cfg(target_os = "linux")]
    let pidfd = open_leader_pidfd(group);
    let pipes = (child.stdout.take(), child.stderr.take());
    let (Some(stdout), Some(stderr)) = pipes else {
        kill_group(group);
        let _ = child.start_kill();
        return Err(io::Error::other("child stdio pipes were not captured"));
    };
    let child_stdin = child.stdin.take();
    let (mut send, receive) = oneshot::channel();
    let join = tokio::spawn(async move {
        // Keep Command's pre_exec captures alive through child/group cleanup.
        let command = command;
        let io_result = {
            let work = async {
                let feed = feed_stdin(child_stdin, stdin.as_ref());
                #[cfg(target_os = "linux")]
                let ((), stdout, stderr, ()) = tokio::try_join!(
                    feed,
                    read_bounded(stdout, byte_limit),
                    read_bounded(stderr, byte_limit),
                    wait_leader_exit_without_reap(group, pidfd),
                )?;
                #[cfg(not(target_os = "linux"))]
                let ((), stdout, stderr) = tokio::try_join!(
                    feed,
                    read_bounded(stdout, byte_limit),
                    read_bounded(stderr, byte_limit),
                )?;
                Ok::<_, io::Error>((stdout, stderr))
            };
            tokio::select! {
                value = tokio::time::timeout(budget, work) => value.unwrap_or_else(|_| Err(timed_out())),
                _ = send.closed() => Err(caller_cancelled()),
                _ = ticket.cancelled() => Err(registry_cancelled()),
            }
        };
        drop(stdin);
        // Leader is still unreaped here, pinning PID/PGID `group` in the kernel so
        // `kill_group(group)` cannot signal a recycled PGID before `child.wait()` reaps it.
        // Bound both leader `child.wait()` and descendant `reap_group` under one `GROUP_REAP_GRACE`
        // early-report deadline so a `'D'`-state leader cannot hang callers indefinitely.
        let mut pending =
            finish_and_reap_group(group, &mut child, io_result, send, |status, io| match io {
                Ok((stdout, stderr)) => status.map(|status| Output {
                    status,
                    stdout,
                    stderr,
                }),
                Err(err) => Err(err),
            })
            .await;
        drop(command);
        if let Some((send, result)) = pending.take() {
            let _ = send.send(result);
        }
        drop(ticket);
    });
    Ok((receive, join))
}

async fn feed_stdin(
    pipe: Option<tokio::process::ChildStdin>,
    data: Option<&SecretBytes>,
) -> io::Result<()> {
    if let (Some(mut pipe), Some(data)) = (pipe, data) {
        if let Err(err) = pipe.write_all(data.expose_secret()).await {
            if err.kind() != io::ErrorKind::BrokenPipe {
                return Err(err);
            }
            return Ok(());
        }
        if let Err(err) = pipe.shutdown().await {
            if err.kind() != io::ErrorKind::BrokenPipe {
                return Err(err);
            }
        }
    }
    Ok(())
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "command execution timed out; resulting state is unconfirmed",
    )
}

fn caller_cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "command caller cancelled")
}

fn registry_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "command cancelled by process supervisor shutdown",
    )
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(output);
        }
        if count > limit.saturating_sub(output.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command output exceeded its capture limit",
            ));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn report_early_error<T, R>(
    send: &mut Option<oneshot::Sender<io::Result<R>>>,
    io_result: &mut Option<io::Result<T>>,
) {
    if let Some(tx) = send.take() {
        let early_err = match io_result.take() {
            Some(Err(err)) => err,
            _ => timed_out(),
        };
        let _ = tx.send(Err(early_err));
    }
}

/// Kills the group while the leader still pins its PGID, re-signals against
/// fork races while draining non-leader members before reaping the leader,
/// then awaits leader reaping and any fallback group exit under a single
/// `GROUP_REAP_GRACE` early-report deadline. If cleanup exceeds `GROUP_REAP_GRACE`,
/// the caller ALWAYS receives an error (never `Ok`) immediately while this detached
/// supervisor retains caller guards (`guard`, `command`, `ticket`) until full cleanup finishes.
async fn finish_and_reap_group<T, R, F>(
    group: Option<u32>,
    child: &mut Child,
    io_result: io::Result<T>,
    send: oneshot::Sender<io::Result<R>>,
    combine: F,
) -> Option<(oneshot::Sender<io::Result<R>>, io::Result<R>)>
where
    F: FnOnce(io::Result<ExitStatus>, io::Result<T>) -> io::Result<R>,
{
    finish_and_reap_group_with_grace(group, child, io_result, send, GROUP_REAP_GRACE, combine).await
}

async fn finish_and_reap_group_with_grace<T, R, F>(
    group: Option<u32>,
    child: &mut Child,
    io_result: io::Result<T>,
    send: oneshot::Sender<io::Result<R>>,
    grace: Duration,
    combine: F,
) -> Option<(oneshot::Sender<io::Result<R>>, io::Result<R>)>
where
    F: FnOnce(io::Result<ExitStatus>, io::Result<T>) -> io::Result<R>,
{
    kill_group(group);
    let force_kill_leader = io_result.is_err();
    if force_kill_leader {
        let _ = child.start_kill();
    }
    let deadline = tokio::time::Instant::now() + grace;
    let mut send = Some(send);
    let mut io_result = Some(io_result);

    #[cfg(target_os = "linux")]
    let mut need_post_reap_fallback = false;

    #[cfg(target_os = "linux")]
    if let Some(pid) = valid_pgid(group) {
        // Phase 1: Keep the leader unreaped (pinning PID/PGID `group` in the kernel)
        // until all leader threads exit, re-signalling on each poll tick to close
        // `kill(-pgid, SIGKILL)` vs `fork()` races.
        while !leader_exited_nowait(pid) {
            kill_group(group);
            if force_kill_leader {
                let _ = child.start_kill();
            }
            if send.is_some() && tokio::time::Instant::now() >= deadline {
                report_early_error(&mut send, &mut io_result);
            }
            tokio::select! {
                _ = tokio::time::sleep(GROUP_REAP_POLL) => {}
                _ = tokio::time::sleep_until(deadline), if send.is_some() => {
                    report_early_error(&mut send, &mut io_result);
                }
            }
        }

        // Phase 2: Leader is now a reapable zombie whose threads have all exited,
        // still pinning PID/PGID `group`. Drain every live non-leader member and
        // re-issue `kill_group(group)` safely before calling `child.wait()`.
        loop {
            match tokio::task::spawn_blocking(move || scan_proc_group_live(pid, Some(pid as u32)))
                .await
                .unwrap_or(ProcGroupScan::Unreadable)
            {
                ProcGroupScan::NoneLive => break,
                ProcGroupScan::Unreadable => {
                    // Issue one final PGID-pinned kill, then reap the zombie leader so
                    // `kill_group_exists(pid)` does not count the zombie leader itself.
                    kill_group(group);
                    need_post_reap_fallback = true;
                    break;
                }
                ProcGroupScan::Live => {
                    kill_group(group);
                    if send.is_some() && tokio::time::Instant::now() >= deadline {
                        report_early_error(&mut send, &mut io_result);
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(GROUP_REAP_POLL) => {}
                        _ = tokio::time::sleep_until(deadline), if send.is_some() => {
                            report_early_error(&mut send, &mut io_result);
                        }
                    }
                }
            }
        }
    }

    let status = {
        let wait_fut = child.wait();
        tokio::pin!(wait_fut);
        tokio::select! {
            status = &mut wait_fut => status,
            _ = tokio::time::sleep_until(deadline), if send.is_some() => {
                report_early_error(&mut send, &mut io_result);
                wait_fut.await
            }
        }
    };

    #[cfg(target_os = "linux")]
    let run_post_reap = need_post_reap_fallback;
    #[cfg(not(target_os = "linux"))]
    let run_post_reap = true;

    if run_post_reap {
        reap_group_until(group, deadline, || {
            report_early_error(&mut send, &mut io_result);
        })
        .await;
    }

    match (send.take(), io_result.take()) {
        (Some(tx), Some(io_res)) => Some((tx, combine(status, io_res))),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn open_leader_pidfd(group: Option<u32>) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let pgid = valid_pgid(group)?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pgid, 0 as libc::c_uint) };
    if raw >= 0 {
        // SAFETY: `pidfd_open` returned a fresh owned file descriptor (`O_CLOEXEC` is implicit).
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as libc::c_int) })
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn leader_exited_nowait(pid: libc::pid_t) -> bool {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return unsafe { info.si_pid() != 0 };
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return true;
    }
}

#[cfg(target_os = "linux")]
async fn wait_leader_exit_without_reap(
    group: Option<u32>,
    pidfd: Option<std::os::fd::OwnedFd>,
) -> io::Result<()> {
    use tokio::io::unix::AsyncFd;

    let Some(pid) = valid_pgid(group) else {
        return Ok(());
    };
    if let Some(fd) = pidfd {
        // SAFETY: `fd` is a fresh owned `pidfd` whose lifetime is governed exclusively by `async_fd`.
        let async_fd =
            unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE)? };
        loop {
            if leader_exited_nowait(pid) {
                return Ok(());
            }
            let mut guard = async_fd.readable().await?;
            if leader_exited_nowait(pid) {
                return Ok(());
            }
            guard.clear_ready();
        }
    }
    while !leader_exited_nowait(pid) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// Waits until no live member of `group` remains. If that takes longer than
/// `deadline`, `report_early` runs (so an unkillable kernel task cannot
/// hang the caller) and cleanup continues; the caller still drops its
/// exclusion captures only after this returns.
async fn reap_group_until(
    group: Option<u32>,
    deadline: tokio::time::Instant,
    report_early: impl FnOnce(),
) {
    if !tokio::task::spawn_blocking(move || group_is_live(group))
        .await
        .unwrap_or(false)
    {
        return;
    }
    let cleanup = async {
        while tokio::task::spawn_blocking(move || group_is_live(group))
            .await
            .unwrap_or(true)
        {
            tokio::time::sleep(GROUP_REAP_POLL).await;
        }
    };
    tokio::pin!(cleanup);
    tokio::select! {
        _ = &mut cleanup => {}
        _ = tokio::time::sleep_until(deadline) => {
            report_early();
            cleanup.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tracked streaming supervisor
// ---------------------------------------------------------------------------

/// Which pipe a [`StreamLine`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSource {
    Stdout,
    Stderr,
}

/// One output line (without its trailing `\n`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamLine {
    pub source: StreamSource,
    pub bytes: Vec<u8>,
    /// The line exceeded `max_line_bytes`; only the prefix is retained.
    pub truncated: bool,
}

/// Bounds for [`spawn_streaming`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    /// Wall-clock budget; exceeding it kills the group (`TimedOut`).
    pub budget: Duration,
    /// Longer lines are truncated to this many bytes (`truncated = true`).
    pub max_line_bytes: usize,
    /// Total bytes across stdout + stderr; exceeding it kills the group
    /// (`InvalidData`).
    pub max_total_bytes: usize,
    /// Capacity of the bounded line channel (backpressure on the child).
    pub channel_capacity: usize,
}

/// Handle to a detached, tracked streaming supervisor.
///
/// - Dropping `lines` does **not** stop the command: remaining output is
///   drained and discarded so the child never blocks on a full pipe.
/// - Dropping `outcome` (or calling [`cancel`](Self::cancel)) cancels the
///   command: its group is killed and reaped.
#[derive(Debug)]
pub struct StreamingSupervisor {
    pub lines: mpsc::Receiver<StreamLine>,
    pub outcome: oneshot::Receiver<io::Result<ExitStatus>>,
}

impl StreamingSupervisor {
    /// Discards remaining lines and waits for the exit status.
    pub async fn wait(self) -> io::Result<ExitStatus> {
        drop(self.lines);
        receive_outcome(self.outcome).await
    }

    /// Cancels the command; the supervisor kills and reaps its group.
    pub fn cancel(self) {
        drop(self);
    }
}

/// Spawns `command` (stdin `/dev/null`) under a detached supervisor tracked by
/// [`global_registry`], streaming bounded stdout/stderr lines over a bounded
/// channel. `guard` (e.g. a snapshot-lock guard) is owned by the supervisor
/// and dropped only after the whole process group has been reaped.
///
/// Must be called from within a Tokio runtime.
pub fn spawn_streaming<G: Send + 'static>(
    command: Command,
    limits: StreamLimits,
    guard: G,
) -> io::Result<StreamingSupervisor> {
    spawn_streaming_in(global_registry(), command, limits, guard)
}

/// [`spawn_streaming`] tracked by an explicit `registry`.
pub fn spawn_streaming_in<G: Send + 'static>(
    registry: &SupervisorRegistry,
    mut command: Command,
    limits: StreamLimits,
    guard: G,
) -> io::Result<StreamingSupervisor> {
    if limits.budget.is_zero() {
        return Err(budget_exhausted());
    }
    if limits.channel_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream channel capacity must be non-zero",
        ));
    }
    let mut ticket = registry.register()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (mut child, group) = spawn_group_leader(&mut command)?;
    #[cfg(target_os = "linux")]
    let pidfd = open_leader_pidfd(group);
    let pipes = (child.stdout.take(), child.stderr.take());
    let (Some(stdout), Some(stderr)) = pipes else {
        kill_group(group);
        let _ = child.start_kill();
        return Err(io::Error::other("child stdio pipes were not captured"));
    };
    let (line_tx, lines) = mpsc::channel(limits.channel_capacity);
    let (mut send, outcome) = oneshot::channel();
    tokio::spawn(async move {
        let command = command;
        let guard = guard;
        let total = AtomicUsize::new(0);
        let io_result = {
            let work = async {
                #[cfg(target_os = "linux")]
                let ((), (), ()) = tokio::try_join!(
                    pump_lines(
                        stdout,
                        StreamSource::Stdout,
                        line_tx.clone(),
                        &total,
                        limits
                    ),
                    pump_lines(
                        stderr,
                        StreamSource::Stderr,
                        line_tx.clone(),
                        &total,
                        limits
                    ),
                    wait_leader_exit_without_reap(group, pidfd),
                )?;
                #[cfg(not(target_os = "linux"))]
                let ((), ()) = tokio::try_join!(
                    pump_lines(
                        stdout,
                        StreamSource::Stdout,
                        line_tx.clone(),
                        &total,
                        limits
                    ),
                    pump_lines(
                        stderr,
                        StreamSource::Stderr,
                        line_tx.clone(),
                        &total,
                        limits
                    ),
                )?;
                Ok::<_, io::Error>(())
            };
            tokio::select! {
                value = tokio::time::timeout(limits.budget, work) => value.unwrap_or_else(|_| Err(timed_out())),
                _ = send.closed() => Err(caller_cancelled()),
                _ = ticket.cancelled() => Err(registry_cancelled()),
            }
        };
        drop(line_tx);
        // Leader is still unreaped here, pinning PID/PGID `group` until `kill_group` runs.
        let mut pending =
            finish_and_reap_group(group, &mut child, io_result, send, |status, io| match io {
                Ok(()) => status,
                Err(err) => Err(err),
            })
            .await;
        drop(guard);
        drop(command);
        if let Some((send, result)) = pending.take() {
            let _ = send.send(result);
        }
        drop(ticket);
    });
    Ok(StreamingSupervisor { lines, outcome })
}

async fn pump_lines(
    mut reader: impl AsyncRead + Unpin,
    source: StreamSource,
    tx: mpsc::Sender<StreamLine>,
    total: &AtomicUsize,
    limits: StreamLimits,
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    let mut line = Vec::new();
    let mut truncated = false;
    let mut forward = true;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            if !line.is_empty() || truncated {
                emit_line(&tx, &mut forward, source, &mut line, &mut truncated).await;
            }
            return Ok(());
        }
        let previous = total.fetch_add(count, Ordering::Relaxed);
        if previous.saturating_add(count) > limits.max_total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "streamed command output exceeded its total capture limit",
            ));
        }
        for segment in buffer[..count].split_inclusive(|byte| *byte == b'\n') {
            let (content, terminated) = match segment.split_last() {
                Some((b'\n', rest)) => (rest, true),
                _ => (segment, false),
            };
            let room = limits.max_line_bytes.saturating_sub(line.len());
            if content.len() > room {
                line.extend_from_slice(&content[..room]);
                truncated = true;
            } else {
                line.extend_from_slice(content);
            }
            if terminated {
                emit_line(&tx, &mut forward, source, &mut line, &mut truncated).await;
            }
        }
    }
}

async fn emit_line(
    tx: &mpsc::Sender<StreamLine>,
    forward: &mut bool,
    source: StreamSource,
    line: &mut Vec<u8>,
    truncated: &mut bool,
) {
    let bytes = std::mem::take(line);
    let was_truncated = std::mem::replace(truncated, false);
    if *forward
        && tx
            .send(StreamLine {
                source,
                bytes,
                truncated: was_truncated,
            })
            .await
            .is_err()
    {
        // Consumer went away: keep draining so the child cannot block.
        *forward = false;
    }
}

// ---------------------------------------------------------------------------
// Group primitives
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn valid_pgid(group: Option<u32>) -> Option<libc::pid_t> {
    group
        .filter(|&g| g > 1 && g <= libc::pid_t::MAX as u32)
        .map(|g| g as libc::pid_t)
}

#[cfg(unix)]
fn kill_group_exists(pgid: libc::pid_t) -> bool {
    let rc = unsafe { libc::kill(-pgid, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Sends `SIGKILL` to every member of process group `group` (no-op for `None`,
/// `<= 1`, `> pid_t::MAX`, and on non-Unix targets).
pub fn kill_group(group: Option<u32>) {
    #[cfg(unix)]
    if let Some(pgid) = valid_pgid(group) {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = group;
}

#[cfg(target_os = "linux")]
fn proc_stat_matches_group_and_live(stat: &str, group: u32) -> Option<bool> {
    let (_, rest) = stat.rsplit_once(") ")?;
    let fields: Vec<_> = rest.split_whitespace().take(18).collect();
    if fields.len() < 3 || fields[2].parse::<u32>().ok() != Some(group) {
        return None;
    }
    if !matches!(fields[0], "Z" | "X") {
        return Some(true);
    }
    // Field 20 (`fields[17]` after `) `) is `num_threads`. When the thread-group leader is `'Z'`
    // under Linux `delay_group_leader`, any remaining non-leader worker thread (`num_threads > 1`)
    // still holds shared `files_struct` descriptors and in-flight I/O.
    let num_threads = fields.get(17).and_then(|s| s.parse::<u32>().ok());
    if num_threads.is_none_or(|n| n > 1) {
        return Some(true);
    }
    Some(false)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcGroupScan {
    Live,
    NoneLive,
    Unreadable,
}

#[cfg(target_os = "linux")]
fn scan_proc_group_live(pgid: libc::pid_t, exclude_tgid: Option<u32>) -> ProcGroupScan {
    let group = pgid as u32;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return ProcGroupScan::Unreadable;
    };
    let mut saw_unreadable = false;
    for entry in entries.flatten() {
        let Ok(tgid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if exclude_tgid == Some(tgid) {
            continue;
        }
        let proc_dir = entry.path();
        match std::fs::read_to_string(proc_dir.join("stat")) {
            Ok(stat) => match proc_stat_matches_group_and_live(&stat, group) {
                Some(true) => return ProcGroupScan::Live,
                Some(false) => {
                    // Cross-check `/proc/<tgid>/task/<tid>/stat` in case a non-leader worker
                    // thread is still live or in `'D'` state while leader is `'Z'`.
                    match std::fs::read_dir(proc_dir.join("task")) {
                        Ok(tasks) => {
                            for task in tasks.flatten() {
                                if task.file_name().to_string_lossy().parse::<u32>().is_err() {
                                    continue;
                                }
                                match std::fs::read_to_string(task.path().join("stat")) {
                                    Ok(tstat) => {
                                        if let Some((_, tfields)) = tstat.rsplit_once(") ") {
                                            let tstate = tfields.split_whitespace().next();
                                            if !matches!(tstate, Some("Z" | "X")) {
                                                return ProcGroupScan::Live;
                                            }
                                        }
                                    }
                                    Err(error)
                                        if error.kind() == io::ErrorKind::NotFound
                                            || error.raw_os_error() == Some(libc::ESRCH) => {}
                                    Err(_) => {
                                        saw_unreadable = true;
                                    }
                                }
                            }
                        }
                        Err(error)
                            if error.kind() == io::ErrorKind::NotFound
                                || error.raw_os_error() == Some(libc::ESRCH) => {}
                        Err(_) => {
                            saw_unreadable = true;
                        }
                    }
                }
                None => {}
            },
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(_) => {
                saw_unreadable = true;
            }
        }
    }
    if saw_unreadable {
        ProcGroupScan::Unreadable
    } else {
        ProcGroupScan::NoneLive
    }
}

/// Returns whether any non-zombie member (including non-leader threads in `/proc/<tgid>/task`)
/// of process group `group` exists.
///
/// On Linux this scans procfs because killed single-thread orphan zombies cannot retain
/// descriptors, while `kill(-pgid, 0)` would count them as alive and keep an otherwise-free
/// lock forever. If a thread-group leader is `'Z'` with `num_threads > 1` or any live task in
/// `/proc/<tgid>/task`, the group is treated as live because shared `files_struct` descriptors
/// remain open until the last thread exits. If procfs cannot be inspected (or unreadable
/// entries prevent proving absence) it falls back to `kill(-pgid, 0)` (treating `EPERM` as
/// alive) so exclusion is never released while the OS reports the group exists.
/// Blocking: call via `spawn_blocking` from async code.
pub fn group_is_live(group: Option<u32>) -> bool {
    #[cfg(unix)]
    let Some(pgid) = valid_pgid(group) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        match scan_proc_group_live(pgid, None) {
            ProcGroupScan::Live => true,
            ProcGroupScan::NoneLive => false,
            ProcGroupScan::Unreadable => kill_group_exists(pgid),
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        kill_group_exists(pgid)
    }
    #[cfg(not(unix))]
    {
        let _ = group;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::lock::ReleaseLockGuard;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/bash");
        command.args(["-c", script]);
        command
    }

    fn scratch(prefix: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        root
    }

    async fn wait_for(path: &Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() || std::fs::read_to_string(path).unwrap_or_default().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    fn read_pid(path: &Path) -> i32 {
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn pid_alive(pid: i32) -> bool {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| !matches!(fields.split_whitespace().next(), Some("Z" | "X")))
    }

    async fn assert_dead_soon(pid: i32) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while pid_alive(pid) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("descendant pid={pid} survived group kill"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_commands_release_inherited_locks_before_returning() {
        let test =
            "process_group::tests::completed_commands_release_inherited_locks_before_returning";
        if std::env::var("AF_COMPLETED_COMMAND_TEST_CHILD").as_deref() != Ok(test) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env("AF_COMPLETED_COMMAND_TEST_CHILD", test)
                .status()
                .unwrap()
                .success());
            return;
        }
        let root = scratch("af-pg-release");
        let lock = root.join("maintenance.lock");
        for iteration in 0..128 {
            let guard = ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
            let mut command = shell(if iteration % 2 == 0 {
                "exit 0"
            } else {
                "exit 7"
            });
            guard.preserve_in_child(command.as_std_mut()).unwrap();
            drop(guard);
            let result = output(command, Duration::from_secs(5), 1024).await.unwrap();
            assert_eq!(
                result.status.code(),
                Some(if iteration % 2 == 0 { 0 } else { 7 })
            );
            let released = ReleaseLockGuard::acquire(&lock, Duration::ZERO);
            assert!(
                released.is_ok(),
                "completed command retained its lock: {released:?}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn captures_nonzero_status_and_refuses_unbounded_output() {
        let out = output(
            shell("printf ok; printf diagnostic >&2; exit 7"),
            Duration::from_secs(5),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(out.stdout, b"ok");
        assert_eq!(out.stderr, b"diagnostic");
        for script in ["yes", "yes >&2"] {
            let error = output(shell(script), Duration::from_secs(5), 64)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        // Exactly at the cap is accepted.
        let out = output(shell("head -c 64 /dev/zero"), Duration::from_secs(5), 64)
            .await
            .unwrap();
        assert_eq!(out.stdout.len(), 64);
    }

    #[tokio::test]
    async fn zero_budget_is_rejected_without_spawning() {
        let root = scratch("af-pg-zero");
        let marker = root.join("ran");
        let mut command = shell("touch \"$AF_MARKER\"");
        command.env("AF_MARKER", &marker);
        let error = output(command, Duration::ZERO, 1024).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn timeout_and_cancellation_kill_descendants_and_release_guard_only_after_cleanup() {
        for cancel in [false, true] {
            let root = scratch("af-pg-timeout");
            let lock = root.join("maintenance.lock");
            let pid_file = root.join("child.pid");
            let guard = ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
            let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
            command.env("AF_CHILD_PID", &pid_file);
            guard.preserve_in_child(command.as_std_mut()).unwrap();
            let task = tokio::spawn(output(command, Duration::from_millis(300), 1024));
            wait_for(&pid_file).await;
            let child = read_pid(&pid_file);
            drop(guard);
            assert!(ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err());
            if cancel {
                task.abort();
                let _ = task.await;
            } else {
                assert_eq!(
                    task.await.unwrap().unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while pid_alive(child) || ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err()
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn child_retaining_a_pipe_after_leader_exit_is_still_bounded() {
        let error = output(shell("sleep 60 & exit 0"), Duration::from_millis(100), 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn successful_command_with_closed_stdio_background_descendant_kills_group_before_return()
    {
        let root = scratch("af-pg-succ");
        let pid_file = root.join("descendant.pid");
        let mut command =
            shell("nohup sleep 60 >/dev/null 2>&1 </dev/null & echo $! > \"$AF_BG_PID\"; exit 0");
        command.env("AF_BG_PID", &pid_file);
        let out = output(command, Duration::from_secs(5), 1024).await.unwrap();
        assert!(out.status.success());
        let child_pid = read_pid(&pid_file);
        assert!(
            !pid_alive(child_pid),
            "background descendant pid={child_pid} stayed alive after output() returned"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stdin_is_delivered_then_closed() {
        let payload = b"{\"username\":\"admin\",\"password\":\"s3cr3t\"}".to_vec();
        let out = output_with_stdin(shell("cat"), payload.clone(), Duration::from_secs(5), 1024)
            .await
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, payload);

        // Large stdin is written concurrently with output capture (no deadlock).
        let big = vec![b'a'; 1024 * 1024];
        let out = output_with_stdin(
            shell("cat; cat >&2 </dev/null"),
            big.clone(),
            Duration::from_secs(10),
            2 * 1024 * 1024,
        )
        .await
        .unwrap();
        assert_eq!(out.stdout.len(), big.len());
    }

    #[tokio::test]
    async fn stdin_child_timeout_kills_group() {
        let root = scratch("af-pg-stdin");
        let pid_file = root.join("child.pid");
        let mut command = shell("cat >/dev/null; sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let error = output_with_stdin(command, b"x".to_vec(), Duration::from_millis(300), 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pid = read_pid(&pid_file);
        assert_dead_soon(pid).await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registry_shutdown_cancels_and_awaits_group_reap() {
        let registry = SupervisorRegistry::new();
        let root = scratch("af-pg-registry");
        let pid_file = root.join("child.pid");
        let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let task = {
            let registry = registry.clone();
            tokio::spawn(async move {
                output_in(&registry, command, Duration::from_secs(60), 1024).await
            })
        };
        wait_for(&pid_file).await;
        let pid = read_pid(&pid_file);
        assert_eq!(registry.active(), 1);

        let report = registry.shutdown(Duration::from_secs(5)).await;
        assert_eq!(
            report,
            ShutdownReport {
                drained: true,
                remaining: 0
            }
        );
        assert!(!pid_alive(pid), "shutdown returned before -pgid reap");
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );

        // A shut-down registry refuses to spawn anything new.
        let marker = root.join("ran");
        let mut late = shell("touch \"$AF_MARKER\"");
        late.env("AF_MARKER", &marker);
        let error = output_in(&registry, late, Duration::from_secs(5), 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(registry.spawn_tracked(|_| async {}).is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn registry_tracks_detached_tasks_until_they_observe_shutdown() {
        let registry = SupervisorRegistry::new();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        registry
            .spawn_tracked(move |mut signal| async move {
                signal.cancelled().await;
                assert!(signal.is_shutting_down());
                tokio::time::sleep(Duration::from_millis(50)).await;
                flag.store(true, Ordering::SeqCst);
            })
            .unwrap();
        assert_eq!(registry.active(), 1);
        let report = registry.shutdown(Duration::from_secs(5)).await;
        assert!(report.drained);
        assert!(finished.load(Ordering::SeqCst));

        // An empty registry drains immediately; a stuck task reports remaining.
        assert!(
            SupervisorRegistry::new()
                .shutdown(Duration::ZERO)
                .await
                .drained
        );
        let stuck = SupervisorRegistry::new();
        let handle = stuck
            .spawn_tracked(|_| std::future::pending::<()>())
            .unwrap();
        let report = stuck.shutdown(Duration::from_millis(50)).await;
        assert_eq!(
            report,
            ShutdownReport {
                drained: false,
                remaining: 1
            }
        );
        handle.abort();
        let _ = handle.await;
        assert_eq!(stuck.active(), 0, "aborted task must release its ticket");
    }

    #[tokio::test]
    async fn blocking_variant_works_inside_a_runtime_and_bounds_output() {
        let out = output_blocking(
            shell("cat; printf err >&2"),
            Some(b"payload".to_vec()),
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert_eq!(out.stdout, b"payload");
        assert_eq!(out.stderr, b"err");
        let error = output_blocking(shell("yes"), None, Duration::from_secs(5), 64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn blocking_variant_works_without_a_runtime_and_kills_group_on_timeout() {
        let root = scratch("af-pg-blocking");
        let pid_file = root.join("child.pid");
        let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let started = std::time::Instant::now();
        let error = output_blocking(command, None, Duration::from_millis(300), 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = read_pid(&pid_file);
        assert!(!pid_alive(pid), "blocking timeout left descendant alive");
        std::fs::remove_dir_all(root).unwrap();
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn limits(budget: Duration) -> StreamLimits {
        StreamLimits {
            budget,
            max_line_bytes: 8,
            max_total_bytes: 64 * 1024,
            channel_capacity: 4,
        }
    }

    #[tokio::test]
    async fn streaming_delivers_bounded_lines_and_releases_guard_after_exit() {
        let registry = SupervisorRegistry::new();
        let released = Arc::new(AtomicBool::new(false));
        let mut supervisor = spawn_streaming_in(
            &registry,
            shell("echo one; echo err >&2; printf 'abcdefghijklmnop\\ntail'"),
            limits(Duration::from_secs(5)),
            DropFlag(Arc::clone(&released)),
        )
        .unwrap();
        let mut lines = Vec::new();
        while let Some(line) = supervisor.lines.recv().await {
            lines.push(line);
        }
        let status = supervisor.wait().await.unwrap();
        assert!(status.success());
        assert!(released.load(Ordering::SeqCst));
        let stdout: Vec<_> = lines
            .iter()
            .filter(|line| line.source == StreamSource::Stdout)
            .map(|line| (line.bytes.clone(), line.truncated))
            .collect();
        assert_eq!(
            stdout,
            vec![
                (b"one".to_vec(), false),
                (b"abcdefgh".to_vec(), true),
                (b"tail".to_vec(), false),
            ]
        );
        assert!(lines
            .iter()
            .any(|line| line.source == StreamSource::Stderr && line.bytes == b"err"));
        assert_eq!(registry.active(), 0);
    }

    #[tokio::test]
    async fn streaming_timeout_kills_group_before_guard_release() {
        let registry = SupervisorRegistry::new();
        let root = scratch("af-pg-stream");
        let pid_file = root.join("child.pid");
        let released = Arc::new(AtomicBool::new(false));
        let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; echo started; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let supervisor = spawn_streaming_in(
            &registry,
            command,
            limits(Duration::from_millis(300)),
            DropFlag(Arc::clone(&released)),
        )
        .unwrap();
        wait_for(&pid_file).await;
        let pid = read_pid(&pid_file);
        let error = supervisor.wait().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!pid_alive(pid));
        assert!(released.load(Ordering::SeqCst));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn streaming_total_cap_cancel_and_shutdown_all_kill_group() {
        // Total byte cap.
        let registry = SupervisorRegistry::new();
        let supervisor =
            spawn_streaming_in(&registry, shell("yes"), limits(Duration::from_secs(5)), ())
                .unwrap();
        assert_eq!(
            supervisor.wait().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // Explicit cancel (dropping the outcome receiver).
        let root = scratch("af-pg-stream-cancel");
        let pid_file = root.join("child.pid");
        let released = Arc::new(AtomicBool::new(false));
        let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let supervisor = spawn_streaming_in(
            &registry,
            command,
            limits(Duration::from_secs(60)),
            DropFlag(Arc::clone(&released)),
        )
        .unwrap();
        wait_for(&pid_file).await;
        let pid = read_pid(&pid_file);
        supervisor.cancel();
        assert!(registry.shutdown(Duration::from_secs(5)).await.drained);
        assert!(!pid_alive(pid));
        assert!(released.load(Ordering::SeqCst));

        // Registry shutdown while the consumer is still attached.
        let registry = SupervisorRegistry::new();
        let pid_file = root.join("child2.pid");
        let mut command = shell("sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait");
        command.env("AF_CHILD_PID", &pid_file);
        let supervisor =
            spawn_streaming_in(&registry, command, limits(Duration::from_secs(60)), ()).unwrap();
        wait_for(&pid_file).await;
        let pid = read_pid(&pid_file);
        assert!(registry.shutdown(Duration::from_secs(5)).await.drained);
        assert!(!pid_alive(pid));
        assert_eq!(
            supervisor.wait().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn group_primitives_handle_absent_and_invalid_groups() {
        assert!(!group_is_live(None));
        assert!(!group_is_live(Some(0)));
        assert!(!group_is_live(Some(1)));
        assert!(!group_is_live(Some(u32::MAX)));
        assert!(!group_is_live(Some(0x8000_0000)));
        kill_group(None);
        kill_group(Some(0));
        kill_group(Some(1));
        kill_group(Some(u32::MAX));
        kill_group(Some(0x8000_0000));
    }

    #[tokio::test]
    async fn leader_closes_stdio_early_and_still_runs_to_exit() {
        // Verify waiting on leader exit without reaping still allows a leader that closes
        // stdout/stderr early to complete normally and return its true exit status.
        let out = output(
            shell("exec >/dev/null 2>&1; sleep 0.15; exit 7"),
            Duration::from_secs(5),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wave1b_r11_proc_stat_treats_zombie_leader_with_live_worker_threads_as_live() {
        // Format after `pid (comm) `: state(0) ppid(1) pgrp(2) ... num_threads(17)
        let mk = |state: &str, pgrp: u32, threads: u32| {
            format!(
                "4242 (worker) {state} 1 {pgrp} {pgrp} 0 -1 0 0 0 0 0 0 0 0 0 20 0 {threads} 0 100"
            )
        };
        assert_eq!(
            proc_stat_matches_group_and_live(&mk("Z", 777, 1), 777),
            Some(false)
        );
        assert_eq!(
            proc_stat_matches_group_and_live(&mk("Z", 777, 2), 777),
            Some(true)
        );
        assert_eq!(
            proc_stat_matches_group_and_live(&mk("D", 777, 1), 777),
            Some(true)
        );
        assert_eq!(
            proc_stat_matches_group_and_live(&mk("S", 888, 4), 777),
            None
        );
    }

    #[tokio::test]
    async fn wave1b_r12_early_report_converts_ok_to_timed_out_error() {
        let (tx, rx) = oneshot::channel::<io::Result<()>>();
        let mut send = Some(tx);
        let mut io_result: Option<io::Result<()>> = Some(Ok(()));
        report_early_error(&mut send, &mut io_result);
        assert!(send.is_none());
        let err = rx.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let (tx2, rx2) = oneshot::channel::<io::Result<()>>();
        let mut send2 = Some(tx2);
        let mut io_result2: Option<io::Result<()>> =
            Some(Err(io::Error::new(io::ErrorKind::InvalidData, "cap")));
        report_early_error(&mut send2, &mut io_result2);
        let err2 = rx2.await.unwrap().unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wave1b_r12_output_blocking_works_inside_tokio_runtime() {
        let out = output_blocking(shell("printf 'ok-r12'"), None, Duration::from_secs(5), 1024)
            .expect("output_blocking inside tokio runtime");
        assert!(out.status.success());
        assert_eq!(out.stdout, b"ok-r12");
    }
}
