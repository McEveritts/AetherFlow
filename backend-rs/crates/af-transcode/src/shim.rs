//! Jellyfin `ffmpeg` shim mode: probe bypass, 2 s handshake budget, no-duplicate-exec start rules,
//! non-blocking stdin forwarding (including EOF and held-open stdin), and signal forwarding.

use crate::argv;
use crate::config::{
    collect_allowed_env_subset, configured_dispatcher_socket_path, configured_handshake_timeout,
    configured_real_ffmpeg_path, validate_real_ffmpeg_path, ConfigError,
    DEFAULT_FRAME_WRITE_TIMEOUT, ENV_SHIM_RECURSION_GUARD,
};
use crate::protocol::{
    bounded_frame_channel, encode_framed, read_frame, write_frame, Frame, ProtocolError,
    SignalKind, StartRequest, MAX_IO_CHUNK_BYTES,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

/// Configuration for shim execution (supports isolated fixtures in tests).
#[derive(Debug, Clone)]
pub struct ShimConfig {
    pub real_ffmpeg: PathBuf,
    pub dispatcher_socket: PathBuf,
    pub handshake_timeout: Duration,
    pub frame_write_timeout: Duration,
}

impl ShimConfig {
    pub fn from_env() -> Self {
        Self {
            real_ffmpeg: configured_real_ffmpeg_path(),
            dispatcher_socket: configured_dispatcher_socket_path(),
            handshake_timeout: configured_handshake_timeout(),
            frame_write_timeout: DEFAULT_FRAME_WRITE_TIMEOUT,
        }
    }
}

/// Definite pre-start condition under which local `exec` of real `ffmpeg` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalFallbackReason {
    ProbeArgs,
    DispatcherUnavailable(String),
    PreSendFailure(String),
    DispatcherRunLocal,
}

/// Outcome of the shim protocol engine before process exit or local `exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimDecision {
    /// Safe to `exec` the configured real `ffmpeg` locally with original args.
    ExecLocal { reason: LocalFallbackReason },
    /// Remote worker executed the job and returned `Frame::Exit(code)`.
    RemoteExited(i32),
    /// Remote execution failed AFTER a complete `Frame::Start` was submitted (or after `Started`).
    /// The shim MUST NOT `exec` locally to avoid duplicate concurrent encodes.
    RemoteFailed { exit_code: i32, reason: String },
}

/// Normalizes a protocol `i32` exit code into a Unix process exit code (`0..=255`)
/// without ever turning a non-zero exit status (e.g. `256` or `-1`) into `0`.
pub fn normalize_exit_code(code: i32) -> i32 {
    if code == 0 {
        0
    } else if (1..=255).contains(&code) {
        code
    } else {
        let low = code & 0xff;
        if low == 0 {
            1
        } else {
            low
        }
    }
}

/// Replaces the current process with the validated real `ffmpeg` binary using the exact
/// original local arguments (no shell, anti-recursion guard armed).
pub fn exec_real_ffmpeg(
    real_ffmpeg: &Path,
    args: &[impl AsRef<OsStr>],
) -> Result<std::convert::Infallible, ConfigError> {
    if env::var_os(ENV_SHIM_RECURSION_GUARD).is_some() {
        return Err(ConfigError::ShimRecursionDetected);
    }
    let validated = validate_real_ffmpeg_path(real_ffmpeg)?;
    let err = StdCommand::new(&validated)
        .args(args)
        .env(ENV_SHIM_RECURSION_GUARD, "1")
        .exec();
    Err(ConfigError::Io {
        path: validated.display().to_string(),
        source: err,
    })
}

/// Runs the full shim entry point: enforces anti-recursion, talks to the dispatcher within
/// the 2 s handshake budget, either `exec`s real `ffmpeg` locally on definite pre-send/RunLocal
/// fallback, or relays stdio/signals and returns the final Unix exit code.
pub async fn run_shim(args: &[OsString], config: ShimConfig) -> i32 {
    if env::var_os(ENV_SHIM_RECURSION_GUARD).is_some() {
        let _ = writeln!(
            io::stderr(),
            "af-transcode: refusing recursive shim execution ({ENV_SHIM_RECURSION_GUARD} is set)"
        );
        return 1;
    }

    // Validate the real ffmpeg path up front so misconfiguration / self-recursion fails loudly
    // even on probe invocations or fallback paths.
    if let Err(err) = validate_real_ffmpeg_path(&config.real_ffmpeg) {
        let _ = writeln!(io::stderr(), "af-transcode: {err}");
        return 1;
    }

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let wire_args: Option<Vec<String>> = args
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect();
    let decision = match wire_args {
        Some(wire_args) => {
            run_shim_protocol(
                &wire_args,
                &config,
                io::stdin().as_raw_fd(),
                &mut stdout,
                &mut stderr,
            )
            .await
        }
        // The protocol uses UTF-8 strings. Unix ffmpeg can consume the original bytes locally.
        None => ShimDecision::ExecLocal {
            reason: LocalFallbackReason::PreSendFailure("argument is not UTF-8".to_string()),
        },
    };

    match decision {
        ShimDecision::ExecLocal { .. } => match exec_real_ffmpeg(&config.real_ffmpeg, args) {
            Ok(never) => match never {},
            Err(err) => {
                let _ = writeln!(
                    io::stderr(),
                    "af-transcode: failed to exec real ffmpeg: {err}"
                );
                1
            }
        },
        ShimDecision::RemoteExited(code) => normalize_exit_code(code),
        ShimDecision::RemoteFailed { exit_code, reason } => {
            let _ = writeln!(io::stderr(), "af-transcode: {reason}");
            let _ = stderr.flush();
            normalize_exit_code(exit_code)
        }
    }
}

/// Creates a close-on-exec OS pipe used to wake `poll(2)` in the stdin reader thread immediately
/// when the dispatcher finishes or disconnects, even if stdin remains open with no data.
fn create_cancel_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read_fd, write_fd))
}

struct StdinPumpHandle {
    cancel_write: Option<OwnedFd>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl StdinPumpHandle {
    fn spawn(stdin_fd: RawFd, tx: mpsc::Sender<Frame>) -> io::Result<Self> {
        let (cancel_read, cancel_write) = create_cancel_pipe()?;
        let thread = std::thread::Builder::new()
            .name("af-transcode-stdin".to_string())
            .spawn(move || {
                let cancel_raw = cancel_read.as_raw_fd();
                let mut buf = vec![0u8; MAX_IO_CHUNK_BYTES];
                loop {
                    let mut pfds = [
                        libc::pollfd {
                            fd: stdin_fd,
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: cancel_raw,
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];

                    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
                    if rc < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        break;
                    }

                    // Cancel pipe signaled or closed -> exit immediately without reading stdin.
                    if pfds[1].revents != 0 {
                        break;
                    }

                    let revents = pfds[0].revents;
                    if revents & libc::POLLNVAL != 0 {
                        break;
                    }
                    if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast(), buf.len()) };
                        if n < 0 {
                            let err = io::Error::last_os_error();
                            if err.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            break;
                        }
                        if n == 0 {
                            let _ = tx.blocking_send(Frame::StdinEof);
                            break;
                        }
                        if tx
                            .blocking_send(Frame::Stdin(buf[..n as usize].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                drop(cancel_read);
            })?;

        Ok(Self {
            cancel_write: Some(cancel_write),
            thread: Some(thread),
        })
    }

    fn stop_and_join(&mut self) {
        // Closing the write end immediately triggers POLLHUP on the poll() loop.
        let _ = self.cancel_write.take();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for StdinPumpHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Core shim protocol engine, separated from `exec()` for deterministic unit/integration testing.
///
/// Start-result safety contract:
/// 1. Probe args (`argv::is_probe`) -> `ExecLocal`.
/// 2. Any failure BEFORE all bytes of the framed `Frame::Start` have been written to the socket
///    (socket absent, connect timeout/error, cwd/encoding error, partial write) -> `ExecLocal`.
/// 3. Explicit `Frame::RunLocal` from the dispatcher within the 2 s budget -> `ExecLocal`.
/// 4. Once all bytes of `Frame::Start` are written, ANY timeout, EOF, protocol error, `Frame::Error`,
///    or dropped stream after `Frame::Started` -> close socket immediately (forcing cleanup) and
///    return `RemoteFailed` (NEVER `ExecLocal`) so duplicate remote + local encodes cannot happen.
pub async fn run_shim_protocol<WOut: Write, WErr: Write>(
    args: &[String],
    config: &ShimConfig,
    stdin_fd: RawFd,
    stdout: &mut WOut,
    stderr: &mut WErr,
) -> ShimDecision {
    if argv::is_probe(args) {
        return ShimDecision::ExecLocal {
            reason: LocalFallbackReason::ProbeArgs,
        };
    }

    let cwd = match env::current_dir() {
        Ok(dir) => match dir.into_os_string().into_string() {
            Ok(s) => s,
            Err(_) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::PreSendFailure(
                        "current working directory is not valid UTF-8".to_string(),
                    ),
                };
            }
        },
        Err(err) => {
            return ShimDecision::ExecLocal {
                reason: LocalFallbackReason::PreSendFailure(format!(
                    "failed to read current working directory: {err}"
                )),
            };
        }
    };

    let start_frame = Frame::Start(StartRequest {
        args: args.to_vec(),
        cwd,
        env_subset: collect_allowed_env_subset(),
    });

    let framed_start = match encode_framed(&start_frame) {
        Ok(bytes) => bytes,
        Err(err) => {
            return ShimDecision::ExecLocal {
                reason: LocalFallbackReason::PreSendFailure(format!(
                    "failed to encode Start frame: {err}"
                )),
            };
        }
    };

    let deadline = tokio::time::Instant::now() + config.handshake_timeout;

    // Phase 1: Connect within handshake budget.
    let mut stream =
        match tokio::time::timeout_at(deadline, UnixStream::connect(&config.dispatcher_socket))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::DispatcherUnavailable(format!(
                        "dispatcher socket '{}' unavailable: {err}",
                        config.dispatcher_socket.display()
                    )),
                };
            }
            Err(_) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::DispatcherUnavailable(format!(
                        "timed out connecting to dispatcher socket '{}' after {} ms",
                        config.dispatcher_socket.display(),
                        config.handshake_timeout.as_millis()
                    )),
                };
            }
        };

    // Phase 2: Transmit Start frame while tracking whether the complete frame was handed to the kernel.
    let mut written = 0usize;
    while written < framed_start.len() {
        match tokio::time::timeout_at(deadline, stream.write(&framed_start[written..])).await {
            Ok(Ok(0)) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::PreSendFailure(
                        "dispatcher closed socket before complete Start frame was sent".to_string(),
                    ),
                };
            }
            Ok(Ok(n)) => {
                written += n;
            }
            Ok(Err(err)) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::PreSendFailure(format!(
                        "socket write failed before complete Start frame was sent: {err}"
                    )),
                };
            }
            Err(_) => {
                return ShimDecision::ExecLocal {
                    reason: LocalFallbackReason::PreSendFailure(
                        "handshake budget expired before complete Start frame was sent".to_string(),
                    ),
                };
            }
        }
    }

    // Ambiguous Submission Boundary crossed: all bytes of `Frame::Start` have been written.
    // From this point on, only an explicit `Frame::RunLocal` authorizes local execution.
    match tokio::time::timeout_at(deadline, stream.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(io_err)) => {
            drop(stream);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: format!(
                    "socket error flushing Start frame (ambiguous remote state; refusing duplicate local exec): {io_err}"
                ),
            };
        }
        Err(_) => {
            drop(stream);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: "handshake budget expired flushing Start frame (ambiguous remote state; refusing duplicate local exec)".to_string(),
            };
        }
    }

    let (mut reader, mut writer) = stream.into_split();

    // Phase 3: Wait for RunLocal or Started within the remaining 2 s handshake budget.
    match tokio::time::timeout_at(deadline, read_frame(&mut reader)).await {
        Ok(Ok(Some(Frame::RunLocal))) => {
            drop(reader);
            drop(writer);
            return ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal,
            };
        }
        Ok(Ok(Some(Frame::Started))) => {}
        Ok(Ok(Some(Frame::Error { kind, message }))) => {
            drop(reader);
            drop(writer);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: format!("remote start failed ({kind:?}): {message}"),
            };
        }
        Ok(Ok(Some(other))) => {
            drop(reader);
            drop(writer);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: format!(
                    "unexpected protocol frame before Started ({other:?}); refusing duplicate local exec"
                ),
            };
        }
        Ok(Ok(None)) => {
            drop(reader);
            drop(writer);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: "dispatcher closed socket before Start acknowledgment (ambiguous remote state; refusing duplicate local exec)".to_string(),
            };
        }
        Ok(Err(err)) => {
            drop(reader);
            drop(writer);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: format!(
                    "protocol error waiting for Start acknowledgment ({err}); refusing duplicate local exec"
                ),
            };
        }
        Err(_) => {
            drop(reader);
            drop(writer);
            return ShimDecision::RemoteFailed {
                exit_code: 1,
                reason: format!(
                    "Start acknowledgment timed out after {} ms (ambiguous remote state; closing socket and refusing duplicate local exec)",
                    config.handshake_timeout.as_millis()
                ),
            };
        }
    }

    use tokio::signal::unix::{signal, SignalKind as UnixSignal};
    let (Ok(mut sigterm), Ok(mut sigint)) = (
        signal(UnixSignal::terminate()),
        signal(UnixSignal::interrupt()),
    ) else {
        return ShimDecision::RemoteFailed {
            exit_code: 1,
            reason: "could not register signal handlers for the remote job".to_string(),
        };
    };

    // Phase 4: Active remote relay (64-frame bounded channels for backpressure in both directions,
    // priority signal forwarding, and poll-based cancellable stdin pumping).
    let (stdin_tx, mut stdin_rx) = bounded_frame_channel();
    let (sig_tx, mut sig_rx) = mpsc::channel::<SignalKind>(16);
    let (inbound_tx, mut inbound_rx) = bounded_frame_channel();
    let (shutdown_tx, mut writer_shutdown_rx) = watch::channel(false);

    let mut stdin_pump = match StdinPumpHandle::spawn(stdin_fd, stdin_tx) {
        Ok(handle) => Some(handle),
        Err(err) => {
            let _ = writeln!(
                stderr,
                "af-transcode: warning: failed to start stdin pump ({err})"
            );
            None
        }
    };

    // Signal listener task forwarding SIGTERM and SIGINT on a priority channel.
    let mut sig_shutdown_rx = shutdown_tx.subscribe();
    let signal_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = sig_shutdown_rx.changed() => break,
                Some(()) = sigterm.recv() => {
                    if sig_tx.send(SignalKind::Term).await.is_err() {
                        break;
                    }
                }
                Some(()) = sigint.recv() => {
                    if sig_tx.send(SignalKind::Int).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Outbound socket writer task (signals take priority over stdin chunks).
    let write_timeout = config.frame_write_timeout;
    let (write_error_tx, mut write_error_rx) = mpsc::channel(1);
    let writer_task = tokio::spawn(async move {
        let mut stdin_closed = false;
        loop {
            let frame = tokio::select! {
                biased;
                _ = writer_shutdown_rx.changed() => break,
                Some(sig) = sig_rx.recv() => Frame::Signal(sig),
                maybe_stdin = stdin_rx.recv(), if !stdin_closed => {
                    match maybe_stdin {
                        Some(frame) => {
                            if matches!(frame, Frame::StdinEof) {
                                stdin_closed = true;
                            }
                            frame
                        }
                        None => {
                            stdin_closed = true;
                            continue;
                        }
                    }
                }
            };

            match tokio::time::timeout(write_timeout, write_frame(&mut writer, &frame)).await {
                Ok(Ok(())) => {}
                // The dispatcher may have sent Exit before closing its read half.
                Ok(Err(ProtocolError::Io(err)))
                    if matches!(
                        err.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break;
                }
                Ok(Err(err)) => {
                    let _ = write_error_tx
                        .try_send(format!("could not write to the dispatcher: {err}"));
                    break;
                }
                Err(_) => {
                    let _ = write_error_tx
                        .try_send("dispatcher stopped reading the job stream".to_string());
                    break;
                }
            }
        }
        drop(writer);
    });

    // Inbound socket reader task feeding the bounded 64-frame inbound channel.
    let (read_err_tx, mut read_err_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    let reader_task = tokio::spawn(async move {
        let terminal_err = loop {
            match read_frame(&mut reader).await {
                Ok(Some(frame)) => {
                    let is_terminal = matches!(frame, Frame::Exit(_) | Frame::Error { .. });
                    if inbound_tx.send(frame).await.is_err() {
                        break None;
                    }
                    if is_terminal {
                        break None;
                    }
                }
                Ok(None) => break None,
                Err(err) => break Some(err.to_string()),
            }
        };
        let _ = read_err_tx.send(terminal_err);
    });

    // Drain inbound frames to stdout/stderr until Exit, Error, or unexpected EOF.
    let decision = loop {
        let frame = tokio::select! {
            Some(reason) = write_error_rx.recv() => {
                break ShimDecision::RemoteFailed { exit_code: 1, reason };
            }
            frame = inbound_rx.recv() => frame,
        };
        match frame {
            Some(Frame::Stdout(bytes)) => {
                if let Err(err) = stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        break ShimDecision::RemoteFailed {
                            exit_code: 1,
                            reason: format!("failed writing remote stdout: {err}"),
                        };
                    }
                }
            }
            Some(Frame::Stderr(bytes)) => {
                if let Err(err) = stderr.write_all(&bytes).and_then(|()| stderr.flush()) {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        break ShimDecision::RemoteFailed {
                            exit_code: 1,
                            reason: format!("failed writing remote stderr: {err}"),
                        };
                    }
                }
            }
            Some(Frame::Exit(code)) => {
                let _ = stdout.flush();
                let _ = stderr.flush();
                break ShimDecision::RemoteExited(code);
            }
            Some(Frame::Error { kind, message }) => {
                let _ = stdout.flush();
                let _ = stderr.flush();
                break ShimDecision::RemoteFailed {
                    exit_code: 1,
                    reason: format!("remote worker error ({kind:?}): {message}"),
                };
            }
            Some(other) => {
                break ShimDecision::RemoteFailed {
                    exit_code: 1,
                    reason: format!(
                        "unexpected frame from dispatcher during active job: {other:?}"
                    ),
                };
            }
            None => {
                let err_detail = read_err_rx
                    .try_recv()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "dispatcher connection closed before Exit".to_string());
                let _ = stdout.flush();
                let _ = stderr.flush();
                break ShimDecision::RemoteFailed {
                    exit_code: 1,
                    reason: err_detail,
                };
            }
        }
    };

    // Tear down all auxiliary tasks and wake the stdin poll loop immediately (even if stdin is held open).
    let _ = shutdown_tx.send(true);
    drop(inbound_rx);
    signal_task.abort();
    reader_task.abort();
    writer_task.abort();
    let _ = signal_task.await;
    let _ = reader_task.await;
    let _ = writer_task.await;
    if let Some(mut pump) = stdin_pump.take() {
        pump.stop_and_join();
    }

    decision
}
