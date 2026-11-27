use af_hardware::RenderNode;
use af_transcode::argv::WORKER_LOCAL_PROTOCOL_WHITELIST;
use af_transcode::capabilities::{probe_capabilities, CapabilitiesConfig, TranscodeCapabilities};
use af_transcode::config::{
    DEFAULT_WORKER_MAX_JOBS, ENV_DISPATCHER_SOCKET, ENV_HANDSHAKE_TIMEOUT_MS, ENV_REAL_FFMPEG,
    ENV_SHIM_RECURSION_GUARD, ENV_WORKER_MAX_JOBS,
};
use af_transcode::protocol::{read_frame, write_frame, ErrorKind, Frame, StartRequest};
use af_transcode::shim::{run_shim_protocol, LocalFallbackReason, ShimConfig, ShimDecision};
use af_transcode::worker::{bind_worker_socket, serve_worker_listener, WorkerConfig};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a short, private `0700` fixture directory under `/tmp` so Unix socket paths
    /// stay well below Linux's 107-byte `sun_path` limit and pass worker parent-dir checks.
    fn new(tag: &str) -> Self {
        let seq = FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = PathBuf::from(format!("/tmp/aft-{tag}-{pid}-{seq}"));
        let _ = fs::remove_dir_all(&path);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .expect("create private temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod +x");
    path
}

fn af_transcode_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_af-transcode"))
}

fn symlink_ffmpeg_shim(dir: &Path) -> PathBuf {
    let shim_link = dir.join("ffmpeg");
    symlink(af_transcode_bin(), &shim_link).expect("symlink ffmpeg shim");
    shim_link
}

#[test]
fn shim_preserves_non_utf8_args_on_local_exec() {
    let dir = TempDir::new("opaque-argv");
    let shim = symlink_ffmpeg_shim(dir.path());
    let fake_ffmpeg =
        write_executable_script(dir.path(), "real-ffmpeg", "#!/bin/sh\nprintf '%s' \"$2\"\n");
    let input = b"movie\xff.mkv";
    let out = StdCommand::new(shim)
        .args([
            OsStr::new("-i"),
            OsStr::from_bytes(input),
            OsStr::new("out.mkv"),
        ])
        .env(ENV_REAL_FFMPEG, fake_ffmpeg)
        .env(ENV_DISPATCHER_SOCKET, dir.path().join("absent.sock"))
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run local shim with an opaque Unix argument");

    assert!(out.status.success(), "{:?}", out.stderr);
    assert_eq!(out.stdout, input);
}

fn pid_is_alive(pid: i32) -> bool {
    match kill(Pid::from_raw(pid), None) {
        Ok(()) => true,
        Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

async fn start_fixture_worker(
    config: WorkerConfig,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let validated_ffmpeg =
        af_transcode::validate_real_ffmpeg_path(&config.real_ffmpeg).expect("validate fake ffmpeg");
    let bound = bind_worker_socket(&config).expect("bind worker socket");
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let _ = serve_worker_listener(bound, config, validated_ffmpeg, async move {
            let _ = rx.await;
        })
        .await;
    });
    (tx, handle)
}

#[tokio::test]
async fn shim_argv0_ffmpeg_probes_run_locally_without_dispatcher() {
    let dir = TempDir::new("probe");
    let shim = symlink_ffmpeg_shim(dir.path());
    let sock = dir.path().join("disp.sock");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'REAL_FFMPEG:%s\\n' \"$*\"\n",
    );

    let listener = UnixListener::bind(&sock).expect("bind dispatcher");
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
        true
    });

    for probe_args in [
        vec!["-version"],
        vec!["-hide_banner", "-encoders"],
        vec!["-h", "encoder=h264_vaapi"],
        vec!["-f", "null", "-"],
    ] {
        let out = StdCommand::new(&shim)
            .args(&probe_args)
            .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
            .env(ENV_DISPATCHER_SOCKET, &sock)
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .output()
            .expect("run ffmpeg shim probe");
        assert!(out.status.success(), "probe {:?} failed", probe_args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.starts_with("REAL_FFMPEG:"),
            "expected local real ffmpeg output, got: {stdout}"
        );
    }

    assert!(
        !accept_task.is_finished(),
        "probe calls must never connect to the dispatcher socket"
    );
    accept_task.abort();
}

#[tokio::test]
async fn shim_falls_back_locally_on_missing_socket_and_run_local_and_filters_env() {
    let dir = TempDir::new("fallback");
    let shim = symlink_ffmpeg_shim(dir.path());
    let missing_sock = dir.path().join("missing.sock");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'LOCAL:%s\\n' \"$*\"\n",
    );

    // 1. Missing dispatcher socket -> definite pre-send failure -> local exec.
    let out = StdCommand::new(&shim)
        .args(["-i", "/srv/media/a.mkv", "-c:v", "h264_vaapi", "out.m3u8"])
        .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
        .env(ENV_DISPATCHER_SOCKET, &missing_sock)
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run shim with missing socket");
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "LOCAL:-i /srv/media/a.mkv -c:v h264_vaapi out.m3u8"
    );

    // 2. Dispatcher returns RunLocal -> local exec; also verify env_subset allowlist.
    let disp_sock = dir.path().join("disp.sock");
    let listener = UnixListener::bind(&disp_sock).expect("bind disp");
    let disp_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let frame = read_frame(&mut stream)
            .await
            .expect("read frame")
            .expect("start frame");
        let Frame::Start(req) = frame else {
            panic!("expected Start, got {frame:?}");
        };
        write_frame(&mut stream, &Frame::RunLocal)
            .await
            .expect("write RunLocal");
        req
    });

    let shim_clone = shim.clone();
    let fake_clone = fake_ffmpeg.clone();
    let disp_clone = disp_sock.clone();
    let tmp_val = dir.path().to_string_lossy().into_owned();
    let out = tokio::task::spawn_blocking(move || {
        StdCommand::new(&shim_clone)
            .args(["-i", "/srv/media/b.mkv", "-c:v", "libx264", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_clone)
            .env(ENV_DISPATCHER_SOCKET, &disp_clone)
            .env("TMPDIR", &tmp_val)
            .env("TZ", "UTC")
            .env("LD_PRELOAD", "/tmp/evil.so")
            .env("LIBVA_DRIVERS_PATH", "/tmp/evil-va")
            .env("ARBITRARY_SECRET", "must-not-leak")
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .output()
            .expect("run shim RunLocal")
    })
    .await
    .expect("join shim");

    let start_req = disp_task.await.expect("dispatcher task");
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "LOCAL:-i /srv/media/b.mkv -c:v libx264 out.m3u8"
    );
    assert!(start_req
        .env_subset
        .iter()
        .any(|(k, v)| k == "TMPDIR" && v == &dir.path().to_string_lossy()));
    assert!(start_req
        .env_subset
        .iter()
        .any(|(k, v)| k == "TZ" && v == "UTC"));
    for forbidden in ["LD_PRELOAD", "LIBVA_DRIVERS_PATH", "ARBITRARY_SECRET"] {
        assert!(
            !start_req.env_subset.iter().any(|(k, _)| k == forbidden),
            "{forbidden} must never be included in Start.env_subset"
        );
    }
}

#[tokio::test]
async fn shim_refuses_duplicate_local_exec_after_ambiguous_start_or_dropped_stream() {
    let dir = TempDir::new("nodup");
    let shim = symlink_ffmpeg_shim(dir.path());
    let sentinel = dir.path().join("local_ran");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        &format!("#!/bin/sh\ntouch '{}'\nexit 0\n", sentinel.display()),
    );

    // Case A: Dispatcher reads full Start and stalls past shim's handshake timeout (ambiguous lost ack).
    let sock_timeout = dir.path().join("timeout.sock");
    let listener = UnixListener::bind(&sock_timeout).expect("bind timeout sock");
    let disp_eof = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let start = read_frame(&mut stream).await.expect("read").expect("start");
        assert!(matches!(start, Frame::Start(_)));
        // Wait for shim to time out and close its socket (signaling cleanup).
        let eof = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut stream))
            .await
            .expect("shim must close socket on handshake timeout");
        matches!(eof, Ok(None))
    });

    let shim_a = shim.clone();
    let fake_a = fake_ffmpeg.clone();
    let sock_a = sock_timeout.clone();
    let out_a = tokio::task::spawn_blocking(move || {
        StdCommand::new(&shim_a)
            .args(["-i", "/srv/media/c.mkv", "-c:v", "h264_vaapi", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_a)
            .env(ENV_DISPATCHER_SOCKET, &sock_a)
            .env(ENV_HANDSHAKE_TIMEOUT_MS, "200")
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .output()
            .expect("run shim timeout case")
    })
    .await
    .expect("join A");

    assert!(
        !out_a.status.success(),
        "ambiguous handshake timeout must fail non-zero"
    );
    assert!(
        !sentinel.exists(),
        "MUST NOT exec local ffmpeg after ambiguous full Start submission"
    );
    assert!(
        disp_eof.await.expect("disp task"),
        "shim must close socket on ambiguous timeout to trigger cleanup"
    );

    // Case B: Dispatcher closes socket immediately after reading full Start without replying.
    let sock_close = dir.path().join("close.sock");
    let listener = UnixListener::bind(&sock_close).expect("bind close sock");
    let disp_b = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_frame(&mut stream).await;
        drop(stream);
    });

    let shim_b = shim.clone();
    let fake_b = fake_ffmpeg.clone();
    let sock_b = sock_close.clone();
    let out_b = tokio::task::spawn_blocking(move || {
        StdCommand::new(&shim_b)
            .args(["-i", "/srv/media/c.mkv", "-c:v", "h264_vaapi", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_b)
            .env(ENV_DISPATCHER_SOCKET, &sock_b)
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .output()
            .expect("run shim close case")
    })
    .await
    .expect("join B");
    disp_b.await.unwrap();
    assert!(!out_b.status.success());
    assert!(
        !sentinel.exists(),
        "MUST NOT exec local ffmpeg after lost ack on closed socket"
    );

    // Case C: Dispatcher sends Started then drops stream mid-job.
    let sock_drop = dir.path().join("drop.sock");
    let listener = UnixListener::bind(&sock_drop).expect("bind drop sock");
    let disp_c = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_frame(&mut stream).await;
        write_frame(&mut stream, &Frame::Started).await.unwrap();
        write_frame(&mut stream, &Frame::Stdout(b"partial".to_vec()))
            .await
            .unwrap();
        drop(stream);
    });

    let out_c = tokio::task::spawn_blocking(move || {
        StdCommand::new(&shim)
            .args(["-i", "/srv/media/c.mkv", "-c:v", "h264_vaapi", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
            .env(ENV_DISPATCHER_SOCKET, &sock_drop)
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .output()
            .expect("run shim drop case")
    })
    .await
    .expect("join C");
    disp_c.await.unwrap();
    assert!(!out_c.status.success());
    assert!(
        !sentinel.exists(),
        "MUST NOT exec local ffmpeg when remote stream drops after Started"
    );
}

#[test]
fn shim_anti_recursion_guard_blocks_self_and_wrapper_loop() {
    let dir = TempDir::new("norec");
    let shim = symlink_ffmpeg_shim(dir.path());

    // 1. Direct symlink pointing real ffmpeg back to shim binary
    let out = StdCommand::new(&shim)
        .args(["-version"])
        .env(ENV_REAL_FFMPEG, &shim)
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run self-pointing shim");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("recursion guard"),
        "expected recursion guard message, got: {stderr}"
    );

    // 2. Indirect wrapper script re-invoking the shim
    let wrapper = write_executable_script(
        dir.path(),
        "wrapper-ffmpeg",
        &format!("#!/bin/sh\nexec '{}' \"$@\"\n", shim.display()),
    );
    let out_wrap = StdCommand::new(&shim)
        .args(["-version"])
        .env(ENV_REAL_FFMPEG, &wrapper)
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run recursive wrapper");
    assert!(!out_wrap.status.success());
    let stderr_wrap = String::from_utf8_lossy(&out_wrap.stderr);
    assert!(
        stderr_wrap.contains("recursive shim execution"),
        "expected indirect recursion guard message, got: {stderr_wrap}"
    );
}

#[tokio::test]
async fn shim_and_worker_relay_stdout_stderr_stdin_eof_and_exit_code() {
    let dir = TempDir::new("io");
    let shim = symlink_ffmpeg_shim(dir.path());
    let worker_sock = dir.path().join("worker.sock");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        r#"#!/bin/sh
echo "OUT_ARGS:$*"
echo "OUT_TMPDIR:${TMPDIR:-unset}"
echo "OUT_LDPRELOAD:${LD_PRELOAD:-unset}"
echo "ERR_START" >&2
while IFS= read -r line; do
    echo "IN:$line"
done
echo "ERR_EOF" >&2
exit 42
"#,
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg.clone());
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    let tmp_val = dir.path().to_string_lossy().into_owned();
    let shim_clone = shim.clone();
    let sock_clone = worker_sock.clone();
    let fake_clone = fake_ffmpeg.clone();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = StdCommand::new(&shim_clone)
            .args(["-i", "/srv/media/in.mkv", "-c:v", "libx264", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_clone)
            .env(ENV_DISPATCHER_SOCKET, &sock_clone)
            .env("TMPDIR", &tmp_val)
            .env("LD_PRELOAD", "/tmp/not-allowed.so")
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shim");

        {
            use std::io::Write;
            let mut stdin = child.stdin.take().expect("stdin");
            stdin.write_all(b"chunk-one\nq\n").expect("write stdin");
            // Dropping stdin sends EOF -> shim sends Frame::StdinEof -> worker closes child stdin.
        }
        child.wait_with_output().expect("wait shim")
    })
    .await
    .expect("join shim");

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;

    assert_eq!(output.status.code(), Some(42));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&format!(
        "OUT_ARGS:-protocol_whitelist {WORKER_LOCAL_PROTOCOL_WHITELIST} -i /srv/media/in.mkv -c:v libx264 out.m3u8"
    )));
    assert!(stdout.contains(&format!("OUT_TMPDIR:{}", dir.path().display())));
    assert!(stdout.contains("OUT_LDPRELOAD:unset"));
    assert!(stdout.contains("IN:chunk-one\n"));
    assert!(stdout.contains("IN:q\n"));
    assert!(stderr.contains("ERR_START\n"));
    assert!(stderr.contains("ERR_EOF\n"));
}

#[tokio::test]
async fn shim_returns_promptly_when_dispatcher_exits_even_if_stdin_held_open() {
    let dir = TempDir::new("openstdin");
    let shim = symlink_ffmpeg_shim(dir.path());
    let fake_ffmpeg = write_executable_script(dir.path(), "real-ffmpeg", "#!/bin/sh\nexit 99\n");

    // 1. Clean Exit while parent keeps stdin pipe open forever.
    let sock_exit = dir.path().join("exit.sock");
    let listener = UnixListener::bind(&sock_exit).expect("bind");
    let disp = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &Frame::Started).await.unwrap();
        write_frame(&mut stream, &Frame::Stdout(b"done\n".to_vec()))
            .await
            .unwrap();
        write_frame(&mut stream, &Frame::Exit(0)).await.unwrap();
        drop(stream);
    });

    let shim_a = shim.clone();
    let fake_a = fake_ffmpeg.clone();
    let sock_a = sock_exit.clone();
    let (status, stdout, elapsed) = tokio::task::spawn_blocking(move || {
        let mut child = StdCommand::new(&shim_a)
            .args(["-i", "/srv/media/in.mkv", "-c:v", "libx264", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_a)
            .env(ENV_DISPATCHER_SOCKET, &sock_a)
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shim");

        // Deliberately keep `_held_stdin` open until AFTER child exits!
        let _held_stdin = child.stdin.take().expect("stdin");
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "shim hung waiting on open stdin after dispatcher Exit!"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let elapsed = start.elapsed();
        let mut out = String::new();
        use std::io::Read;
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        drop(_held_stdin);
        (status, out, elapsed)
    })
    .await
    .expect("join");

    disp.await.unwrap();
    assert!(status.success(), "expected exit 0, got {status:?}");
    assert_eq!(stdout, "done\n");
    assert!(elapsed < Duration::from_secs(2));

    // 2. Dispatcher crashes/exits abruptly without Exit while parent keeps stdin pipe open.
    let sock_crash = dir.path().join("crash.sock");
    let listener = UnixListener::bind(&sock_crash).expect("bind");
    let disp2 = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _ = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &Frame::Started).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(stream);
    });

    let status2 = tokio::task::spawn_blocking(move || {
        let mut child = StdCommand::new(&shim)
            .args(["-i", "/srv/media/in.mkv", "-c:v", "libx264", "out.m3u8"])
            .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
            .env(ENV_DISPATCHER_SOCKET, &sock_crash)
            .env_remove(ENV_SHIM_RECURSION_GUARD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shim");

        let _held_stdin = child.stdin.take().expect("stdin");
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "shim hung waiting on open stdin after dispatcher disconnect!"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(_held_stdin);
        status
    })
    .await
    .expect("join 2");

    disp2.await.unwrap();
    assert!(!status2.success());
}

#[tokio::test]
async fn shim_and_worker_forward_sigterm_and_sigint() {
    let dir = TempDir::new("signals");
    let shim = symlink_ffmpeg_shim(dir.path());
    let worker_sock = dir.path().join("worker.sock");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        r#"#!/bin/sh
trap 'echo CAUGHT_TERM; exit 77' TERM
trap 'echo CAUGHT_INT; exit 78' INT
echo READY
while :; do
    sleep 1 &
    wait $!
done
"#,
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg.clone());
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    for (sig, expected_line, expected_code) in [
        (Signal::SIGTERM, "CAUGHT_TERM", 77),
        (Signal::SIGINT, "CAUGHT_INT", 78),
    ] {
        let shim_c = shim.clone();
        let fake_c = fake_ffmpeg.clone();
        let sock_c = worker_sock.clone();
        let (code, output) = tokio::task::spawn_blocking(move || {
            let mut child = StdCommand::new(&shim_c)
                .args(["-i", "/srv/media/sig.mkv", "-c:v", "libx264", "out.m3u8"])
                .env(ENV_REAL_FFMPEG, &fake_c)
                .env(ENV_DISPATCHER_SOCKET, &sock_c)
                .env_remove(ENV_SHIM_RECURSION_GUARD)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn shim");

            let _held_stdin = child.stdin.take();
            let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
            let mut first_line = String::new();
            reader.read_line(&mut first_line).expect("read READY");
            assert_eq!(first_line.trim(), "READY");

            kill(Pid::from_raw(child.id() as i32), sig).expect("send signal to shim");

            let mut rest = String::new();
            use std::io::Read;
            reader.read_to_string(&mut rest).expect("read remaining");
            let status = child.wait().expect("wait shim");
            (status.code(), rest)
        })
        .await
        .expect("join signal test");

        assert_eq!(code, Some(expected_code), "signal {sig:?} exit code");
        assert!(
            output.contains(expected_line),
            "expected '{expected_line}' in stdout, got '{output}'"
        );
    }

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;
}

#[tokio::test]
async fn shim_exits_when_dispatcher_stops_reading_active_stdin() {
    use std::os::fd::AsRawFd;

    let dir = TempDir::new("shim-stalled-write");
    let dispatcher_socket = dir.path().join("dispatcher.sock");
    let listener = UnixListener::bind(&dispatcher_socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            read_frame(&mut stream).await.unwrap(),
            Some(Frame::Start(_))
        ));
        write_frame(&mut stream, &Frame::Started).await.unwrap();
        std::future::pending::<()>().await;
    });
    let input = fs::File::open("/dev/zero").unwrap();
    let config = ShimConfig {
        real_ffmpeg: dir.path().join("ffmpeg"),
        dispatcher_socket,
        handshake_timeout: Duration::from_secs(1),
        frame_write_timeout: Duration::from_millis(100),
    };
    let args = ["-i", "input.mkv", "output.mkv"].map(str::to_owned);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        run_shim_protocol(&args, &config, input.as_raw_fd(), &mut stdout, &mut stderr),
    )
    .await;
    server.abort();
    assert!(matches!(
        result.expect("shim did not release the stalled stream"),
        ShimDecision::RemoteFailed { reason, .. } if reason.contains("stopped reading")
    ));
}

#[tokio::test]
async fn worker_reaps_disconnected_job_with_eof_queued_behind_full_stdin() {
    use af_transcode::protocol::{FRAME_CHANNEL_CAPACITY, MAX_IO_CHUNK_BYTES};
    use std::os::fd::AsRawFd;

    let dir = TempDir::new("worker-stdin-eof");
    let socket_path = dir.path().join("worker.sock");
    let ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf '%s' \"$$\"\nexec /bin/sleep 20\n",
    );
    let mut cfg = WorkerConfig::for_paths(socket_path.clone(), ffmpeg);
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown, worker) = start_fixture_worker(cfg).await;
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    write_frame(
        &mut client,
        &Frame::Start(StartRequest {
            args: ["-i", "input.mkv", "output.mkv"]
                .map(str::to_owned)
                .to_vec(),
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut client).await.unwrap(), Some(Frame::Started));
    let Some(Frame::Stdout(value)) = read_frame(&mut client).await.unwrap() else {
        panic!("fixture did not report its PID");
    };
    let pid = std::str::from_utf8(&value).unwrap().parse::<i32>().unwrap();
    let child_stdin = fs::File::open(format!("/proc/{pid}/fd/0")).unwrap();
    // SAFETY: child_stdin is a live pipe descriptor. F_GETPIPE_SZ does not take a third argument.
    let pipe_size = unsafe { libc::fcntl(child_stdin.as_raw_fd(), libc::F_GETPIPE_SZ) };
    assert!(pipe_size > 0);
    drop(child_stdin);

    tokio::time::timeout(Duration::from_secs(3), async {
        let frame = Frame::Stdin(vec![0xcc; MAX_IO_CHUNK_BYTES]);
        let chunks = pipe_size as usize / MAX_IO_CHUNK_BYTES + 1 + FRAME_CHANNEL_CAPACITY;
        for _ in 0..chunks {
            write_frame(&mut client, &frame).await.unwrap();
        }
        write_frame(&mut client, &Frame::StdinEof).await.unwrap();
    })
    .await
    .expect("send full stdin queue and EOF");
    drop(client);

    let reaped = tokio::time::timeout(Duration::from_secs(2), async {
        while pid_is_alive(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let _ = shutdown.send(());
    worker.await.unwrap();
    reaped.expect("disconnect left the worker child running");
}

#[tokio::test]
async fn worker_kills_entire_process_group_when_socket_closes_without_exit() {
    let dir = TempDir::new("pgroup");
    let worker_sock = dir.path().join("worker.sock");
    let pid_file = dir.path().join("pids.txt");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        &format!(
            r#"#!/bin/sh
sleep 60 &
GRANDCHILD=$!
printf '%s %s\n' "$$" "$GRANDCHILD" > '{}'
echo SPAWNED
wait
"#,
            pid_file.display()
        ),
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg);
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    let mut stream = UnixStream::connect(&worker_sock)
        .await
        .expect("connect worker");
    write_frame(
        &mut stream,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "/srv/media/pg.mkv".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();

    assert_eq!(read_frame(&mut stream).await.unwrap(), Some(Frame::Started));
    let mut got_spawned = false;
    while let Some(frame) = read_frame(&mut stream).await.unwrap() {
        if let Frame::Stdout(bytes) = frame {
            if String::from_utf8_lossy(&bytes).contains("SPAWNED") {
                got_spawned = true;
                break;
            }
        }
    }
    assert!(got_spawned);

    let pid_text = fs::read_to_string(&pid_file).expect("read pid file");
    let pids: Vec<i32> = pid_text
        .split_whitespace()
        .map(|tok| tok.parse::<i32>().expect("pid"))
        .collect();
    assert_eq!(pids.len(), 2, "expected child and grandchild PIDs");
    assert!(pid_is_alive(pids[0]));
    assert!(pid_is_alive(pids[1]));

    // Abruptly close socket without sending Exit (simulates Jellyfin SIGKILL of shim).
    drop(stream);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !pid_is_alive(pids[0]) && !pid_is_alive(pids[1]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    assert!(!pid_is_alive(pids[0]), "fake ffmpeg child must be dead");
    assert!(
        !pid_is_alive(pids[1]),
        "grandchild process in ffmpeg process group must be dead"
    );

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;
}

#[tokio::test]
async fn worker_validates_start_env_cwd_concurrency_and_vendor_render_node_rewrite() {
    let dir = TempDir::new("validate");
    let worker_sock = dir.path().join("worker.sock");

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg.clone());
    cfg.render_nodes_override = Some(vec![
        RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()), // AMD
        },
        RenderNode {
            path: PathBuf::from("/dev/dri/renderD129"),
            vendor_id: Some("0x8086".to_string()), // Intel
        },
    ]);
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    // Verify socket permissions are restricted (0660, zero world bits).
    let sock_meta = fs::symlink_metadata(&worker_sock).expect("socket metadata");
    assert_eq!(sock_meta.permissions().mode() & 0o777, 0o660);

    // 1. Reject LD_PRELOAD / loader / arbitrary env vars.
    for bad_env in [
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp/evil"),
        ("PATH", "/tmp/evil"),
        ("LIBVA_DRIVERS_PATH", "/tmp/evil"),
        ("FFREPORT", "file=/tmp/pwn"),
    ] {
        let mut s = UnixStream::connect(&worker_sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args: vec!["-i".into(), "/srv/media/x.mkv".into(), "out.m3u8".into()],
                cwd: dir.path().to_string_lossy().into_owned(),
                env_subset: vec![(bad_env.0.into(), bad_env.1.into())],
            }),
        )
        .await
        .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(
            matches!(
                reply,
                Frame::Error {
                    kind: ErrorKind::InvalidRequest,
                    ..
                }
            ),
            "expected InvalidRequest for env {}, got {:?}",
            bad_env.0,
            reply
        );
    }

    // 2. Reject invalid cwd (relative / traversal / missing) and empty args / NUL args.
    for (args, cwd) in [
        (vec![], dir.path().to_string_lossy().into_owned()),
        (
            vec!["-i".into(), "a\0b".into()],
            dir.path().to_string_lossy().into_owned(),
        ),
        (vec!["-i".into(), "a.mkv".into()], "relative/dir".into()),
        (vec!["-i".into(), "a.mkv".into()], "/tmp/../etc".into()),
        (
            vec!["-i".into(), "a.mkv".into()],
            "/nonexistent-af-transcode-dir-xyz".into(),
        ),
    ] {
        let mut s = UnixStream::connect(&worker_sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args,
                cwd,
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(
            matches!(
                reply,
                Frame::Error {
                    kind: ErrorKind::InvalidRequest,
                    ..
                }
            ),
            "expected InvalidRequest, got {reply:?}"
        );
    }

    // 3. Reject wrong first frame with ProtocolViolation.
    {
        let mut s = UnixStream::connect(&worker_sock).await.unwrap();
        write_frame(&mut s, &Frame::Stdin(b"hi".to_vec()))
            .await
            .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(matches!(
            reply,
            Frame::Error {
                kind: ErrorKind::ProtocolViolation,
                ..
            }
        ));
    }

    // 4. QSV job selects Intel renderD129 (skipping AMD renderD128) and rewrites ONLY device slots.
    {
        let mut s = UnixStream::connect(&worker_sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args: vec![
                    "-init_hw_device".into(),
                    "vaapi=va:/dev/dri/renderD128,driver=iHD".into(),
                    "-init_hw_device".into(),
                    "qsv=qs@va".into(),
                    "-hwaccel".into(),
                    "qsv".into(),
                    "-i".into(),
                    "/srv/media/dev/dri/renderD128/clip.mkv".into(),
                    "-c:v".into(),
                    "hevc_qsv".into(),
                    "out.m3u8".into(),
                ],
                cwd: dir.path().to_string_lossy().into_owned(),
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        assert_eq!(read_frame(&mut s).await.unwrap(), Some(Frame::Started));
        let mut out = Vec::new();
        while let Some(frame) = read_frame(&mut s).await.unwrap() {
            match frame {
                Frame::Stdout(b) => out.extend_from_slice(&b),
                Frame::Exit(code) => {
                    assert_eq!(code, 0);
                    break;
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        let lines: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .map(ToString::to_string)
            .collect();
        assert_eq!(lines[1], "vaapi=va:/dev/dri/renderD129,driver=iHD");
        assert_eq!(lines[6], "-protocol_whitelist");
        assert_eq!(lines[7], WORKER_LOCAL_PROTOCOL_WHITELIST);
        assert_eq!(lines[8], "-i");
        assert_eq!(lines[9], "/srv/media/dev/dri/renderD128/clip.mkv");
    }

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;

    // 5. DeviceUnavailable when QSV requested on AMD-only worker + Busy concurrency cap.
    let slow_ffmpeg = write_executable_script(dir.path(), "slow-ffmpeg", "#!/bin/sh\nsleep 2\n");
    let worker_sock2 = dir.path().join("worker2.sock");
    let mut cfg2 = WorkerConfig::for_paths(worker_sock2.clone(), slow_ffmpeg);
    cfg2.max_concurrent_jobs = 1;
    cfg2.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()), // AMD only
    }]);
    cfg2.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx2, worker_handle2) = start_fixture_worker(cfg2).await;

    // QSV fails with DeviceUnavailable on AMD-only worker.
    {
        let mut s = UnixStream::connect(&worker_sock2).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args: vec![
                    "-qsv_device".into(),
                    "/dev/dri/renderD128".into(),
                    "-i".into(),
                    "/srv/media/x.mkv".into(),
                    "-c:v".into(),
                    "hevc_qsv".into(),
                    "out.m3u8".into(),
                ],
                cwd: dir.path().to_string_lossy().into_owned(),
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(matches!(
            reply,
            Frame::Error {
                kind: ErrorKind::DeviceUnavailable,
                ..
            }
        ));
    }

    // Hold the 1 concurrency slot with job 1 -> job 2 must receive ErrorKind::Busy.
    let mut s1 = UnixStream::connect(&worker_sock2).await.unwrap();
    write_frame(
        &mut s1,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "/srv/media/1.mkv".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut s1).await.unwrap(), Some(Frame::Started));

    let mut s2 = UnixStream::connect(&worker_sock2).await.unwrap();
    write_frame(
        &mut s2,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "/srv/media/2.mkv".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    let busy_reply = read_frame(&mut s2).await.unwrap().expect("busy reply");
    assert!(matches!(
        busy_reply,
        Frame::Error {
            kind: ErrorKind::Busy,
            ..
        }
    ));

    drop(s1);
    let _ = shutdown_tx2.send(());
    let _ = worker_handle2.await;
}

#[tokio::test]
async fn worker_socket_binding_enforces_ownership_permissions_and_stale_safety() {
    let dir = TempDir::new("socksec");
    let fake_ffmpeg = write_executable_script(dir.path(), "real-ffmpeg", "#!/bin/sh\nexit 0\n");

    // 1. Refuse world-writable parent directory
    let ww_dir = dir.path().join("ww");
    fs::create_dir(&ww_dir).unwrap();
    fs::set_permissions(&ww_dir, fs::Permissions::from_mode(0o777)).unwrap();
    let ww_cfg = WorkerConfig::for_paths(ww_dir.join("w.sock"), fake_ffmpeg.clone());
    assert!(bind_worker_socket(&ww_cfg).is_err());

    // 2. Refuse symlinked parent directory
    let real_parent = dir.path().join("real");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&real_parent)
        .unwrap();
    let sym_parent = dir.path().join("sym");
    symlink(&real_parent, &sym_parent).unwrap();
    let sym_cfg = WorkerConfig::for_paths(sym_parent.join("w.sock"), fake_ffmpeg.clone());
    assert!(bind_worker_socket(&sym_cfg).is_err());

    // 3. Refuse to overwrite a regular file at socket_path
    let regular_file = real_parent.join("not-a-sock");
    fs::write(&regular_file, b"keep-me").unwrap();
    let reg_cfg = WorkerConfig::for_paths(regular_file.clone(), fake_ffmpeg.clone());
    assert!(bind_worker_socket(&reg_cfg).is_err());
    assert_eq!(fs::read(&regular_file).unwrap(), b"keep-me");

    // 4. Safely replace a confirmed stale socket, but refuse to hijack a live listening socket
    let sock_path = real_parent.join("worker.sock");
    {
        let stale_listener = StdUnixListener::bind(&sock_path).unwrap();
        drop(stale_listener); // Leaves stale socket file on disk
    }
    assert!(sock_path.exists());

    let mut cfg = WorkerConfig::for_paths(sock_path.clone(), fake_ffmpeg.clone());
    cfg.socket_mode = 0o600;
    let bound = bind_worker_socket(&cfg).expect("must recover stale socket");
    let mode = fs::symlink_metadata(&sock_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    // Live listener is active -> second bind MUST fail and NOT remove the live socket!
    assert!(bind_worker_socket(&cfg).is_err());
    assert!(sock_path.exists());

    // Dropping BoundWorkerSocket cleans up our socket cleanly.
    drop(bound);
    assert!(!sock_path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_worker_binds_publish_once_with_a_long_socket_path() {
    let dir = TempDir::new("bind-race");
    let parent = dir
        .path()
        .join("x".repeat(100 - dir.path().as_os_str().len() - 1));
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
    let socket_path = parent.join("w.sock");
    assert_eq!(socket_path.as_os_str().len(), 107);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let config = WorkerConfig::for_paths(socket_path.clone(), dir.path().join("ffmpeg"));
    let start = |config: WorkerConfig| {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            bind_worker_socket(&config)
        })
    };
    let (one, two) = tokio::join!(start(config.clone()), start(config));
    let (one, two) = (one.unwrap(), two.unwrap());
    assert_ne!(
        one.is_ok(),
        two.is_ok(),
        "exactly one worker should bind: {:?}, {:?}",
        one.as_ref().err(),
        two.as_ref().err(),
    );
    let bound = one.or(two).unwrap();
    let _client = UnixStream::connect(&socket_path).await.unwrap();
    assert_eq!(
        fs::read_dir(&parent).unwrap().count(),
        1,
        "staging directory leaked"
    );
    drop(bound);
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn capabilities_probe_and_cli_use_af_hardware_and_disposable_fixtures() {
    let dir = TempDir::new("caps");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 8.1.3-Jellyfin Copyright (c) 2000-2026 the FFmpeg developers"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V....D h264_vaapi           H.264/AVC (VAAPI)
 V..... hevc_qsv             HEVC (Intel Quick Sync)
 V....D libx264              libx264 H.264
 A....D aac                  AAC
EOF
    exit 0
fi
exit 1
"#,
    );
    let fake_dpkg = write_executable_script(
        dir.path(),
        "dpkg-query",
        "#!/bin/sh\nprintf 'unknown ok not-installed\\tjellyfin-ffmpeg\\t\\ninstall ok installed\\tjellyfin-ffmpeg8\\t8.1.3-1-trixie\\n'\n",
    );

    let cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg.clone(),
        dpkg_query_path: Some(fake_dpkg),
        vainfo_path: None,
        render_nodes_override: Some(vec![RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x8086".to_string()),
        }]),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: None,
        vulkan_video_override: None,
    };

    let report = probe_capabilities(&cfg).await.expect("probe capabilities");
    assert_eq!(report.ffmpeg_version.as_deref(), Some("8.1.3-Jellyfin"));
    assert_eq!(report.package_name.as_deref(), Some("jellyfin-ffmpeg8"));
    assert_eq!(report.package_version.as_deref(), Some("8.1.3-1-trixie"));
    assert_eq!(report.encoders, vec!["h264_vaapi", "hevc_qsv", "libx264"]);
    assert_eq!(report.render_nodes.len(), 1);
    assert_eq!(report.render_nodes[0].path, "/dev/dri/renderD128");
    assert_eq!(report.render_nodes[0].vendor_id.as_deref(), Some("0x8086"));
    assert_eq!(report.render_nodes[0].vendor.as_deref(), Some("intel"));
    assert_eq!(
        report.primary_render_node.as_deref(),
        Some("/dev/dri/renderD128")
    );

    // Exercise `af-transcode capabilities` CLI end-to-end (invokes real `af_hardware::detect_render_nodes()`).
    let out = StdCommand::new(af_transcode_bin())
        .arg("capabilities")
        .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
        .output()
        .expect("run af-transcode capabilities");
    assert!(out.status.success(), "capabilities CLI failed");
    let parsed: TranscodeCapabilities =
        serde_json::from_slice(&out.stdout).expect("valid capabilities JSON");
    assert_eq!(parsed.ffmpeg_version.as_deref(), Some("8.1.3-Jellyfin"));
    assert_eq!(parsed.encoders, vec!["h264_vaapi", "hevc_qsv", "libx264"]);
    assert_eq!(parsed.worker_max_jobs, Some(DEFAULT_WORKER_MAX_JOBS));

    // Verify `AF_TRANSCODE_WORKER_MAX_JOBS` is advertised in `worker_max_jobs`.
    let out_custom = StdCommand::new(af_transcode_bin())
        .arg("capabilities")
        .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
        .env(ENV_WORKER_MAX_JOBS, "12")
        .output()
        .expect("run af-transcode capabilities with worker max jobs");
    assert!(
        out_custom.status.success(),
        "capabilities CLI custom max jobs failed"
    );
    let parsed_custom: TranscodeCapabilities =
        serde_json::from_slice(&out_custom.stdout).expect("valid custom capabilities JSON");
    assert_eq!(parsed_custom.worker_max_jobs, Some(12));
}

#[tokio::test]
async fn shim_protocol_handles_pre_send_and_malformed_handshake_frame_cases() {
    let dir = TempDir::new("protoerr");
    let fake_ffmpeg = write_executable_script(dir.path(), "real-ffmpeg", "#!/bin/sh\nexit 0\n");
    let sock = dir.path().join("badproto.sock");

    let listener = UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_frame(&mut stream).await.unwrap();
        // Send an oversized length header back after full Start was received.
        stream
            .write_all(&((af_transcode::MAX_FRAME_BYTES as u32) + 100).to_be_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });

    let cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(2),
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let dev_null = fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let decision = run_shim_protocol(
        &["-i".into(), "/srv/media/x.mkv".into(), "out.m3u8".into()],
        &cfg,
        dev_null.as_raw_fd(),
        &mut out,
        &mut err,
    )
    .await;
    server.await.unwrap();

    assert!(
        matches!(decision, ShimDecision::RemoteFailed { exit_code: 1, .. }),
        "malformed reply after full Start must fail without local exec, got {decision:?}"
    );

    // Pre-send probe check via direct protocol engine
    let probe_decision = run_shim_protocol(
        &["-version".into()],
        &cfg,
        dev_null.as_raw_fd(),
        &mut out,
        &mut err,
    )
    .await;
    assert_eq!(
        probe_decision,
        ShimDecision::ExecLocal {
            reason: LocalFallbackReason::ProbeArgs
        }
    );
}

#[tokio::test]
async fn worker_streams_high_volume_output_across_64_frame_backpressure_boundary() {
    let dir = TempDir::new("backpressure");
    let worker_sock = dir.path().join("worker.sock");
    // Emit > 5 MiB (> 80 x 64 KiB chunks, exceeding the 64-frame bounded channel) across stdout.
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\ndd if=/dev/zero bs=65536 count=96 status=none\nprintf 'DONE_ERR\\n' >&2\nexit 0\n",
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg);
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    let mut stream = UnixStream::connect(&worker_sock).await.unwrap();
    write_frame(
        &mut stream,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "/srv/media/big.mkv".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), Some(Frame::Started));

    let mut total_stdout_bytes = 0usize;
    let mut stderr_buf = Vec::new();
    let mut exit_code = None;
    while let Some(frame) = read_frame(&mut stream).await.unwrap() {
        match frame {
            Frame::Stdout(b) => total_stdout_bytes += b.len(),
            Frame::Stderr(b) => stderr_buf.extend_from_slice(&b),
            Frame::Exit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    assert_eq!(exit_code, Some(0));
    assert_eq!(total_stdout_bytes, 96 * 65536);
    assert_eq!(String::from_utf8_lossy(&stderr_buf), "DONE_ERR\n");

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;
}

#[tokio::test]
async fn worker_backpressures_high_volume_stdin_and_reaps_overflowing_disconnect() {
    use af_transcode::protocol::{FRAME_CHANNEL_CAPACITY, MAX_IO_CHUNK_BYTES};

    let dir = TempDir::new("stdin-backpressure");
    let worker_sock = dir.path().join("worker.sock");

    // 1. Slow-reading child must receive > 64 frames (> 4 MiB) cleanly via backpressure.
    let slow_reader = write_executable_script(
        dir.path(),
        "slow-reader-ffmpeg",
        "#!/usr/bin/python3\nimport sys, time\ntotal = 0\nwhile True:\n    chunk = sys.stdin.buffer.read(65536)\n    if not chunk:\n        break\n    total += len(chunk)\n    if total % (512 * 1024) == 0:\n        time.sleep(0.01)\nprint(total)\n",
    );
    let (shutdown_tx, worker_handle) =
        start_fixture_worker(WorkerConfig::for_paths(worker_sock.clone(), slow_reader)).await;

    let mut stream = UnixStream::connect(&worker_sock).await.unwrap();
    write_frame(
        &mut stream,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "pipe:0".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), Some(Frame::Started));

    let total_chunks = FRAME_CHANNEL_CAPACITY + 24;
    let payload = vec![0xab; MAX_IO_CHUNK_BYTES];
    for _ in 0..total_chunks {
        write_frame(&mut stream, &Frame::Stdin(payload.clone()))
            .await
            .unwrap();
    }
    write_frame(&mut stream, &Frame::StdinEof).await.unwrap();

    let mut out = Vec::new();
    let mut exit_code = None;
    while let Some(frame) = read_frame(&mut stream).await.unwrap() {
        match frame {
            Frame::Stdout(b) => out.extend_from_slice(&b),
            Frame::Exit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected frame during stdin backpressure: {other:?}"),
        }
    }
    assert_eq!(exit_code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out).trim(),
        (total_chunks * MAX_IO_CHUNK_BYTES).to_string()
    );
    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;

    // 2. Paused child whose client overflows into pending_stdin and disconnects is still reaped immediately.
    let paused_sock = dir.path().join("paused.sock");
    let paused_ffmpeg = write_executable_script(
        dir.path(),
        "paused-ffmpeg",
        "#!/bin/sh\nprintf '%s' \"$$\"\nexec /bin/sleep 20\n",
    );
    let mut paused_cfg = WorkerConfig::for_paths(paused_sock.clone(), paused_ffmpeg);
    paused_cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown2, worker2) = start_fixture_worker(paused_cfg).await;

    let mut client = UnixStream::connect(&paused_sock).await.unwrap();
    write_frame(
        &mut client,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "pipe:0".into(), "out.m3u8".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut client).await.unwrap(), Some(Frame::Started));
    let Some(Frame::Stdout(pid_bytes)) = read_frame(&mut client).await.unwrap() else {
        panic!("expected child pid");
    };
    let pid: i32 = std::str::from_utf8(&pid_bytes).unwrap().parse().unwrap();

    // Push enough frames to fill OS pipe + 64-frame queue + pending_stdin (non-blocking bounded attempt).
    let chunk = Frame::Stdin(vec![0xcd; MAX_IO_CHUNK_BYTES]);
    for _ in 0..(FRAME_CHANNEL_CAPACITY + 10) {
        if tokio::time::timeout(Duration::from_millis(50), write_frame(&mut client, &chunk))
            .await
            .is_err()
        {
            break;
        }
    }
    drop(client);

    let reaped = tokio::time::timeout(Duration::from_secs(2), async {
        while pid_is_alive(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let _ = shutdown2.send(());
    worker2.await.unwrap();
    reaped.expect("overflowing paused-stdin disconnect left child running");
}

#[tokio::test]
async fn worker_rejects_network_protocols_and_widened_whitelist_without_spawning_ffmpeg() {
    let dir = TempDir::new("ssrf-reject");
    let worker_sock = dir.path().join("worker.sock");
    let sentinel = dir.path().join("ffmpeg-spawned");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        &format!("#!/bin/sh\ntouch '{}'\nexit 0\n", sentinel.display()),
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg);
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    let rejected_cases: &[(&str, &[&str])] = &[
        (
            "http input",
            &["-i", "http://169.254.169.254/latest/meta-data", "out.m3u8"],
        ),
        (
            "https input",
            &["-i", "https://example.com/live.m3u8", "out.m3u8"],
        ),
        (
            "rtsp input",
            &["-i", "rtsp://10.0.0.1:554/stream", "out.m3u8"],
        ),
        (
            "unix socket input",
            &["-i", "unix:/run/aetherflow/runner.sock", "out.m3u8"],
        ),
        (
            "nested subfile http",
            &[
                "-i",
                "subfile,,start,0,end,64,,:http://127.0.0.1/x",
                "out.m3u8",
            ],
        ),
        (
            "concat remote",
            &[
                "-i",
                "concat:/srv/media/a.ts|http://127.0.0.1/b.ts",
                "out.m3u8",
            ],
        ),
        (
            "positional udp output",
            &[
                "-i",
                "/srv/media/a.mkv",
                "-f",
                "mpegts",
                "udp://10.0.0.1:1234",
            ],
        ),
        (
            "progress http exfil",
            &[
                "-i",
                "/srv/media/a.mkv",
                "-progress",
                "http://127.0.0.1/p",
                "out.m3u8",
            ],
        ),
        (
            "lavfi movie SSRF",
            &[
                "-f",
                "lavfi",
                "-i",
                r"movie=http\://127.0.0.1/a.mp4",
                "out.m3u8",
            ],
        ),
        (
            "caller widens protocol_whitelist",
            &[
                "-protocol_whitelist",
                "file,http,https,tcp,tls",
                "-i",
                "/srv/media/a.m3u8",
                "out.m3u8",
            ],
        ),
        (
            "caller protocol_whitelist unix",
            &[
                "-protocol_whitelist",
                "file,unix",
                "-i",
                "/srv/media/a.mkv",
                "out.m3u8",
            ],
        ),
        (
            "caller protocol_whitelist all",
            &[
                "-protocol_whitelist",
                "all",
                "-i",
                "/srv/media/a.mkv",
                "out.m3u8",
            ],
        ),
    ];

    for (name, raw_args) in rejected_cases {
        let mut s = UnixStream::connect(&worker_sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args: raw_args.iter().map(|a| (*a).to_string()).collect(),
                cwd: dir.path().to_string_lossy().into_owned(),
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(
            matches!(
                reply,
                Frame::Error {
                    kind: ErrorKind::InvalidRequest,
                    ..
                }
            ),
            "case '{name}' must be rejected with InvalidRequest, got {reply:?}"
        );
    }

    assert!(
        !sentinel.exists(),
        "real ffmpeg must NEVER be spawned for SSRF/network-protocol requests"
    );

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;
}

#[tokio::test]
async fn worker_injects_local_whitelist_per_input_and_clamps_untrusted_and_symlinked_cwd() {
    let dir = TempDir::new("cwd-wl");
    let worker_sock = dir.path().join("worker.sock");
    let allowed_sub = dir.path().join("sub");
    fs::create_dir(&allowed_sub).unwrap();
    let escape_symlink = dir.path().join("escape-to-etc");
    symlink("/etc", &escape_symlink).unwrap();

    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'PWD:%s\\n' \"$(pwd -P)\"\nprintf 'ARG:%s\\n' \"$@\"\n",
    );

    let mut cfg = WorkerConfig::for_paths(worker_sock.clone(), fake_ffmpeg);
    cfg.capabilities_override = Some(TranscodeCapabilities::default());
    let (shutdown_tx, worker_handle) = start_fixture_worker(cfg).await;

    let run_job = |args: Vec<String>, cwd: String| {
        let sock = worker_sock.clone();
        async move {
            let mut s = UnixStream::connect(&sock).await.unwrap();
            write_frame(
                &mut s,
                &Frame::Start(StartRequest {
                    args,
                    cwd,
                    env_subset: vec![],
                }),
            )
            .await
            .unwrap();
            assert_eq!(read_frame(&mut s).await.unwrap(), Some(Frame::Started));
            let mut out = Vec::new();
            while let Some(frame) = read_frame(&mut s).await.unwrap() {
                match frame {
                    Frame::Stdout(b) => out.extend_from_slice(&b),
                    Frame::Exit(code) => {
                        assert_eq!(code, 0);
                        break;
                    }
                    other => panic!("unexpected frame: {other:?}"),
                }
            }
            String::from_utf8_lossy(&out).into_owned()
        }
    };

    let canonical_safe = fs::canonicalize(dir.path()).unwrap();
    let canonical_sub = fs::canonicalize(&allowed_sub).unwrap();

    // 1. Out-of-root cwd (`/`) is clamped to worker safe directory; multi-input receives whitelist before EACH `-i`.
    let out_root = run_job(
        vec![
            "-protocol_whitelist".into(),
            "file,pipe".into(),
            "-i".into(),
            "/media/Movie: Part 1.mkv".into(),
            "-i".into(),
            "file:///media/sub.srt".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.m3u8".into(),
        ],
        "/".to_string(),
    )
    .await;
    let lines: Vec<&str> = out_root.lines().collect();
    assert_eq!(lines[0], format!("PWD:{}", canonical_safe.display()));
    assert_eq!(
        &lines[1..],
        &[
            "ARG:-protocol_whitelist",
            "ARG:file,pipe",
            "ARG:-i",
            "ARG:/media/Movie: Part 1.mkv",
            "ARG:-protocol_whitelist",
            &format!("ARG:{WORKER_LOCAL_PROTOCOL_WHITELIST}"),
            "ARG:-i",
            "ARG:file:///media/sub.srt",
            "ARG:-c:v",
            "ARG:libx264",
            "ARG:out.m3u8",
        ]
    );

    // 2. Symlink escape (`dir/escape-to-etc -> /etc`) is canonicalized and clamped to worker safe directory.
    let out_sym = run_job(
        vec!["-i".into(), "/srv/media/a.mkv".into(), "out.m3u8".into()],
        escape_symlink.to_string_lossy().into_owned(),
    )
    .await;
    assert_eq!(
        out_sym.lines().next(),
        Some(format!("PWD:{}", canonical_safe.display()).as_str())
    );

    // 3. Allowed subdirectory inside worker safe root is preserved.
    let out_sub = run_job(
        vec!["-i".into(), "/srv/media/a.mkv".into(), "out.m3u8".into()],
        allowed_sub.to_string_lossy().into_owned(),
    )
    .await;
    assert_eq!(
        out_sub.lines().next(),
        Some(format!("PWD:{}", canonical_sub.display()).as_str())
    );

    let _ = shutdown_tx.send(());
    let _ = worker_handle.await;
}

#[tokio::test]
async fn capabilities_probe_with_fake_vainfo_filters_encoders_and_reports_hw_decoders() {
    let dir = TempDir::new("vainfo-caps");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 8.1.3-Jellyfin"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V..... av1_qsv              AV1 QSV
 V....D av1_vaapi            AV1 VAAPI
 V....D h264_qsv             H.264 QSV
 V....D h264_vaapi           H.264 VAAPI
 V..... hevc_qsv             HEVC QSV
 V....D hevc_vaapi           HEVC VAAPI
 V....D libx264              libx264 H.264
 V..... vp9_qsv              VP9 QSV
 V....D vp9_vaapi            VP9 VAAPI
EOF
    exit 0
fi
exit 1
"#,
    );
    let fake_vainfo = write_executable_script(
        dir.path(),
        "vainfo",
        r#"#!/bin/sh
cat <<'EOF'
vainfo: Driver version: Intel iHD driver 25.2.3
vainfo: Supported profile and entrypoints
      VAProfileNone                   :	VAEntrypointVideoProc
      VAProfileH264Main               :	VAEntrypointVLD
      VAProfileH264Main               :	VAEntrypointEncSlice
      VAProfileHEVCMain               :	VAEntrypointVLD
      VAProfileHEVCMain               :	VAEntrypointEncSlice
      VAProfileHEVCMain10             :	VAEntrypointVLD
      VAProfileHEVCMain10             :	VAEntrypointEncSlice
      VAProfileVP9Profile0            :	VAEntrypointVLD
      VAProfileVP9Profile2            :	VAEntrypointVLD
EOF
"#,
    );

    // 1. Intel HD 630 fixture: keeps h264/hevc vaapi+qsv and libx264; strips av1 & vp9 hw encoders.
    let intel_cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg.clone(),
        dpkg_query_path: None,
        vainfo_path: Some(fake_vainfo.clone()),
        render_nodes_override: Some(vec![RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x8086".to_string()),
        }]),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: None,
        vulkan_video_override: None,
    };
    let intel_report = probe_capabilities(&intel_cfg).await.expect("probe intel");
    assert!(intel_report.hw_encoders_verified);
    assert_eq!(
        intel_report.encoders,
        vec![
            "h264_qsv",
            "h264_vaapi",
            "hevc_qsv",
            "hevc_vaapi",
            "libx264"
        ]
    );
    assert_eq!(
        intel_report.hw_decoders,
        vec!["h264", "hevc", "hevc_10bit", "vp9", "vp9_10bit"]
    );
    assert_eq!(
        intel_report.render_nodes[0].vaapi_driver.as_deref(),
        Some("Intel iHD driver 25.2.3")
    );
    assert!(intel_report.render_nodes[0].supports_vpp);

    // 2. AMD-only fixture: strips ALL *_qsv encoders while keeping supported *_vaapi and libx264.
    let amd_cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg,
        dpkg_query_path: None,
        vainfo_path: Some(fake_vainfo),
        render_nodes_override: Some(vec![RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: None,
        vulkan_video_override: None,
    };
    let amd_report = probe_capabilities(&amd_cfg).await.expect("probe amd");
    assert!(amd_report.hw_encoders_verified);
    assert_eq!(
        amd_report.encoders,
        vec!["h264_vaapi", "hevc_vaapi", "libx264"]
    );
}

#[tokio::test]
async fn worker_backend_adaptation_thread_cap_vulkan_opt_and_env_invariants() {
    use af_transcode::config::{BackendAdaptMode, ENV_WORKER_SOCKET};

    let dir = TempDir::new("adapt-opt");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\n",
    );

    let run_worker_args = |sock: PathBuf, args: Vec<String>, cwd: String| async move {
        let mut s = UnixStream::connect(&sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args,
                cwd,
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let first = read_frame(&mut s).await.unwrap().expect("first frame");
        match first {
            Frame::Started => {
                let mut out = Vec::new();
                while let Some(frame) = read_frame(&mut s).await.unwrap() {
                    match frame {
                        Frame::Stdout(b) => out.extend_from_slice(&b),
                        Frame::Exit(code) => {
                            assert_eq!(code, 0);
                            break;
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                Ok(String::from_utf8_lossy(&out)
                    .lines()
                    .filter_map(|l| l.strip_prefix("ARG:"))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>())
            }
            Frame::Error { kind, message } => Err((kind, message)),
            other => panic!("unexpected initial reply: {other:?}"),
        }
    };

    // 1. AMD-only worker with Gpu adaptation + thread cap 4 + Vulkan tonemap optimization.
    let amd_sock = dir.path().join("amd.sock");
    let mut amd_cfg = WorkerConfig::for_paths(amd_sock.clone(), fake_ffmpeg.clone());
    amd_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    amd_cfg.adapt_backend_mode = BackendAdaptMode::Gpu;
    amd_cfg.ffmpeg_max_threads = Some(4);
    amd_cfg.optimize_vulkan_tonemap = true;
    let (amd_shutdown, amd_worker) = start_fixture_worker(amd_cfg).await;

    let cwd = dir.path().to_string_lossy().into_owned();

    // 1a. QSV job adapts to VA-API on AMD node, strips QSV-only flags, caps threads, injects whitelist.
    let qsv_adapted = run_worker_args(
        amd_sock.clone(),
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD129,driver=iHD".into(),
            "-init_hw_device".into(),
            "qsv=qs@va".into(),
            "-filter_hw_device".into(),
            "qs".into(),
            "-hwaccel".into(),
            "qsv".into(),
            "-hwaccel_output_format".into(),
            "qsv".into(),
            "-c:v".into(),
            "hevc_qsv".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-vf".into(),
            "vpp_qsv=w=1920:h=1080:format=nv12".into(),
            "-c:v".into(),
            "h264_qsv".into(),
            "-preset".into(),
            "faster".into(),
            "-global_quality".into(),
            "20".into(),
            "-threads".into(),
            "0".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("QSV job should adapt on AMD");
    assert_eq!(
        qsv_adapted,
        vec![
            "-init_hw_device",
            "vaapi=va:/dev/dri/renderD128",
            "-filter_hw_device",
            "va",
            "-hwaccel",
            "vaapi",
            "-hwaccel_output_format",
            "vaapi",
            "-c:v",
            "hevc",
            "-threads",
            "4",
            "-protocol_whitelist",
            WORKER_LOCAL_PROTOCOL_WHITELIST,
            "-i",
            "/srv/media/in.mkv",
            "-vf",
            "scale_vaapi=w=1920:h=1080:format=nv12",
            "-c:v",
            "h264_vaapi",
            "-qp",
            "20",
            "-threads",
            "4",
            "out.m3u8",
        ]
    );

    // 1b. Unadaptable QSV vpp_qsv=tonemap=1 fails with DeviceUnavailable.
    let bad_qsv = run_worker_args(
        amd_sock.clone(),
        vec![
            "-qsv_device".into(),
            "/dev/dri/renderD128".into(),
            "-i".into(),
            "/srv/media/hdr.mkv".into(),
            "-vf".into(),
            "vpp_qsv=tonemap=1:format=nv12".into(),
            "-c:v".into(),
            "h264_qsv".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await;
    assert!(matches!(bad_qsv, Err((ErrorKind::DeviceUnavailable, _))));

    // 1c. VA-API + Vulkan libplacebo job receives scale_vaapi pre-scaling before hwmap.
    let vk_opt = run_worker_args(
        amd_sock.clone(),
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD128".into(),
            "-init_hw_device".into(),
            "vulkan=vk@va".into(),
            "-filter_hw_device".into(),
            "va".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-hwaccel_output_format".into(),
            "vaapi".into(),
            "-i".into(),
            "/srv/media/hdr.mkv".into(),
            "-vf".into(),
            "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=bt.2390:format=nv12,hwmap=derive_device=vaapi:reverse=1".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("VA-API + Vulkan job should succeed");
    assert!(vk_opt.iter().any(|a| a.starts_with(
        "scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo="
    )));

    // 1d. Caller env_subset still rejects newly added worker GPU vars (e.g. RUSTICL_ENABLE).
    for forbidden_caller_env in [
        ("RUSTICL_ENABLE", "radeonsi"),
        ("RADV_PERFTEST", "video_decode"),
        ("MESA_SHADER_CACHE_DIR", "/tmp/shader-cache"),
        ("MESA_SHADER_CACHE_MAX_SIZE", "512M"),
        ("VK_DRIVER_FILES", "/usr/share/vulkan/icd.d/radeon_icd.json"),
        ("OCL_ICD_VENDORS", "/etc/OpenCL/vendors"),
    ] {
        let mut s = UnixStream::connect(&amd_sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args: vec!["-i".into(), "/srv/media/a.mkv".into(), "out.m3u8".into()],
                cwd: cwd.clone(),
                env_subset: vec![(forbidden_caller_env.0.into(), forbidden_caller_env.1.into())],
            }),
        )
        .await
        .unwrap();
        let reply = read_frame(&mut s).await.unwrap().expect("error reply");
        assert!(
            matches!(
                reply,
                Frame::Error {
                    kind: ErrorKind::InvalidRequest,
                    ..
                }
            ),
            "caller env {} must be rejected with InvalidRequest",
            forbidden_caller_env.0
        );
    }

    let _ = amd_shutdown.send(());
    let _ = amd_worker.await;

    // 2. Intel worker with PreferQsv upgrades clean VA-API job to QSV.
    let intel_sock = dir.path().join("intel.sock");
    let mut intel_cfg = WorkerConfig::for_paths(intel_sock.clone(), fake_ffmpeg.clone());
    intel_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD129"),
        vendor_id: Some("0x8086".to_string()),
    }]);
    intel_cfg.adapt_backend_mode = BackendAdaptMode::PreferQsv;
    let (intel_shutdown, intel_worker) = start_fixture_worker(intel_cfg).await;

    let qsv_upgraded = run_worker_args(
        intel_sock,
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD128".into(),
            "-filter_hw_device".into(),
            "va".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-hwaccel_output_format".into(),
            "vaapi".into(),
            "-c:v".into(),
            "hevc".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-vf".into(),
            "scale_vaapi=w=1280:h=720:format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("PreferQsv should upgrade clean VA-API job");
    assert!(qsv_upgraded.contains(&"qsv=qs@va".to_string()));
    assert!(qsv_upgraded.contains(&"hevc_qsv".to_string()));
    assert!(qsv_upgraded.contains(&"h264_qsv".to_string()));
    assert!(qsv_upgraded.contains(&"scale_qsv=w=1280:h=720:format=nv12".to_string()));

    let _ = intel_shutdown.send(());
    let _ = intel_worker.await;

    // 3. CPU-only worker with All adapts VA-API H.264 to libx264, while still rejecting tonemap_vaapi.
    let cpu_sock = dir.path().join("cpu.sock");
    let mut cpu_cfg = WorkerConfig::for_paths(cpu_sock.clone(), fake_ffmpeg);
    cpu_cfg.render_nodes_override = Some(vec![]);
    cpu_cfg.adapt_backend_mode = BackendAdaptMode::All;
    let (cpu_shutdown, cpu_worker) = start_fixture_worker(cpu_cfg).await;

    let cpu_adapted = run_worker_args(
        cpu_sock.clone(),
        vec![
            "-vaapi_device".into(),
            "/dev/dri/renderD128".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-vf".into(),
            "scale_vaapi=w=1280:h=720:format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("All mode should adapt VA-API H.264 to CPU");
    assert_eq!(
        cpu_adapted,
        vec![
            "-protocol_whitelist",
            WORKER_LOCAL_PROTOCOL_WHITELIST,
            "-i",
            "/srv/media/in.mkv",
            "-vf",
            "scale=w=1280:h=720,format=yuv420p",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "out.m3u8",
        ]
    );

    let cpu_tonemap_err = run_worker_args(
        cpu_sock,
        vec![
            "-vaapi_device".into(),
            "/dev/dri/renderD128".into(),
            "-i".into(),
            "/srv/media/hdr.mkv".into(),
            "-vf".into(),
            "tonemap_vaapi=format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await;
    assert!(matches!(
        cpu_tonemap_err,
        Err((ErrorKind::DeviceUnavailable, _))
    ));

    let _ = cpu_shutdown.send(());
    let _ = cpu_worker.await;

    // 4. Real `af-transcode worker` subprocess passes worker-local GPU env vars and creates MESA_SHADER_CACHE_DIR.
    let env_sock = dir.path().join("env-worker.sock");
    let shader_cache = dir.path().join("mesa-cache/sub");
    let env_ffmpeg = write_executable_script(
        dir.path(),
        "env-ffmpeg",
        "#!/bin/sh\nprintf 'RUSTICL=%s\\nRADV=%s\\nCACHE=%s\\nCACHE_MAX=%s\\n' \"$RUSTICL_ENABLE\" \"$RADV_PERFTEST\" \"$MESA_SHADER_CACHE_DIR\" \"$MESA_SHADER_CACHE_MAX_SIZE\"\n",
    );
    let mut worker_proc = StdCommand::new(af_transcode_bin())
        .arg("worker")
        .env(ENV_WORKER_SOCKET, &env_sock)
        .env(ENV_REAL_FFMPEG, &env_ffmpeg)
        .env("RUSTICL_ENABLE", "radeonsi")
        .env("RADV_PERFTEST", "video_decode,video_encode")
        .env("MESA_SHADER_CACHE_DIR", &shader_cache)
        .env("MESA_SHADER_CACHE_MAX_SIZE", "512M")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn af-transcode worker");

    let wait_deadline = Instant::now() + Duration::from_secs(3);
    while !env_sock.exists() && Instant::now() < wait_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(env_sock.exists(), "worker socket did not appear in time");

    let mut s = UnixStream::connect(&env_sock).await.unwrap();
    write_frame(
        &mut s,
        &Frame::Start(StartRequest {
            args: vec!["-i".into(), "/srv/media/in.mkv".into(), "out.m3u8".into()],
            cwd,
            env_subset: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut s).await.unwrap(), Some(Frame::Started));
    let mut env_out = Vec::new();
    while let Some(frame) = read_frame(&mut s).await.unwrap() {
        match frame {
            Frame::Stdout(b) => env_out.extend_from_slice(&b),
            Frame::Exit(code) => {
                assert_eq!(code, 0);
                break;
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    let env_text = String::from_utf8_lossy(&env_out);
    assert!(env_text.contains("RUSTICL=radeonsi\n"), "got: {env_text}");
    assert!(
        env_text.contains("RADV=video_decode,video_encode\n"),
        "got: {env_text}"
    );
    assert!(
        env_text.contains(&format!("CACHE={}\n", shader_cache.display())),
        "got: {env_text}"
    );
    assert!(env_text.contains("CACHE_MAX=512M\n"), "got: {env_text}");
    assert!(
        shader_cache.is_dir(),
        "worker must create clean absolute MESA_SHADER_CACHE_DIR"
    );

    let _ = kill(Pid::from_raw(worker_proc.id() as i32), Signal::SIGTERM);
    let _ = worker_proc.wait();
}

#[tokio::test]
async fn worker_unifies_plan_backend_adaptation_with_probed_encoders_and_hw_decoders() {
    use af_transcode::capabilities::RenderNodeInfo;
    use af_transcode::config::BackendAdaptMode;

    let dir = TempDir::new("adapt-unified");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\n",
    );
    let cwd = dir.path().to_string_lossy().into_owned();

    let run_worker_args = |sock: PathBuf, args: Vec<String>, cwd: String| async move {
        let mut s = UnixStream::connect(&sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args,
                cwd,
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let first = read_frame(&mut s).await.unwrap().expect("first frame");
        match first {
            Frame::Started => {
                let mut out = Vec::new();
                while let Some(frame) = read_frame(&mut s).await.unwrap() {
                    match frame {
                        Frame::Stdout(b) => out.extend_from_slice(&b),
                        Frame::Exit(code) => {
                            assert_eq!(code, 0);
                            break;
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                Ok(String::from_utf8_lossy(&out)
                    .lines()
                    .filter_map(|l| l.strip_prefix("ARG:"))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>())
            }
            Frame::Error { kind, message } => Err((kind, message)),
            other => panic!("unexpected initial reply: {other:?}"),
        }
    };

    // 1. Intel HD 630 GPU worker lacking AV1 HW decode (hw_decoders = ["h264", "hevc"]),
    //    encoders = ["h264_vaapi", "libx264"], adapt_backend_mode = All:
    //    AV1 VA-API job MUST adapt to CPU (`libx264`), NOT run unadapted native VA-API!
    let hd630_sock = dir.path().join("hd630.sock");
    let mut hd630_cfg = WorkerConfig::for_paths(hd630_sock.clone(), fake_ffmpeg.clone());
    hd630_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x8086".to_string()),
    }]);
    hd630_cfg.adapt_backend_mode = BackendAdaptMode::All;
    hd630_cfg.capabilities_override = Some(TranscodeCapabilities {
        ffmpeg_path: fake_ffmpeg.to_string_lossy().into_owned(),
        encoders: vec!["h264_vaapi".into(), "libx264".into()],
        hw_decoders: vec!["h264".into(), "hevc".into()],
        render_nodes: vec![RenderNodeInfo {
            path: "/dev/dri/renderD128".into(),
            vendor_id: Some("0x8086".into()),
            vendor: Some("intel".into()),
            vaapi_decode_codecs: vec!["h264".into(), "hevc".into()],
            vaapi_encode_codecs: vec!["h264".into()],
            ..Default::default()
        }],
        primary_render_node: Some("/dev/dri/renderD128".into()),
        hw_encoders_verified: true,
        adapt_backend_mode: Some(BackendAdaptMode::All),
        ..Default::default()
    });
    let (hd630_shutdown, hd630_worker) = start_fixture_worker(hd630_cfg).await;

    let av1_adapted = run_worker_args(
        hd630_sock.clone(),
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD128".into(),
            "-filter_hw_device".into(),
            "va".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-hwaccel_output_format".into(),
            "vaapi".into(),
            "-c:v".into(),
            "av1".into(),
            "-i".into(),
            "/srv/media/av1.mkv".into(),
            "-vf".into(),
            "scale_vaapi=w=1280:h=720:format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("HD 630 in All mode should adapt unsupported AV1 VA-API job to CPU");
    assert!(
        av1_adapted.contains(&"libx264".to_string()),
        "expected CPU libx264 adaptation, got: {av1_adapted:?}"
    );
    assert!(
        !av1_adapted.contains(&"h264_vaapi".to_string())
            && !av1_adapted.contains(&"-hwaccel".to_string()),
        "must not execute unadapted VA-API command when worker lacks AV1 HW decode: {av1_adapted:?}"
    );

    let _ = hd630_shutdown.send(());
    let _ = hd630_worker.await;

    // 2. Intel node in PreferQsv mode WITHOUT `h264_qsv` in worker encoders:
    //    VA-API H.264 job MUST stay Native (`h264_vaapi`), NOT rewrite to `h264_qsv`!
    let no_qsv_sock = dir.path().join("intel-no-qsv.sock");
    let mut no_qsv_cfg = WorkerConfig::for_paths(no_qsv_sock.clone(), fake_ffmpeg.clone());
    no_qsv_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD129"),
        vendor_id: Some("0x8086".to_string()),
    }]);
    no_qsv_cfg.adapt_backend_mode = BackendAdaptMode::PreferQsv;
    no_qsv_cfg.capabilities_override = Some(TranscodeCapabilities {
        ffmpeg_path: fake_ffmpeg.to_string_lossy().into_owned(),
        encoders: vec!["h264_vaapi".into(), "libx264".into()],
        hw_decoders: vec!["h264".into(), "hevc".into()],
        render_nodes: vec![RenderNodeInfo {
            path: "/dev/dri/renderD129".into(),
            vendor_id: Some("0x8086".into()),
            vendor: Some("intel".into()),
            ..Default::default()
        }],
        primary_render_node: Some("/dev/dri/renderD129".into()),
        hw_encoders_verified: true,
        adapt_backend_mode: Some(BackendAdaptMode::PreferQsv),
        ..Default::default()
    });
    let (no_qsv_shutdown, no_qsv_worker) = start_fixture_worker(no_qsv_cfg).await;

    let stayed_native = run_worker_args(
        no_qsv_sock,
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD128".into(),
            "-filter_hw_device".into(),
            "va".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-hwaccel_output_format".into(),
            "vaapi".into(),
            "-c:v".into(),
            "hevc".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-vf".into(),
            "scale_vaapi=w=1280:h=720:format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("PreferQsv without h264_qsv should stay Native VA-API");
    assert!(
        stayed_native.contains(&"h264_vaapi".to_string()),
        "expected Native h264_vaapi, got: {stayed_native:?}"
    );
    assert!(
        !stayed_native.contains(&"h264_qsv".to_string()),
        "must not rewrite to missing h264_qsv: {stayed_native:?}"
    );
    assert!(
        stayed_native.contains(&"vaapi=va:/dev/dri/renderD129".to_string()),
        "Native path must still remap render node to renderD129: {stayed_native:?}"
    );

    let _ = no_qsv_shutdown.send(());
    let _ = no_qsv_worker.await;

    // 3. Intel node in Gpu mode lacking `h264_vaapi` but having `h264_qsv`:
    //    VA-API H.264 job adapts to QSV (`h264_qsv`) even though render node exists!
    let qsv_fb_sock = dir.path().join("intel-qsv-fb.sock");
    let mut qsv_fb_cfg = WorkerConfig::for_paths(qsv_fb_sock.clone(), fake_ffmpeg.clone());
    qsv_fb_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD129"),
        vendor_id: Some("0x8086".to_string()),
    }]);
    qsv_fb_cfg.adapt_backend_mode = BackendAdaptMode::Gpu;
    qsv_fb_cfg.capabilities_override = Some(TranscodeCapabilities {
        ffmpeg_path: fake_ffmpeg.to_string_lossy().into_owned(),
        encoders: vec!["h264_qsv".into(), "libx264".into()],
        hw_decoders: vec!["h264".into(), "hevc".into()],
        render_nodes: vec![RenderNodeInfo {
            path: "/dev/dri/renderD129".into(),
            vendor_id: Some("0x8086".into()),
            vendor: Some("intel".into()),
            ..Default::default()
        }],
        primary_render_node: Some("/dev/dri/renderD129".into()),
        hw_encoders_verified: true,
        adapt_backend_mode: Some(BackendAdaptMode::Gpu),
        ..Default::default()
    });
    let (qsv_fb_shutdown, qsv_fb_worker) = start_fixture_worker(qsv_fb_cfg).await;

    let adapted_to_qsv = run_worker_args(
        qsv_fb_sock,
        vec![
            "-init_hw_device".into(),
            "vaapi=va:/dev/dri/renderD128".into(),
            "-filter_hw_device".into(),
            "va".into(),
            "-hwaccel".into(),
            "vaapi".into(),
            "-hwaccel_output_format".into(),
            "vaapi".into(),
            "-c:v".into(),
            "hevc".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-vf".into(),
            "scale_vaapi=w=1280:h=720:format=nv12".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd,
    )
    .await
    .expect("Gpu mode should fall back VA-API -> QSV when worker only has h264_qsv");
    assert!(
        adapted_to_qsv.contains(&"h264_qsv".to_string()),
        "expected VA-API -> QSV fallback, got: {adapted_to_qsv:?}"
    );
    assert!(
        adapted_to_qsv.contains(&"vaapi=va:/dev/dri/renderD129".to_string()),
        "expected render node renderD129, got: {adapted_to_qsv:?}"
    );

    let _ = qsv_fb_shutdown.send(());
    let _ = qsv_fb_worker.await;
}

#[tokio::test]
async fn capabilities_probe_separates_vulkan_compute_from_vulkan_video() {
    let dir = TempDir::new("vk-caps");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 8.1.3-Jellyfin"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V....D av1_vulkan           AV1 (Vulkan)
 V....D ffv1_vulkan          FFV1 (Vulkan)
 V....D h264_vaapi           H.264/AVC (VAAPI)
 V....D h264_vulkan          H.264/AVC (Vulkan)
 V....D hevc_vulkan          H.265/HEVC (Vulkan)
 V....D libx264              libx264 H.264
EOF
    exit 0
fi
if [ "$4" = "-init_hw_device" ] && [ "$5" = "vulkan=vk" ]; then
    cat >&2 <<'EOF'
[Vulkan @ 0x55a100001000] Device 0 selected: AMD Radeon Graphics (RADV REMBRANDT) (integrated) (0x1681)
[Vulkan @ 0x55a100001000] Queue families:
[Vulkan @ 0x55a100001000]     0: graphics compute transfer sparse (queues: 1)
[Vulkan @ 0x55a100001000]     1: transfer decode (queues: 1)
[Vulkan @ 0x55a100001000]     2: transfer encode (queues: 1)
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_queue
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_encode_queue
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_h264
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_h265
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_encode_h264
EOF
    exit 0
fi
exit 1
"#,
    );

    let amd_node = vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }];

    // 1. Compute enabled, Video disabled (default policy): advertises vulkan_compute=true & device,
    //    vulkan_video=false, strips all *_vulkan encoders.
    let compute_only_cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg.clone(),
        dpkg_query_path: None,
        vainfo_path: None,
        render_nodes_override: Some(amd_node.clone()),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: Some(true),
        vulkan_video_override: Some(false),
    };
    let r1 = probe_capabilities(&compute_only_cfg)
        .await
        .expect("probe compute only");
    assert_eq!(r1.vulkan_compute, Some(true));
    assert_eq!(
        r1.vulkan_device.as_deref(),
        Some("AMD Radeon Graphics (RADV REMBRANDT)")
    );
    assert_eq!(r1.vulkan_video, Some(false));
    assert!(r1.vulkan_video_decode_codecs.is_empty());
    assert!(r1.vulkan_video_encode_codecs.is_empty());
    assert_eq!(r1.encoders, vec!["h264_vaapi", "libx264"]);

    // 2. Both Compute and Video enabled: advertises probed codecs and keeps only supported h264_vulkan.
    let both_cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg.clone(),
        dpkg_query_path: None,
        vainfo_path: None,
        render_nodes_override: Some(amd_node.clone()),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: Some(true),
        vulkan_video_override: Some(true),
    };
    let r2 = probe_capabilities(&both_cfg).await.expect("probe both");
    assert_eq!(r2.vulkan_compute, Some(true));
    assert_eq!(r2.vulkan_video, Some(true));
    assert_eq!(r2.vulkan_video_decode_codecs, vec!["h264", "hevc"]);
    assert_eq!(r2.vulkan_video_encode_codecs, vec!["h264"]);
    assert_eq!(r2.encoders, vec!["h264_vaapi", "h264_vulkan", "libx264"]);

    // 3. Both Compute and Video disabled: short-circuits without spawning the Vulkan probe subprocess,
    //    clears vulkan_device, and strips all *_vulkan encoders.
    let vk_probe_sentinel = dir.path().join("vk-probe-ran");
    let sentinel_ffmpeg = write_executable_script(
        dir.path(),
        "sentinel-ffmpeg",
        &format!(
            r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 8.1.3-Jellyfin"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V....D av1_vulkan           AV1 (Vulkan)
 V....D h264_vaapi           H.264/AVC (VAAPI)
 V....D h264_vulkan          H.264/AVC (Vulkan)
 V....D libx264              libx264 H.264
EOF
    exit 0
fi
touch '{}'
exit 1
"#,
            vk_probe_sentinel.display()
        ),
    );
    let disabled_cfg = CapabilitiesConfig {
        real_ffmpeg: sentinel_ffmpeg,
        dpkg_query_path: None,
        vainfo_path: None,
        render_nodes_override: Some(amd_node),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: Some(false),
        vulkan_video_override: Some(false),
    };
    let r3 = probe_capabilities(&disabled_cfg)
        .await
        .expect("probe disabled");
    assert_eq!(r3.vulkan_compute, Some(false));
    assert_eq!(r3.vulkan_video, Some(false));
    assert_eq!(r3.vulkan_device, None);
    assert!(r3.vulkan_video_decode_codecs.is_empty());
    assert!(r3.vulkan_video_encode_codecs.is_empty());
    assert_eq!(r3.encoders, vec!["h264_vaapi", "libx264"]);
    assert!(
        !vk_probe_sentinel.exists(),
        "Vulkan probe subprocess must not spawn when both vulkan_compute and vulkan_video are disabled"
    );

    // 4. Empty render_nodes_override (CPU-only fixture) synthesizes probed=true, compute=false
    //    without touching host GPU.
    let cpu_cfg = CapabilitiesConfig {
        real_ffmpeg: fake_ffmpeg,
        dpkg_query_path: None,
        vainfo_path: None,
        render_nodes_override: Some(vec![]),
        probe_timeout: Duration::from_secs(5),
        vulkan_compute_override: Some(true),
        vulkan_video_override: Some(true),
    };
    let r4 = probe_capabilities(&cpu_cfg).await.expect("probe cpu-only");
    assert_eq!(r4.vulkan_compute, Some(false));
    assert_eq!(r4.vulkan_video, Some(false));
    assert_eq!(r4.vulkan_device, None);
    assert_eq!(r4.encoders, vec!["h264_vaapi", "libx264"]);
}

#[tokio::test]
async fn worker_and_shim_enforce_vulkan_compute_vs_video_separation_and_local_tonemap_opt() {
    use af_transcode::config::{
        BackendAdaptMode, ENV_WORKER_OPTIMIZE_VULKAN_TONEMAP, ENV_WORKER_VULKAN_COMPUTE,
    };

    let dir = TempDir::new("vk-sep");
    let fake_ffmpeg = write_executable_script(
        dir.path(),
        "real-ffmpeg",
        "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\n",
    );
    let cwd = dir.path().to_string_lossy().into_owned();

    let run_worker_args = |sock: PathBuf, args: Vec<String>, cwd: String| async move {
        let mut s = UnixStream::connect(&sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args,
                cwd,
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let first = read_frame(&mut s).await.unwrap().expect("first frame");
        match first {
            Frame::Started => {
                let mut out = Vec::new();
                while let Some(frame) = read_frame(&mut s).await.unwrap() {
                    match frame {
                        Frame::Stdout(b) => out.extend_from_slice(&b),
                        Frame::Exit(code) => {
                            assert_eq!(code, 0);
                            break;
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                Ok(String::from_utf8_lossy(&out)
                    .lines()
                    .filter_map(|l| l.strip_prefix("ARG:"))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>())
            }
            Frame::Error { kind, message } => Err((kind, message)),
            other => panic!("unexpected initial reply: {other:?}"),
        }
    };

    let hdr_tonemap_args = vec![
        "-init_hw_device".to_string(),
        "vaapi=va:/dev/dri/renderD128".to_string(),
        "-init_hw_device".to_string(),
        "vulkan=vk@va".to_string(),
        "-filter_hw_device".to_string(),
        "va".to_string(),
        "-hwaccel".to_string(),
        "vaapi".to_string(),
        "-hwaccel_output_format".to_string(),
        "vaapi".to_string(),
        "-c:v".to_string(),
        "hevc".to_string(),
        "-i".to_string(),
        "/srv/media/hdr.mkv".to_string(),
        "-vf".to_string(),
        "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=bt.2390:format=nv12,hwmap=derive_device=vaapi:reverse=1".to_string(),
        "-c:v".to_string(),
        "h264_vaapi".to_string(),
        "out.m3u8".to_string(),
    ];

    let vk_video_args = vec![
        "-init_hw_device".to_string(),
        "vulkan=vk".to_string(),
        "-hwaccel".to_string(),
        "vulkan".to_string(),
        "-hwaccel_output_format".to_string(),
        "vulkan".to_string(),
        "-c:v".to_string(),
        "hevc".to_string(),
        "-i".to_string(),
        "/srv/media/clip.mkv".to_string(),
        "-c:v".to_string(),
        "h264_vulkan".to_string(),
        "out.m3u8".to_string(),
    ];

    // 1. Off-mode worker with default vulkan_compute=true, vulkan_video=false:
    //    HDR Vulkan Compute succeeds; Vulkan Video fails closed with DeviceUnavailable.
    let off_sock = dir.path().join("off.sock");
    let mut off_cfg = WorkerConfig::for_paths(off_sock.clone(), fake_ffmpeg.clone());
    off_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    off_cfg.optimize_vulkan_tonemap = true;
    let (off_shutdown, off_worker) = start_fixture_worker(off_cfg).await;

    let ok_compute = run_worker_args(off_sock.clone(), hdr_tonemap_args.clone(), cwd.clone())
        .await
        .expect("Vulkan Compute HDR tonemap must succeed with vulkan_video=false");
    assert!(ok_compute.iter().any(|a| a.starts_with(
        "scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo="
    )));

    let err_video = run_worker_args(off_sock, vk_video_args.clone(), cwd.clone()).await;
    assert!(matches!(err_video, Err((ErrorKind::DeviceUnavailable, _))));

    let _ = off_shutdown.send(());
    let _ = off_worker.await;

    // 2. Off-mode worker with vulkan_compute=false fails closed on Vulkan Compute jobs.
    let no_compute_sock = dir.path().join("nocompute.sock");
    let mut no_compute_cfg = WorkerConfig::for_paths(no_compute_sock.clone(), fake_ffmpeg.clone());
    no_compute_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    no_compute_cfg.vulkan_compute = false;
    no_compute_cfg.optimize_vulkan_tonemap = true;
    let (nc_shutdown, nc_worker) = start_fixture_worker(no_compute_cfg).await;

    let err_compute = run_worker_args(no_compute_sock, hdr_tonemap_args.clone(), cwd.clone()).await;
    assert!(matches!(
        err_compute,
        Err((ErrorKind::DeviceUnavailable, _))
    ));

    let _ = nc_shutdown.send(());
    let _ = nc_worker.await;

    // 2b. Off-mode worker with vulkan_compute=true but capabilities_override reporting
    //     vulkan_compute=Some(false) fails closed on Vulkan Compute jobs.
    let unavail_compute_sock = dir.path().join("unavailcompute.sock");
    let mut unavail_cfg =
        WorkerConfig::for_paths(unavail_compute_sock.clone(), fake_ffmpeg.clone());
    unavail_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    unavail_cfg.capabilities_override = Some(TranscodeCapabilities {
        ffmpeg_path: fake_ffmpeg.to_string_lossy().into_owned(),
        encoders: vec!["h264_vaapi".into(), "libx264".into()],
        vulkan_compute: Some(false),
        vulkan_video: Some(false),
        ..Default::default()
    });
    let (uc_shutdown, uc_worker) = start_fixture_worker(unavail_cfg).await;
    let err_unavail =
        run_worker_args(unavail_compute_sock, hdr_tonemap_args.clone(), cwd.clone()).await;
    assert!(matches!(
        err_unavail,
        Err((ErrorKind::DeviceUnavailable, _))
    ));
    let _ = uc_shutdown.send(());
    let _ = uc_worker.await;

    // 2c. Off-mode worker with vulkan_video=true and codec-specific capabilities_override allows
    //     supported Vulkan Video decode/encode codecs and rejects unsupported codecs.
    let vkv_sock = dir.path().join("vkvideo.sock");
    let mut vkv_cfg = WorkerConfig::for_paths(vkv_sock.clone(), fake_ffmpeg.clone());
    vkv_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    vkv_cfg.vulkan_video = true;
    vkv_cfg.capabilities_override = Some(TranscodeCapabilities {
        ffmpeg_path: fake_ffmpeg.to_string_lossy().into_owned(),
        encoders: vec!["h264_vulkan".into(), "libx264".into()],
        vulkan_compute: Some(true),
        vulkan_video: Some(true),
        vulkan_video_decode_codecs: vec!["h264".into(), "hevc".into()],
        vulkan_video_encode_codecs: vec!["h264".into()],
        ..Default::default()
    });
    let (vkv_shutdown, vkv_worker) = start_fixture_worker(vkv_cfg).await;

    let ok_vkv = run_worker_args(vkv_sock.clone(), vk_video_args.clone(), cwd.clone())
        .await
        .expect("supported Vulkan Video decode(hevc)+encode(h264) should succeed");
    assert!(ok_vkv.contains(&"h264_vulkan".to_string()));

    let mut unsupported_dec = vk_video_args.clone();
    unsupported_dec[7] = "av1".to_string();
    let err_vkv_dec = run_worker_args(vkv_sock.clone(), unsupported_dec, cwd.clone()).await;
    assert!(matches!(
        err_vkv_dec,
        Err((ErrorKind::DeviceUnavailable, _))
    ));

    let mut unsupported_enc = vk_video_args.clone();
    unsupported_enc[11] = "hevc_vulkan".to_string();
    let err_vkv_enc = run_worker_args(vkv_sock, unsupported_enc, cwd.clone()).await;
    assert!(matches!(
        err_vkv_enc,
        Err((ErrorKind::DeviceUnavailable, _))
    ));
    let _ = vkv_shutdown.send(());
    let _ = vkv_worker.await;

    // 3. Adapt mode All with vulkan_video=false adapts pure Vulkan Video job to CPU (libx264),
    //    while Gpu mode rejects it (fallback encoders must NOT synthesize *_vulkan when disabled).
    let gpu_sock = dir.path().join("gpu.sock");
    let mut gpu_cfg = WorkerConfig::for_paths(gpu_sock.clone(), fake_ffmpeg.clone());
    gpu_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    gpu_cfg.adapt_backend_mode = BackendAdaptMode::Gpu;
    let (gpu_shutdown, gpu_worker) = start_fixture_worker(gpu_cfg).await;

    let gpu_vk_err = run_worker_args(gpu_sock, vk_video_args.clone(), cwd.clone()).await;
    assert!(matches!(gpu_vk_err, Err((ErrorKind::DeviceUnavailable, _))));

    let _ = gpu_shutdown.send(());
    let _ = gpu_worker.await;

    let all_sock = dir.path().join("all.sock");
    let mut all_cfg = WorkerConfig::for_paths(all_sock.clone(), fake_ffmpeg.clone());
    all_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    all_cfg.adapt_backend_mode = BackendAdaptMode::All;
    let (all_shutdown, all_worker) = start_fixture_worker(all_cfg).await;

    let cpu_from_vk = run_worker_args(all_sock, vk_video_args.clone(), cwd.clone())
        .await
        .expect("All mode should adapt pure Vulkan Video job to CPU libx264");
    assert!(cpu_from_vk.contains(&"libx264".to_string()));
    assert!(!cpu_from_vk.contains(&"h264_vulkan".to_string()));

    let _ = all_shutdown.send(());
    let _ = all_worker.await;

    // 4. Local shim fallback applies scale_vaapi pre-scale by default, and respects opt-out env vars.
    let shim = symlink_ffmpeg_shim(dir.path());
    let missing_sock = dir.path().join("absent.sock");

    let local_opt = StdCommand::new(&shim)
        .args(&hdr_tonemap_args)
        .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
        .env(ENV_DISPATCHER_SOCKET, &missing_sock)
        .env(ENV_WORKER_OPTIMIZE_VULKAN_TONEMAP, "1")
        .env(ENV_WORKER_VULKAN_COMPUTE, "1")
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run local shim with HDR tonemap");
    assert!(local_opt.status.success());
    let local_opt_stdout = String::from_utf8_lossy(&local_opt.stdout);
    assert!(
        local_opt_stdout.contains(
            "ARG:scale_vaapi=w=1920:h=1080:format=p010,hwmap=derive_device=vulkan,libplacebo="
        ),
        "expected local shim pre-scale optimization, got: {local_opt_stdout}"
    );

    let local_opt_out = StdCommand::new(&shim)
        .args(&hdr_tonemap_args)
        .env(ENV_REAL_FFMPEG, &fake_ffmpeg)
        .env(ENV_DISPATCHER_SOCKET, &missing_sock)
        .env(ENV_WORKER_OPTIMIZE_VULKAN_TONEMAP, "0")
        .env(ENV_WORKER_VULKAN_COMPUTE, "1")
        .env_remove(ENV_SHIM_RECURSION_GUARD)
        .output()
        .expect("run local shim with tonemap opt disabled");
    assert!(local_opt_out.status.success());
    let local_opt_out_stdout = String::from_utf8_lossy(&local_opt_out.stdout);
    assert!(
        !local_opt_out_stdout.contains("scale_vaapi="),
        "opt-out must skip pre-scale rewrite, got: {local_opt_out_stdout}"
    );
}

#[tokio::test]
async fn worker_off_mode_startup_probes_vulkan_and_enforces_hardware_render_nodes() {
    let dir = TempDir::new("off-vk-probe");
    let cwd = dir.path().to_string_lossy().into_owned();

    let run_worker_args = |sock: PathBuf, args: Vec<String>, cwd: String| async move {
        let mut s = UnixStream::connect(&sock).await.unwrap();
        write_frame(
            &mut s,
            &Frame::Start(StartRequest {
                args,
                cwd,
                env_subset: vec![],
            }),
        )
        .await
        .unwrap();
        let first = read_frame(&mut s).await.unwrap().expect("first frame");
        match first {
            Frame::Started => {
                let mut out = Vec::new();
                while let Some(frame) = read_frame(&mut s).await.unwrap() {
                    match frame {
                        Frame::Stdout(b) => out.extend_from_slice(&b),
                        Frame::Exit(code) => {
                            assert_eq!(code, 0);
                            break;
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                Ok(String::from_utf8_lossy(&out)
                    .lines()
                    .filter_map(|l| l.strip_prefix("ARG:"))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>())
            }
            Frame::Error { kind, message } => Err((kind, message)),
            other => panic!("unexpected initial reply: {other:?}"),
        }
    };

    let pure_vk_compute_args = vec![
        "-init_hw_device".to_string(),
        "vulkan=vk".to_string(),
        "-c:v".to_string(),
        "hevc".to_string(),
        "-i".to_string(),
        "/srv/media/hdr.mkv".to_string(),
        "-vf".to_string(),
        "format=p010,hwupload,libplacebo=tonemapping=bt.2390:format=nv12,hwdownload,format=nv12"
            .to_string(),
        "-c:v".to_string(),
        "libx264".to_string(),
        "out.m3u8".to_string(),
    ];

    let vk_video_args = |dec: &str, enc: &str| {
        vec![
            "-init_hw_device".to_string(),
            "vulkan=vk".to_string(),
            "-hwaccel".to_string(),
            "vulkan".to_string(),
            "-hwaccel_output_format".to_string(),
            "vulkan".to_string(),
            "-c:v".to_string(),
            dec.to_string(),
            "-i".to_string(),
            "/srv/media/clip.mkv".to_string(),
            "-c:v".to_string(),
            enc.to_string(),
            "out.m3u8".to_string(),
        ]
    };

    // 1. Off-mode worker WITHOUT capabilities_override probing a real `[Vulkan @ ...]` GPU
    //    (compute + h264/hevc decode + h264 encode) enforces per-codec Vulkan Video checks.
    let hw_vk_ffmpeg = write_executable_script(
        dir.path(),
        "hw-vk-ffmpeg",
        r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 8.1.3-Jellyfin"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V....D h264_vulkan          H.264/AVC (Vulkan)
 V....D hevc_vulkan          H.265/HEVC (Vulkan)
 V....D libx264              libx264 H.264
EOF
    exit 0
fi
if [ "$4" = "-init_hw_device" ] && [ "$5" = "vulkan=vk" ]; then
    cat >&2 <<'EOF'
[Vulkan @ 0x55a100001000] Device 0 selected: AMD Radeon Graphics (RADV REMBRANDT) (integrated) (0x1681)
[Vulkan @ 0x55a100001000] Queue families:
[Vulkan @ 0x55a100001000]     0: graphics compute transfer sparse (queues: 1)
[Vulkan @ 0x55a100001000]     1: transfer decode (queues: 1)
[Vulkan @ 0x55a100001000]     2: transfer encode (queues: 1)
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_queue
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_encode_queue
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_h264
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_decode_h265
[Vulkan @ 0x55a100001000] Using device extension VK_KHR_video_encode_h264
EOF
    exit 0
fi
printf 'ARG:%s\n' "$@"
"#,
    );

    let hw_sock = dir.path().join("off-hw-vk.sock");
    let mut hw_cfg = WorkerConfig::for_paths(hw_sock.clone(), hw_vk_ffmpeg);
    hw_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    hw_cfg.vulkan_compute = true;
    hw_cfg.vulkan_video = true;
    assert!(hw_cfg.capabilities_override.is_none());
    let (hw_shutdown, hw_worker) = start_fixture_worker(hw_cfg).await;

    let ok_compute = run_worker_args(hw_sock.clone(), pure_vk_compute_args.clone(), cwd.clone())
        .await
        .expect("probed hardware Vulkan Compute job must succeed in Off mode");
    assert!(ok_compute.contains(&"libx264".to_string()));

    let ok_vkv = run_worker_args(
        hw_sock.clone(),
        vk_video_args("hevc", "h264_vulkan"),
        cwd.clone(),
    )
    .await
    .expect("probed hevc decode + h264_vulkan encode must succeed in Off mode");
    assert!(ok_vkv.contains(&"h264_vulkan".to_string()));

    let err_vkv_dec = run_worker_args(
        hw_sock.clone(),
        vk_video_args("av1", "h264_vulkan"),
        cwd.clone(),
    )
    .await;
    assert!(
        matches!(err_vkv_dec, Err((ErrorKind::DeviceUnavailable, _))),
        "unsupported AV1 Vulkan Video decode must fail pre-Started: {err_vkv_dec:?}"
    );

    let err_vkv_enc = run_worker_args(
        hw_sock.clone(),
        vk_video_args("hevc", "hevc_vulkan"),
        cwd.clone(),
    )
    .await;
    assert!(
        matches!(err_vkv_enc, Err((ErrorKind::DeviceUnavailable, _))),
        "unsupported hevc_vulkan encode must fail pre-Started: {err_vkv_enc:?}"
    );

    let err_vkv_unknown_dec = run_worker_args(
        hw_sock.clone(),
        vk_video_args("ffv1_vulkan", "h264_vulkan"),
        cwd.clone(),
    )
    .await;
    assert!(
        matches!(err_vkv_unknown_dec, Err((ErrorKind::DeviceUnavailable, _))),
        "unrecognized ffv1_vulkan decoder must fail closed pre-Started: {err_vkv_unknown_dec:?}"
    );

    let _ = hw_shutdown.send(());
    let _ = hw_worker.await;

    // 2. Off-mode worker WITHOUT capabilities_override probing FFmpeg 7.x `llvmpipe (cpu)`
    //    must reject Vulkan Compute jobs pre-Started even when a render node exists.
    let llvmpipe_ffmpeg = write_executable_script(
        dir.path(),
        "llvmpipe-ffmpeg",
        r#"#!/bin/sh
if [ "$1" = "-version" ]; then
    echo "ffmpeg version 7.1.5-Jellyfin"
    exit 0
fi
if [ "$1" = "-hide_banner" ] && [ "$2" = "-encoders" ]; then
    cat <<'EOF'
Encoders:
 V..... = Video
 ------
 V....D libx264              libx264 H.264
EOF
    exit 0
fi
if [ "$4" = "-init_hw_device" ] && [ "$5" = "vulkan=vk" ]; then
    cat >&2 <<'EOF'
[AVHWDeviceContext @ 0x55d8f0002400] Device 0 selected: llvmpipe (LLVM 19.1.7, 256 bits) (cpu) (0x0)
[AVHWDeviceContext @ 0x55d8f0002400] Queue families:
[AVHWDeviceContext @ 0x55d8f0002400]     0: graphics compute transfer (queues: 1)
EOF
    exit 0
fi
printf 'ARG:%s\n' "$@"
"#,
    );

    let sw_vk_sock = dir.path().join("off-llvmpipe.sock");
    let mut sw_vk_cfg = WorkerConfig::for_paths(sw_vk_sock.clone(), llvmpipe_ffmpeg);
    sw_vk_cfg.render_nodes_override = Some(vec![RenderNode {
        path: PathBuf::from("/dev/dri/renderD128"),
        vendor_id: Some("0x1002".to_string()),
    }]);
    sw_vk_cfg.vulkan_compute = true;
    sw_vk_cfg.vulkan_video = false;
    assert!(sw_vk_cfg.capabilities_override.is_none());
    let (sw_vk_shutdown, sw_vk_worker) = start_fixture_worker(sw_vk_cfg).await;

    let err_llvmpipe = run_worker_args(
        sw_vk_sock.clone(),
        pure_vk_compute_args.clone(),
        cwd.clone(),
    )
    .await;
    assert!(
        matches!(err_llvmpipe, Err((ErrorKind::DeviceUnavailable, _))),
        "llvmpipe (cpu) Off-mode worker must reject Vulkan Compute pre-Started: {err_llvmpipe:?}"
    );

    let ok_cpu_on_llvmpipe = run_worker_args(
        sw_vk_sock,
        vec![
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await
    .expect("software-only job must still succeed on llvmpipe worker");
    assert!(ok_cpu_on_llvmpipe.contains(&"libx264".to_string()));

    let _ = sw_vk_shutdown.send(());
    let _ = sw_vk_worker.await;

    // 3. GPU-less Off-mode worker WITHOUT capabilities_override (`render_nodes_override = Some([])`)
    //    must reject pure Vulkan Compute jobs (no explicit `/dev/dri/renderD*` arg) AND implicit
    //    VA-API jobs pre-Started with `ErrorKind::DeviceUnavailable`, while allowing pure CPU jobs.
    let generic_ffmpeg = write_executable_script(
        dir.path(),
        "generic-ffmpeg",
        "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\n",
    );
    let gpuless_sock = dir.path().join("off-gpuless.sock");
    let mut gpuless_cfg = WorkerConfig::for_paths(gpuless_sock.clone(), generic_ffmpeg);
    gpuless_cfg.render_nodes_override = Some(vec![]);
    gpuless_cfg.vulkan_compute = true;
    gpuless_cfg.vulkan_video = false;
    assert!(gpuless_cfg.capabilities_override.is_none());
    let (gpuless_shutdown, gpuless_worker) = start_fixture_worker(gpuless_cfg).await;

    let err_gpuless_vk =
        run_worker_args(gpuless_sock.clone(), pure_vk_compute_args, cwd.clone()).await;
    assert!(
        matches!(err_gpuless_vk, Err((ErrorKind::DeviceUnavailable, _))),
        "GPU-less Off-mode worker must reject pure Vulkan Compute pre-Started: {err_gpuless_vk:?}"
    );

    let err_gpuless_vaapi = run_worker_args(
        gpuless_sock.clone(),
        vec![
            "-hwaccel".into(),
            "vaapi".into(),
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-c:v".into(),
            "h264_vaapi".into(),
            "out.m3u8".into(),
        ],
        cwd.clone(),
    )
    .await;
    assert!(
        matches!(err_gpuless_vaapi, Err((ErrorKind::DeviceUnavailable, _))),
        "GPU-less Off-mode worker must reject implicit VA-API hardware job pre-Started: {err_gpuless_vaapi:?}"
    );

    let ok_gpuless_cpu = run_worker_args(
        gpuless_sock,
        vec![
            "-i".into(),
            "/srv/media/in.mkv".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.m3u8".into(),
        ],
        cwd,
    )
    .await
    .expect("GPU-less Off-mode worker must still accept pure CPU jobs");
    assert!(ok_gpuless_cpu.contains(&"libx264".to_string()));

    let _ = gpuless_shutdown.send(());
    let _ = gpuless_worker.await;
}
