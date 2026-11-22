use std::time::Duration;

fn spawn_bounded_pipe_reader<R>(
    pipe: Option<R>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tx: std::sync::mpsc::SyncSender<Vec<u8>>,
) where
    R: std::io::Read + std::os::unix::io::AsRawFd + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        const MAX_PROBE_OUTPUT_BYTES: usize = 65536;
        if let Some(pipe) = pipe {
            #[cfg(unix)]
            {
                use std::sync::atomic::Ordering;
                let fd = pipe.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                    if flags >= 0 {
                        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
                let mut scratch = [0u8; 4096];
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                };
                loop {
                    if stop.load(Ordering::Relaxed) {
                        loop {
                            let n = unsafe {
                                libc::read(
                                    fd,
                                    scratch.as_mut_ptr() as *mut libc::c_void,
                                    scratch.len(),
                                )
                            };
                            if n > 0 {
                                let to_take = (MAX_PROBE_OUTPUT_BYTES - buf.len()).min(n as usize);
                                if to_take > 0 {
                                    buf.extend_from_slice(&scratch[..to_take]);
                                }
                            } else {
                                break;
                            }
                        }
                        break;
                    }

                    let ret = unsafe { libc::poll(&mut pfd, 1, 25) };
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        break;
                    }
                    if ret > 0 {
                        let mut eof = false;
                        loop {
                            let n = unsafe {
                                libc::read(
                                    fd,
                                    scratch.as_mut_ptr() as *mut libc::c_void,
                                    scratch.len(),
                                )
                            };
                            if n > 0 {
                                let to_take = (MAX_PROBE_OUTPUT_BYTES - buf.len()).min(n as usize);
                                if to_take > 0 {
                                    buf.extend_from_slice(&scratch[..to_take]);
                                }
                            } else if n == 0 {
                                eof = true;
                                break;
                            } else {
                                let err = std::io::Error::last_os_error();
                                if err.raw_os_error() == Some(libc::EAGAIN)
                                    || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                                {
                                    break;
                                }
                                if err.raw_os_error() == Some(libc::EINTR) {
                                    continue;
                                }
                                eof = true;
                                break;
                            }
                        }
                        if eof || (pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0) {
                            break;
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                use std::io::Read;
                let mut pipe = pipe;
                let _ = pipe
                    .by_ref()
                    .take(MAX_PROBE_OUTPUT_BYTES as u64)
                    .read_to_end(&mut buf);
            }
        }
        let _ = tx.send(buf);
    });
}

#[cfg(test)]
pub static INJECT_WAITID_EPERM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
pub(crate) fn is_process_zombie_linux(pid: i32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(contents) = std::fs::read_to_string(&stat_path) {
        if let Some(idx) = contents.rfind(')') {
            let rest = contents[idx + 1..].trim_start();
            if let Some(ch) = rest.chars().next() {
                return ch == 'Z';
            }
        }
    }
    false
}

pub fn run_bounded_probe_command_cancellable<F>(
    cmd: &mut std::process::Command,
    timeout: Duration,
    mut is_cancelled: F,
) -> Result<std::process::Output, String>
where
    F: FnMut() -> bool,
{
    use std::process::Stdio;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn probe command: {}", e))?;
    #[cfg(unix)]
    let pgid = child.id() as i32;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stop_reading = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (stdout_tx, stdout_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let (stderr_tx, stderr_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);

    spawn_bounded_pipe_reader(stdout_pipe, stop_reading.clone(), stdout_tx);
    spawn_bounded_pipe_reader(stderr_pipe, stop_reading.clone(), stderr_tx);

    let start = std::time::Instant::now();
    let mut exit_status = None;
    let mut child_exited = false;
    let poll_interval = Duration::from_millis(15);

    while start.elapsed() < timeout {
        if is_cancelled() {
            #[cfg(unix)]
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
                libc::kill(pgid, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
            let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
            return Err("probe command cancelled".to_string());
        }

        #[cfg(unix)]
        {
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waitid_res = {
                #[cfg(test)]
                if INJECT_WAITID_EPERM.load(std::sync::atomic::Ordering::SeqCst) {
                    -1
                } else {
                    unsafe {
                        libc::waitid(
                            libc::P_PID,
                            pgid as libc::id_t,
                            &mut siginfo,
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                        )
                    }
                }
                #[cfg(not(test))]
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pgid as libc::id_t,
                        &mut siginfo,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                }
            };
            let waitid_pid = unsafe { siginfo.si_pid() };
            if waitid_res == 0 && waitid_pid == pgid {
                child_exited = true;
                break;
            } else if waitid_res != 0 {
                let errno = if waitid_res == -1 {
                    #[cfg(test)]
                    if INJECT_WAITID_EPERM.load(std::sync::atomic::Ordering::SeqCst) {
                        libc::EPERM
                    } else {
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                    }
                    #[cfg(not(test))]
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                };
                if errno == libc::EINTR {
                    std::thread::sleep(poll_interval);
                    continue;
                }

                #[cfg(target_os = "linux")]
                {
                    if is_process_zombie_linux(pgid) {
                        // Leader exited but is still an unreaped zombie holding the PID/PGID.
                        // Kill all descendant processes in the process group BEFORE reaping the leader!
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        match child.wait() {
                            Ok(status) => {
                                exit_status = Some(status);
                                child_exited = true;
                                break;
                            }
                            Err(e) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                                let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                                return Err(format!("error waiting for probe child: {}", e));
                            }
                        }
                    } else if !std::path::Path::new("/proc").exists() {
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        match child.wait() {
                            Ok(status) => {
                                exit_status = Some(status);
                                child_exited = true;
                                break;
                            }
                            Err(e) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                                let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                                return Err(format!("error waiting for probe child: {}", e));
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    match child.wait() {
                        Ok(status) => {
                            exit_status = Some(status);
                            child_exited = true;
                            break;
                        }
                        Err(e) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                            let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                            let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                            return Err(format!("error waiting for probe child: {}", e));
                        }
                    }
                }
            }
            std::thread::sleep(poll_interval);
        }
        #[cfg(not(unix))]
        {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    child_exited = true;
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                    let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                    return Err(format!("error waiting for probe child: {}", e));
                }
            }
        }
    }

    let timed_out = !child_exited;
    let status = if timed_out {
        #[cfg(unix)]
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
            libc::kill(pgid, libc::SIGKILL);
        }
        let _ = child.kill();
        child
            .wait()
            .map_err(|e| format!("failed waiting for child after kill: {}", e))?
    } else {
        #[cfg(unix)]
        if exit_status.is_none() {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        match exit_status {
            Some(s) => s,
            None => child
                .wait()
                .map_err(|e| format!("failed waiting for child: {}", e))?,
        }
    };

    stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);

    let stdout = stdout_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();
    let stderr = stderr_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();

    if timed_out {
        return Err(format!("probe command timed out after {:?}", timeout));
    }

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

pub fn run_bounded_probe_command(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    run_bounded_probe_command_cancellable(cmd, timeout, || false)
}
