//! Bounded command capture with supervised process-group cleanup.
//!
//! The supervisor outlives a cancelled HTTP caller. It retains the Command
//! (including any inherited-lock clone in its pre_exec closure) until the
//! required process group is no longer live. A timeout is never success.
use std::io;
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::oneshot;

pub async fn output(
    mut command: Command,
    budget: Duration,
    byte_limit: usize,
) -> io::Result<Output> {
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "command execution budget exhausted",
        ));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;
    let group = child.id();
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (mut send, receive) = oneshot::channel();
    tokio::spawn(async move {
        // Keep Command's pre_exec captures alive through child/group cleanup.
        let _command = command;
        let work = async {
            let (stdout, stderr, status) = tokio::try_join!(
                read_bounded(stdout, byte_limit),
                read_bounded(stderr, byte_limit),
                child.wait(),
            )?;
            Ok::<_, io::Error>(Output {
                status,
                stdout,
                stderr,
            })
        };
        let result = tokio::select! {
            value = tokio::time::timeout(budget, work) => match value {
                Ok(value) => value,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "command execution timed out; resulting state is unconfirmed")),
            },
            _ = send.closed() => Err(io::Error::new(io::ErrorKind::Interrupted, "command caller cancelled")),
        };
        if result.is_err() {
            kill_group(group);
            let _ = child.start_kill();
            let cleanup = async {
                let _ = child.wait().await;
                while tokio::task::spawn_blocking(move || group_is_live(group))
                    .await
                    .unwrap_or(true)
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            };
            tokio::pin!(cleanup);
            tokio::select! {
                _ = &mut cleanup => {},
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    // An unkillable kernel task must not hang the response or
                    // cause exclusion to disappear. Continue cleanup detached.
                    let _ = send.send(result);
                    cleanup.await;
                    return;
                }
            }
            let _ = send.send(result);
        } else {
            let _ = send.send(result);
        }
    });
    receive
        .await
        .map_err(|_| io::Error::other("command supervisor stopped before reporting an outcome"))?
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

fn kill_group(group: Option<u32>) {
    #[cfg(unix)]
    if let Some(group) = group.filter(|group| *group > 0) {
        unsafe {
            libc::kill(-(group as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = group;
}

fn group_is_live(group: Option<u32>) -> bool {
    let Some(group) = group else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        // Killed orphan zombies cannot retain descriptors. kill(-pgid, 0)
        // counts them as alive and would keep an otherwise-free lock forever.
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return true;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            match std::fs::read_to_string(entry.path().join("stat")) {
                Ok(stat) => {
                    let Some((_, fields)) = stat.rsplit_once(") ") else {
                        continue;
                    };
                    let fields: Vec<_> = fields.split_whitespace().take(3).collect();
                    if fields.len() == 3
                        && fields[2].parse::<u32>().ok() == Some(group)
                        && !matches!(fields[0], "Z" | "X")
                    {
                        return true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    // If procfs cannot be inspected, do not release exclusion
                    // while the OS still reports the group exists.
                    return unsafe { libc::kill(-(group as libc::pid_t), 0) == 0 };
                }
            }
        }
        false
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        unsafe { libc::kill(-(group as libc::pid_t), 0) == 0 }
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
    use std::path::Path;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/bash");
        command.args(["-c", script]);
        command
    }

    async fn wait_for(path: &Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn captures_nonzero_status_and_refuses_unbounded_output() {
        let out = output(
            shell("printf ok; printf diagnostic >&2; exit 7"),
            Duration::from_secs(2),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(out.stdout, b"ok");
        assert_eq!(out.stderr, b"diagnostic");
        for script in ["yes", "yes >&2"] {
            let error = output(shell(script), Duration::from_secs(2), 64)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn timeout_and_cancellation_kill_descendants_and_release_guard_only_after_cleanup() {
        for cancel in [false, true] {
            let root = std::env::temp_dir().join(format!("af-command-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let lock = root.join("maintenance.lock");
            let pid_file = root.join("child.pid");
            let guard = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
            let script = "sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait";
            let mut command = shell(script);
            command.env("AF_CHILD_PID", &pid_file);
            guard.preserve_in_child(command.as_std_mut()).unwrap();
            let task = tokio::spawn(output(command, Duration::from_millis(200), 1024));
            wait_for(&pid_file).await;
            let child: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            drop(guard);
            assert!(af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err());
            if cancel {
                task.abort();
                let _ = task.await;
            } else {
                assert_eq!(
                    task.await.unwrap().unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let stat =
                        std::fs::read_to_string(format!("/proc/{child}/stat")).unwrap_or_default();
                    let alive = stat
                        .rsplit_once(") ")
                        .is_some_and(|(_, fields)| !fields.starts_with("Z "));
                    if !alive
                        && af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_ok()
                    {
                        break;
                    }
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
}
