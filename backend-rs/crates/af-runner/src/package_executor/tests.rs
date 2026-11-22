use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::AtomicUsize;

fn legacy_env(req: &PackageRunnerRequest) -> HashMap<String, Option<String>> {
    let mut cmd = Command::new("bash");
    apply_legacy_package_environment(&mut cmd, req);
    cmd.as_std()
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

/// Serializes async execution tests that share process-global `PACKAGE_MUTEX`,
/// `ACTIVE_CANCELLATIONS`, or environment variable state (`ENV_TEST_MUTEX`).
pub(super) use crate::ENV_TEST_MUTEX as TEST_EXECUTION_SERIALIZER;

/// Deterministic mock command runner that records every command invocation and never executes
/// live privileged OS commands.
#[derive(Clone, Default)]
struct MockCommandRunner {
    recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
    fail_on_call: Option<usize>,
    fail_program: Option<String>,
    cancel_on_call: Option<(usize, CancellationToken)>,
    call_counter: Arc<AtomicUsize>,
    dpkg_version_stdout: Option<String>,
    fail_systemctl_is_active: bool,
}

impl MockCommandRunner {
    fn recorded_commands(&self) -> Vec<RecordedCommand> {
        self.recorded.lock().unwrap().clone()
    }
}

impl CommandRunner for MockCommandRunner {
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
        Box::pin(async move {
            let idx = self.call_counter.fetch_add(1, Ordering::SeqCst);
            if let Some((trigger_idx, ref token)) = self.cancel_on_call {
                if idx == trigger_idx {
                    token.cancel();
                }
            }
            if cancel.is_cancelled() {
                return Err(PackageExecutorError::Cancelled(program.to_string()));
            }

            self.recorded.lock().unwrap().push(RecordedCommand {
                program: program.to_string(),
                args: args.to_vec(),
                env: env_vars.to_vec(),
            });

            if self.fail_on_call == Some(idx) || self.fail_program.as_deref() == Some(program) {
                return Ok(CommandOutput {
                    exit_code: 100,
                    stdout: String::new(),
                    stderr: format!("simulated failure in {} {:?}", program, args),
                });
            }

            if self.fail_systemctl_is_active
                && program == "systemctl"
                && args.first().map(String::as_str) == Some("is-active")
            {
                return Ok(CommandOutput {
                    exit_code: 3,
                    stdout: "inactive\n".to_string(),
                    stderr: String::new(),
                });
            }

            // Simulate `id -u <user>` returning non-zero on first check so `useradd` is exercised
            if program == "id" {
                return Ok(CommandOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "no such user".to_string(),
                });
            }

            // Simulate `dpkg-query -W -f=${db:Status-Status} ${Version}\n <pkg>` or `-f=${Version}` returning a Debian epoch+revision version
            if program == "dpkg-query" {
                let raw = self
                    .dpkg_version_stdout
                    .clone()
                    .unwrap_or_else(|| "1:0.14.2-1ubuntu2\n".to_string());
                let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                let stdout = if wants_status && !raw.trim().contains(' ') {
                    format!("installed {}\n", raw.trim())
                } else {
                    raw
                };
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout,
                    stderr: String::new(),
                });
            }

            if program == "curl" {
                let has_auth = args.iter().any(|a| a == "-K");
                let is_unauth_rc = args
                    .iter()
                    .any(|a| a.contains("/metrics") || a.contains("/core/version"));
                let status = if is_unauth_rc && !has_auth {
                    "401"
                } else {
                    "200"
                };
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("\n{status}\n"),
                    stderr: String::new(),
                });
            }

            Ok(CommandOutput {
                exit_code: 0,
                stdout: format!("ok: {} {}", program, args.join(" ")),
                stderr: String::new(),
            })
        })
    }
}

fn create_isolated_test_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = env::temp_dir().join(format!(
        "af-runner-pkg-test-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn create_mock_elf_payload(size: usize) -> Vec<u8> {
    create_mock_elf_payload_for_arch(size, 62) // EM_X86_64 = 62
}

fn create_mock_elf_payload_for_arch(size: usize, e_machine: u16) -> Vec<u8> {
    let mut data = vec![0x7f, b'E', b'L', b'F'];
    data.resize(size.max(2048), 0x90);
    // ELF little-endian (EI_DATA = 1 at offset 5) and e_machine at offset 18..20
    data[4] = if e_machine == 40 { 1 } else { 2 }; // ELFCLASS32 for ARM, ELFCLASS64 for x86_64/aarch64
    data[5] = 1; // ELFDATA2LSB
    let machine_bytes = e_machine.to_le_bytes();
    data[18] = machine_bytes[0];
    data[19] = machine_bytes[1];
    data
}

struct LocalHttpServer {
    pub port: u16,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

async fn start_local_http_server<F>(handler: F) -> LocalHttpServer
where
    F: Fn(&str, &str, Option<&str>) -> (u16, &'static str, String) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                conn = listener.accept() => {
                    let Ok((mut socket, _)) = conn else { break };
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 4096];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let mut lines = req.lines();
                        let first_line = lines.next().unwrap_or("");
                        let mut parts = first_line.split_whitespace();
                        let method = parts.next().unwrap_or("GET");
                        let path = parts.next().unwrap_or("/");

                        let mut auth_header = None;
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("authorization") {
                                    auth_header = Some(v.trim().to_string());
                                }
                            }
                        }

                        let (status, content_type, body) = handler(method, path, auth_header.as_deref());
                        let status_text = match status {
                            200 => "OK",
                            401 => "Unauthorized",
                            404 => "Not Found",
                            405 => "Method Not Allowed",
                            _ => "Error",
                        };
                        let mut resp = format!(
                            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            status,
                            status_text,
                            content_type,
                            body.len()
                        );
                        if status == 401 {
                            resp.push_str("WWW-Authenticate: Basic realm=\"rclone\"\r\n");
                        }
                        resp.push_str("\r\n");
                        resp.push_str(&body);

                        let _ = socket.write_all(resp.as_bytes()).await;
                        let _ = socket.flush().await;
                    });
                }
            }
        }
    });

    LocalHttpServer {
        port,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    }
}

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvVarGuard {
    fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            saved.push((*key, env::var_os(key)));
            match value {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }
    }
}

mod blueprint_and_apache;
mod quassel_threadfin_parity;
mod rclone_and_readiness;
mod recipes_and_security;
mod reinstall_and_rollback;
mod snapshot_and_policy;
mod staging_and_diagnostics;

include!("../native_catalog_regressions.rs");
