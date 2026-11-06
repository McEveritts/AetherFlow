use super::*;
use base64::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn isolated(name: &str) -> bool {
    if std::env::var("AF_LOG_AUTH_CHILD").as_deref() == Ok(name) {
        return true;
    }
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_LOG_AUTH_CHILD", name)
        .status()
        .unwrap()
        .success());
    false
}

struct Fixture {
    root: PathBuf,
    server: tokio::task::JoinHandle<()>,
    address: std::net::SocketAddr,
}

impl Fixture {
    async fn new(role: &str, plugin: bool) -> Self {
        let root = std::env::temp_dir().join(format!("log-auth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("bin")).unwrap();
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            std::env::set_var(key, root.join("fixture.sqlite"));
        }
        std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        std::env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("missing-creds"));
        std::env::set_var("AF_LOG_AUTH_ROOT", &root);
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap()
            ),
        );
        let journal = root.join("bin/journalctl");
        std::fs::write(
            &journal,
            r#"#!/usr/bin/python3
import os,pathlib,time
root=pathlib.Path(os.environ['AF_LOG_AUTH_ROOT'])
(root/'journal.pid').write_text(str(os.getpid()))
previous=''
while True:
    try: line=(root/'next-line').read_text()
    except FileNotFoundError: line=''
    if line and line!=previous:
        print(line,flush=True)
        previous=line
    time.sleep(0.01)
"#,
        )
        .unwrap();
        std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o755)).unwrap();
        af_db::init_db().unwrap();
        af_db::get_conn()
            .unwrap()
            .execute(
                "INSERT INTO users(id,username,role) VALUES(1,'log-observer',?1)",
                [role],
            )
            .unwrap();
        let user = crate::auth::AuthUser {
            user_id: 1,
            username: "log-observer".into(),
            role: role.into(),
            jti: "disposable-log-session".into(),
            plugin_id: plugin.then(|| "fixture-plugin".into()),
            plugin_scopes: Vec::new(),
        };
        let router = axum::Router::new()
            .route("/logs", axum::routing::get(handle_log_websocket))
            .layer(axum::Extension(user));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            root,
            server,
            address,
        }
    }

    async fn connect(&self) -> (tokio::net::TcpStream, String) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let websocket_key = base64::engine::general_purpose::STANDARD.encode([0_u8; 16]);
        stream
            .write_all(
                format!("GET /logs HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {websocket_key}\r\n\r\n", self.address).as_bytes(),
            )
            .await
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 8192);
            header.push(
                tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        (stream, String::from_utf8(header).unwrap())
    }

    fn send_line(&self, line: &str) {
        std::fs::write(
            self.root.join("next-line"),
            format!("2026-11-06T00:00:00 host installer: {line}"),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        if let Ok(pid) = std::fs::read_to_string(self.root.join("journal.pid")) {
            if let Ok(pid) = pid.parse::<i32>() {
                if pid > 1 {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn frame(stream: &mut tokio::net::TcpStream) -> (u8, String) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let first = stream.read_u8().await.unwrap();
        let second = stream.read_u8().await.unwrap();
        assert_eq!(second & 0x80, 0, "server frames are unmasked");
        let length = match second & 0x7f {
            126 => stream.read_u16().await.unwrap() as usize,
            127 => stream.read_u64().await.unwrap() as usize,
            length => length as usize,
        };
        assert!(length < 64 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        (first & 0x0f, String::from_utf8_lossy(&body).into_owned())
    })
    .await
    .unwrap()
}

async fn revoked_log_delivery(kind: &str) {
    let fixture = Fixture::new("admin", false).await;
    let (mut stream, header) = fixture.connect().await;
    assert!(header.starts_with("HTTP/1.1 101"), "{header}");
    assert!(frame(&mut stream)
        .await
        .1
        .contains("Connected to AetherFlow Rust log stream"));
    fixture.send_line("SYNTHETIC_AUTHORIZED_LOG");
    assert!(frame(&mut stream)
        .await
        .1
        .contains("SYNTHETIC_AUTHORIZED_LOG"));
    match kind {
        "demote" => {
            af_db::get_conn()
                .unwrap()
                .execute("UPDATE users SET role='user' WHERE id=1", [])
                .unwrap();
        }
        "delete" => {
            af_db::get_conn()
                .unwrap()
                .execute("DELETE FROM users WHERE id=1", [])
                .unwrap();
        }
        "uncertain" => {
            af_db::get_conn()
                .unwrap()
                .execute_batch("DROP TABLE users")
                .unwrap();
        }
        _ => panic!("invalid fixture scenario"),
    }
    fixture.send_line("SYNTHETIC_PRIVATE_AFTER_REVOCATION");
    let (opcode, body) = frame(&mut stream).await;
    assert_eq!(opcode, 8, "revoked socket delivered {body}");
    assert!(!body.contains("SYNTHETIC_PRIVATE_AFTER_REVOCATION"));
}

#[tokio::test]
async fn dedicated_logs_close_after_admin_demotion() {
    if isolated("ws::log_authorization_regressions::dedicated_logs_close_after_admin_demotion") {
        revoked_log_delivery("demote").await;
    }
}

#[tokio::test]
async fn dedicated_logs_close_after_account_deletion() {
    if isolated("ws::log_authorization_regressions::dedicated_logs_close_after_account_deletion") {
        revoked_log_delivery("delete").await;
    }
}

#[tokio::test]
async fn dedicated_logs_close_on_authorization_read_failure() {
    if isolated(
        "ws::log_authorization_regressions::dedicated_logs_close_on_authorization_read_failure",
    ) {
        revoked_log_delivery("uncertain").await;
    }
}

#[tokio::test]
async fn dedicated_logs_deny_non_admin_sessions() {
    if !isolated("ws::log_authorization_regressions::dedicated_logs_deny_non_admin_sessions") {
        return;
    }
    let fixture = Fixture::new("user", false).await;
    let (_, header) = fixture.connect().await;
    assert!(header.starts_with("HTTP/1.1 403"), "{header}");
}

#[tokio::test]
async fn dedicated_logs_deny_plugin_admin_sessions() {
    if !isolated("ws::log_authorization_regressions::dedicated_logs_deny_plugin_admin_sessions") {
        return;
    }
    let fixture = Fixture::new("admin", true).await;
    let (_, header) = fixture.connect().await;
    assert!(header.starts_with("HTTP/1.1 403"), "{header}");
}
