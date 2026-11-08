use super::*;
use af_runner::af_release;
use axum::{http::Request, Router};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    runner: tokio::task::JoinHandle<()>,
    reply: Arc<Mutex<af_models::RunnerResponse>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.runner.abort();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    async fn new() -> Self {
        let root = env::temp_dir().join(format!("update-observer-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let sock_name = format!("u-{}.sock", &uuid::Uuid::new_v4().to_string()[..8]);
        let candidate = env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join(&sock_name);
        let socket = if candidate.as_os_str().len() < 95 {
            candidate
        } else {
            PathBuf::from("/tmp").join(sock_name)
        };
        for key in [
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_CONFIG_ROOT",
            "AETHERFLOW_RELEASE_ROOT",
        ] {
            env::set_var(key, &root);
        }
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, root.join("fixture.sqlite"));
        }
        env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        fs::write(root.join("packages.json"), "[]").unwrap();
        fs::write(root.join("automation.json"), "{}").unwrap();
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
        env::set_var(
            "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
            root.join("automation.json"),
        );
        af_db::init_db().unwrap();
        af_db::get_conn()
            .unwrap()
            .execute(
                "INSERT INTO users(id,username,role) VALUES (1,'update-observer','user')",
                [],
            )
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let reply = Arc::new(Mutex::new(af_models::RunnerResponse::default()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let runner_reply = reply.clone();
        let runner_requests = requests.clone();
        let runner = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..count]);
                    if let Some(header_end) = raw.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&raw[..header_end]);
                        let mut request_line = header.lines().next().unwrap().split_whitespace();
                        assert_eq!(request_line.next(), Some("POST"));
                        assert!(request_line
                            .next()
                            .unwrap()
                            .ends_with("/v1/self-update/status"));
                        let length: usize = header
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if raw.len() >= header_end + 4 + length {
                            runner_requests.lock().unwrap().push(
                                serde_json::from_slice(
                                    &raw[header_end + 4..header_end + 4 + length],
                                )
                                .unwrap(),
                            );
                            let body = serde_json::to_vec(&*runner_reply.lock().unwrap()).unwrap();
                            stream.write_all(format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len(),
                            ).as_bytes()).await.unwrap();
                            stream.write_all(&body).await.unwrap();
                            break;
                        }
                    }
                }
            }
        });
        Self {
            root,
            socket,
            runner,
            reply,
            requests,
        }
    }

    fn status(&self, status: Value) {
        *self.reply.lock().unwrap() = af_models::RunnerResponse {
            success: true,
            output: status.to_string(),
            error: String::new(),
        };
    }
}

async fn request(router: &Router, suffix: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(format!("/api/v1/auth/system/update/status{suffix}"));
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn actual_http_discovers_durable_jobs_and_fences_identity_action_and_authorization() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let fixture = Fixture::new().await;
    let router = crate::routes::build_router();
    let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let unit = "aetherflow-self-update-deploy-stable-01234567.service";
    let running = json!({"job_unit":unit,"status":"running","completed":false,"success":false,"error":"","exit_code":null});
    fixture.status(running.clone());
    let (status, discovered) = request(&router, "", Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh authenticated client must reach runner discovery: {discovered}"
    );
    assert_eq!(discovered["active_job_unit"], unit);
    assert_eq!(discovered["action"], "deploy");
    assert_eq!(discovered["state"], "running");
    assert_eq!(fixture.requests.lock().unwrap()[0]["job_unit"], "");
    let suffix = format!("?job_unit={unit}&action=deploy");
    assert_eq!(
        request(&router, &suffix, Some(&token)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            &format!("?job_unit={unit}&action=rollback"),
            Some(&token)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut different_job = running.clone();
    different_job["job_unit"] = json!("aetherflow-self-update-rollback-stable-89abcdef.service");
    fixture.status(different_job);
    assert_eq!(
        request(&router, &suffix, Some(&token)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut padded_identity = running.clone();
    padded_identity["job_unit"] = json!(format!(" {unit}"));
    fixture.status(padded_identity);
    assert_eq!(
        request(&router, &suffix, Some(&token)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for progress in ["initiated", "queued", "launching"] {
        let mut pending = running.clone();
        pending["status"] = json!(progress);
        fixture.status(pending);
        let (status, payload) = request(&router, "", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["state"], "running");
        assert_eq!(payload["active_job_unit"], unit);
    }
    fixture.status(json!({"job_unit":unit,"status":"failed","completed":true,"success":false,"error":"private /root/release.log","exit_code":9}));
    let (status, failed) = request(&router, &suffix, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["exit_code"], 9);
    assert!(!failed.to_string().contains("/root/"));
    fixture.status(json!({"job_unit":"","status":"succeeded","completed":true,"success":true,"error":"","exit_code":0}));
    let (status, idle) = request(&router, "", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(idle["state"], "idle");
    assert_eq!(idle["active_job_unit"], "");
    fixture.status(json!({"job_unit":"","status":"recovery_required","completed":false,"success":false,"error":"private /root/recovery.json","exit_code":null}));
    let (_, recovery) = request(&router, "", Some(&token)).await;
    assert_eq!(recovery["state"], "interrupted");
    assert!(!recovery.to_string().contains("/root/"));
    *fixture.reply.lock().unwrap() = af_models::RunnerResponse {
        success: false,
        output: String::new(),
        error: "cannot inspect /private/receipt.json".into(),
    };
    let (status, unavailable) = request(&router, "", Some(&token)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!unavailable.to_string().contains("/private/"));
    *fixture.reply.lock().unwrap() = af_models::RunnerResponse {
        success: false,
        output: String::new(),
        error: "receipt not found at /private/missing.json".into(),
    };
    let (status, missing) = request(&router, &suffix, Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!missing.to_string().contains("/private/"));
    let before = fixture.requests.lock().unwrap().len();
    assert_eq!(request(&router, "", None).await.0, StatusCode::UNAUTHORIZED);
    let (plugin, _) =
        crate::auth::mint_plugin_jwt(1, "observer-fixture", &["telemetry:read".into()], 60)
            .unwrap();
    assert_eq!(
        request(&router, "", Some(&plugin)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, mut legacy_claims) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    legacy_claims.plugin_id = "observer-fixture".into();
    legacy_claims.plugin_scopes = vec!["telemetry:read".into()];
    let legacy_plugin = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &legacy_claims,
        &jsonwebtoken::EncodingKey::from_secret(&crate::auth::jwt_secret_bytes()),
    )
    .unwrap();
    assert_eq!(
        request(&router, "", Some(&legacy_plugin)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), before);
}

#[tokio::test]
async fn deploy_worker_rejects_live_removal_before_dns_native_vhost_or_ingress_mutation() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let fixture = Fixture::new().await;
    fixture.status(json!({"job_unit":"","status":"succeeded","completed":true,"success":true,"error":"","exit_code":0}));
    fs::write(
        fixture.root.join("packages.json"),
        json!([{
            "name":"sonarr", "label":"Sonarr", "description":"isolated deployment fixture",
            "lock_file":"/install/.sonarr.lock", "category":"test", "service_type":"systemd",
            "service_name":"sonarr", "default_port":18989
        }])
        .to_string(),
    )
    .unwrap();
    let files = [
        ("etc/hosts", "127.0.0.1 localhost\n"),
        ("etc/dnsmasq.d/aetherflow-local.conf", "# existing DNS\n"),
        (
            "etc/pihole/custom.list",
            "127.0.0.1 existing.example.test\n",
        ),
        (
            "opt/Sonarr/config.xml",
            "<Config><Port>18989</Port></Config>\n",
        ),
        (
            "etc/apache2/sites-available/sonarr.conf",
            "# existing vhost\n",
        ),
    ];
    for (path, content) in files {
        let path = fixture.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    env::set_var("AETHERFLOW_HOSTS_FILE", fixture.root.join("etc/hosts"));
    env::set_var("AETHERFLOW_DNSMASQ_DIR", fixture.root.join("etc/dnsmasq.d"));
    env::set_var("AETHERFLOW_PIHOLE_DIR", fixture.root.join("etc/pihole"));
    let mut connection = rusqlite::Connection::open(fixture.root.join("fixture.sqlite")).unwrap();
    af_release::lifecycle::initialize_schema(&connection).unwrap();
    let lease = af_release::lifecycle::admit_job(
        &mut connection,
        "sonarr",
        "live-removal",
        "remove",
        "fixture",
        &["sonarr".into()],
    )
    .unwrap();
    let response = handle_deploy_process(
        axum::Extension(AuthUser {
            user_id: 1,
            username: "fixture-admin".into(),
            role: "admin".into(),
            jti: "fixture".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }),
        Path("sonarr".into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let mut receiver = DEPLOY_STREAMS
        .lock()
        .unwrap()
        .get("sonarr")
        .unwrap()
        .subscribe();
    let messages = tokio::time::timeout(StdDuration::from_secs(5), async {
        let mut messages = Vec::new();
        loop {
            let message = receiver.recv().await.unwrap();
            let terminal = message.starts_with("[ROLLBACK]")
                || message.starts_with("[ERROR]")
                || message.starts_with("[SUCCESS]");
            messages.push(message);
            if terminal {
                return messages;
            }
        }
    })
    .await
    .unwrap();
    assert!(
        messages.last().unwrap().starts_with("[ROLLBACK]"),
        "{messages:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.starts_with("[STEP 4]")),
        "service callbacks must not run on rejected admission"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.starts_with("[STEP 1]")),
        "admission must precede DNS synchronization"
    );
    for (path, content) in files {
        assert_eq!(
            fs::read_to_string(fixture.root.join(path)).unwrap(),
            content,
            "no side effects allowed at {path}"
        );
    }
    assert!(af_db::get_app_ingress_config("sonarr").unwrap().is_none());
    assert_eq!(
        fs::read_dir(fixture.root.join("etc/apache2/sites-available"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM package_lifecycle_jobs WHERE package_id='sonarr'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "uninstalling"
    );
    drop(lease);
}
