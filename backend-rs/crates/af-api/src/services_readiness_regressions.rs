use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn short_socket_path(root: &std::path::Path, filename: &str) -> PathBuf {
    let candidate = root.join(filename);
    if candidate.as_os_str().len() < 95 {
        return candidate;
    }
    let short_name = format!(
        "af-{}-{}.sock",
        &uuid::Uuid::new_v4().simple().to_string()[..10],
        filename.trim_end_matches(".sock")
    );
    let tmpdir_cand = env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
        .join(&short_name);
    if tmpdir_cand.as_os_str().len() < 95 {
        tmpdir_cand
    } else {
        PathBuf::from("/tmp").join(short_name)
    }
}

struct MockRunnerSocket {
    path: PathBuf,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockRunnerSocket {
    fn start(path: PathBuf, response: Option<Vec<u8>>) -> Self {
        let _ = fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut held_streams = Vec::new();
            while let Ok((mut stream, _)) = listener.accept().await {
                if let Some(ref bytes) = response {
                    let mut buf = Vec::with_capacity(512);
                    let mut chunk = [0u8; 512];
                    let mut header_end = None;
                    let mut content_len = 0usize;
                    while buf.len() < 8192 {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if header_end.is_none() {
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                header_end = Some(pos + 4);
                                let headers = String::from_utf8_lossy(&buf[..pos]);
                                for line in headers.lines() {
                                    if let Some((k, v)) = line.split_once(':') {
                                        if k.eq_ignore_ascii_case("content-length") {
                                            content_len = v.trim().parse().unwrap_or(0);
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(end) = header_end {
                            if buf.len() >= end + content_len {
                                break;
                            }
                        }
                    }
                    let _ = stream.write_all(bytes).await;
                    let _ = stream.shutdown().await;
                } else {
                    let mut chunk = [0u8; 256];
                    let _ = stream.read(&mut chunk).await;
                    held_streams.push(stream);
                }
            }
        });
        Self {
            path,
            task: Some(task),
        }
    }

    async fn close(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for MockRunnerSocket {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn http_json_response(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    token: String,
    probe: tokio::net::UnixListener,
}

impl Fixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("nrp-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("install")).unwrap();
        for key in [
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_CONFIG_ROOT",
            "AETHERFLOW_RELEASE_ROOT",
        ] {
            env::set_var(key, &root);
        }
        let database = root.join("fixture.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &database);
        }
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("missing-creds"));
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
        env::set_var(
            "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
            root.join("automation.json"),
        );
        env::set_var("AF_READINESS_CALLS", root.join("calls"));
        let socket = short_socket_path(&root, "p.sock");
        env::set_var("AF_READINESS_PROBE_SOCKET", &socket);
        let probe = tokio::net::UnixListener::bind(&socket).unwrap();
        env::set_var(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                env::var("PATH").unwrap()
            ),
        );
        let packages: Vec<_> = (0..6).map(|index| {
            let name = format!("slow-{index}");
            fs::write(root.join(format!("install/.{name}.lock")), "fixture").unwrap();
            json!({ "name": name, "label": name, "category": "test", "description": "fixture",
                "service_type": "systemd", "service_name": name, "lock_file": format!("/install/.{name}.lock") })
        }).collect();
        fs::write(
            root.join("packages.json"),
            serde_json::to_vec(&packages).unwrap(),
        )
        .unwrap();
        fs::write(root.join("automation.json"), "{}").unwrap();
        let command = root.join("bin/systemctl");
        fs::write(&command, "#!/usr/bin/python3\nimport os,signal,socket,sys\nwith open(os.environ['AF_READINESS_CALLS'], 'a') as output: output.write(' '.join(sys.argv[1:])+'\\n')\nassert sys.argv[1] == 'show'\nif sys.argv[2] in ('aetherflow-api','aetherflow-runner','apache2'):\n print('LoadState=loaded\\nActiveState=active\\nSubState=running')\nelse:\n probe=socket.socket(socket.AF_UNIX)\n probe.connect(os.environ['AF_READINESS_PROBE_SOCKET'])\n probe.close()\n signal.pause()\n").unwrap();
        fs::set_permissions(command, fs::Permissions::from_mode(0o755)).unwrap();
        af_db::init_db().unwrap();
        af_services::initialize_package_jobs(rusqlite::Connection::open(database).unwrap())
            .unwrap();
        af_db::get_conn()
            .unwrap()
            .execute(
                "INSERT INTO users(id,username,role) VALUES(1,'readiness-observer','admin')",
                [],
            )
            .unwrap();
        let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
        Self {
            root,
            socket,
            token,
            probe,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn isolated(name: &str) -> bool {
    if env::var("AF_READINESS_REGRESSION_CHILD").as_deref() == Ok(name) {
        return true;
    }
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_READINESS_REGRESSION_CHILD", name)
        .status()
        .unwrap()
        .success());
    false
}

async fn request(router: Router, path: &str, token: Option<&str>) -> Response {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    router
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn payload(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_readiness_is_independent_of_slow_coalesced_inventory() {
    if !isolated("routes::services_readiness_regressions::authenticated_readiness_is_independent_of_slow_coalesced_inventory") {
        return;
    }
    let fixture = Fixture::new();
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");
    let router = build_router();
    assert_eq!(
        request(router.clone(), "/api/v1/auth/ready", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    af_services::clear_service_status_cache();
    let started = Instant::now();
    let mut inventories = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let router = router.clone();
        let token = fixture.token.clone();
        inventories
            .spawn(async move { request(router, "/api/v1/auth/services", Some(&token)).await });
    }
    tokio::time::timeout(Duration::from_secs(2), fixture.probe.accept())
        .await
        .unwrap()
        .unwrap();
    let readiness_start = Instant::now();
    let response = request(router.clone(), "/api/v1/auth/ready", Some(&fixture.token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        payload(response).await,
        json!({
            "service": "aetherflow-api",
            "status": "ready",
            "database": "ok",
            "runner": "disabled"
        })
    );
    let readiness_elapsed = readiness_start.elapsed();
    assert!(readiness_elapsed < Duration::from_millis(500));
    while let Some(result) = inventories.join_next().await {
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let services = payload(response).await;
        assert_eq!(services["AetherFlow API"]["status"], "running");
        assert_eq!(services["AetherFlow Runner"]["status"], "running");
        assert!(services.get("AetherFlow Frontend").is_none());
        assert_eq!(services["Apache2 Web Server"]["status"], "running");
        for index in 0..6 {
            assert_eq!(services[format!("slow-{index}")]["status"], "unknown");
        }
    }
    println!(
        "HTTP overlapping inventory {:?}; readiness {:?}",
        started.elapsed(),
        readiness_elapsed
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let before = fs::read_to_string(fixture.root.join("calls")).unwrap();
    assert_eq!(
        before.lines().count(),
        9,
        "HTTP requests duplicated unit probes: {before}"
    );
    let repeated = Instant::now();
    assert_eq!(
        request(
            router.clone(),
            "/api/v1/auth/services",
            Some(&fixture.token)
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert!(repeated.elapsed() < Duration::from_millis(500));
    assert_eq!(
        fs::read_to_string(fixture.root.join("calls")).unwrap(),
        before
    );
    fs::write(fixture.root.join("packages.json"), "malformed catalog").unwrap();
    let ready = request(router.clone(), "/api/v1/auth/ready", Some(&fixture.token)).await;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(payload(ready).await["status"], "ready");
    assert_eq!(
        request(router, "/api/v1/auth/services", Some(&fixture.token))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_database_is_not_ready_and_has_a_request_deadline() {
    if !isolated("routes::services_readiness_regressions::unavailable_database_is_not_ready_and_has_a_request_deadline") {
        return;
    }
    let _fixture = Fixture::new();
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");
    let connections: Vec<_> = (0..8).map(|_| af_db::get_read_conn().unwrap()).collect();
    let started = Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(3), authenticated_ready())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        payload(response).await,
        json!({
            "service": "aetherflow-api",
            "status": "not_ready",
            "database": "unreachable",
            "runner": "disabled"
        })
    );
    assert!(started.elapsed() >= Duration::from_secs(2));
    drop(connections);
    assert_eq!(authenticated_ready().await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn coalesced_observations_preserve_companions_ingress_and_credential_authorization() {
    if !isolated("routes::services_readiness_regressions::coalesced_observations_preserve_companions_ingress_and_credential_authorization") {
        return;
    }
    let fixture = Fixture::new();
    fs::write(fixture.root.join("packages.json"), json!([{
        "name": "sonarr", "label": "Sonarr", "category": "test", "description": "fixture",
        "service_type": "systemd", "service_name": "sonarr", "lock_file": "/install/.sonarr.lock", "default_port": 8989
    }]).to_string()).unwrap();
    fs::write(fixture.root.join("install/.sonarr.lock"), "fixture").unwrap();
    fs::write(
        fixture.root.join("automation.json"),
        json!({"sonarr": {"sandbox_service_units": ["sonarr-side"]}}).to_string(),
    )
    .unwrap();
    fs::create_dir_all(fixture.root.join("var/lib/sonarr")).unwrap();
    fs::write(
        fixture.root.join("var/lib/sonarr/config.xml"),
        "<Config><ApiKey>fixture-owned-key</ApiKey><Port>18989</Port></Config>",
    )
    .unwrap();
    af_db::set_app_ingress_config(&AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "fixture.example.test".into(),
        external_access_enabled: true,
        tls_enabled: false,
        listen_port: 18989,
        ..Default::default()
    })
    .unwrap();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO users(id,username,role) VALUES(2,'readiness-viewer','user')",
            [],
        )
        .unwrap();
    let (viewer, _) = crate::auth::create_standard_jwt(2, &HeaderMap::new()).unwrap();
    let router = build_router();
    let admin = request(
        router.clone(),
        "/api/v1/auth/services",
        Some(&fixture.token),
    )
    .await;
    assert_eq!(admin.status(), StatusCode::OK);
    let admin = payload(admin).await;
    assert_eq!(admin["Sonarr"]["status"], "unknown");
    assert_eq!(admin["Sonarr"]["units"], json!(["sonarr", "sonarr-side"]));
    assert_eq!(admin["Sonarr"]["components"].as_array().unwrap().len(), 2);
    assert_eq!(admin["Sonarr"]["api_key"], "fixture-owned-key");
    assert_eq!(admin["Sonarr"]["active_port"], 18989);
    assert_eq!(admin["Sonarr"]["public_domain"], "fixture.example.test");
    assert_eq!(admin["Sonarr"]["external_access_enabled"], true);
    assert_eq!(admin["Sonarr"]["tls_enabled"], false);
    let before = fs::read_to_string(fixture.root.join("calls")).unwrap();
    let member = request(router.clone(), "/api/v1/auth/services", Some(&viewer)).await;
    assert_eq!(member.status(), StatusCode::OK);
    let member = payload(member).await;
    assert_eq!(member["Sonarr"]["status"], "unknown");
    assert!(member["Sonarr"].get("api_key").is_none());
    assert_eq!(
        fs::read_to_string(fixture.root.join("calls")).unwrap(),
        before
    );
    for path in ["/api/v1/auth/blueprints", "/api/v1/auth/blueprints/sonarr"] {
        let response = request(router.clone(), path, Some(&viewer)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = request(router.clone(), path, Some(&fixture.token)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

async fn assert_readiness_routes(
    router: &Router,
    token: &str,
    expected_status: StatusCode,
    expected_state: &str,
    expected_db: &str,
    expected_runner: &str,
    forbidden_substrings: &[&str],
) {
    let public = request(router.clone(), "/health/ready", None).await;
    assert_eq!(public.status(), expected_status);
    let public_body = payload(public).await;
    let public_obj = public_body.as_object().unwrap();
    assert_eq!(public_obj.len(), 6, "unexpected public keys: {public_body}");
    assert_eq!(public_body["database"], expected_db);
    assert_eq!(public_body["runner"], expected_runner);
    assert_eq!(public_body["redis"], "disabled");
    assert_eq!(public_body["status"], expected_state);
    assert!(public_body["uptime"].is_string());
    assert!(public_body["version"].is_string());
    let serialized = public_body.to_string();
    for needle in forbidden_substrings {
        assert!(
            !serialized.contains(needle),
            "public readiness payload leaked `{needle}`: {serialized}"
        );
    }

    let authed = request(router.clone(), "/api/v1/auth/ready", Some(token)).await;
    assert_eq!(authed.status(), expected_status);
    assert_eq!(authed.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        payload(authed).await,
        json!({
            "service": "aetherflow-api",
            "status": expected_state,
            "database": expected_db,
            "runner": expected_runner,
        })
    );

    let live = request(router.clone(), "/health/live", None).await;
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(payload(live).await, json!({ "status": "alive" }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_readiness_gates_public_and_authenticated_routes_within_deadline() {
    if !isolated("routes::services_readiness_regressions::runner_readiness_gates_public_and_authenticated_routes_within_deadline") {
        return;
    }
    let fixture = Fixture::new();
    let router = build_router();
    let runner_sock = short_socket_path(&fixture.root, "r.sock");
    let sock_str = runner_sock.to_string_lossy().to_string();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &runner_sock);

    // 1. Disabled runner (unset and false) uses SQLite alone and reports runner=disabled.
    env::remove_var("PRIVILEGED_RUNNER_ENABLED");
    assert_readiness_routes(
        &router,
        &fixture.token,
        StatusCode::OK,
        "ready",
        "ok",
        "disabled",
        &[&sock_str],
    )
    .await;
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");
    assert_readiness_routes(
        &router,
        &fixture.token,
        StatusCode::OK,
        "ready",
        "ok",
        "disabled",
        &[&sock_str],
    )
    .await;

    // 2. Enabled runner with a missing socket fails closed (503) while SQLite stays ok and liveness stays 200.
    env::set_var("PRIVILEGED_RUNNER_ENABLED", " True ");
    assert_readiness_routes(
        &router,
        &fixture.token,
        StatusCode::SERVICE_UNAVAILABLE,
        "not_ready",
        "ok",
        "unreachable",
        &[&sock_str],
    )
    .await;

    // 3. Enabled runner answering HTTP 200 with the expected ready payload passes for all truthy values.
    let valid_body = r#"{"success":true,"output":"ready","error":""}"#;
    let healthy_listener = MockRunnerSocket::start(
        runner_sock.clone(),
        Some(http_json_response("200 OK", valid_body)),
    );
    for truthy in ["1", "true", " YES ", " On "] {
        env::set_var("PRIVILEGED_RUNNER_ENABLED", truthy);
        assert_readiness_routes(
            &router,
            &fixture.token,
            StatusCode::OK,
            "ready",
            "ok",
            "ok",
            &[&sock_str],
        )
        .await;
    }
    healthy_listener.close().await;

    // 4. Non-2xx HTTP status with the valid JSON body is rejected.
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");
    let non_2xx_listener = MockRunnerSocket::start(
        runner_sock.clone(),
        Some(http_json_response("503 Service Unavailable", valid_body)),
    );
    assert_readiness_routes(
        &router,
        &fixture.token,
        StatusCode::SERVICE_UNAVAILABLE,
        "not_ready",
        "ok",
        "unreachable",
        &[&sock_str],
    )
    .await;
    non_2xx_listener.close().await;

    // 5. HTTP 2xx with invalid readiness payloads (non-ready JSON and malformed JSON) is rejected without leaking details.
    for bad_body in [
        r#"{"success":true,"output":"starting","error":"internal-runner-diagnostic"}"#,
        "not-valid-json-diagnostic",
    ] {
        let bad_listener = MockRunnerSocket::start(
            runner_sock.clone(),
            Some(http_json_response("200 OK", bad_body)),
        );
        assert_readiness_routes(
            &router,
            &fixture.token,
            StatusCode::SERVICE_UNAVAILABLE,
            "not_ready",
            "ok",
            "unreachable",
            &[
                &sock_str,
                "internal-runner-diagnostic",
                "not-valid-json-diagnostic",
            ],
        )
        .await;
        bad_listener.close().await;
    }

    // 6. Exhausted SQLite read pool + stalling runner socket run concurrently and return 503 within 3 seconds.
    let stalling_listener = MockRunnerSocket::start(runner_sock.clone(), None);
    let connections: Vec<_> = (0..8).map(|_| af_db::get_read_conn().unwrap()).collect();
    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        request(router.clone(), "/health/ready", None),
    )
    .await
    .expect("concurrent SQLite + runner timeout exceeded 3 seconds");
    let elapsed = started.elapsed();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = payload(response).await;
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["database"], "unreachable");
    assert_eq!(body["runner"], "unreachable");
    assert_eq!(body["redis"], "disabled");
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3),
        "expected concurrent 2s timeout within 3s ceiling, got {elapsed:?}"
    );
    drop(connections);
    stalling_listener.close().await;
}
