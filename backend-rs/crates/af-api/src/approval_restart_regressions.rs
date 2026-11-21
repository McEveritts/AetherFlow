use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use axum::routing::post;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[derive(Clone)]
enum MockStatusResponse {
    Json(StatusCode, Value),
    DropConnection,
}

#[derive(Clone)]
enum MockSystemctlResponse {
    AcceptedUnit(String),
    RawOutput(StatusCode, Value),
    LifecycleBusy,
    OkService,
    DropConnection,
}

struct MockRunnerState {
    dispatch_count: AtomicUsize,
    dispatched: Mutex<Vec<(String, String)>>,
    discovery_status: Mutex<MockStatusResponse>,
    receipt_statuses: Mutex<HashMap<String, MockStatusResponse>>,
    next_systemctl: Mutex<MockSystemctlResponse>,
}

impl MockRunnerState {
    fn new() -> Self {
        Self {
            dispatch_count: AtomicUsize::new(0),
            dispatched: Mutex::new(Vec::new()),
            discovery_status: Mutex::new(MockStatusResponse::Json(
                StatusCode::OK,
                json!({
                    "success": true,
                    "output": json!({
                        "status": "succeeded",
                        "completed": true,
                        "success": true,
                        "job_unit": "",
                        "error": "",
                        "exit_code": 0
                    }).to_string(),
                    "error": ""
                }),
            )),
            receipt_statuses: Mutex::new(HashMap::new()),
            next_systemctl: Mutex::new(MockSystemctlResponse::OkService),
        }
    }

    fn set_discovery_running(&self, unit: &str) {
        *self.discovery_status.lock().unwrap() = MockStatusResponse::Json(
            StatusCode::OK,
            json!({
                "success": true,
                "output": json!({
                    "status": "running",
                    "completed": false,
                    "success": false,
                    "job_unit": unit,
                    "error": "",
                    "exit_code": null
                }).to_string(),
                "error": ""
            }),
        );
    }

    fn set_discovery_idle(&self) {
        *self.discovery_status.lock().unwrap() = MockStatusResponse::Json(
            StatusCode::OK,
            json!({
                "success": true,
                "output": json!({
                    "status": "succeeded",
                    "completed": true,
                    "success": true,
                    "job_unit": "",
                    "error": "",
                    "exit_code": 0
                }).to_string(),
                "error": ""
            }),
        );
    }

    fn set_receipt(&self, unit: &str, response: MockStatusResponse) {
        self.receipt_statuses
            .lock()
            .unwrap()
            .insert(unit.to_string(), response);
    }

    fn set_systemctl(&self, response: MockSystemctlResponse) {
        *self.next_systemctl.lock().unwrap() = response;
    }
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    token: String,
    runner: Arc<MockRunnerState>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "af-appr-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..10]
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("install")).unwrap();
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

        let socket = root.join("runner.sock");
        env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
        env::set_var(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                env::var("PATH").unwrap_or_default()
            ),
        );

        fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
        fs::write(
            root.join("packages.json"),
            json!([{
                "name": "sonarr",
                "label": "Sonarr",
                "category": "test",
                "description": "fixture",
                "service_type": "systemd",
                "service_name": "sonarr",
                "lock_file": "/install/.sonarr.lock"
            }])
            .to_string(),
        )
        .unwrap();
        fs::write(root.join("automation.json"), "{}").unwrap();

        let systemctl = root.join("bin/systemctl");
        fs::write(
            &systemctl,
            "#!/bin/sh\ntest \"$1\" = show || exit 99\nprintf 'LoadState=loaded\\nActiveState=active\\nSubState=running\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

        let runner = Arc::new(MockRunnerState::new());
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let state_for_server = Arc::clone(&runner);
        let server = tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/v1/systemctl",
                    post({
                        let st = Arc::clone(&state_for_server);
                        move |Json(req): Json<Value>| {
                            let st = Arc::clone(&st);
                            async move {
                                let svc = req["service"].as_str().unwrap_or("").to_string();
                                let act = req["action"].as_str().unwrap_or("").to_string();
                                st.dispatch_count.fetch_add(1, Ordering::SeqCst);
                                st.dispatched.lock().unwrap().push((svc, act));
                                let behavior = st.next_systemctl.lock().unwrap().clone();
                                match behavior {
                                    MockSystemctlResponse::AcceptedUnit(unit) => (
                                        StatusCode::ACCEPTED,
                                        Json(json!({
                                            "success": true,
                                            "output": json!({
                                                "status": "accepted",
                                                "job_unit": unit,
                                                "completed": false,
                                                "success": false
                                            }).to_string(),
                                            "error": ""
                                        })),
                                    )
                                        .into_response(),
                                    MockSystemctlResponse::RawOutput(code, body) => {
                                        (code, Json(body)).into_response()
                                    }
                                    MockSystemctlResponse::LifecycleBusy => (
                                        StatusCode::CONFLICT,
                                        Json(json!({
                                            "success": false,
                                            "output": "",
                                            "error": af_runner::LifecycleBusy.to_string()
                                        })),
                                    )
                                        .into_response(),
                                    MockSystemctlResponse::OkService => (
                                        StatusCode::OK,
                                        Json(json!({
                                            "success": true,
                                            "output": "ok",
                                            "error": ""
                                        })),
                                    )
                                        .into_response(),
                                    MockSystemctlResponse::DropConnection => (
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        Json(json!({
                                            "success": false,
                                            "output": "",
                                            "error": "Could not schedule core restart: Err(Elapsed(()))"
                                        })),
                                    )
                                        .into_response(),
                                }
                            }
                        }
                    }),
                )
                .route(
                    "/v1/self-update/status",
                    post({
                        let st = Arc::clone(&state_for_server);
                        move |Json(req): Json<Value>| {
                            let st = Arc::clone(&st);
                            async move {
                                let unit = req["job_unit"].as_str().unwrap_or("").to_string();
                                let resp = if unit.is_empty() {
                                    st.discovery_status.lock().unwrap().clone()
                                } else {
                                    st.receipt_statuses
                                        .lock()
                                        .unwrap()
                                        .get(&unit)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            MockStatusResponse::Json(
                                                StatusCode::NOT_FOUND,
                                                json!({
                                                    "success": false,
                                                    "output": "",
                                                    "error": format!("self-update job '{unit}' not found")
                                                }),
                                            )
                                        })
                                };
                                match resp {
                                    MockStatusResponse::Json(code, body) => {
                                        (code, Json(body)).into_response()
                                    }
                                    MockStatusResponse::DropConnection => (
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        Json(json!({
                                            "success": false,
                                            "output": "",
                                            "error": "Cannot determine authoritative systemd state; receipt retained as unresolved."
                                        })),
                                    )
                                        .into_response(),
                                }
                            }
                        }
                    }),
                );

            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            let req = req.map(Body::new);
                            Ok::<_, std::convert::Infallible>(app.oneshot(req).await.unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        af_db::init_db().unwrap();
        af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap())
            .unwrap();
        af_db::get_conn()
            .unwrap()
            .execute(
                "INSERT INTO users(id,username,role) VALUES(1,'inbox-admin','admin')",
                [],
            )
            .unwrap();
        let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
        Self {
            root,
            socket,
            token,
            runner,
            server,
        }
    }

    fn queue_action(&self, action: &str, classification: &str) -> i64 {
        match af_db::queue_action(classification, "FlowAI", action, "fixture test") {
            af_db::QueueActionOutcome::Queued { action_id } if action_id > 0 => action_id,
            other => panic!("expected committed pending action id, got {other:?}"),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn isolated(name: &str) -> bool {
    if env::var("AF_APPROVAL_RESTART_CHILD").as_deref() == Ok(name) {
        return true;
    }
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_APPROVAL_RESTART_CHILD", name)
        .status()
        .unwrap()
        .success());
    false
}

async fn get_json(router: Router, path: &str, token: &str) -> (StatusCode, Value) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post_json(router: Router, path: &str, token: &str) -> (StatusCode, Value) {
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn receipt_ok(
    unit: &str,
    status: &str,
    completed: bool,
    success: bool,
    exit_code: Option<i32>,
    error: &str,
) -> MockStatusResponse {
    MockStatusResponse::Json(
        StatusCode::OK,
        json!({
            "success": true,
            "output": json!({
                "status": status,
                "completed": completed,
                "success": success,
                "job_unit": unit,
                "error": error,
                "exit_code": exit_code
            }).to_string(),
            "error": ""
        }),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_core_restart_persists_receipt_and_reconciles_working_to_executed() {
    if !isolated("routes::approval_restart_regressions::deferred_core_restart_persists_receipt_and_reconciles_working_to_executed") {
        return;
    }
    let fixture = Fixture::new().await;
    let router = build_router();
    let unit = "aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service";
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::AcceptedUnit(unit.into()));
    fixture
        .runner
        .set_receipt(unit, receipt_ok(unit, "running", false, false, None, ""));

    let id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (status, body) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "queued");
    assert_eq!(body["job_unit"], unit);
    assert_eq!(body["action"]["status"], "queued");
    assert_eq!(body["action"]["job_unit"], unit);
    assert_eq!(fixture.runner.dispatch_count.load(Ordering::SeqCst), 1);

    // While receipt is running: detail, queued filter, and approved_history show queued; executed filter does not.
    let (st, detail) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(detail["status"], "queued");
    assert_eq!(detail["job_unit"], unit);

    let (st, hist) = get_json(
        router.clone(),
        "/api/v1/admin/actions/pending?status=approved_history",
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hist["total"], 1);
    assert_eq!(hist["actions"][0]["status"], "queued");
    assert_eq!(hist["actions"][0]["job_unit"], unit);

    let (st, exec_list) = get_json(
        router.clone(),
        "/api/v1/admin/actions/pending?status=executed",
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(exec_list["total"], 0);

    // Retry while queued must refuse with 409 CONFLICT and never replay host work.
    let (st, retry) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{retry}");
    assert_eq!(retry["status"], "queued");
    assert_eq!(retry["job_unit"], unit);
    assert_eq!(fixture.runner.dispatch_count.load(Ordering::SeqCst), 1);

    // Transient 503 reports unavailable without losing the persisted queued row or replaying.
    fixture
        .runner
        .set_receipt(unit, MockStatusResponse::DropConnection);
    let (st, unavail_detail) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(unavail_detail["status"], "unavailable");
    assert_eq!(unavail_detail["job_unit"], unit);
    assert_eq!(
        af_db::get_pending_action_by_id(id).unwrap().unwrap().status,
        "queued"
    );

    // Once durable receipt reports succeeded, get_core_restart_status reconciles pending_actions to executed.
    fixture
        .runner
        .set_receipt(unit, receipt_ok(unit, "succeeded", true, true, Some(0), ""));
    let (st, restart_status) = get_json(
        router.clone(),
        &format!("/api/v1/admin/services/restart/status?job_unit={unit}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{restart_status}");
    assert_eq!(restart_status["state"], "complete");
    assert_eq!(restart_status["completed"], true);
    assert_eq!(restart_status["success"], true);

    let (st, done_detail) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(done_detail["status"], "executed");
    assert_eq!(done_detail["job_unit"], unit);

    // Retry after executed also refuses with 409 and never replays.
    let (st, _) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(fixture.runner.dispatch_count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_core_restart_receipt_failure_missing_and_corrupt_never_claim_executed() {
    if !isolated("routes::approval_restart_regressions::deferred_core_restart_receipt_failure_missing_and_corrupt_never_claim_executed") {
        return;
    }
    let fixture = Fixture::new().await;
    let router = build_router();

    // 1. Runner receipt fails -> action becomes failed.
    let fail_unit = "aetherflow-self-update-restart-aetherflow-runner-1111111111111111.service";
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::AcceptedUnit(fail_unit.into()));
    fixture.runner.set_receipt(
        fail_unit,
        receipt_ok(fail_unit, "running", false, false, None, ""),
    );
    let fail_id = fixture.queue_action("restart_service:aetherflow-runner:systemd", "critical");
    let (st, _) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{fail_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    fixture.runner.set_receipt(
        fail_unit,
        receipt_ok(
            fail_unit,
            "failed",
            true,
            false,
            Some(1),
            "Core restart failed; inspect service logs and readiness.",
        ),
    );
    let (st, failed) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{fail_id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["job_unit"], fail_unit);

    // 2. Receipt disappears (404) -> action becomes unavailable and remains in approved_history.
    let missing_unit = "aetherflow-self-update-restart-aetherflow-api-2222222222222222.service";
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::AcceptedUnit(missing_unit.into()));
    let missing_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (st, _) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{missing_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    // Do not register receipt -> mock returns 404 not found.
    let (st, missing) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{missing_id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(missing["status"], "unavailable");
    assert_eq!(missing["job_unit"], missing_unit);

    // 3. Corrupt / mismatched receipt -> action becomes unavailable.
    let corrupt_unit = "aetherflow-self-update-restart-aetherflow-api-3333333333333333.service";
    let wrong_unit = "aetherflow-self-update-restart-aetherflow-api-4444444444444444.service";
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::AcceptedUnit(corrupt_unit.into()));
    let corrupt_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (st, _) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{corrupt_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    fixture.runner.set_receipt(
        corrupt_unit,
        receipt_ok(wrong_unit, "succeeded", true, true, Some(0), ""),
    );
    let (st, corrupt) = get_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{corrupt_id}"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(corrupt["status"], "unavailable");

    let (st, unavail_list) = get_json(
        router.clone(),
        "/api/v1/admin/actions/pending?status=unavailable",
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(unavail_list["total"], 2);
    let (st, exec_list) = get_json(
        router.clone(),
        "/api/v1/admin/actions/pending?status=executed",
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(exec_list["total"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_approvals_interrupted_dispatch_and_active_lifecycle_prevent_duplicate_host_work(
) {
    if !isolated("routes::approval_restart_regressions::concurrent_approvals_interrupted_dispatch_and_active_lifecycle_prevent_duplicate_host_work") {
        return;
    }
    let fixture = Fixture::new().await;
    let router = build_router();

    // 1. Concurrent approvals for the same pending core restart only dispatch once.
    let race_unit = "aetherflow-self-update-restart-aetherflow-api-5555555555555555.service";
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::AcceptedUnit(race_unit.into()));
    fixture.runner.set_receipt(
        race_unit,
        receipt_ok(race_unit, "launching", false, false, None, ""),
    );
    let race_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let r = router.clone();
        let tok = fixture.token.clone();
        set.spawn(async move {
            post_json(r, &format!("/api/v1/admin/actions/{race_id}/approve"), &tok).await
        });
    }
    let mut accepted = 0usize;
    let mut conflicts = 0usize;
    while let Some(res) = set.join_next().await {
        let (st, _) = res.unwrap();
        match st {
            StatusCode::ACCEPTED => accepted += 1,
            StatusCode::CONFLICT => conflicts += 1,
            other => panic!("unexpected concurrent status: {other}"),
        }
    }
    assert_eq!(accepted, 1);
    assert_eq!(conflicts, 5);
    assert_eq!(fixture.runner.dispatch_count.load(Ordering::SeqCst), 1);

    // 2. Active lifecycle operation blocks pending approval without dispatching.
    let blocked_id = fixture.queue_action("restart_service:aetherflow-runner:systemd", "critical");
    fixture.runner.set_discovery_running(race_unit);
    let (st, blocked) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{blocked_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{blocked}");
    assert_eq!(blocked["code"], "SYSTEM_UPDATE_IN_PROGRESS");
    assert_eq!(
        af_db::get_pending_action_by_id(blocked_id)
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    assert_eq!(fixture.runner.dispatch_count.load(Ordering::SeqCst), 1);
    fixture.runner.set_discovery_idle();

    // 3. Ambiguous / interrupted dispatch marks unavailable (never pending or executed) and blocks retries.
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::DropConnection);
    let ambig_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (st, ambig) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{ambig_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{ambig}");
    assert_eq!(ambig["code"], "RESTART_RECEIPT_UNAVAILABLE");
    assert_eq!(
        af_db::get_pending_action_by_id(ambig_id)
            .unwrap()
            .unwrap()
            .status,
        "unavailable"
    );
    let before_retry = fixture.runner.dispatch_count.load(Ordering::SeqCst);
    let (st, _) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{ambig_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(
        fixture.runner.dispatch_count.load(Ordering::SeqCst),
        before_retry
    );

    // 4. Interrupted row stuck in `approved` without receipt cannot be replayed.
    let interrupted_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    af_db::resolve_action(interrupted_id, "approved", "prior-admin").unwrap();
    let (st, interrupted) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{interrupted_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{interrupted}");
    assert_eq!(interrupted["status"], "approved");
    assert_eq!(
        fixture.runner.dispatch_count.load(Ordering::SeqCst),
        before_retry
    );

    // 5. TOCTOU LifecycleBusy from runner returns 409 LIFECYCLE_BUSY, marks failed, and blocks replay.
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::LifecycleBusy);
    let busy_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (st, busy_resp) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{busy_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{busy_resp}");
    assert_eq!(busy_resp["code"], "LIFECYCLE_BUSY");
    assert_eq!(
        af_db::get_pending_action_by_id(busy_id)
            .unwrap()
            .unwrap()
            .status,
        "failed"
    );

    // 6. Runner accepting without a valid core-restart receipt identity marks unavailable and blocks replay.
    fixture.runner.set_systemctl(MockSystemctlResponse::RawOutput(
        StatusCode::ACCEPTED,
        json!({
            "success": true,
            "output": json!({"status": "accepted", "job_unit": "aetherflow-self-update-deploy-stable-1234567890abcdef.service"}).to_string(),
            "error": ""
        }),
    ));
    let bad_unit_id = fixture.queue_action("restart_service:aetherflow-api:systemd", "critical");
    let (st, bad_unit_resp) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{bad_unit_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{bad_unit_resp}");
    assert_eq!(bad_unit_resp["code"], "RESTART_RECEIPT_UNAVAILABLE");
    assert_eq!(
        af_db::get_pending_action_by_id(bad_unit_id)
            .unwrap()
            .unwrap()
            .status,
        "unavailable"
    );

    // 7. Non-deferred service action preserves synchronous 200 OK `executed` API contract.
    fixture
        .runner
        .set_systemctl(MockSystemctlResponse::OkService);
    let sync_id = fixture.queue_action("restart_service:sonarr:systemd", "warn");
    let (st, sync_resp) = post_json(
        router.clone(),
        &format!("/api/v1/admin/actions/{sync_id}/approve"),
        &fixture.token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{sync_resp}");
    assert_eq!(sync_resp["status"], "executed");
    assert_eq!(sync_resp["action"]["status"], "executed");
    assert!(sync_resp["action"].get("job_unit").is_none());
}
