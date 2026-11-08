use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn subprocess(test: &str) -> bool {
    const CHILD: &str = "AF_LIFECYCLE_TEST_CHILD";
    if env::var(CHILD).as_deref() == Ok(test) {
        return false;
    }
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, test)
        .status()
        .unwrap()
        .success());
    true
}

fn fixture_root() -> PathBuf {
    let dir_name = format!("ar-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let base = env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let candidate = base.join(&dir_name);
    let root = if candidate.join("installer.sock").as_os_str().len() < 95 {
        candidate
    } else {
        PathBuf::from("/tmp").join(dir_name)
    };
    fs::create_dir(&root).unwrap();
    env::set_var("AETHERFLOW_FS_ROOT", &root);
    env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    env::set_var(
        "AETHERFLOW_ALLOWED_RUNNER_UIDS",
        unsafe { libc::geteuid() }.to_string(),
    );
    let mut packages: Vec<af_models::Package> =
        serde_json::from_str(EMBEDDED_PACKAGES_JSON).unwrap();
    for name in ["fixture", "queued", "unrelated"] {
        packages.push(af_models::Package {
            name: name.into(),
            service_name: name.into(),
            ..Default::default()
        });
    }
    let catalog = root.join("packages.json");
    fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
    let automation = root.join("package_automation.json");
    fs::write(&automation, EMBEDDED_AUTOMATION_JSON).unwrap();
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    root
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn receipt(unit: &str, status: &str) -> SelfUpdateJobStatus {
    SelfUpdateJobStatus {
        status: status.into(),
        completed: false,
        success: false,
        job_unit: unit.into(),
        error: String::new(),
        exit_code: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn surviving_runner_child_retains_maintenance_after_runner_crash() {
    use std::io::{Read, Write};
    const WORKER: &str = "AF_SURVIVING_RUNNER_ROOT";
    let test = "lifecycle_tests::surviving_runner_child_retains_maintenance_after_runner_crash";
    if let Some(root) = env::var_os(WORKER) {
        let root = PathBuf::from(root);
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let database = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        let conn = rusqlite::Connection::open(&database).unwrap();
        let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES ('fixture','job','update','updating','now',?1)", [&owner.id]).unwrap();
        let guard = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        env::set_var("AETHERFLOW_TEST_REAL_COMMAND_RUNNER", "1");
        PACKAGE_MAINTENANCE_LEASE
            .scope(std::sync::Arc::new(guard), async {
                TokioCommandRunner
                    .run_command(
                        "/bin/sh",
                        &[
                            "-c".into(),
                            "printf ready > \"$1\"; read -r release < \"$2\"".into(),
                            "fixture".into(),
                            root.join("ready").to_string_lossy().into_owned(),
                            root.join("release").to_string_lossy().into_owned(),
                        ],
                        &[],
                        &CancellationToken::new(),
                    )
                    .await
                    .unwrap();
            })
            .await;
        drop(owner);
        return;
    }
    let root = env::temp_dir().join(format!("af-survivor-{}", uuid::Uuid::new_v4()));
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .args([root.join("ready"), root.join("release")])
        .status()
        .unwrap()
        .success());
    let mut worker = std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(WORKER, &root)
        .spawn()
        .unwrap();
    let mut ready = String::new();
    std::fs::File::open(root.join("ready"))
        .unwrap()
        .read_to_string(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready");
    worker.kill().unwrap();
    worker.wait().unwrap();
    assert!(acquire_lifecycle_admission_lock(Some(&root)).is_err());
    let status: String = conn
        .query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "updating");
    std::fs::OpenOptions::new()
        .write(true)
        .open(root.join("release"))
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    let lock_path = af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
    assert!(std::process::Command::new("flock")
        .arg("-w")
        .arg("5")
        .arg(lock_path)
        .arg("/bin/true")
        .status()
        .unwrap()
        .success());
    let admission = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    af_release::admin::ensure_no_active_package_lifecycle_jobs(
        &cfg,
        af_release::ReleaseCommand::Deploy,
    )
    .unwrap();
    let status: String = conn
        .query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "interrupted");
    drop((admission, conn));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uds_reservation_covers_post_script_callbacks_and_conflicting_cli_process() {
    let test =
        "lifecycle_tests::uds_reservation_covers_post_script_callbacks_and_conflicting_cli_process";
    if env::var_os("AF_DIRECT_CLI_FIXTURE").is_some() {
        let result =
            dispatch_package_action_with_options("remove", "fixture", "unused", 0, false, |_| {})
                .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains(&LifecycleBusy.to_string()));
        return;
    }
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    let queued_owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    let job = uuid::Uuid::new_v4().to_string();
    for (package, identity, lease) in [
        ("fixture", job.as_str(), &owner),
        ("queued", "queued-job", &queued_owner),
    ] {
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units)
            VALUES (?1,?2,'update','updating','now',?3,?4)", rusqlite::params![package, identity, lease.id, format!("[\"{package}.service\"]")]).unwrap();
    }
    let fake_systemctl = root.join("systemctl");
    executable(&fake_systemctl, "#!/bin/sh\nexit 0\n");
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_systemctl);
    env::set_var(
        "PATH",
        format!("{}:{}", root.display(), env::var("PATH").unwrap()),
    );
    let socket = root.join("runner.sock");
    env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let root_handler = root.clone();
    let app = Router::new()
        .route(
            "/v1/package",
            post(move |Json(req): Json<PackageRunnerRequest>| {
                let mut execution = PackageExecutionEnv::isolated(&root_handler);
                execution.lifecycle_job_id = req.lifecycle_job_id;
                let action = PackageAction::parse(&req.action).unwrap();
                let recipe = package_executor::DeclarativePackageRecipe {
                    package_id: req.package_id.clone(),
                    label: "Isolated fixture".into(),
                    default_port: 0,
                    service_name: req.package_id.clone(),
                    lock_file: format!("/install/.{}.lock", req.package_id),
                    apply_systemd_sandbox: false,
                    install_steps: vec![],
                    update_steps: vec![],
                    remove_steps: vec![],
                };
                async move {
                    let stream = package_executor::execute_declarative_recipe_stream(
                        std::sync::Arc::new(package_executor::DeclarativePackageExecutor::new(
                            execution,
                        )),
                        recipe,
                        action,
                        CancellationToken::new(),
                    );
                    Response::new(Body::from_stream(stream))
                }
            }),
        )
        .route("/v1/systemctl", post(handle_systemctl))
        .route("/v1/sandbox", post(handle_sandbox));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_runner_connections(listener, app, async {
        let _ = shutdown_rx.await;
    }));
    let (post_script_tx, post_script_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let api = tokio::spawn(PACKAGE_JOB_ID.scope(job.clone(), async move {
        dispatch_systemctl("fixture.service", "stop").await.unwrap();
        dispatch_package_action_with_options("update", "fixture", "unused", 0, false, |_| {})
            .await
            .unwrap();
        post_script_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        dispatch_systemctl("fixture.service", "start")
            .await
            .unwrap();
    }));
    post_script_rx.await.unwrap();
    assert!(root.join("install/.fixture.lock").is_file());
    for action in ["update", "remove"] {
        let error =
            dispatch_package_action_with_options(action, "fixture", "unused", 0, false, |_| {})
                .await
                .unwrap_err();
        // Package streams carry the sanitized terminal error line; typed
        // HTTP conflicts are specific to service-control responses.
        assert!(
            error.to_string().contains(&LifecycleBusy.to_string()),
            "{error:#}"
        );
    }
    assert!(dispatch_systemctl("fixture.service", "restart")
        .await
        .is_err());
    assert!(dispatch_systemctl("aetherflow-api", "restart-deferred")
        .await
        .is_err());
    let sandbox_owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('sonarr','sandbox-job','update','updating','now',?1,'[\"sonarr.service\"]')", [&sandbox_owner.id]).unwrap();
    let sandbox_root = root.join("sandbox");
    env::set_var("AETHERFLOW_SYSTEMD_ROOT", &sandbox_root);
    assert!(dispatch_sandbox_apply("sonarr")
        .await
        .unwrap_err()
        .to_string()
        .contains(&LifecycleBusy.to_string()));
    assert!(!sandbox_root.exists());
    PACKAGE_JOB_ID
        .scope("sandbox-job".to_string(), async {
            dispatch_sandbox_apply("sonarr").await.unwrap();
        })
        .await;
    assert!(sandbox_root
        .join("sonarr.service.d/aetherflow-sandbox.conf")
        .is_file());
    assert!(apply_package_sandbox_local("not-a-managed-package")
        .await
        .is_err());
    PACKAGE_JOB_ID
        .scope(job.clone(), async {
            assert!(dispatch_package_action_with_options(
                "remove",
                "fixture",
                "unused",
                0,
                false,
                |_| {}
            )
            .await
            .is_err());
        })
        .await;
    dispatch_package_action_with_options("install", "unrelated", "unused", 0, false, |_| {})
        .await
        .unwrap();
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("AF_DIRECT_CLI_FIXTURE", "1")
        .status()
        .unwrap()
        .success());
    finish_tx.send(()).unwrap();
    api.await.unwrap();
    {
        let _admission = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='completed' WHERE job_id=?1",
            [&job],
        )
        .unwrap();
    }
    dispatch_package_action_with_options("remove", "fixture", "unused", 0, false, |_| {})
        .await
        .unwrap();
    assert!(!root.join("install/.fixture.lock").exists());
    PACKAGE_JOB_ID
        .scope("queued-job".into(), async {
            dispatch_package_action_with_options("update", "queued", "unused", 0, false, |_| {})
                .await
                .unwrap();
        })
        .await;
    shutdown_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    drop((owner, queued_owner, conn));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launch_status_waits_for_live_admission_then_trusts_unit_and_terminal_writer() {
    let test = "lifecycle_tests::launch_status_waits_for_live_admission_then_trusts_unit_and_terminal_writer";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    env::set_var("AETHERFLOW_ENABLE_RUST_RELEASE", "1");
    env::remove_var("AETHERFLOW_FORCE_BASH_RELEASE");
    let barrier = root.join("launch.sock");
    let listener = tokio::net::UnixListener::bind(&barrier).unwrap();
    let state = root.join("unit-state");
    fs::write(&state, "LoadState=not-found\nActiveState=inactive\n").unwrap();
    let systemctl = root.join("fake-systemctl");
    executable(
        &systemctl,
        &format!("#!/bin/sh\ncat '{}'\n", state.display()),
    );
    let systemd_run = root.join("fake-systemd-run");
    executable(&systemd_run, &format!("#!/usr/bin/python3\nimport socket\nconnection=socket.socket(socket.AF_UNIX)\nconnection.connect({:?})\nconnection.sendall(b'R')\nconnection.recv(1)\nopen({:?},'w').write('LoadState=loaded\\nActiveState=active\\nSubState=running\\n')\n", barrier, state));
    let cli = root.join("fake-af");
    executable(&cli, "#!/bin/sh\nexit 0\n");
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", systemctl);
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", systemd_run);
    env::set_var("AETHERFLOW_CLI_BIN", cli);
    let launch = tokio::spawn(execute_self_update_request_owned());
    let (mut connection, _) = listener.accept().await.unwrap();
    let mut entered = [0u8];
    connection.read_exact(&mut entered).await.unwrap();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let dir = resolve_self_update_jobs_dir_for_cfg(&cfg).unwrap();
    let path = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .unwrap();
    let unit = path.file_stem().unwrap().to_str().unwrap();
    let pending = query_self_update_job_at(unit, &path).await.unwrap();
    assert_eq!(pending.status, "launching");
    assert!(!pending.completed);
    assert!(!discover_system_update(&cfg).await.unwrap().completed);
    connection.write_all(b"G").await.unwrap();
    let (code, response) = launch.await.unwrap();
    assert_eq!(code, StatusCode::OK, "{}", response.error);
    assert_eq!(
        query_self_update_job_at(unit, &path).await.unwrap().status,
        "running"
    );
    let terminal = SelfUpdateJobStatus {
        status: "succeeded".into(),
        completed: true,
        success: true,
        job_unit: unit.into(),
        error: String::new(),
        exit_code: Some(0),
    };
    write_self_update_job_status_atomic(&path, &terminal).unwrap();
    write_self_update_job_status_atomic(&path, &pending).unwrap();
    assert_eq!(
        query_self_update_job_at(unit, &path).await.unwrap(),
        terminal
    );
    assert!(claim_self_update_job(&path, unit).is_err());
    fs::remove_dir_all(root).unwrap();
}

async fn execute_self_update_request_owned() -> (StatusCode, RunnerResponse) {
    execute_self_update_request(
        &SelfUpdateRequest {
            command: "deploy".into(),
            channel: "nightly".into(),
        },
        true,
    )
    .await
}

#[tokio::test]
async fn orphan_launch_unknown_state_and_late_worker_are_reconciled_without_false_success() {
    let test = "lifecycle_tests::orphan_launch_unknown_state_and_late_worker_are_reconciled_without_false_success";
    if let Some(path) = env::var_os("AF_LAUNCH_OWNER_WORKER") {
        use std::io::{Read, Write};
        let path = PathBuf::from(path);
        let owner = job_receipts::begin_launch(&path).unwrap();
        let unit = "aetherflow-self-update-deploy-nightly-aabbccdd.service";
        write_self_update_job_status_atomic(&path, &receipt(unit, "launching")).unwrap();
        println!("LAUNCH_READY");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0u8]).unwrap();
        drop(owner);
        return;
    }
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let path = root.join("job.json");
    let unit = "aetherflow-self-update-deploy-nightly-aabbccdd.service";
    let launching = receipt(unit, "launching");
    let mut launcher = std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("AF_LAUNCH_OWNER_WORKER", &path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::BufRead;
        let mut output = std::io::BufReader::new(launcher.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(output.read_line(&mut line).unwrap(), 0);
            if line.contains("LAUNCH_READY") {
                break;
            }
        }
    }
    let systemctl = root.join("systemctl");
    executable(&systemctl, "#!/bin/sh\nexit 1\n");
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &systemctl);
    assert_eq!(
        query_self_update_job_at(unit, &path).await.unwrap(),
        launching
    );
    launcher.kill().unwrap();
    launcher.wait().unwrap();
    assert_eq!(
        query_self_update_job_at(unit, &path).await.unwrap_err().0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        serde_json::from_slice::<SelfUpdateJobStatus>(&fs::read(&path).unwrap()).unwrap(),
        launching
    );
    executable(
        &systemctl,
        "#!/bin/sh\nprintf 'LoadState=not-found\\nActiveState=inactive\\n'\n",
    );
    let failed = query_self_update_job_at(unit, &path).await.unwrap();
    assert!(failed.completed && !failed.success);
    assert!(failed.error.contains("without writing completion"));
    assert!(claim_self_update_job(&path, unit).is_err());
    write_self_update_job_status_atomic(&path, &receipt(unit, "running")).unwrap();
    assert_eq!(query_self_update_job_at(unit, &path).await.unwrap(), failed);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_receipt_wins_over_inflight_unit_probe() {
    let test = "lifecycle_tests::terminal_receipt_wins_over_inflight_unit_probe";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let path = root.join("job.json");
    let unit = "aetherflow-self-update-deploy-nightly-aabbccdd.service";
    let running = receipt(unit, "running");
    write_self_update_job_status_atomic(&path, &running).unwrap();
    let socket = root.join("status.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let systemctl = root.join("systemctl");
    executable(&systemctl, &format!("#!/usr/bin/python3\nimport socket\nconnection=socket.socket(socket.AF_UNIX)\nconnection.connect({:?})\nconnection.sendall(b'R')\nconnection.recv(1)\nprint('LoadState=not-found\\nActiveState=inactive')\n", socket));
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", systemctl);
    let status_path = path.clone();
    let status = tokio::spawn(async move { query_self_update_job_at(unit, &status_path).await });
    let (mut connection, _) = listener.accept().await.unwrap();
    let mut entered = [0u8];
    connection.read_exact(&mut entered).await.unwrap();
    let terminal = SelfUpdateJobStatus {
        status: "succeeded".into(),
        completed: true,
        success: true,
        job_unit: unit.into(),
        error: String::new(),
        exit_code: Some(0),
    };
    write_self_update_job_status_atomic(&path, &terminal).unwrap();
    connection.write_all(b"G").await.unwrap();
    assert_eq!(status.await.unwrap().unwrap(), terminal);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_core_restart_reserves_timer_window_and_records_worker_completion() {
    let test = "lifecycle_tests::deferred_core_restart_reserves_timer_window_and_records_worker_completion";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let scheduler_args = root.join("scheduler-args.json");
    executable(&root.join("systemd-run"), &format!("#!/usr/bin/python3\nimport json,sys\nwith open({:?},'w') as output: json.dump(sys.argv[1:],output)\n", scheduler_args));
    env::set_var(
        "PATH",
        format!("{}:{}", root.display(), env::var("PATH").unwrap()),
    );
    let probe = root.join("probe");
    executable(&probe, "#!/usr/bin/python3\nimport sys\nprint('LoadState=loaded\\nActiveState=active\\nSubState=waiting' if sys.argv[-1].endswith('.timer') else 'LoadState=not-found\\nActiveState=inactive')\n");
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", probe);
    let (code, Json(response)) = handle_systemctl(Json(SystemctlRequest {
        service: "aetherflow-api".into(),
        action: "restart-deferred".into(),
        lifecycle_job_id: String::new(),
    }))
    .await;
    assert_eq!(code, StatusCode::ACCEPTED, "{}", response.error);
    let payload: serde_json::Value = serde_json::from_str(&response.output).unwrap();
    let unit = payload["job_unit"].as_str().unwrap();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let path = resolve_self_update_jobs_dir_for_cfg(&cfg)
        .unwrap()
        .join(format!("{unit}.json"));
    assert_eq!(
        query_self_update_job_at(unit, &path).await.unwrap().status,
        "running"
    );
    assert!(acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Package("unrelated"),
        "",
        Some("install")
    )
    .await
    .is_err());
    let socket = root.join("restart.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let control = root.join("control");
    let commands = root.join("commands");
    executable(&control, &format!("#!/usr/bin/python3\nimport socket,sys\nopen({:?},'a').write(sys.argv[1]+'\\n')\nif sys.argv[1]=='restart':\n connection=socket.socket(socket.AF_UNIX)\n connection.connect({:?})\n connection.sendall(b'R')\n connection.recv(1)\n", commands, socket));
    let lock_path = resolve_self_update_lock_path_for_cfg(&cfg).unwrap();
    let arguments: Vec<String> =
        serde_json::from_slice(&fs::read(scheduler_args).unwrap()).unwrap();
    let receipt_identity = (
        arguments[arguments.len() - 2].parse::<u64>().unwrap(),
        arguments[arguments.len() - 1].parse::<u64>().unwrap(),
    );
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(&lock_path).unwrap();
    let exclusion = af_release::ReleaseLockGuard::acquire(&lock_path, Duration::ZERO).unwrap();
    let mut worker = Command::new("/bin/bash")
        .args([
            "-c",
            include_str!("core_restart_worker.sh"),
            "core-restart-fixture",
        ])
        .arg("aetherflow-api")
        .arg(&path)
        .arg(unit)
        .arg(&lock_path)
        .arg(&control)
        .arg(metadata.dev().to_string())
        .arg(metadata.ino().to_string())
        .arg(receipt_identity.0.to_string())
        .arg(receipt_identity.1.to_string())
        .spawn()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    assert!(!commands.exists());
    drop(exclusion);
    let (mut connection, _) = listener.accept().await.unwrap();
    let mut entered = [0u8];
    connection.read_exact(&mut entered).await.unwrap();
    assert!(acquire_lifecycle_admission_lock(Some(&root)).is_err());
    assert!(
        !query_self_update_job_at(unit, &path)
            .await
            .unwrap()
            .completed
    );
    connection.write_all(b"G").await.unwrap();
    assert!(worker.wait().await.unwrap().success());
    let completed = query_self_update_job_at(unit, &path).await.unwrap();
    assert!(completed.completed && completed.success);
    assert_eq!(
        fs::read_to_string(&commands).unwrap(),
        "restart\nis-active\n"
    );
    assert!(Command::new("/bin/bash")
        .args([
            "-c",
            include_str!("core_restart_worker.sh"),
            "late-core-fixture"
        ])
        .arg("aetherflow-api")
        .arg(&path)
        .arg(unit)
        .arg(&lock_path)
        .arg(&control)
        .arg(metadata.dev().to_string())
        .arg(metadata.ino().to_string())
        .arg(receipt_identity.0.to_string())
        .arg(receipt_identity.1.to_string())
        .output()
        .await
        .unwrap()
        .status
        .code()
        .is_some_and(|code| code != 0));
    assert_eq!(
        fs::read_to_string(&commands).unwrap(),
        "restart\nis-active\n"
    );
    drop(
        acquire_package_maintenance_guard(
            Some(&root),
            af_release::lifecycle::ReservationTarget::Package("unrelated"),
            "",
            Some("install"),
        )
        .await
        .unwrap(),
    );
    executable(&root.join("probe"), "#!/usr/bin/python3\nimport sys\nprint('LoadState=loaded\\nActiveState=active\\nSubState=elapsed' if sys.argv[-1].endswith('.timer') else 'LoadState=not-found\\nActiveState=inactive')\n");
    let orphan_unit = build_self_update_transient_unit_name("restart", "expired");
    let orphan_path = path.parent().unwrap().join(format!("{orphan_unit}.json"));
    let owner = job_receipts::begin_launch(&orphan_path).unwrap();
    job_receipts::write(&orphan_path, &receipt(&orphan_unit, "launching")).unwrap();
    drop(owner);
    let expired = query_self_update_job_at(&orphan_unit, &orphan_path)
        .await
        .unwrap();
    assert!(expired.completed && !expired.success);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn core_restart_worker_refuses_lock_swaps_without_creating_targets() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let test = "lifecycle_tests::core_restart_worker_refuses_lock_swaps_without_creating_targets";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let control = root.join("control");
    let commands = root.join("commands");
    executable(
        &control,
        &format!("#!/bin/sh\nprintf '%s\\n' \"$1\" >> {:?}\n", commands),
    );
    for variant in [
        "symlink",
        "missing",
        "directory",
        "fifo",
        "replacement",
        "ancestor",
        "receipt-directory-replacement",
    ] {
        let directory = root.join(variant);
        fs::create_dir_all(&directory).unwrap();
        let lock = directory.join("maintenance.lock");
        let scheduled = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
        let metadata = fs::metadata(&lock).unwrap();
        let receipt_directory = root.join(format!("{variant}-receipts"));
        fs::create_dir_all(&receipt_directory).unwrap();
        let receipt = receipt_directory.join("job.json");
        let receipt_identity = {
            let owner = job_receipts::begin_launch(&receipt).unwrap();
            owner.directory_identity().unwrap()
        };
        let unit = build_self_update_transient_unit_name("restart", "aetherflow-api");
        job_receipts::write(
            &receipt,
            &super::lifecycle_tests::receipt(&unit, "launching"),
        )
        .unwrap();
        let target = root.join(format!("arbitrary-{variant}"));
        fs::remove_file(&lock).unwrap();
        match variant {
            "symlink" => symlink(&target, &lock).unwrap(),
            "directory" => fs::create_dir(&lock).unwrap(),
            "fifo" => {
                assert!(std::process::Command::new("mkfifo")
                    .arg(&lock)
                    .status()
                    .unwrap()
                    .success());
            }
            "replacement" => fs::write(&lock, "different inode").unwrap(),
            "ancestor" => {
                let moved = root.join("moved-ancestor");
                fs::rename(&directory, &moved).unwrap();
                fs::write(moved.join("maintenance.lock"), "replacement").unwrap();
                symlink(&moved, &directory).unwrap();
            }
            "receipt-directory-replacement" => {
                let moved = root.join("moved-receipt-directory");
                fs::rename(&receipt_directory, &moved).unwrap();
                fs::create_dir(&receipt_directory).unwrap();
            }
            _ => {}
        }
        let result = Command::new("/bin/bash")
            .args(["-c", include_str!("core_restart_worker.sh"), "core-fixture"])
            .arg("aetherflow-api")
            .arg(&receipt)
            .arg(&unit)
            .arg(&lock)
            .arg(&control)
            .arg(metadata.dev().to_string())
            .arg(metadata.ino().to_string())
            .arg(receipt_identity.0.to_string())
            .arg(receipt_identity.1.to_string())
            .output()
            .await
            .unwrap();
        assert!(
            !result.status.success(),
            "unsafe variant {variant} was accepted"
        );
        assert!(!target.exists());
        assert!(!commands.exists());
        if variant != "receipt-directory-replacement" {
            // Refusal before the receipt directory is authenticated leaves the
            // original launching receipt unresolved; it must never claim success.
            let observed: SelfUpdateJobStatus =
                serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
            assert!(!observed.success);
            assert!(matches!(observed.status.as_str(), "launching" | "failed"));
        }
        drop(scheduled);
    }
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_detached_helper_does_not_capture_owned_restore_lock() {
    use futures::StreamExt;
    let test = "lifecycle_tests::legacy_detached_helper_does_not_capture_owned_restore_lock";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let common = root.join("common.sh");
    let helper = root.join("helper");
    let helper_socket = root.join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&helper_socket).unwrap();
    executable(&helper, &format!("#!/usr/bin/python3\nimport socket\nconnection=socket.socket(socket.AF_UNIX)\nconnection.connect({:?})\nconnection.sendall(b'R')\nconnection.recv(1)\n", helper_socket));
    fs::write(
        &common,
        fs::read_to_string(source_root.join("packages/common.sh"))
            .unwrap()
            .replace("/usr/local/bin/af-certbot-sync", &helper.to_string_lossy()),
    )
    .unwrap();
    let scripts = root.join("packages/package/install");
    fs::create_dir_all(&scripts).unwrap();
    let script = format!("installpackage-hillclimb-{}", uuid::Uuid::new_v4());
    executable(&scripts.join(&script), &format!("#!/bin/bash\nexport LOCK_DIR={:?} LOGFILE={:?}\nsource {:?}\nwrite_lock fixture\nprintf 'installer done\\n'\n", root.join("install"), root.join("install.log"), common));
    env::set_current_dir(&root).unwrap();
    env::set_var("AETHERFLOW_PACKAGE_ENGINE", "legacy");
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('fixture','owned','update','updating','now',?1,'[\"fixture.service\"]')", [&owner.id]).unwrap();
    let request = PackageRunnerRequest {
        package_id: "fixture".into(),
        action: "update".into(),
        script_name: script,
        lifecycle_job_id: "owned".into(),
        ..Default::default()
    };
    let output: Vec<_> = tokio::time::timeout(
        Duration::from_secs(5),
        package_executor::execute_package_request_stream(request).collect(),
    )
    .await
    .unwrap();
    let output = output.into_iter().map(Result::unwrap).collect::<String>();
    assert!(output.contains("installer done"), "{output}");
    assert!(!output.contains("__RUNNER_EXIT_ERROR__"), "{output}");
    let (mut detached, _) = listener.accept().await.unwrap();
    let mut entered = [0];
    detached.read_exact(&mut entered).await.unwrap();
    let restore = acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Service("fixture.service"),
        "owned",
        None,
    )
    .await
    .unwrap();
    assert!(acquire_lifecycle_admission_lock(Some(&root)).is_err());
    drop(restore);
    let control = root.join("systemctl");
    executable(&control, "#!/bin/sh\nexit 0\n");
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &control);
    env::set_var(
        "PATH",
        format!("{}:{}", root.display(), env::var("PATH").unwrap()),
    );
    let handoff = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    let mut restoring = tokio::spawn(handle_systemctl(Json(SystemctlRequest {
        service: "fixture.service".into(),
        action: "start".into(),
        lifecycle_job_id: "owned".into(),
    })));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut restoring)
            .await
            .is_err()
    );
    assert!(acquire_lifecycle_admission_lock(Some(&root)).is_err());
    drop(handoff);
    let (code, Json(result)) = restoring.await.unwrap();
    assert_eq!(code, StatusCode::OK, "{}", result.error);
    assert!(acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Service("fixture.service"),
        "",
        None
    )
    .await
    .is_err());
    detached.write_all(b"G").await.unwrap();
    drop((conn, owner));
    env::set_current_dir(&source_root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn surviving_legacy_installer_keeps_exclusion_after_api_process_death() {
    let test =
        "lifecycle_tests::surviving_legacy_installer_keeps_exclusion_after_api_process_death";
    if let Some(root) = env::var_os("AF_LEGACY_CRASH_ROOT") {
        use futures::StreamExt;
        let root = PathBuf::from(root);
        env::set_var("AETHERFLOW_FS_ROOT", &root);
        env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        env::set_current_dir(&root).unwrap();
        let cfg = af_release::ReleaseConfig::for_root(&root);
        let database = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        let conn = rusqlite::Connection::open(&database).unwrap();
        let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
        conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('fixture','owned-crash','update','updating','now',?1,'[\"fixture.service\"]')", [&owner.id]).unwrap();
        let request = PackageRunnerRequest {
            package_id: "fixture".into(),
            action: "update".into(),
            script_name: "installpackage-legacy-crash-fixture".into(),
            lifecycle_job_id: "owned-crash".into(),
            ..Default::default()
        };
        let stream = package_executor::execute_package_request_stream(request);
        tokio::pin!(stream);
        while let Some(line) = stream.next().await {
            assert!(!line.unwrap().contains("__RUNNER_EXIT_ERROR__"));
        }
        return;
    }
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let helper_socket = root.join("helper.sock");
    let installer_socket = root.join("installer.sock");
    let helper_listener = tokio::net::UnixListener::bind(&helper_socket).unwrap();
    let installer_listener = tokio::net::UnixListener::bind(&installer_socket).unwrap();
    let gate = |socket: &Path| {
        format!("import socket; connection=socket.socket(socket.AF_UNIX); connection.connect({:?}); connection.sendall(b'R'); connection.recv(1)", socket)
    };
    let helper = root.join("helper");
    executable(
        &helper,
        &format!("#!/usr/bin/python3\n{}\n", gate(&helper_socket)),
    );
    let common = root.join("common.sh");
    fs::write(
        &common,
        fs::read_to_string(source_root.join("packages/common.sh"))
            .unwrap()
            .replace("/usr/local/bin/af-certbot-sync", &helper.to_string_lossy()),
    )
    .unwrap();
    let scripts = root.join("packages/package/install");
    fs::create_dir_all(&scripts).unwrap();
    executable(&scripts.join("installpackage-legacy-crash-fixture"), &format!("#!/bin/bash\nexport LOCK_DIR={:?} LOGFILE={:?}\nsource {:?}\nwrite_lock fixture\npython3 -c {:?}\n", root.join("install"), root.join("install.log"), common, gate(&installer_socket)));
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let mut api = Command::new(env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("AF_LEGACY_CRASH_ROOT", &root)
        .spawn()
        .unwrap();
    let (mut installer, _) =
        tokio::time::timeout(Duration::from_secs(5), installer_listener.accept())
            .await
            .unwrap()
            .unwrap();
    let (mut helper, _) = tokio::time::timeout(Duration::from_secs(5), helper_listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut ready = [0];
    installer.read_exact(&mut ready).await.unwrap();
    helper.read_exact(&mut ready).await.unwrap();
    api.kill().await.unwrap();
    api.wait().await.unwrap();
    helper.write_all(b"G").await.unwrap();
    assert!(
        acquire_lifecycle_admission_lock(Some(&root)).is_err(),
        "surviving installer must retain exclusion after API death and helper release"
    );
    installer.write_all(b"G").await.unwrap();
    let lock = resolve_self_update_lock_path_for_cfg(&cfg).unwrap();
    assert!(Command::new("flock")
        .arg("-w")
        .arg("5")
        .arg(lock)
        .arg("/bin/true")
        .status()
        .await
        .unwrap()
        .success());
    let _admission = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    af_release::admin::ensure_no_active_package_lifecycle_jobs(
        &cfg,
        af_release::ReleaseCommand::Deploy,
    )
    .unwrap();
    let status: String = conn
        .query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "interrupted");
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn surviving_core_restart_controller_retains_lock_after_worker_death() {
    let test = "lifecycle_tests::surviving_core_restart_controller_retains_lock_after_worker_death";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let guard = acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    let (device, inode) = guard.file_identity().unwrap();
    let lock = guard.path().to_owned();
    drop(guard);
    let unit = build_self_update_transient_unit_name("restart", "aetherflow-api");
    let status = root.join("receipt.json");
    let launch_owner = job_receipts::begin_launch(&status).unwrap();
    let receipt_identity = launch_owner.directory_identity().unwrap();
    job_receipts::write(&status, &receipt(&unit, "launching")).unwrap();
    drop(launch_owner);
    let socket = root.join("controller.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let control = root.join("systemctl");
    executable(&control, &format!("#!/usr/bin/python3\nimport socket\nconnection=socket.socket(socket.AF_UNIX)\nconnection.connect({:?})\nconnection.sendall(b'R')\nconnection.recv(1)\n", socket));
    let mut worker = Command::new("/bin/bash")
        .args([
            "-c",
            include_str!("core_restart_worker.sh"),
            "worker-death-fixture",
        ])
        .arg("aetherflow-api")
        .arg(&status)
        .arg(&unit)
        .arg(&lock)
        .arg(&control)
        .arg(device.to_string())
        .arg(inode.to_string())
        .arg(receipt_identity.0.to_string())
        .arg(receipt_identity.1.to_string())
        .spawn()
        .unwrap();
    let (mut controller, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut ready = [0];
    controller.read_exact(&mut ready).await.unwrap();
    worker.kill().await.unwrap();
    worker.wait().await.unwrap();
    let excluded = acquire_lifecycle_admission_lock(Some(&root)).is_err();
    controller.write_all(b"G").await.unwrap();
    assert!(Command::new("flock")
        .arg("-w")
        .arg("5")
        .arg(&lock)
        .arg("/bin/true")
        .status()
        .await
        .unwrap()
        .success());
    assert!(
        excluded,
        "a surviving foreground controller must keep maintenance exclusion after worker death"
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn update_launch_ack_preserves_fast_terminal_receipts_for_both_engines() {
    let test =
        "lifecycle_tests::update_launch_ack_preserves_fast_terminal_receipts_for_both_engines";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let scheduler = root.join("systemd-run-fixture");
    executable(
        &scheduler,
        r#"#!/bin/bash
set -eu
receipt=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--job-status-file" ]; then shift; receipt="$1"; fi
    shift
done
python3 - "$receipt" "$AF_TERMINAL_FIXTURE" <<'PYWORKER'
import fcntl, json, os, sys
path, status = sys.argv[1:]
with open(path + '.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    with open(path) as source: value = json.load(source)
    value.update(status=status, completed=True, success=status == 'succeeded', exit_code=0 if status == 'succeeded' else 9, error='' if status == 'succeeded' else 'Fixture update failed.')
    with open(path + '.fixture', 'w') as target: json.dump(value, target)
    os.replace(path + '.fixture', path)
PYWORKER
"#,
    );
    let cli = root.join("af-fixture");
    executable(&cli, "#!/bin/sh\nexit 91\n");
    let legacy = root.join("release-fixture");
    executable(&legacy, "#!/bin/sh\nexit 92\n");
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &scheduler);
    env::set_var("AETHERFLOW_CLI_BIN", cli);
    env::set_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT", legacy);
    env::set_var("AETHERFLOW_ENABLE_RUST_RELEASE", "1");
    env::set_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE", "1");
    for engine in ["native_rust_release", "legacy_bash_release"] {
        env::set_var(
            "AETHERFLOW_FORCE_BASH_RELEASE",
            if engine == "legacy_bash_release" {
                "1"
            } else {
                "0"
            },
        );
        for status in ["succeeded", "failed"] {
            env::set_var("AF_TERMINAL_FIXTURE", status);
            let (code, response) = execute_self_update_request(
                &SelfUpdateRequest {
                    command: "deploy".into(),
                    channel: "stable".into(),
                },
                true,
            )
            .await;
            assert_eq!(code, StatusCode::OK, "{engine}: {}", response.error);
            assert!(
                response.success,
                "the request returns the authoritative receipt even when the operation failed"
            );
            let payload: Value = serde_json::from_str(&response.output).unwrap();
            assert_eq!(payload["engine"], engine);
            assert_eq!(
                payload["status"], status,
                "never acknowledge an already terminal job as initiated"
            );
            assert_eq!(payload["completed"], true);
            assert_eq!(payload["success"], status == "succeeded");
            assert_eq!(
                payload["exit_code"],
                if status == "succeeded" { 0 } else { 9 }
            );
            let observed = query_self_update_status_local(payload["job_unit"].as_str().unwrap())
                .await
                .unwrap();
            assert_eq!(observed.status, status);
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn local_service_admission_types_reservation_and_updater_contention() {
    let test = "lifecycle_tests::local_service_admission_types_reservation_and_updater_contention";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('fixture','fixture-job','update','updating','now',?1,'[\"fixture.service\"]')", [&owner.id]).unwrap();
    let error = acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Service("fixture"),
        "",
        None,
    )
    .await
    .err()
    .expect("live package reservation must exclude unrelated local control");
    assert!(is_lifecycle_busy(&error), "{error:#}");
    drop(owner);
    conn.execute("UPDATE package_lifecycle_jobs SET status='completed'", [])
        .unwrap();
    let unit = build_self_update_transient_unit_name("deploy", "stable");
    let path = resolve_self_update_jobs_dir_for_cfg(&cfg)
        .unwrap()
        .join(format!("{unit}.json"));
    let launch_owner = job_receipts::begin_launch(&path).unwrap();
    write_self_update_job_status_atomic(&path, &receipt(&unit, "launching")).unwrap();
    let error = acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Service("fixture"),
        "",
        None,
    )
    .await
    .err()
    .expect("an active updater must exclude local control");
    assert!(is_lifecycle_busy(&error), "{error:#}");
    drop(launch_owner);
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_cancellation_after_output_eof_reaps_child_and_releases_locks() {
    use futures::StreamExt;
    let test = "lifecycle_tests::legacy_cancellation_after_output_eof_reaps_child_and_releases_locks";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let ready_socket = root.join("ready.sock");
    let listener = tokio::net::UnixListener::bind(&ready_socket).unwrap();
    let scripts = root.join("packages/package/install");
    fs::create_dir_all(&scripts).unwrap();
    executable(
        &scripts.join("installpackage-fixture"),
        &format!(
            "#!/bin/bash\nexec python3 -c 'import os, socket; open({:?}, \"w\").write(str(os.getpid())); os.close(1); os.close(2); connection=socket.socket(socket.AF_UNIX); connection.connect({:?}); connection.sendall(b\"R\"); connection.recv(1)'\n",
            root.join("pid").to_string_lossy(),
            ready_socket.to_string_lossy()
        ),
    );
    env::set_current_dir(&root).unwrap();
    env::set_var("AETHERFLOW_FORCE_BASH_PACKAGES", "1");
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('fixture','eof-owned','install','installing','now',?1,'[\"fixture.service\"]')", [&owner.id]).unwrap();
    let request = PackageRunnerRequest {
        package_id: "fixture".into(),
        action: "install".into(),
        script_name: "installpackage-fixture".into(),
        lifecycle_job_id: "eof-owned".into(),
        ..Default::default()
    };
    let stream = package_executor::execute_package_request_stream(request);
    tokio::pin!(stream);
    let (mut ready, _) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            connection = listener.accept() => connection.unwrap(),
            line = stream.next() => panic!("installer exited before readiness: {line:?}"),
        }
    })
    .await
    .unwrap();
    let mut marker = [0];
    ready.read_exact(&mut marker).await.unwrap();
    assert_eq!(marker, [b'R']);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(package_executor::cancel_package_execution("fixture"));
    let output = tokio::time::timeout(Duration::from_secs(5), stream.collect::<Vec<_>>()).await;
    let pid: i32 = fs::read_to_string(root.join("pid")).unwrap().parse().unwrap();
    if output.is_err() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let output = output
        .expect("cancellation after both output pipes reach EOF must remain effective")
        .into_iter()
        .map(Result::unwrap)
        .collect::<String>();
    assert!(output.contains("operation cancelled for package 'fixture'"), "{output}");
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "cancelled child must be reaped");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    assert!(!package_executor::is_package_execution_active("fixture"));
    assert!(af_release::ReleaseLockGuard::acquire(
        &af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap(),
        Duration::ZERO
    )
    .is_ok());
    drop((ready, owner, conn));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_output_overflow_is_failed_and_reaps_child_before_releasing_maintenance() {
    use futures::StreamExt;
    let test = "lifecycle_tests::legacy_output_overflow_is_failed_and_reaps_child_before_releasing_maintenance";
    if subprocess(test) {
        return;
    }
    let root = fixture_root();
    let scripts = root.join("packages/package/install");
    fs::create_dir_all(&scripts).unwrap();
    let script = "installpackage-overflow-fixture";
    executable(&scripts.join(script), &format!("#!/bin/bash\nexec python3 -c 'import os, time; open({:?}, \"w\").write(str(os.getpid())); os.write(1, b\"x\" * (2 * 1024 * 1024) + bytes([10])); time.sleep(30)'\n", root.join("pid").to_string_lossy()));
    env::set_current_dir(&root).unwrap();
    env::set_var("AETHERFLOW_PACKAGE_ENGINE", "legacy");
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('fixture','output-owned','install','installing','now',?1,'[\"fixture.service\"]')", [&owner.id]).unwrap();
    let request = PackageRunnerRequest {
        package_id: "fixture".into(),
        action: "install".into(),
        script_name: script.into(),
        lifecycle_job_id: "output-owned".into(),
        ..Default::default()
    };
    let stream = package_executor::execute_package_request_stream(request);
    tokio::pin!(stream);
    let mut failed = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(line) = stream.next().await {
            let line = line.unwrap();
            assert!(
                line.len() <= 64 * 1024,
                "producer allocated/emitted an oversized record: {} bytes",
                line.len()
            );
            if line.contains("__RUNNER_EXIT_ERROR__") {
                assert!(line.contains("output record exceeds"), "{line}");
                let pid: i32 = fs::read_to_string(root.join("pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(
                    unsafe { libc::kill(pid, 0) },
                    -1,
                    "required installer must be reaped before failure is exposed"
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
                assert!(
                    af_release::ReleaseLockGuard::acquire(
                        &af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap(),
                        Duration::ZERO
                    )
                    .is_err(),
                    "stream still owns maintenance while failure is emitted"
                );
                failed = true;
            }
        }
    })
    .await
    .unwrap();
    assert!(failed, "oversized installer output must fail explicitly");
    drop(stream);
    assert!(af_release::ReleaseLockGuard::acquire(
        &af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap(),
        Duration::ZERO
    )
    .is_ok());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}
