use super::*;

#[tokio::test]
async fn blueprint_apply_route_mutates_native_files_and_arr_routes() {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let _env = ENV_TEST_MUTEX.lock().await;
    let root = std::env::temp_dir().join(format!("af-blueprint-route-{}", uuid::Uuid::new_v4()));
    let app_dir = root.join("var/lib/sonarr");
    fs::create_dir_all(&app_dir).unwrap();
    let config = app_dir.join("config.xml");
    fs::write(&config, b"<Config><Port>8989</Port></Config>\n").unwrap();

    let state_path = root.join("state.sqlite");
    let state = rusqlite::Connection::open(&state_path).unwrap();
    af_release::lifecycle::initialize_schema(&state).unwrap();
    state
        .execute_batch(
            "CREATE TABLE app_ingress_configs(app_name TEXT, listen_port INTEGER);
             INSERT INTO app_ingress_configs VALUES('qbittorrent', 18081);",
        )
        .unwrap();

    let clients_path = app_dir.join("sonarr.db");
    let clients = rusqlite::Connection::open(&clients_path).unwrap();
    clients.execute_batch(
            "CREATE TABLE DownloadClients(Id INTEGER PRIMARY KEY, Implementation TEXT, Settings TEXT);"
        ).unwrap();
    clients
        .execute(
            "INSERT INTO DownloadClients VALUES(1, 'QBittorrent', ?1)",
            [json!({"host": "127.0.0.1", "port": 8180}).to_string()],
        )
        .unwrap();
    let old_root = env::var_os("AETHERFLOW_CONFIG_ROOT");
    let old_db = env::var_os("AF_DB_PATH");
    env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    env::set_var("AF_DB_PATH", &state_path);

    let call = |app: &str, port: i32| {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/blueprint/apply")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"app_name": app, "listen_port": port}).to_string(),
            ))
            .unwrap();
        build_runner_router().oneshot(req)
    };
    let failed = call("sonarr", 65536).await.unwrap();
    let applied = call("sonarr", 18989).await.unwrap();
    let unchanged = call("sonarr", 18989).await.unwrap();
    clients
        .execute_batch("DROP TABLE DownloadClients; CREATE TABLE DownloadClients(Id INTEGER);")
        .unwrap();
    let rejected = call("sonarr", 18990).await.unwrap();

    for (key, old) in [("AETHERFLOW_CONFIG_ROOT", old_root), ("AF_DB_PATH", old_db)] {
        if let Some(value) = old {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rejected.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let decode = |bytes: hyper::body::Bytes| {
        let response: RunnerResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(response.success, "{}", response.error);
        serde_json::from_str::<af_models::RunnerBlueprintApplyResponse>(&response.output).unwrap()
    };
    let result = decode(applied.into_body().collect().await.unwrap().to_bytes());
    assert_eq!(result.sqlite_routes_injected, 1);
    assert_eq!(result.mutated_files.len(), 2);
    let result = decode(unchanged.into_body().collect().await.unwrap().to_bytes());
    assert_eq!(result.sqlite_routes_injected, 0);
    assert!(result.mutated_files.is_empty());
    let updated = fs::read_to_string(config).unwrap();
    assert!(updated.contains("<Port>18989</Port>"));
    assert!(!updated.contains("<Port>18990</Port>"));
    drop(clients);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn runner_peer_allows_test_executable_and_rejects_same_uid_shell() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let pid = std::process::id() as i32;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    assert!(trusted_runner_peer_exe(pid));
    assert!(authorize_runner_socket_peer(uid, gid, Some(pid), "/v1/health").is_ok());
    let mut shell = Command::new("/bin/sh")
        .args(["-c", "echo ready; read keep_open"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(shell.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let shell_pid = shell.id() as i32;
    let trusted = trusted_runner_peer_exe(shell_pid);
    let decision = authorize_runner_socket_peer(uid, gid, Some(shell_pid), "/v1/health");
    drop(shell.stdin.take());
    shell.wait().unwrap();
    assert_eq!(ready.trim(), "ready");
    assert!(!trusted);
    if uid != 0 {
        assert_eq!(decision.unwrap_err().0, StatusCode::FORBIDDEN);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_signal_handles_sigint_and_sigterm_in_isolated_processes() {
    const ENV: &str = "AETHERFLOW_SHUTDOWN_TEST_SIGNAL";
    if let Ok(number) = env::var(ENV) {
        let signal = shutdown_signal().unwrap();
        let number = number.parse::<i32>().unwrap();
        assert_eq!(unsafe { libc::kill(std::process::id() as i32, number) }, 0);
        tokio::time::timeout(Duration::from_secs(2), signal)
            .await
            .unwrap();
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::shutdown_signal_handles_sigint_and_sigterm_in_isolated_processes",
                "--nocapture",
            ])
            .env(ENV, signal.to_string())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "Signal {signal} must complete the graceful-shutdown future"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn runner_shutdown_drains_inflight_response_before_exiting() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir_name = format!("ad-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let base = env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let candidate = base.join(&dir_name);
    let root = if candidate.join("runner.sock").as_os_str().len() < 95 {
        candidate
    } else {
        PathBuf::from("/tmp").join(dir_name)
    };
    fs::create_dir(&root).unwrap();
    let path = root.join("runner.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    // Test auth in a child so process-global peer settings cannot affect other tests.
    const ENV: &str = "AETHERFLOW_RUNNER_DRAIN_TEST";
    if env::var_os(ENV).is_none() {
        drop(listener);
        fs::remove_dir_all(root).unwrap();
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::runner_shutdown_drains_inflight_response_before_exiting",
                "--nocapture",
            ])
            .env(ENV, "1")
            .env(
                "AETHERFLOW_ALLOWED_RUNNER_UIDS",
                unsafe { libc::geteuid() }.to_string(),
            )
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let enter_handler = entered.clone();
    let release_handler = release.clone();
    let app = Router::new().route(
        "/v1/drain-test",
        axum::routing::get(move || {
            let entered = enter_handler.clone();
            let release = release_handler.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                "completed-before-exit"
            }
        }),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_runner_connections(listener, app, async {
        let _ = shutdown_rx.await;
    }));
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    stream
        .write_all(b"GET /v1/drain-test HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    shutdown_tx.send(()).unwrap();
    tokio::task::yield_now().await;
    assert!(
        !server.is_finished(),
        "Active request must keep runner alive during drain"
    );
    release.notify_one();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.contains("completed-before-exit"));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_package_script_resolution_prefers_current_release() {
    let defaults = package_script_roots();
    assert_eq!(
        defaults[0],
        PathBuf::from("/opt/AetherFlow/current/packages/package")
    );
    assert_eq!(
        defaults[1],
        PathBuf::from("/opt/AetherFlow/packages/package")
    );
    assert_eq!(
        defaults[2],
        PathBuf::from("/usr/local/bin/AetherFlow/package")
    );

    let scratch = env::temp_dir().join(format!("af-script-paths-{}", uuid::Uuid::new_v4()));
    let roots: Vec<_> = defaults[..3]
        .iter()
        .map(|root| scratch.join(root.strip_prefix("/").unwrap()))
        .collect();
    for root in &roots {
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir_all(root.join("update")).unwrap();
        fs::create_dir_all(root.join("remove")).unwrap();
        fs::write(root.join("install/installpackage-dispatcharr"), "release").unwrap();
        fs::write(root.join("remove/removepackage-dispatcharr"), "remove").unwrap();
    }
    // A stale dedicated updater must not override the current installer.
    fs::write(roots[1].join("update/updatepackage-dispatcharr"), "stale").unwrap();
    for name in ["installpackage-dispatcharr", "updatepackage-dispatcharr"] {
        assert_eq!(
            resolve_package_script_in_roots("update", name, &roots),
            Some(roots[0].join("install/installpackage-dispatcharr"))
        );
    }
    for action in ["remove", "uninstall"] {
        assert_eq!(
            resolve_package_script_in_roots(action, "removepackage-dispatcharr", &roots),
            Some(roots[0].join("remove/removepackage-dispatcharr"))
        );
    }
    fs::write(roots[0].join("update/updatepackage-dispatcharr"), "current").unwrap();
    assert_eq!(
        resolve_package_script_in_roots("update", "installpackage-dispatcharr", &roots),
        Some(roots[0].join("update/updatepackage-dispatcharr"))
    );
    fs::remove_file(roots[0].join("install/installpackage-dispatcharr")).unwrap();
    assert_eq!(
        resolve_package_script_in_roots("install", "installpackage-dispatcharr", &roots),
        Some(roots[1].join("install/installpackage-dispatcharr"))
    );
    fs::remove_file(roots[1].join("install/installpackage-dispatcharr")).unwrap();
    assert_eq!(
        resolve_package_script_in_roots("install", "installpackage-dispatcharr", &roots),
        Some(roots[2].join("install/installpackage-dispatcharr"))
    );
    assert!(resolve_package_script_in_roots("install", "../dispatcharr", &roots).is_none());
    assert!(
        resolve_package_script_in_roots("invalid", "installpackage-dispatcharr", &roots).is_none()
    );
    fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn test_core_restart_is_independent_and_restricted() {
    let args = deferred_restart_arguments("aetherflow-api.service").unwrap();
    assert!(args.contains(&"--on-active=2s".to_string()));
    assert!(args[0].starts_with("--unit=aetherflow-self-update-restart-"));
    assert_eq!(args.last().unwrap(), "aetherflow-api");
    assert!(args
        .iter()
        .any(|arg| arg == include_str!("core_restart_worker.sh")));
    assert!(deferred_restart_arguments("sonarr").is_err());
    assert!(deferred_restart_arguments("../aetherflow-api").is_err());
}

#[tokio::test]
async fn test_heal_restart_skips_active_package_operation() {
    let _operation = PACKAGE_MUTEX.lock().await;
    let (status, Json(response)) = handle_systemctl(Json(SystemctlRequest {
        service: "gitea".into(),
        action: "heal".into(),
        lifecycle_job_id: String::new(),
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(response.success);
    assert_eq!(response.output, "skipped");
    let (status, Json(response)) = handle_systemctl(Json(SystemctlRequest {
        service: "gitea".into(),
        action: "restart".into(),
        lifecycle_job_id: String::new(),
    }))
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!response.success);
}

#[test]
fn test_package_output_propagates_failure_markers() {
    let mut lines = Vec::new();
    let result = consume_package_output(
        "installing\n__RUNNER_EXIT_ERROR__:exit status 7\nlast log\n",
        |line| lines.push(line),
    );
    assert!(result.unwrap_err().to_string().contains("exit status 7"));
    assert_eq!(lines, vec!["installing", "last log"]);
    assert!(consume_package_output("__RUNNER_EXIT_ERROR__:\n", |_| {}).is_err());
}

#[test]
fn test_package_output_accepts_success_logs() {
    let mut lines = Vec::new();
    consume_package_output("\nready\n\ncomplete\n", |line| lines.push(line)).unwrap();
    assert_eq!(lines, vec!["ready", "complete"]);
}

#[test]
fn test_incremental_decoder_handles_split_chunks_and_overlong_lines() {
    let mut lines = Vec::new();
    let mut decoder = IncrementalPackageLineDecoder::default();
    decoder.push_bytes(b"[PROGRESS:20] Part ", &mut |l| lines.push(l));
    assert!(lines.is_empty());
    decoder.push_bytes(b"one\nSecond ", &mut |l| lines.push(l));
    assert_eq!(lines, vec!["[PROGRESS:20] Part one"]);

    // Feed an overlong line (> MAX_PACKAGE_STREAM_LINE_BYTES) and ensure memory stays bounded
    let huge = vec![b'x'; MAX_PACKAGE_STREAM_LINE_BYTES + 8192];
    decoder.push_bytes(&huge, &mut |l| lines.push(l));
    assert!(decoder.pending.len() <= MAX_PACKAGE_STREAM_LINE_BYTES);
    decoder.push_bytes(b"\n[PROGRESS:100] Done\n", &mut |l| lines.push(l));
    decoder.finish(&mut |l| lines.push(l)).unwrap();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2], "[PROGRESS:100] Done");
}

#[test]
fn test_regex_allowlists() {
    assert!(SAFE_SCRIPT_NAME.is_match("installpackage-jellyfin"));
    assert!(!SAFE_SCRIPT_NAME.is_match("../etc/passwd"));
    assert!(SAFE_PKG_ID.is_match("sonarr"));
    assert!(!SAFE_PKG_ID.is_match("../sonarr"));
    assert!(SAFE_USERNAME.is_match("alice_01"));
    assert!(!SAFE_USERNAME.is_match("1invalid;rm"));
    assert!(SAFE_QUOTA_SIZE.is_match("500G"));
    assert!(SAFE_QUOTA_SIZE.is_match("500GB"));
    assert!(SAFE_QUOTA_SIZE.is_match("1073741824"));
    assert!(SAFE_QUOTA_SIZE_REGEX.is_match("500G"));
    assert!(SAFE_QUOTA_SIZE_REGEX.is_match("0"));
    assert!(!SAFE_QUOTA_SIZE_REGEX.is_match("500G; rm -rf /"));
}

#[test]
fn test_render_systemd_sandbox_dropin() {
    let dropin = render_systemd_sandbox_dropin(
        "dotnet",
        "sonarr",
        &["/var/lib/sonarr".to_string(), "-/mnt".to_string()],
    );
    assert!(dropin.contains("NoNewPrivileges=yes"));
    assert!(dropin.contains("PrivateTmp=yes"));
    assert!(dropin.contains("ProtectSystem=strict"));
    assert!(!dropin.contains("MemoryDenyWriteExecute=yes"));
    assert!(dropin.contains("ReadWritePaths="));

    let native_dropin = render_systemd_sandbox_dropin("native", "plexmediaserver", &[]);
    assert!(native_dropin.contains("PrivateDevices=no"));
    assert!(native_dropin.contains("MemoryDenyWriteExecute=yes"));
}

#[test]
fn test_sandbox_master_credentials_formats() {
    assert_eq!(
        sandbox_master_user(r#"{"username":"media_owner","password":"secret"}"#),
        Some("media_owner".into())
    );
    assert_eq!(
        sandbox_master_user("username=media_owner\r\npassword=secret"),
        Some("media_owner".into())
    );
    assert_eq!(
        sandbox_master_user("media_owner:secret\n"),
        Some("media_owner".into())
    );
    assert_eq!(sandbox_master_user("username=../../etc"), None);
    assert_eq!(sandbox_master_user("password=secret"), None);
    assert_eq!(sandbox_master_user(""), None);
}

#[test]
fn test_sandbox_paths_use_distinct_service_and_master_identities() {
    assert_eq!(
        expand_sandbox_path(
            "-/home/{{MASTER_USER}}/Google/Media/Music Import",
            "sonarr",
            "/var/lib/sonarr",
            "media_owner"
        ),
        "\"-/home/media_owner/Google/Media/Music Import\""
    );
    assert_eq!(
        expand_sandbox_path(
            "-{{SERVICE_HOME}}/{{SERVICE_USER}}",
            "sonarr",
            "/var/lib/sonarr",
            "media_owner"
        ),
        "-/var/lib/sonarr/sonarr"
    );
}

#[tokio::test]
async fn test_handle_sandbox_and_quota_graceful_fallback() {
    let (code, Json(resp)) = handle_sandbox_with(
        SandboxRunnerRequest {
            package: "sonarr".to_string(),
            package_id: String::new(),
            lifecycle_job_id: String::new(),
        },
        |_| async { Ok("sandbox fixture applied".into()) },
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(resp.success);

    let (bad_code, Json(bad_resp)) = handle_sandbox_with(
        SandboxRunnerRequest {
            package: "../evil".to_string(),
            package_id: String::new(),
            lifecycle_job_id: String::new(),
        },
        |_| async { Ok("sandbox fixture applied".into()) },
    )
    .await;
    assert_eq!(bad_code, StatusCode::BAD_REQUEST);
    assert!(!bad_resp.success);

    env::set_var("AETHERFLOW_QUOTA_DRY_RUN", "1");
    let (q_code, Json(q_resp)) = handle_quota(Json(QuotaRunnerRequest {
        username: "mediauser".to_string(),
        size: "500G".to_string(),
    }))
    .await;
    assert_eq!(q_code, StatusCode::OK);
    assert!(q_resp.success);
    assert!(q_resp.output.contains("mediauser"));
}

#[tokio::test]
async fn test_handle_app_meta_wire_format() {
    let (code, Json(resp)) = handle_app_meta(Json(AppMetaRunnerRequest {
        app_name: "sonarr".to_string(),
    }))
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(resp.success);
    let decoded: AppRuntimeMeta = serde_json::from_str(&resp.output).unwrap();
    assert!(decoded.configured_port >= 0);
}

#[tokio::test]
async fn test_handle_app_meta_extracts_retained_url_bases_and_rejects_malformed() {
    const ISOLATION_ENV: &str = "AF_RUNNER_URL_BASE_TEST_ISOLATED";
    if env::var_os(ISOLATION_ENV).is_none() {
        let name = std::thread::current()
            .name()
            .expect("named test thread")
            .to_string();
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(ISOLATION_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success(), "isolated test failed: {name}");
        return;
    }

    let root = env::temp_dir().join(format!("af-runner-url-base-{}", uuid::Uuid::new_v4()));
    let write_rel = |rel: &str, body: &str| {
        let full = root.join(rel);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, body).unwrap();
        full
    };

    write_rel(
        "var/lib/sonarr/config.xml",
        "<Config><Port>18989</Port><ApiKey>s-key</ApiKey><UrlBase> /tv/sonarr/ </UrlBase></Config>",
    );
    write_rel(
        "var/lib/radarr/config.xml",
        "<Config><Port>17878</Port><UrlBase>radarr</UrlBase></Config>",
    );
    write_rel(
        "var/lib/lidarr/config.xml",
        "<Config><Port>18686</Port><UrlBase>/music/lidarr/</UrlBase></Config>",
    );
    write_rel(
        "var/lib/prowlarr/config.xml",
        "<Config><Port>19696</Port><UrlBase>/prowlarr/../admin</UrlBase></Config>",
    );
    write_rel(
        "var/lib/prowlarr/config/config.xml",
        "<Config><Port>19696</Port><UrlBase>/stale-secondary</UrlBase></Config>",
    );
    write_rel(
        "var/lib/bazarr/config/config.yaml",
        concat!(
            "auth:\n",
            "  apikey: bazarr-key\n",
            "general: # operator config\n",
            "  proxy:\n",
            "    exclude:\n",
            "    - localhost\n",
            "    base_url: /nested-ignored\n",
            "  ip: 127.0.0.1\n",
            "  port: 16767\n",
            "  base_url: '/subs/bazarr/' # retained\n",
            "sonarr:\n",
            "  base_url: /sonarr\n",
        ),
    );
    write_rel(
        "var/lib/sabnzbd/sabnzbd.ini",
        concat!(
            "__version__ = 19\n",
            "[servers]\n",
            "[[news.local]]\n",
            "url_base = /wrong\n",
            "[misc]\n",
            "port = 18085\n",
            "url_base = /sabnzbd/ # retained\n",
        ),
    );
    write_rel(
        "var/lib/tautulli/config.ini",
        "[General]\nhttp_port = 18181\nhttp_root = \"/tautulli\"\n",
    );

    env::set_var("AETHERFLOW_CONFIG_ROOT", &root);

    for (app, expected_port, expected_base) in [
        ("sonarr", 18989, "/tv/sonarr"),
        ("radarr", 17878, "/radarr"),
        ("lidarr", 18686, "/music/lidarr"),
        ("prowlarr", 19696, ""),
        ("bazarr", 16767, "/subs/bazarr"),
        ("sabnzbd", 18085, "/sabnzbd"),
        ("tautulli", 18181, "/tautulli"),
    ] {
        let (code, Json(resp)) = handle_app_meta(Json(AppMetaRunnerRequest {
            app_name: app.to_string(),
        }))
        .await;
        assert_eq!(code, StatusCode::OK, "{app}");
        assert!(resp.success, "{app}");
        let decoded: AppRuntimeMeta = serde_json::from_str(&resp.output).unwrap();
        assert_eq!(decoded.configured_port, expected_port, "{app}");
        assert_eq!(decoded.url_base, expected_base, "{app}");
        if expected_base.is_empty() {
            assert!(
                !resp.output.contains("url_base"),
                "{app} empty url_base should be omitted on wire: {}",
                resp.output
            );
        }
    }

    // Legacy Bazarr INI fallback when config.yaml is absent.
    fs::remove_file(root.join("var/lib/bazarr/config/config.yaml")).unwrap();
    write_rel(
        "var/lib/bazarr/config/config.ini",
        "[sonarr]\nbase_url = /sonarr\n[general]\nport = 16768\nbase_url = /bazarr-ini/\n",
    );
    let bazarr_ini = extract_app_runtime_meta_local("bazarr");
    assert_eq!(bazarr_ini.configured_port, 16768);
    assert_eq!(bazarr_ini.url_base, "/bazarr-ini");

    // Confined reader must refuse symlinked config files.
    let target = write_rel(
        "outside-config.xml",
        "<Config><Port>18787</Port><UrlBase>/readarr</UrlBase></Config>",
    );
    let readarr_xml = root.join("var/lib/readarr/config.xml");
    fs::create_dir_all(readarr_xml.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &readarr_xml).unwrap();
    let symlinked = extract_app_runtime_meta_local("readarr");
    assert_eq!(symlinked.configured_port, 0);
    assert!(symlinked.url_base.is_empty());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_dispatcharr_runtime_port_and_package_fallback() {
    assert_eq!(dispatcharr_runtime_port("DISPATCHARR_PORT=19200\n"), 19200);
    assert_eq!(
        dispatcharr_runtime_port("DISPATCHARR_PORT=\"9191\"\n"),
        9191
    );
    assert_eq!(dispatcharr_runtime_port("DISPATCHARR_PORT=70000\n"), 0);
    assert_eq!(dispatcharr_runtime_port("POSTGRES_PORT=5432\n"), 0);
    assert!(package_script_roots().contains(&PathBuf::from("../../packages/package")));
}

#[test]
fn test_dispatcharr_credential_sync_drops_privileges_and_preserves_literals() {
    let username = "user'\"$`\\";
    let password = "p'\"\\$(touch /tmp/not-executed)\npassword";
    let command = dispatcharr_credentials_command(username, password);
    let command = command.as_std();
    assert_eq!(command.get_program(), "runuser");
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect();
    assert_eq!(&args[..5], &["-u", "dispatcharr", "--", "/bin/bash", "-ec"]);
    assert!(args
        .last()
        .unwrap()
        .contains("source /etc/dispatcharr/dispatcharr.env"));
    assert!(!args
        .iter()
        .any(|arg| arg.contains(password) || arg.contains(username)));
    let variables: HashMap<_, _> = command.get_envs().collect();
    assert_eq!(
        variables[std::ffi::OsStr::new("AF_ADMIN_USER")],
        Some(std::ffi::OsStr::new(username))
    );
    assert_eq!(
        variables[std::ffi::OsStr::new("AF_ADMIN_PASS")],
        Some(std::ffi::OsStr::new(password))
    );
    assert!(DISPATCHARR_ADMIN_SCRIPT.contains("user.user_level = 10"));
    assert!(DISPATCHARR_ADMIN_SCRIPT.contains("os.environ[\"AF_ADMIN_PASS\"]"));
}

#[tokio::test]
async fn test_dispatcharr_sync_rejects_invalid_credentials_before_execution() {
    for (username, password) in [("", "secret"), ("admin", ""), ("admin\0", "secret")] {
        let (status, Json(response)) =
            handle_dispatcharr_credentials(Json(DispatcharrCredentialsRequest {
                username: username.to_string(),
                password: password.to_string(),
            }))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!response.success);
    }
}

#[tokio::test]
async fn test_handle_package_rejects_purge_for_non_remove_actions() {
    for action in ["install", "update"] {
        let response = handle_package(Json(PackageRunnerRequest {
            action: action.to_string(),
            package_id: "sonarr".to_string(),
            script_name: "installpackage-sonarr".to_string(),
            lifecycle_job_id: String::new(),
            app_port: 0,
            delete_data: true,
            ..Default::default()
        }))
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{}", action);
    }
    let error = dispatch_package_action_with_options(
        "update",
        "sonarr",
        "installpackage-sonarr",
        0,
        true,
        |_| {},
    )
    .await
    .expect_err("client must refuse purge outside removal");
    assert!(error.to_string().contains("only valid for package removal"));
}

#[tokio::test]
async fn test_handle_package_cancel_validation_and_signalling() {
    let (bad_code, Json(bad_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
        package: "../bad".to_string(),
        package_id: String::new(),
        lifecycle_job_id: String::new(),
    }))
    .await;
    assert_eq!(bad_code, StatusCode::BAD_REQUEST);
    assert!(!bad_resp.success);

    let tok = CancellationToken::new();
    let _guard = register_package_cancellation("cancel-handler-test", tok.clone()).unwrap();
    let (ok_code, Json(ok_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
        package: String::new(),
        package_id: "cancel-handler-test".to_string(),
        lifecycle_job_id: String::new(),
    }))
    .await;
    assert_eq!(ok_code, StatusCode::OK);
    assert!(ok_resp.success);
    assert!(ok_resp.output.contains("cancellation signalled"));
    assert!(tok.is_cancelled());
}

#[tokio::test]
async fn test_update_discovery_and_admission_survive_api_restart_and_fail_closed() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let root = env::temp_dir().join(format!("af-admission-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let cfg = af_release::ReleaseConfig::load_for_root_from_process_env(Some(&root), None).unwrap();
    assert!(discover_system_update(&cfg).await.unwrap().completed);
    let lock = af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
    let guard = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
    assert!(
        af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err(),
        "simultaneous updater/package admission cannot both hold the lock"
    );
    drop(guard);
    let dir = resolve_self_update_jobs_dir_for_cfg(&cfg).unwrap();
    let unit = "aetherflow-self-update-deploy-nightly-1234abcd.service";
    let path = dir.join(format!("{}.json", unit));
    let mut receipt = SelfUpdateJobStatus {
        status: "running".into(),
        completed: false,
        success: false,
        job_unit: unit.into(),
        error: String::new(),
        exit_code: None,
    };
    write_self_update_job_status_atomic(&path, &receipt).unwrap();
    // No ACTIVE_SYSTEM_UPDATE flag is set. Read from a fresh config, as a
    // restarted API would. A fake launcher disables real systemd queries.
    let previous = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", root.join("unused-fixture"));
    assert!(!discover_system_update(&cfg).await.unwrap().completed);
    assert!(acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Package("fixture"),
        "",
        Some("update")
    )
    .await
    .is_err());
    receipt.status = "failed".into();
    receipt.completed = true;
    receipt.exit_code = Some(1);
    receipt.error = "fixture failure".into();
    write_self_update_job_status_atomic(&path, &receipt).unwrap();
    assert!(discover_system_update(&cfg).await.unwrap().completed);
    let package_guard = acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Package("fixture"),
        "",
        Some("update"),
    )
    .await
    .unwrap();
    assert!(af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err());
    drop(package_guard);
    fs::write(&path, "{invalid receipt").unwrap();
    assert!(discover_system_update(&cfg).await.is_err());
    assert!(acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Package("fixture"),
        "",
        Some("update")
    )
    .await
    .is_err());
    fs::remove_file(&path).unwrap();
    let mut recovery = af_release::RecoveryState::new(
        af_release::ReleaseCommand::Deploy,
        af_release::ReleaseChannel::Nightly,
        false,
    );
    recovery.save(&cfg.releases_dir).unwrap();
    let recovery_status = discover_system_update(&cfg).await.unwrap();
    assert!(!update_status_allows_launch(
        &recovery_status,
        af_release::ReleaseCommand::Deploy
    ));
    assert!(update_status_allows_launch(
        &recovery_status,
        af_release::ReleaseCommand::Rollback
    ));
    assert!(!recovery_status.completed);
    assert!(acquire_package_maintenance_guard(
        Some(&root),
        af_release::lifecycle::ReservationTarget::Package("fixture"),
        "",
        Some("update")
    )
    .await
    .is_err());
    match previous {
        Some(value) => env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", value),
        None => env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN"),
    }
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn test_release_engine_rollout_control_and_self_update_validation() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    assert_eq!(
        select_release_engine_with_flags(false, false),
        ReleaseEngineMode::LegacyBashRelease
    );
    assert_eq!(
        select_release_engine_with_flags(true, false),
        ReleaseEngineMode::NativeRustRelease
    );
    assert_eq!(
        select_release_engine_with_flags(true, true),
        ReleaseEngineMode::LegacyBashRelease
    );

    let (bad_cmd_code, bad_cmd_resp) = execute_self_update_request(
        &SelfUpdateRequest {
            command: "rm -rf /".to_string(),
            channel: "stable".to_string(),
        },
        false,
    )
    .await;
    assert_eq!(bad_cmd_code, StatusCode::BAD_REQUEST);
    assert!(!bad_cmd_resp.success);

    let (bad_chan_code, bad_chan_resp) = execute_self_update_request(
        &SelfUpdateRequest {
            command: "deploy".to_string(),
            channel: "untrusted-channel".to_string(),
        },
        false,
    )
    .await;
    assert_eq!(bad_chan_code, StatusCode::BAD_REQUEST);
    assert!(!bad_chan_resp.success);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let test_dir = env::temp_dir().join(format!(
            "af-runner-self-update-unit-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&test_dir).unwrap();

        let args_log = test_dir.join("systemd-run.args");
        let fake_systemd_run = test_dir.join("fake-systemd-run.sh");
        fs::write(
            &fake_systemd_run,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nexit 0\n",
                args_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_af = test_dir.join("af");
        fs::write(&fake_af, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_af, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_rm = test_dir.join("release-manager.sh");
        fs::write(&fake_rm, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_rm, fs::Permissions::from_mode(0o755)).unwrap();

        env::set_var("AETHERFLOW_RELEASE_ROOT", &test_dir);
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_systemd_run);
        env::set_var("AETHERFLOW_CLI_BIN", &fake_af);
        env::set_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT", &fake_rm);
        env::set_var("AETHERFLOW_ENABLE_RUST_RELEASE", "1");
        env::remove_var("AETHERFLOW_FORCE_BASH_RELEASE");
        env::set_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE", "1");

        let (ok_code, ok_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "deploy".to_string(),
                channel: "stable".to_string(),
            },
            true,
        )
        .await;
        assert_eq!(ok_code, StatusCode::OK);
        assert!(ok_resp.success);
        let parsed_native: Value = serde_json::from_str(&ok_resp.output).unwrap();
        assert_eq!(parsed_native["status"], "initiated");
        assert_eq!(parsed_native["completed"], false);
        assert_eq!(parsed_native["engine"], "native_rust_release");
        let native_unit = parsed_native["job_unit"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(native_unit.starts_with("aetherflow-self-update-deploy-stable-"));
        let logged_native = fs::read_to_string(&args_log).unwrap();
        assert!(logged_native.contains("--no-block"));
        assert!(logged_native.contains("--root"));
        assert!(logged_native.contains(test_dir.to_string_lossy().as_ref()));
        assert!(logged_native.contains("release"));
        assert!(logged_native.contains("--local"));
        assert!(logged_native.contains("--job-status-file"));
        assert!(logged_native.contains("--setenv=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1"));

        // Verify durable status is initially "running" (completed=false)
        let running_st = query_self_update_status_local(&native_unit).await.unwrap();
        assert_eq!(running_st.status, "running");
        assert!(!running_st.completed);
        assert!(!running_st.success);

        // Simulate completion receipt write and verify query_self_update_status_local returns it
        let status_file = test_dir
            .join("var/lib/aetherflow/.self-update-jobs")
            .join(format!("{}.json", native_unit));
        write_self_update_job_status_atomic(
            &status_file,
            &SelfUpdateJobStatus {
                status: "succeeded".to_string(),
                completed: true,
                success: true,
                job_unit: native_unit.clone(),
                error: String::new(),
                exit_code: Some(0),
            },
        )
        .unwrap();
        let done_st = query_self_update_status_local(&native_unit).await.unwrap();
        assert_eq!(done_st.status, "succeeded");
        assert!(done_st.completed);
        assert!(done_st.success);
        assert_eq!(done_st.exit_code, Some(0));

        env::set_var("AETHERFLOW_FORCE_BASH_RELEASE", "1");
        let (bash_code, bash_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "rollback".to_string(),
                channel: "nightly".to_string(),
            },
            true,
        )
        .await;
        assert_eq!(bash_code, StatusCode::OK);
        assert!(bash_resp.success);
        let parsed_bash: Value = serde_json::from_str(&bash_resp.output).unwrap();
        assert_eq!(parsed_bash["status"], "initiated");
        assert_eq!(parsed_bash["completed"], false);
        assert_eq!(parsed_bash["engine"], "legacy_bash_release");
        let logged_bash = fs::read_to_string(&args_log).unwrap();
        let directory =
            fs::metadata(test_dir.join("var/lib/aetherflow/.self-update-jobs")).unwrap();
        assert!(logged_bash.contains(&format!(
            "--setenv=AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV={}",
            std::os::unix::fs::MetadataExt::dev(&directory)
        )));
        assert!(logged_bash.contains(&format!(
            "--setenv=AETHERFLOW_SELF_UPDATE_DIRECTORY_INO={}",
            std::os::unix::fs::MetadataExt::ino(&directory)
        )));
        assert!(logged_bash.contains("/bin/bash"));
        assert!(logged_bash.contains("rollback"));
        assert!(logged_bash.contains("--root"));
        assert!(logged_bash.contains("--config"));
        assert!(logged_bash.contains("--job-status-file"));
        assert!(logged_bash.contains("--setenv=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1"));

        let bash_unit = parsed_bash["job_unit"].as_str().unwrap();
        write_self_update_job_status_atomic(
            &test_dir
                .join("var/lib/aetherflow/.self-update-jobs")
                .join(format!("{}.json", bash_unit)),
            &SelfUpdateJobStatus {
                status: "succeeded".into(),
                completed: true,
                success: true,
                job_unit: bash_unit.into(),
                error: String::new(),
                exit_code: Some(0),
            },
        )
        .unwrap();

        env::remove_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE");
        spawn_self_update_transient_unit(
            "aetherflow-self-update-deploy-stable-12345678.service",
            &fake_af,
            &[],
            &[],
        )
        .await
        .unwrap();
        let logged_without_opt_in = fs::read_to_string(&args_log).unwrap();
        assert!(!logged_without_opt_in.contains("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE"));

        // Verify malformed release-manager.conf fails closed instead of defaulting
        let bad_conf = test_dir.join("malformed.conf");
        fs::write(&bad_conf, "BROKEN_LINE_WITHOUT_EQUALS\n").unwrap();
        env::set_var("AETHERFLOW_RELEASE_CONF", &bad_conf);
        let (mal_code, mal_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "deploy".to_string(),
                channel: "stable".to_string(),
            },
            true,
        )
        .await;
        assert_eq!(mal_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!mal_resp.success);
        env::remove_var("AETHERFLOW_RELEASE_CONF");

        let fail_systemd_run = test_dir.join("fail-systemd-run.sh");
        fs::write(
            &fail_systemd_run,
            "#!/bin/sh\necho 'dbus unit limit exceeded' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&fail_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fail_systemd_run);

        let (fail_code, fail_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "deploy".to_string(),
                channel: "stable".to_string(),
            },
            true,
        )
        .await;
        assert_eq!(fail_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!fail_resp.success);
        assert!(fail_resp.error.contains("failed to start"));

        env::remove_var("AETHERFLOW_RELEASE_ROOT");
        env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN");
        env::remove_var("AETHERFLOW_CLI_BIN");
        env::remove_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT");
        env::remove_var("AETHERFLOW_ENABLE_RUST_RELEASE");
        env::remove_var("AETHERFLOW_FORCE_BASH_RELEASE");
        env::remove_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE");
        let _ = fs::remove_dir_all(&test_dir);
    }
}

#[tokio::test]
async fn test_handle_backup_create_verify_list_restore_and_prune() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let root = env::temp_dir().join(format!(
        "af-runner-backup-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let host_root = root.join("host");
    let db_path = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    let backup_dir = host_root.join("var/lib/aetherflow/backups");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    env::set_var(
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        host_root.to_string_lossy().as_ref(),
    );

    assert!(authorize_runner_peer_credentials(0, 0, "/v1/backup").is_ok());
    let (unauth_code, unauth_msg) =
        authorize_runner_peer_credentials(65534, 65534, "/v1/backup").unwrap_err();
    assert_eq!(unauth_code, StatusCode::FORBIDDEN);
    assert!(unauth_msg.contains("unauthorized unix socket peer"));

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
                 PRAGMA user_version = 7;
                 CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT NOT NULL);
                 INSERT INTO settings (id, base_domain) VALUES (1, 'runner.example.test');",
        )
        .unwrap();
    }

    let (bad_code, Json(bad_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "drop_table".to_string(),
        ..Default::default()
    }))
    .await;
    assert_eq!(bad_code, StatusCode::BAD_REQUEST);
    assert!(!bad_resp.success);

    let (forbid_code, Json(forbid_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "delete".to_string(),
        filename: "aetherflow-db-20261103_000000.sqlite".to_string(),
        backup_dir: "/etc".to_string(),
        ..Default::default()
    }))
    .await;
    assert_eq!(forbid_code, StatusCode::FORBIDDEN);
    assert!(!forbid_resp.success);

    let (create_code, Json(create_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "create_sqlite".to_string(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        db_path: db_path.to_string_lossy().into_owned(),
        app_version: "v4.0.0".to_string(),
        ..Default::default()
    }))
    .await;
    assert_eq!(create_code, StatusCode::OK);
    assert!(create_resp.success);
    let created: BackupRunnerResponse = serde_json::from_str(&create_resp.output).unwrap();
    assert!(created.verified);
    assert!(created.filename.ends_with(".sqlite"));

    let (ver_code, Json(ver_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "verify".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await;
    assert_eq!(ver_code, StatusCode::OK);
    assert!(ver_resp.success);

    let stage_target = root.join("restore-stage");
    let (pf_code, Json(pf_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_preflight".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await;
    assert_eq!(pf_code, StatusCode::OK);
    assert!(pf_resp.success);

    let (unconf_code, Json(unconf_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_execute".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        confirm_destructive_restore: false,
        ..Default::default()
    }))
    .await;
    assert_eq!(unconf_code, StatusCode::BAD_REQUEST);
    assert!(!unconf_resp.success);

    let (self_stop_code, Json(self_stop_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_execute".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        confirm_destructive_restore: true,
        allow_overwrite: true,
        quiesce_services: vec!["aetherflow-runner.service".to_string()],
        ..Default::default()
    }))
    .await;
    assert_eq!(self_stop_code, StatusCode::BAD_REQUEST);
    assert!(!self_stop_resp.success);

    let (bypass_code, Json(bypass_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_execute".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        confirm_destructive_restore: true,
        allow_overwrite: true,
        quiesce_services: vec!["none".to_string()],
        ..Default::default()
    }))
    .await;
    assert_eq!(bypass_code, StatusCode::BAD_REQUEST);
    assert!(!bypass_resp.success);

    let (rest_code, Json(rest_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_execute".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        confirm_destructive_restore: true,
        allow_overwrite: true,
        quiesce_services: vec!["custom-writer.service".to_string()],
        ..Default::default()
    }))
    .await;
    assert_eq!(rest_code, StatusCode::OK);
    assert!(rest_resp.success);
    let restored: BackupRunnerResponse = serde_json::from_str(&rest_resp.output).unwrap();
    assert!(restored.verified);
    assert_eq!(restored.restored_files, 1);
    assert_eq!(
        restored.details["quiesced_services"],
        json!(["aetherflow-api.service", "custom-writer.service"])
    );

    let (rec_code, Json(rec_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "recover_interrupted".to_string(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_target.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await;
    assert_eq!(rec_code, StatusCode::OK, "{}", rec_resp.error);
    assert!(rec_resp.success);

    let custom_db = host_root.join("srv/custom-af/aetherflow.sqlite");
    fs::create_dir_all(custom_db.parent().unwrap()).unwrap();
    fs::copy(&db_path, &custom_db).unwrap();
    env::set_var("AF_DB_PATH", custom_db.to_string_lossy().as_ref());

    let stage_contained = root.join("restore-stage-contained");
    let (pf2_code, Json(pf2_resp)) = handle_backup(Json(BackupRunnerRequest {
        action: "restore_preflight".to_string(),
        filename: created.filename.clone(),
        backup_dir: backup_dir.to_string_lossy().into_owned(),
        target_root: stage_contained.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await;
    assert_eq!(pf2_code, StatusCode::OK, "{}", pf2_resp.error);
    let pf2_parsed: BackupRunnerResponse = serde_json::from_str(&pf2_resp.output).unwrap();
    let dest_str = pf2_parsed.details["items"][0]["destination_path"]
        .as_str()
        .unwrap();
    assert!(
        Path::new(dest_str).starts_with(&stage_contained),
        "staging preflight destination '{}' escaped staging target '{}'",
        dest_str,
        stage_contained.display()
    );
    env::remove_var("AF_DB_PATH");

    env::remove_var("AETHERFLOW_BACKUP_ISOLATED_ROOT");
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_self_update_status_honors_custom_data_dir_and_rejects_contradictory_receipts() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let test_dir = env::temp_dir().join(format!(
        "af-runner-status-datadir-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let custom_data_dir = test_dir.join("srv/aetherflow-data");
    let etc_dir = test_dir.join("etc/aetherflow");
    fs::create_dir_all(&custom_data_dir).unwrap();
    fs::create_dir_all(&etc_dir).unwrap();
    fs::write(
        etc_dir.join("release-manager.conf"),
        format!("DATA_DIR=\"{}\"\n", custom_data_dir.display()),
    )
    .unwrap();

    env::set_var("AETHERFLOW_RELEASE_ROOT", &test_dir);
    let jobs_dir = resolve_self_update_jobs_dir_from_env().unwrap();
    assert_eq!(jobs_dir, custom_data_dir.join(".self-update-jobs"));

    let unit_name = "aetherflow-self-update-deploy-stable-11223344.service";
    let status_file = jobs_dir.join(format!("{}.json", unit_name));
    write_self_update_job_status_atomic(
        &status_file,
        &SelfUpdateJobStatus {
            status: "succeeded".to_string(),
            completed: true,
            success: true,
            job_unit: unit_name.to_string(),
            error: String::new(),
            exit_code: Some(0),
        },
    )
    .unwrap();
    let valid_res = query_self_update_status_local(unit_name).await.unwrap();
    assert!(valid_res.completed);
    assert!(valid_res.success);

    fs::write(
        &status_file,
        serde_json::to_vec(&SelfUpdateJobStatus {
            status: "running".to_string(),
            completed: false,
            success: true,
            job_unit: unit_name.to_string(),
            error: String::new(),
            exit_code: None,
        })
        .unwrap(),
    )
    .unwrap();
    let corrupt_err = query_self_update_status_local(unit_name)
        .await
        .expect_err("contradictory receipt must fail closed");
    assert_eq!(corrupt_err.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(corrupt_err.1.contains("corrupt self-update status file"));

    #[cfg(target_os = "linux")]
    {
        let vanished_unit = "aetherflow-self-update-deploy-stable-99887766.service";
        let vanished_file = jobs_dir.join(format!("{}.json", vanished_unit));
        write_self_update_job_status_atomic(
            &vanished_file,
            &SelfUpdateJobStatus {
                status: "running".to_string(),
                completed: false,
                success: false,
                job_unit: vanished_unit.to_string(),
                error: String::new(),
                exit_code: None,
            },
        )
        .unwrap();
        // A missing unit is a fixture, never a query to the host manager.
        use std::os::unix::fs::PermissionsExt;
        let fake_ctl = test_dir.join("systemctl-fixture");
        fs::write(&fake_ctl, "#!/bin/sh\nprintf 'LoadState=not-found\\nActiveState=inactive\\nExecMainStatus=0\\n'\n").unwrap();
        fs::set_permissions(&fake_ctl, fs::Permissions::from_mode(0o755)).unwrap();
        env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_ctl);
        let reconciled = query_self_update_status_local(vanished_unit).await.unwrap();
        env::remove_var("AETHERFLOW_SYSTEMCTL_BIN");
        assert_eq!(reconciled.status, "failed");
        assert!(reconciled.completed);
        assert!(!reconciled.success);
        assert_eq!(reconciled.exit_code, Some(1));
    }

    env::remove_var("AETHERFLOW_RELEASE_ROOT");
    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_tailscale_and_wireguard_exempt_from_sandbox() {
    assert!(is_exempt_sandbox_unit("tailscale"));
    assert!(is_exempt_sandbox_unit("tailscaled"));
    assert!(is_exempt_sandbox_unit("tailscale.service"));
    assert!(is_exempt_sandbox_unit("tailscaled.service"));
    assert!(is_exempt_sandbox_unit("wg-quick@wg0.service"));
    assert!(is_exempt_sandbox_unit("wireguard.service"));
    assert!(!is_exempt_sandbox_unit("sonarr.service"));
}

#[test]
fn production_hosts_lock_uses_protected_runtime_directory() {
    assert_eq!(
        resolve_hosts_lock_path(Path::new("/etc/hosts")),
        Path::new("/run/aetherflow/hosts.lock")
    );
    assert_eq!(
        resolve_hosts_lock_path(Path::new("/tmp/fixture/hosts")),
        Path::new("/tmp/fixture/hosts.lock")
    );
}

#[cfg(unix)]
#[test]
fn hosts_reconciliation_rejects_a_symlink_lock_without_changing_hosts() {
    let scratch_dir = env::temp_dir().join(format!("af-hosts-lock-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");
    let lock_file = scratch_dir.join("hosts.lock");
    let unrelated_file = scratch_dir.join("unrelated");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    fs::write(&unrelated_file, "preserve me").unwrap();
    std::os::unix::fs::symlink(&unrelated_file, &lock_file).unwrap();
    assert!(reconcile_hosts_file_at_path(
        &hosts_file,
        &lock_file,
        &["app.aether.local".into()],
        "127.0.0.1"
    )
    .is_err());
    assert_eq!(
        fs::read_to_string(&hosts_file).unwrap(),
        "127.0.0.1 localhost\n"
    );
    assert_eq!(fs::read_to_string(&unrelated_file).unwrap(), "preserve me");
    fs::remove_dir_all(&scratch_dir).unwrap();
}

#[test]
fn test_hosts_file_preserves_unrelated_host_aliases_and_multi_app() {
    let scratch_dir = env::temp_dir().join(format!("af-hosts-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");

    // Initial hosts file with unrelated alias on the same line as appa.aether.local
    let initial_content = "127.0.0.1 localhost\n192.168.1.10 server.lan appa.aether.local\n";
    fs::write(&hosts_file, initial_content).unwrap();

    // 1. Update with appb.aether.local: both apps and server.lan must be preserved!
    update_hosts_file_at_path(&hosts_file, &["appb.aether.local".to_string()], false).unwrap();
    let content_after_appb = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_appb.contains("server.lan"));
    assert!(content_after_appb.contains("appb.aether.local"));

    // 2. Remove appa.aether.local: server.lan must remain!
    update_hosts_file_at_path(&hosts_file, &["appa.aether.local".to_string()], true).unwrap();
    let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_remove.contains("192.168.1.10\tserver.lan"));
    assert!(!content_after_remove.contains("appa.aether.local"));
    assert!(content_after_remove.contains("appb.aether.local"));

    // 3. Reconcile with authoritative list [appc.aether.local]:
    // server.lan must still remain, appb pruned, appc added.
    let lock_file = scratch_dir.join("hosts.lock");
    reconcile_hosts_file_at_path(
        &hosts_file,
        &lock_file,
        &["appc.aether.local".to_string()],
        "127.0.0.1",
    )
    .unwrap();
    let content_after_reconcile = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_reconcile.contains("192.168.1.10\tserver.lan"));
    assert!(!content_after_reconcile.contains("appb.aether.local"));
    assert!(content_after_reconcile.contains("appc.aether.local"));

    let _ = fs::remove_dir_all(&scratch_dir);
}

#[test]
fn test_hosts_managed_block_preserves_comments_and_multi_alias_lines() {
    let _env_guard = ENV_TEST_MUTEX.blocking_lock();
    let scratch_dir =
        env::temp_dir().join(format!("af-hosts-comment-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");
    let lock_file = scratch_dir.join("hosts.lock");

    // Initial hosts file containing managed block with internal comments and multi-alias lines
    let initial = "\
127.0.0.1 localhost
# BEGIN AETHERFLOW MANAGED BLOCK
# Internal managed note
10.0.0.5 app1.aether.local custom.lan # note
127.0.0.1 app2.aether.local
# END AETHERFLOW MANAGED BLOCK
";
    fs::write(&hosts_file, initial).unwrap();

    // 1. Update: add app3.aether.local
    update_hosts_file_at_path(&hosts_file, &["app3.aether.local".to_string()], false).unwrap();
    let content_after_update = fs::read_to_string(&hosts_file).unwrap();
    assert!(
        content_after_update.contains("# Internal managed note"),
        "managed comments must be preserved"
    );
    assert!(
        content_after_update.contains("10.0.0.5\tcustom.lan # note"),
        "non-aether alias must be preserved with comment"
    );
    assert!(content_after_update.contains("app1.aether.local"));
    assert!(content_after_update.contains("app2.aether.local"));
    assert!(content_after_update.contains("app3.aether.local"));

    // 2. Remove: remove app1.aether.local
    update_hosts_file_at_path(&hosts_file, &["app1.aether.local".to_string()], true).unwrap();
    let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_remove.contains("# Internal managed note"));
    assert!(content_after_remove.contains("10.0.0.5\tcustom.lan # note"));
    assert!(!content_after_remove.contains("app1.aether.local"));
    assert!(content_after_remove.contains("app2.aether.local"));
    assert!(content_after_remove.contains("app3.aether.local"));

    // 3. Reconcile: authoritative list is [app4.aether.local]
    reconcile_hosts_file_at_path(
        &hosts_file,
        &lock_file,
        &["app4.aether.local".to_string()],
        "127.0.0.1",
    )
    .unwrap();
    let content_after_reconcile = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_reconcile.contains("# Internal managed note"));
    assert!(content_after_reconcile.contains("10.0.0.5\tcustom.lan # note"));
    assert!(!content_after_reconcile.contains("app2.aether.local"));
    assert!(!content_after_reconcile.contains("app3.aether.local"));
    assert!(content_after_reconcile.contains("127.0.0.1\tapp4.aether.local"));

    // 4. CLI reconcile test: empty domains clears managed entries while preserving comments & custom aliases
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    fs::create_dir_all(&pihole_dir).unwrap();
    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
    env::set_var(
        "AETHERFLOW_DNSMASQ_DIR",
        dnsmasq_dir.to_string_lossy().as_ref(),
    );
    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );

    let cli_res = run_hosts_cli(&["reconcile".to_string(), "127.0.0.1".to_string()]);
    assert!(cli_res.is_ok());
    let content_after_cli_empty = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_cli_empty.contains("# Internal managed note"));
    assert!(content_after_cli_empty.contains("10.0.0.5\tcustom.lan # note"));
    assert!(!content_after_cli_empty.contains("app4.aether.local"));

    // Check dnsmasq and pihole files were written
    assert!(dnsmasq_dir.join("aetherflow.conf").exists());
    assert!(pihole_dir.join("custom.list").exists());

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[test]
fn test_hosts_ip_validation_rejects_injections_and_invalid_ips() {
    let scratch_dir = env::temp_dir().join(format!("af-hosts-ip-val-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");
    let lock_file = scratch_dir.join("hosts.lock");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    let domains = vec!["sonarr.aether.local".to_string()];

    let injection_ip = "127.0.0.1\n10.0.0.1 injected.host";
    let invalid_ip = "not-an-ip";
    let leading_space_ip = " 127.0.0.1";
    let trailing_space_ip = "127.0.0.1 ";
    let tab_ip = "\t127.0.0.1\t";

    for bad_ip in [
        injection_ip,
        invalid_ip,
        leading_space_ip,
        trailing_space_ip,
        tab_ip,
    ] {
        assert!(validate_hosts_ip(bad_ip).is_err());
        // Verify update_hosts_file_with_ip_at_path and reconcile_hosts_file_at_path reject invalid IPs
        assert!(update_hosts_file_with_ip_at_path(
            &hosts_file,
            &lock_file,
            &domains,
            bad_ip,
            false
        )
        .is_err());
        assert!(reconcile_hosts_file_at_path(&hosts_file, &lock_file, &domains, bad_ip).is_err());

        // Verify modify_hosts_file_at_path directly
        assert!(modify_hosts_file_at_path(
            &hosts_file,
            &lock_file,
            &domains,
            HostsModifyAction::Update { ip: bad_ip }
        )
        .is_err());
        assert!(modify_hosts_file_at_path(
            &hosts_file,
            &lock_file,
            &domains,
            HostsModifyAction::Reconcile { ip: bad_ip }
        )
        .is_err());

        // Verify sync_dns_provider_files and execute_hosts_cli_command
        assert!(sync_dns_provider_files(bad_ip, &domains).is_err());
        assert!(execute_hosts_cli_command("update", bad_ip, &domains).is_err());
        assert!(execute_hosts_cli_command("reconcile", bad_ip, &domains).is_err());
    }

    let _ = fs::remove_dir_all(&scratch_dir);
}

#[test]
fn test_hosts_removes_or_updates_last_alias_preserves_standalone_comment() {
    let scratch_dir = env::temp_dir().join(format!(
        "af-hosts-comment-preserve-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");
    let lock_file = scratch_dir.join("hosts.lock");

    // 1. Direct filter_hosts_line test
    let line = "127.0.0.1 sonarr.aether.local # admin note";
    let filtered = filter_hosts_line(line, |host| host == "sonarr.aether.local");
    assert_eq!(filtered, Some("# admin note".to_string()));

    // 2. Removing last alias on an outside-block line preserves # admin note as standalone comment line
    let initial_remove = "127.0.0.1 sonarr.aether.local # admin note\n";
    fs::write(&hosts_file, initial_remove).unwrap();
    update_hosts_file_with_ip_at_path(
        &hosts_file,
        &lock_file,
        &["sonarr.aether.local".to_string()],
        "127.0.0.1",
        true,
    )
    .unwrap();
    let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
    assert!(
        content_after_remove.contains("# admin note"),
        "standalone comment must be preserved on removal: {}",
        content_after_remove
    );
    assert!(!content_after_remove.contains("sonarr.aether.local"));
    assert!(content_after_remove
        .lines()
        .any(|l| l.trim() == "# admin note"));

    // 3. Updating last alias on an outside-block line preserves # admin note as standalone comment line
    let initial_update = "127.0.0.1 sonarr.aether.local # admin note\n";
    fs::write(&hosts_file, initial_update).unwrap();
    update_hosts_file_with_ip_at_path(
        &hosts_file,
        &lock_file,
        &["sonarr.aether.local".to_string()],
        "10.0.0.2",
        false,
    )
    .unwrap();
    let content_after_update = fs::read_to_string(&hosts_file).unwrap();
    assert!(
        content_after_update.contains("# admin note"),
        "standalone comment must be preserved on update: {}",
        content_after_update
    );
    assert!(content_after_update
        .lines()
        .any(|l| l.trim() == "# admin note"));
    assert!(content_after_update.contains("10.0.0.2\tsonarr.aether.local"));

    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_pihole_custom_list_preserves_unmanaged_records_aliases_and_comments() {
    let initial_content = "\
# Pi-hole Custom Domain List
192.168.1.1 router.home
192.168.1.50 nas.home.lan
192.168.1.10 app.aether.local keep.lan # custom note
192.168.1.20 oldapp.aether.local # aetherflow-managed
192.168.1.30 sonarr.aether.local # user note
";
    let reconciled = reconcile_pihole_custom_list_content(
        initial_content,
        "192.168.1.200",
        &[
            "sonarr.aether.local".to_string(),
            "radarr.aether.local".to_string(),
        ],
        true,
    );

    // Header and unmanaged records preserved
    assert!(reconciled.contains("# Pi-hole Custom Domain List"));
    assert!(reconciled.contains("192.168.1.1 router.home"));
    assert!(reconciled.contains("192.168.1.50 nas.home.lan"));

    // Multi-alias line with unmanaged hostname keep.lan preserved intact without app.aether.local
    assert!(reconciled.contains("192.168.1.10 keep.lan # custom note"));
    assert!(!reconciled.contains("192.168.1.10 app.aether.local"));

    // Multi-alias line with # aetherflow-managed tag preserves unmanaged aliases
    let managed_multi_line = "192.168.1.10 old.aether.local unrelated.lan # aetherflow-managed\n";
    let reconciled_multi = reconcile_pihole_custom_list_content(
        managed_multi_line,
        "192.168.1.200",
        &["sonarr.aether.local".to_string()],
        true,
    );
    assert!(
        reconciled_multi.contains("192.168.1.10 unrelated.lan"),
        "unrelated.lan must be preserved even if line has # aetherflow-managed: {}",
        reconciled_multi
    );
    assert!(
        !reconciled_multi.contains("old.aether.local"),
        "old.aether.local must be dropped on reconcile: {}",
        reconciled_multi
    );
    assert!(reconciled_multi.contains("192.168.1.200 sonarr.aether.local # aetherflow-managed"));

    // Old managed domain dropped on reconcile
    assert!(!reconciled.contains("oldapp.aether.local"));

    // Single-domain user note preserved with updated IP
    assert!(reconciled.contains("192.168.1.200 sonarr.aether.local # user note"));

    // Newly added domain appended
    assert!(reconciled.contains("192.168.1.200 radarr.aether.local # aetherflow-managed"));

    // Now test removal
    let after_removal =
        remove_pihole_custom_list_content(&reconciled, &["sonarr.aether.local".to_string()]);
    assert!(!after_removal.contains("sonarr.aether.local"));
    assert!(after_removal.contains("192.168.1.1 router.home"));
    assert!(after_removal.contains("192.168.1.10 keep.lan # custom note"));
    assert!(after_removal.contains("192.168.1.200 radarr.aether.local # aetherflow-managed"));

    // Test removing one alias from multi-alias line
    let multi_alias = "192.168.1.99 host1.lan host2.lan host3.lan # my comment\n";
    let removed_alias = remove_pihole_custom_list_content(multi_alias, &["host2.lan".to_string()]);
    assert_eq!(
        removed_alias.trim(),
        "192.168.1.99 host1.lan host3.lan # my comment"
    );
}

#[tokio::test]
async fn test_pihole_custom_list_invalid_utf8_fails_closed_and_leaves_file_intact() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let scratch_dir = env::temp_dir().join(format!("af-pihole-utf8-test-{}", uuid::Uuid::new_v4()));
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&pihole_dir).unwrap();

    let custom_list = pihole_dir.join("custom.list");
    let invalid_bytes = vec![0xff, 0xfe, b'a', b'b', b'c'];
    fs::write(&custom_list, &invalid_bytes).unwrap();

    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );

    // Test sync fails closed
    let sync_res = sync_dns_provider_files_with_mode(
        "192.168.1.100",
        &["sonarr.aether.local".to_string()],
        true,
    );
    assert!(sync_res.is_err(), "sync must fail on invalid UTF-8");
    // Verify file is untouched on disk
    let on_disk_after_sync = fs::read(&custom_list).unwrap();
    assert_eq!(on_disk_after_sync, invalid_bytes);

    // Test remove fails closed
    let rm_res = remove_dns_provider_files(&["sonarr.aether.local".to_string()]);
    assert!(rm_res.is_err(), "remove must fail on invalid UTF-8");
    // Verify file is untouched on disk
    let on_disk_after_rm = fs::read(&custom_list).unwrap();
    assert_eq!(on_disk_after_rm, invalid_bytes);

    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_runner_hosts_handler_separates_loopback_hosts_from_provider_lan_ip_and_public_domains(
) {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let scratch_dir = env::temp_dir().join(format!("af-runner-sep-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();

    let hosts_file = scratch_dir.join("hosts");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&pihole_dir).unwrap();

    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
    env::set_var(
        "AETHERFLOW_DNSMASQ_DIR",
        dnsmasq_dir.to_string_lossy().as_ref(),
    );
    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );

    let req = HostsUpdateRequest {
        action: "reconcile".to_string(),
        ip: "127.0.0.1".to_string(),
        domains: vec!["sonarr.aether.local".to_string()],
        provider_ip: Some("192.168.1.50".to_string()),
        provider_domains: Some(vec![
            "sonarr.aether.local".to_string(),
            "media.example.com".to_string(),
        ]),
        ..Default::default()
    };

    let resp = apply_hosts_update(req).await.unwrap();
    assert!(resp.success);
    assert_eq!(resp.output, "hosts reconciled");

    // 1. /etc/hosts must contain 127.0.0.1 sonarr.aether.local only
    let hosts_content = fs::read_to_string(&hosts_file).unwrap();
    assert!(hosts_content.contains("127.0.0.1\tsonarr.aether.local"));
    assert!(!hosts_content.contains("192.168.1.50"));
    assert!(!hosts_content.contains("media.example.com"));

    // 2. dnsmasq must contain 192.168.1.50 and both domains, but not 127.0.0.1
    let dnsmasq_conf = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
    assert!(dnsmasq_conf.contains("address=/sonarr.aether.local/192.168.1.50"));
    assert!(dnsmasq_conf.contains("address=/media.example.com/192.168.1.50"));
    assert!(!dnsmasq_conf.contains("127.0.0.1"));

    // 3. Pi-hole custom.list must contain 192.168.1.50 and both domains, but not 127.0.0.1
    let pihole_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(pihole_list.contains("192.168.1.50 sonarr.aether.local # aetherflow-managed"));
    assert!(pihole_list.contains("192.168.1.50 media.example.com # aetherflow-managed"));
    assert!(!pihole_list.contains("127.0.0.1"));

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_hosts_cli_remove_clears_providers_and_propagates_errors() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let scratch_dir = env::temp_dir().join(format!("af-cli-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();

    let hosts_file = scratch_dir.join("hosts");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&pihole_dir).unwrap();

    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
    env::set_var(
        "AETHERFLOW_DNSMASQ_DIR",
        dnsmasq_dir.to_string_lossy().as_ref(),
    );
    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );

    // 1. Add entry
    let add_res = run_hosts_cli(&[
        "update".to_string(),
        "10.0.0.50".to_string(),
        "sonarr.aether.local".to_string(),
    ]);
    assert!(add_res.is_ok(), "{:?}", add_res);

    let hosts_after_add = fs::read_to_string(&hosts_file).unwrap();
    assert!(hosts_after_add.contains("sonarr.aether.local"));
    let dnsmasq_after_add = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
    assert!(dnsmasq_after_add.contains("sonarr.aether.local"));
    let pihole_after_add = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(pihole_after_add.contains("sonarr.aether.local"));

    // 2. Remove entry via CLI
    let rm_res = run_hosts_cli(&["remove".to_string(), "sonarr.aether.local".to_string()]);
    assert!(rm_res.is_ok(), "{:?}", rm_res);

    let hosts_after_rm = fs::read_to_string(&hosts_file).unwrap();
    assert!(!hosts_after_rm.contains("sonarr.aether.local"));
    let dnsmasq_after_rm = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
    assert!(!dnsmasq_after_rm.contains("sonarr.aether.local"));
    let pihole_after_rm = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(!pihole_after_rm.contains("sonarr.aether.local"));

    // 3. Provider error propagation: write to read-only dir
    let ro_dir = scratch_dir.join("ro_dir");
    fs::create_dir_all(&ro_dir).unwrap();
    fs::write(
        ro_dir.join("custom.list"),
        "10.0.0.50 testfail.aether.local\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o444));
        env::set_var("AETHERFLOW_PIHOLE_DIR", ro_dir.to_string_lossy().as_ref());
        let err_res = run_hosts_cli(&[
            "update".to_string(),
            "10.0.0.50".to_string(),
            "testfail.aether.local".to_string(),
        ]);
        assert!(err_res.is_err(), "provider sync error must be propagated");

        let err_rm = run_hosts_cli(&["remove".to_string(), "testfail.aether.local".to_string()]);
        assert!(err_rm.is_err(), "remove provider error must be propagated");
        let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755));
    }

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[test]
fn canonical_config_candidates_prioritize_repo_config_and_isolate_legacy_fallback() {
    let candidates = canonical_config_candidates("packages.json");
    let strings: Vec<String> = candidates
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    assert_eq!(strings[0], "config/packages.json");
    assert_eq!(strings[1], "../config/packages.json");
    assert_eq!(strings[2], "../../config/packages.json");
    assert!(
        !strings
            .iter()
            .any(|s| s == "backend/config/packages.json" || s == "../backend/config/packages.json"),
        "dead relative backend/config paths must be removed: {strings:?}"
    );
    let opt_canonical_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/current/config/packages.json")
        .unwrap();
    let opt_root_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/config/packages.json")
        .unwrap();
    let legacy_curr_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/current/backend/config/packages.json")
        .unwrap();
    let legacy_root_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/backend/config/packages.json")
        .unwrap();
    assert!(opt_canonical_idx < opt_root_idx);
    assert!(opt_root_idx < legacy_curr_idx);
    assert!(legacy_curr_idx < legacy_root_idx);
    let root = Path::new("/disposable-aetherflow");
    assert_eq!(
        installed_config_candidates(root, "packages.json").to_vec(),
        strings[opt_canonical_idx..]
            .iter()
            .map(|path| root.join(path.trim_start_matches('/')))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn load_runner_config_or_embedded_prefers_canonical_over_legacy_relative() {
    struct CwdRestore(PathBuf);
    impl Drop for CwdRestore {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.0);
        }
    }

    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let _cwd_guard = CwdRestore(env::current_dir().unwrap());
    let prev_env = env::var_os("AETHERFLOW_TEST_CFG_PATH");
    env::remove_var("AETHERFLOW_TEST_CFG_PATH");

    let scratch = env::temp_dir().join(format!("af-runner-cfg-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(scratch.join("backend/config")).unwrap();
    fs::write(
        scratch.join("backend/config/test_only_cfg.json"),
        r#"{"source":"legacy-relative"}"#,
    )
    .unwrap();
    env::set_current_dir(&scratch).unwrap();

    // Relative backend/config/ must be ignored in favor of embedded fallback when canonical config/ is absent.
    let without_canonical = try_load_runner_config_or_embedded(
        "AETHERFLOW_TEST_CFG_PATH",
        "test_only_cfg.json",
        r#"{"source":"embedded"}"#,
    )
    .unwrap();
    assert_eq!(without_canonical, r#"{"source":"embedded"}"#);

    // Once canonical config/ exists, it wins immediately.
    fs::create_dir_all(scratch.join("config")).unwrap();
    fs::write(
        scratch.join("config/test_only_cfg.json"),
        r#"{"source":"canonical"}"#,
    )
    .unwrap();
    let with_canonical = try_load_runner_config_or_embedded(
        "AETHERFLOW_TEST_CFG_PATH",
        "test_only_cfg.json",
        r#"{"source":"embedded"}"#,
    )
    .unwrap();
    assert_eq!(with_canonical, r#"{"source":"canonical"}"#);

    // Symlinked config candidate must fail closed instead of silently falling back to embedded.
    #[cfg(unix)]
    {
        let link_path = scratch.join("symlink_cfg.json");
        std::os::unix::fs::symlink(scratch.join("config/test_only_cfg.json"), &link_path).unwrap();
        env::set_var("AETHERFLOW_TEST_CFG_PATH", &link_path);
        let err = try_load_runner_config_or_embedded(
            "AETHERFLOW_TEST_CFG_PATH",
            "test_only_cfg.json",
            r#"{"source":"embedded"}"#,
        )
        .expect_err("symlinked config override must fail closed");
        let err_msg = format!("{err:#}");
        assert!(
            err_msg.contains("Failed to open config")
                || err_msg.contains("ELOOP")
                || err_msg.contains("Too many levels"),
            "unexpected symlink error: {err_msg}"
        );
        env::remove_var("AETHERFLOW_TEST_CFG_PATH");
    }

    if let Some(val) = prev_env {
        env::set_var("AETHERFLOW_TEST_CFG_PATH", val);
    }
    drop(_cwd_guard);
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn test_librespeed_sandbox_dropin_preserves_protect_home_yes_and_minimal_rw_paths() {
    let rendered = render_systemd_sandbox_dropin(
        "native",
        "librespeed.service",
        &["/opt/librespeed".to_string()],
    );
    assert!(
        rendered.contains("\nProtectHome=yes\n"),
        "librespeed drop-in must preserve ProtectHome=yes, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("ProtectHome=read-only"),
        "librespeed drop-in must not downgrade ProtectHome to read-only"
    );
    assert!(
        rendered.contains("\nReadWritePaths=/opt/librespeed\n")
            || rendered.contains("\nReadWritePaths=-/opt/librespeed\n"),
        "expected confined /opt/librespeed ReadWritePaths, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("/home/"),
        "librespeed drop-in must not expose /home paths, got:\n{rendered}"
    );
}

#[tokio::test]
async fn authorize_runner_peer_credentials_is_thread_safe_under_concurrent_load() {
    let mut handles = Vec::new();
    for tid in 0..8usize {
        handles.push(tokio::task::spawn_blocking(move || {
            for iter in 0..50u32 {
                assert!(authorize_runner_peer_credentials(0, 0, "/v1/health").is_ok());
                let denied = authorize_runner_peer_credentials(
                    60_000 + tid as u32 * 100 + iter,
                    65534,
                    "/v1/ingress/vhost",
                );
                assert!(denied.is_err());
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn is_runner_available_requires_unix_socket_and_rejects_regular_files() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
    let scratch = PathBuf::from("/tmp").join(format!(
        "af-sock-test-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    ));
    fs::create_dir_all(&scratch).unwrap();

    let reg_file = scratch.join("stale.sock");
    fs::write(&reg_file, b"stale").unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &reg_file);
    assert!(
        !is_runner_available(),
        "regular file must NOT be reported as an available runner socket"
    );

    let dir_path = scratch.join("dir.sock");
    fs::create_dir_all(&dir_path).unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &dir_path);
    assert!(
        !is_runner_available(),
        "directory must NOT be reported as an available runner socket"
    );

    let real_sock = scratch.join("real.sock");
    let _listener = tokio::net::UnixListener::bind(&real_sock).unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &real_sock);
    assert!(
        is_runner_available(),
        "real UnixListener socket must be reported as available"
    );

    match prev_sock {
        Some(v) => env::set_var("AETHERFLOW_RUNNER_SOCK", v),
        None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn sandbox_dropin_writes_only_canonical_10_conf_removes_legacy_and_propagates_errors() {
    let scratch = env::temp_dir().join(format!("af-sandbox-unit-{}", uuid::Uuid::new_v4()));
    let dropin_dir = scratch.join("sonarr.service.d");
    fs::create_dir_all(&dropin_dir).unwrap();
    let legacy = dropin_dir.join("aetherflow-sandbox.conf");
    let canonical = dropin_dir.join("10-aetherflow-sandbox.conf");
    let unrelated = dropin_dir.join("local-policy.conf");
    fs::write(&legacy, "stale legacy content\n").unwrap();
    fs::write(&unrelated, "keep-policy\n").unwrap();

    apply_sandbox_dropins_in_dir(
        &scratch,
        &["sonarr.service".to_string()],
        "native",
        &["/var/lib/sonarr".to_string()],
    )
    .unwrap();

    assert!(canonical.is_file(), "10-aetherflow-sandbox.conf must exist");
    assert!(
        !legacy.exists(),
        "legacy aetherflow-sandbox.conf must be removed"
    );
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "keep-policy\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&canonical).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    // Real filesystem write errors must propagate instead of being swallowed.
    #[cfg(unix)]
    if unsafe { libc::geteuid() != 0 } {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dropin_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let err = apply_sandbox_dropins_in_dir(
            &scratch,
            &["sonarr.service".to_string()],
            "native",
            &["/var/lib/sonarr".to_string()],
        );
        let _ = fs::set_permissions(&dropin_dir, fs::Permissions::from_mode(0o755));
        assert!(err.is_err(), "unwritable drop-in directory must return Err");
    }

    let _ = fs::remove_dir_all(&scratch);
}

#[cfg(unix)]
#[tokio::test]
async fn ingress_vhost_validates_rejects_symlinks_and_rolls_back_on_configtest_failure() {
    let scratch = env::temp_dir().join(format!("af-vhost-{}", uuid::Uuid::new_v4()));
    let available = scratch.join("sites-available");
    let enabled = scratch.join("sites-enabled");
    let req = RunnerApacheVhostRequest {
        app_name: "sonarr".to_string(),
        listen_port: 8989,
        internal_domain: Some("sonarr.aether.local".to_string()),
        public_domain: Some("sonarr.example.com".to_string()),
        external_access_enabled: true,
        ..Default::default()
    };
    for app_name in ["", "../evil", "Sonarr", "unknown-ingress-app"] {
        assert!(validate_ingress_vhost_request(&RunnerApacheVhostRequest {
            app_name: app_name.to_string(),
            ..req.clone()
        })
        .is_err());
    }
    for domain in [
        "bad.example\n",
        "bad.-example.com",
        "a..example.com",
        "name.example\"",
    ] {
        assert!(validate_ingress_vhost_request(&RunnerApacheVhostRequest {
            public_domain: Some(domain.to_string()),
            ..req.clone()
        })
        .is_err());
    }
    for port in [0, 65536, -1] {
        assert!(validate_ingress_vhost_request(&RunnerApacheVhostRequest {
            listen_port: port,
            ..req.clone()
        })
        .is_err());
    }
    apply_ingress_vhost_with_hooks(&req, &scratch, || async { Ok(()) }, || async { Ok(()) })
        .await
        .unwrap();
    let internal = available.join("aetherflow-app-sonarr.conf");
    let external = available.join("aetherflow-ext-sonarr.conf");
    let stale = available.join("aetherflow-ext-sonarr-le-ssl.conf");
    let stale_link = enabled.join("aetherflow-ext-sonarr-le-ssl.conf");
    let internal_before = fs::read_to_string(&internal).unwrap();
    let external_before = fs::read_to_string(&external).unwrap();
    assert!(internal_before.contains("Require ip 127.0.0.0/8 ::1"));
    assert!(internal_before.contains("RewriteRule ^ - [F,L]"));
    assert!(external_before.contains("ServerName sonarr.example.com"));
    assert_eq!(
        fs::read_link(enabled.join("aetherflow-app-sonarr.conf")).unwrap(),
        Path::new("../sites-available/aetherflow-app-sonarr.conf")
    );
    fs::write(&stale, "previous SSL config").unwrap();
    std::os::unix::fs::symlink(
        "../sites-available/aetherflow-ext-sonarr-le-ssl.conf",
        &stale_link,
    )
    .unwrap();
    let updated = RunnerApacheVhostRequest {
        listen_port: 18989,
        reload_apache: true,
        ..req.clone()
    };
    let err = apply_ingress_vhost_with_hooks(
        &updated,
        &scratch,
        || async { anyhow::bail!("apache syntax error") },
        || async { Ok(()) },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("apache syntax error"));
    let err = apply_ingress_vhost_with_hooks(
        &updated,
        &scratch,
        || async { Ok(()) },
        || async { anyhow::bail!("apache reload failed") },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("apache reload failed"));
    assert_eq!(fs::read_to_string(&internal).unwrap(), internal_before);
    assert_eq!(fs::read_to_string(&external).unwrap(), external_before);
    assert_eq!(fs::read_to_string(&stale).unwrap(), "previous SSL config");
    assert!(fs::symlink_metadata(&stale_link)
        .unwrap()
        .file_type()
        .is_symlink());

    let victim = scratch.join("victim");
    fs::write(&victim, "keep").unwrap();
    fs::remove_file(&external).unwrap();
    std::os::unix::fs::symlink(&victim, &external).unwrap();
    assert!(apply_ingress_vhost_with_hooks(
        &updated,
        &scratch,
        || async { Ok(()) },
        || async { Ok(()) }
    )
    .await
    .is_err());
    assert_eq!(fs::read_to_string(victim).unwrap(), "keep");
    fs::remove_file(&external).unwrap();
    apply_ingress_vhost_with_hooks(&updated, &scratch, || async { Ok(()) }, || async { Ok(()) })
        .await
        .unwrap();
    assert!(!stale.exists());
    assert!(fs::symlink_metadata(&stale_link).is_err());

    let remove = RunnerApacheVhostRequest {
        app_name: req.app_name,
        remove_only: true,
        ..Default::default()
    };
    apply_ingress_vhost_with_hooks(&remove, &scratch, || async { Ok(()) }, || async { Ok(()) })
        .await
        .unwrap();
    assert!(!internal.exists());
    assert!(!external.exists());
    fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn confined_provider_preserves_permissions_and_refuses_symlinks_hardlinks_and_fifos() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = env::temp_dir().join(format!("af-confined-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let custom = root.join("custom.list");
    fs::write(&custom, "old").unwrap();
    fs::set_permissions(&custom, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::metadata(&custom).unwrap();
    write_dns_provider_text(&custom, "new", true).unwrap();
    let updated = fs::metadata(&custom).unwrap();
    assert_eq!(updated.mode() & 0o777, 0o600);
    assert_eq!(
        (updated.uid(), updated.gid()),
        (original.uid(), original.gid())
    );

    let alias = root.join("alias");
    std::os::unix::fs::symlink(&custom, &alias).unwrap();
    assert!(read_dns_provider_text(&alias, true).is_err());
    assert!(write_dns_provider_text(&alias, "wrong", true).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&custom, &alias).unwrap();
    assert!(write_dns_provider_text(&custom, "wrong", true).is_err());
    fs::remove_file(&alias).unwrap();
    let fifo = root.join("fifo");
    assert_eq!(
        unsafe {
            libc::mkfifo(
                job_receipts::c_name(fifo.as_os_str()).unwrap().as_ptr(),
                0o600,
            )
        },
        0
    );
    assert!(read_dns_provider_text(&fifo, true).is_err());
    let parent_alias = root.join("parent-alias");
    std::os::unix::fs::symlink(&root, &parent_alias).unwrap();
    assert!(dns_provider_directory_exists(&parent_alias, true).is_err());
    assert!(write_dns_provider_text(&parent_alias.join("custom.list"), "wrong", true).is_err());
    assert_eq!(fs::read_to_string(custom).unwrap(), "new");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sqlite_probe_uses_a_snapshot_and_rejects_linked_databases() {
    let root = env::temp_dir().join(format!("af-sqlite-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("app.db");
    let logical = Path::new("/var/lib/calibre-web/app.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE settings(config_port INTEGER); INSERT INTO settings VALUES (8084); PRAGMA journal_mode=WAL;").unwrap();
    drop(conn);
    let query = |path: &Path| {
        query_app_metadata_sqlite(
            path,
            logical,
            &[af_models::app_metadata::CALIBRE_WEB_PORT_QUERY],
            std::time::Instant::now() + Duration::from_secs(2),
        )
    };
    assert_eq!(query(&path).as_deref(), Some("8084"));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    let alias = root.join("alias.db");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert_eq!(query(&alias), None);
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    assert_eq!(query(&path), None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_lock_directory_mode_survives_restrictive_creation_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = env::temp_dir().join(format!("af-install-{}", uuid::Uuid::new_v4()));
    let install = root.join("install");
    create_package_lock_directory(&install).unwrap();
    assert_eq!(
        fs::metadata(&install).unwrap().permissions().mode() & 0o777,
        0o750
    );
    fs::set_permissions(&install, fs::Permissions::from_mode(0o550)).unwrap();
    create_package_lock_directory(&install).unwrap();
    assert_eq!(
        fs::metadata(&install).unwrap().permissions().mode() & 0o777,
        0o550
    );
    fs::set_permissions(&install, fs::Permissions::from_mode(0o750)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn release_selector_accepts_both_aliases_and_explicit_engine() {
    let keys = [
        "AETHERFLOW_ENABLE_RUST_RELEASE",
        "AETHERFLOW_USE_RUST_RELEASE",
        "AETHERFLOW_RELEASE_ENGINE",
        "AETHERFLOW_FORCE_BASH_RELEASE",
    ];
    let saved = keys.map(env::var_os);
    for key in keys {
        env::remove_var(key);
    }
    for key in &keys[..3] {
        env::set_var(
            key,
            if key.ends_with("ENGINE") {
                "rust"
            } else {
                "true"
            },
        );
        assert_eq!(
            select_release_engine(),
            ReleaseEngineMode::NativeRustRelease
        );
        env::set_var(keys[3], "1");
        assert_eq!(
            select_release_engine(),
            ReleaseEngineMode::LegacyBashRelease
        );
        env::remove_var(keys[3]);
        env::remove_var(key);
    }
    for (key, value) in keys.into_iter().zip(saved) {
        if let Some(value) = value {
            env::set_var(key, value);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn certbot_sync_rejects_symlinks_and_executes_verified_script_with_timeout() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = env::temp_dir().join(format!("af-certbot-unit-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch).unwrap();

    let real_script = scratch.join("af-certbot-sync");
    fs::write(&real_script, "#!/bin/sh\necho synced-ok\n").unwrap();
    fs::set_permissions(&real_script, fs::Permissions::from_mode(0o755)).unwrap();

    // Symlink must be refused.
    let sym_script = scratch.join("af-certbot-sync-link");
    std::os::unix::fs::symlink(&real_script, &sym_script).unwrap();
    let sym_err = execute_certbot_sync_with_candidates(
        &[sym_script.as_path()],
        false,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(sym_err.to_string().contains("symlink"));

    // Non-root owner rejected when require_root_owner=true (unless running test as root).
    if unsafe { libc::geteuid() != 0 } {
        let owner_err = execute_certbot_sync_with_candidates(
            &[real_script.as_path()],
            true,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(owner_err.to_string().contains("owned by root"));
    }

    // Valid regular executable succeeds.
    let missing = scratch.join("missing");
    let out = execute_certbot_sync_with_candidates(
        &[missing.as_path(), real_script.as_path()],
        false,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(out, "synced-ok");

    // Timeout bounds execution.
    let slow_script = scratch.join("slow-sync");
    fs::write(&slow_script, "#!/bin/sh\nsleep 5\n").unwrap();
    fs::set_permissions(&slow_script, fs::Permissions::from_mode(0o755)).unwrap();
    let timeout_err = execute_certbot_sync_with_candidates(
        &[slow_script.as_path()],
        false,
        Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    assert!(timeout_err.to_string().contains("timed out"));

    let _ = fs::remove_dir_all(&scratch);
}

#[cfg(unix)]
#[tokio::test]
async fn ingress_vhost_router_end_to_end_via_runner_socket() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
    let prev_apache = env::var_os("AETHERFLOW_APACHE_DIR");

    let scratch = PathBuf::from("/tmp").join(format!(
        "af-vhost-e2e-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    ));
    fs::create_dir_all(&scratch).unwrap();
    let sock_path = scratch.join("runner.sock");
    let apache_dir = scratch.join("apache2");
    fs::create_dir_all(apache_dir.join("sites-available")).unwrap();
    fs::create_dir_all(apache_dir.join("sites-enabled")).unwrap();

    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    env::set_var("AETHERFLOW_APACHE_DIR", &apache_dir);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(
        listener,
        build_runner_router(),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let resp = sync_apache_vhost_via_runner(&RunnerApacheVhostRequest {
        app_name: "sonarr".to_string(),
        listen_port: 8989,
        internal_domain: Some("sonarr.aether.local".to_string()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(resp.success);
    assert!(apache_dir
        .join("sites-available/aetherflow-app-sonarr.conf")
        .is_file());
    assert!(apache_dir
        .join("sites-enabled/aetherflow-app-sonarr.conf")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());

    let disable_resp = sync_apache_vhost_via_runner(&RunnerApacheVhostRequest {
        app_name: "sonarr".to_string(),
        remove_only: true,
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(disable_resp.success);
    assert!(!apache_dir
        .join("sites-available/aetherflow-app-sonarr.conf")
        .exists());

    let _ = shutdown_tx.send(());
    let _ = server.await;
    match prev_sock {
        Some(v) => env::set_var("AETHERFLOW_RUNNER_SOCK", v),
        None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    match prev_apache {
        Some(v) => env::set_var("AETHERFLOW_APACHE_DIR", v),
        None => env::remove_var("AETHERFLOW_APACHE_DIR"),
    }
    let _ = fs::remove_dir_all(&scratch);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a privileged systemd test host"]
fn updater_survives_caller_restart() {
    let status = std::process::Command::new("python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/self_update_systemd_smoke.py"),
        )
        .arg("--test-binary")
        .arg(env::current_exe().unwrap())
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "started by the systemd smoke test"]
async fn self_update_smoke_caller() {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn request(path: &str, payload: Value) -> RunnerResponse {
        let request = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = build_runner_router().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response: RunnerResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parts.status, StatusCode::OK, "{}", response.error);
        assert!(response.success, "{}", response.error);
        response
    }

    let root = PathBuf::from(env::var_os("AF_SELF_UPDATE_SMOKE_ROOT").unwrap());
    assert!(
        root.starts_with("/var/tmp")
            && root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("af-self-update-test-")
    );
    let marker = root.join("admitted");
    if let Ok(unit) = fs::read_to_string(&marker) {
        tokio::time::timeout(Duration::from_secs(15), async {
            while !root.join("worker-complete").is_file() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        let response = request("/v1/self-update/status", json!({"job_unit": unit})).await;
        let status: SelfUpdateJobStatus = serde_json::from_str(&response.output).unwrap();
        assert!(status.completed && status.success && status.exit_code == Some(0));
        fs::write(root.join("verified"), "").unwrap();
    } else {
        fs::write(root.join("caller-pid"), std::process::id().to_string()).unwrap();
        let response = request(
            "/v1/self-update",
            json!({"command": "deploy", "channel": "nightly"}),
        )
        .await;
        let output: Value = serde_json::from_str(&response.output).unwrap();
        let unit = output["job_unit"].as_str().unwrap();
        validate_self_update_job_unit_name(unit).unwrap();
        write_file_atomically_with_mode(&marker, unit.as_bytes(), 0o600).unwrap();
    }
    std::future::pending::<()>().await;
}

#[test]
fn app_metadata_accepts_canonical_service_users() {
    for (path, owner) in [
        ("/opt/Tautulli/config.ini", "tautulli"),
        ("/opt/AdGuardHome/AdGuardHome.yaml", "adguardhome"),
        ("/opt/Ombi/config.json", "ombi"),
        ("/opt/Kavita/appsettings.json", "kavita"),
        ("/etc/paperless.conf", "paperless"),
        ("/etc/paperless.conf", "paperless-ngx"),
        ("/var/www/organizr/api/config/config.php", "www-data"),
        (
            "/home/homeassistant/.homeassistant/configuration.yaml",
            "homeassistant",
        ),
    ] {
        assert!(
            app_metadata_users(Path::new(path)).contains(&owner.to_owned()),
            "{path}"
        );
    }
}

#[test]
fn core_units_cannot_receive_sandbox_dropins() {
    let root = env::temp_dir().join(format!("af-exempt-sandbox-{}", uuid::Uuid::new_v4()));
    for unit in ["aetherflow-api", "aetherflow-runner.service"] {
        assert!(is_exempt_sandbox_unit(unit));
        assert!(render_systemd_sandbox_dropin("native", unit, &[]).is_empty());
        apply_sandbox_dropins_in_dir(&root, &[unit.to_string()], "native", &[]).unwrap();
    }
    assert!(!root.exists());
}

#[test]
fn managed_units_admit_only_the_cataloged_home_assistant_instance() {
    assert!(is_managed_runner_systemd_unit(
        "home-assistant@homeassistant"
    ));
    assert!(is_managed_runner_systemd_unit(
        "home-assistant@homeassistant.service"
    ));
    assert!(!is_managed_runner_systemd_unit(
        "home-assistant@other.service"
    ));
    assert!(!is_managed_runner_systemd_unit(
        "home-assistant@homeassistant.timer"
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn lifecycle_snapshot_routes_store_and_preserve_recovery_via_runner_socket() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let saved_vars: Vec<(&str, Option<std::ffi::OsString>)> = [
        "AETHERFLOW_RUNNER_SOCK",
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_INSTALL_ROOT",
        "AETHERFLOW_RECOVERY_ROOT",
        "AF_RECOVERY_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ]
    .into_iter()
    .map(|k| (k, env::var_os(k)))
    .collect();

    // Short private directory under /var/tmp so UNIX socket path stays well under sun_path limits.
    let base_tmp = if Path::new("/var/tmp").is_dir() {
        PathBuf::from("/var/tmp")
    } else {
        env::temp_dir()
    };
    let scratch = base_tmp.join(format!(
        "af-snap-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    ));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&scratch).unwrap();
    let root = scratch.join("root");
    fs::create_dir_all(&root).unwrap();

    // Seed isolated release config + SQLite reservation DB + live Sonarr data.
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    let job_preserve = "job-preserve-1";
    let job_restore = "job-restore-2";
    conn.execute(
        "INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) \
         VALUES ('sonarr',?1,'update','updating','now',?2,'[\"sonarr.service\"]')",
        rusqlite::params![job_preserve, &owner.id],
    )
    .unwrap();

    let live_dir = root.join("var/lib/sonarr");
    fs::create_dir_all(&live_dir).unwrap();
    let config_file = live_dir.join("config.xml");
    fs::write(&config_file, b"<Config>original-v1</Config>").unwrap();

    let sock_path = scratch.join("r.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    env::set_var("AETHERFLOW_FS_ROOT", &root);
    env::remove_var("AETHERFLOW_INSTALL_ROOT");
    env::remove_var("AETHERFLOW_RECOVERY_ROOT");
    env::remove_var("AF_RECOVERY_ROOT");
    env::remove_var("AETHERFLOW_RELEASE_ROOT");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(
        listener,
        build_runner_router(),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    // 1. Capture over real runner UDS -> backup created under persistent recovery root (0700), not tmp.
    PACKAGE_JOB_ID
        .scope(job_preserve.to_string(), async {
            dispatch_package_lifecycle_snapshot_capture("sonarr", &[])
                .await
                .unwrap();
        })
        .await;

    let recovery_root = root.join("var/backups/aetherflow-recovery");
    assert!(recovery_root.is_dir(), "recovery root must exist");
    assert_eq!(
        fs::symlink_metadata(&recovery_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let preserved_backup =
        package_lifecycle::admitted_lifecycle_snapshot_backup_root("sonarr", job_preserve)
            .expect("admitted snapshot must register its backup_root");
    assert_eq!(preserved_backup.parent(), Some(recovery_root.as_path()));
    assert_eq!(
        fs::symlink_metadata(&preserved_backup)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        !root.join("tmp").exists(),
        "runner snapshot must not create or write into tmp"
    );

    // 2. Discard with preserve_backup=true -> survives runner restart/shutdown on persistent root.
    dispatch_package_lifecycle_snapshot_discard_for_job("sonarr", job_preserve, true)
        .await
        .unwrap();
    assert!(
        preserved_backup.is_dir(),
        "preserved recovery backup must stay on disk after preserve discard"
    );

    // 3. Re-capture on a new job, mutate live state, restore over UDS -> live state restored and backup removed.
    conn.execute(
        "UPDATE package_lifecycle_jobs SET job_id=?1, status='updating' WHERE package_id='sonarr'",
        rusqlite::params![job_restore],
    )
    .unwrap();
    PACKAGE_JOB_ID
        .scope(job_restore.to_string(), async {
            dispatch_package_lifecycle_snapshot_capture("sonarr", &[])
                .await
                .unwrap();
        })
        .await;
    let restore_backup =
        package_lifecycle::admitted_lifecycle_snapshot_backup_root("sonarr", job_restore)
            .expect("second admitted snapshot must register its backup_root");
    assert_eq!(restore_backup.parent(), Some(recovery_root.as_path()));
    fs::write(&config_file, b"<Config>corrupted-v2</Config>").unwrap();
    PACKAGE_JOB_ID
        .scope(job_restore.to_string(), async {
            dispatch_package_lifecycle_snapshot_restore("sonarr")
                .await
                .unwrap();
        })
        .await;
    assert_eq!(
        fs::read(&config_file).unwrap(),
        b"<Config>original-v1</Config>"
    );
    assert!(
        !restore_backup.exists(),
        "ordinary restore must clean up its snapshot backup directory"
    );

    // 4. Shut down runner server -> preserved backup from job 1 still exists outside tmp.
    let _ = shutdown_tx.send(());
    let _ = server.await;
    assert!(
        preserved_backup.is_dir(),
        "preserved recovery backup must survive runner shutdown"
    );

    for (key, prev) in saved_vars {
        match prev {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
    }
    let _ = fs::remove_dir_all(&scratch);
}

#[tokio::test]
async fn rclone_app_metadata_parses_split_port_gui_dropin_and_ignores_env_api_port_as_gui() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let saved_config = env::var_os("AETHERFLOW_CONFIG_ROOT");
    let saved_fs = env::var_os("AETHERFLOW_FS_ROOT");

    let root = env::temp_dir().join(format!("af-rclone-meta-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("etc/systemd/system/rclone.service.d")).unwrap();
    fs::create_dir_all(root.join("etc/rclone")).unwrap();
    env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    env::set_var("AETHERFLOW_FS_ROOT", &root);

    // 1. Split-port rclone gui --addr + --api-addr parses both ports cleanly.
    fs::write(
        root.join("etc/systemd/system/rclone.service"),
        "[Service]\nExecStart=/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:17005 --api-addr=127.0.0.1:17006 --rc-enable-metrics\n",
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let meta = extract_app_runtime_meta_local_until("rclone", deadline);
    assert_eq!(meta.configured_port, 17005);
    assert_eq!(meta.secondary_port, 17006);
    assert_eq!(
        rclone_secondary_port_update_for_root(Some(&root), 17005, None),
        Some((af_models::RCLONE_RC_API_PORT_ROLE, Some(17006)))
    );

    // 2. Drop-in ExecStart= reset + override supersedes primary unit.
    fs::write(
        root.join("etc/systemd/system/rclone.service.d/override.conf"),
        "[Service]\nExecStart=\nExecStart=/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:17111 --api-addr=127.0.0.1:17112\n",
    )
    .unwrap();
    let meta_dropin = extract_app_runtime_meta_local_until("rclone", deadline);
    assert_eq!(meta_dropin.configured_port, 17111);
    assert_eq!(meta_dropin.secondary_port, 17112);

    // 3. Single-port rcd unit reports configured_port with secondary_port = 0.
    fs::remove_file(root.join("etc/systemd/system/rclone.service.d/override.conf")).unwrap();
    fs::write(
        root.join("etc/systemd/system/rclone.service"),
        "[Service]\nExecStart=/opt/AetherFlow/apps/rclone/rclone rcd --rc-web-gui --rc-addr=127.0.0.1:5572\n",
    )
    .unwrap();
    let meta_rcd = extract_app_runtime_meta_local_until("rclone", deadline);
    assert_eq!(meta_rcd.configured_port, 5572);
    assert_eq!(meta_rcd.secondary_port, 0);
    assert_eq!(
        rclone_secondary_port_update_for_root(Some(&root), 5572, None),
        Some((af_models::RCLONE_RC_API_PORT_ROLE, None))
    );

    // 4. RCLONE_API_PORT in rclone.env never leaks into GUI configured_port when unit is absent.
    fs::remove_file(root.join("etc/systemd/system/rclone.service")).unwrap();
    fs::write(
        root.join("etc/rclone/rclone.env"),
        "RCLONE_RC_USER=admin\nRCLONE_RC_PASS=secret\nRCLONE_API_PORT=17222\n",
    )
    .unwrap();
    let meta_env_only = extract_app_runtime_meta_local_until("rclone", deadline);
    assert_eq!(meta_env_only.configured_port, 0);
    assert_eq!(meta_env_only.secondary_port, 0);

    match saved_config {
        Some(v) => env::set_var("AETHERFLOW_CONFIG_ROOT", v),
        None => env::remove_var("AETHERFLOW_CONFIG_ROOT"),
    }
    match saved_fs {
        Some(v) => env::set_var("AETHERFLOW_FS_ROOT", v),
        None => env::remove_var("AETHERFLOW_FS_ROOT"),
    }
    let _ = fs::remove_dir_all(&root);
}
