use super::*;

#[test]
fn test_resolve_patched_ingress_config_preserves_omitted_fields_and_rejects_port_change() {
    let now = Utc::now();
    let existing = AppIngressConfig {
        app_name: "radarr".to_string(),
        public_domain: "radarr.example.com".to_string(),
        external_access_enabled: true,
        listen_port: 17878,
        tls_enabled: true,
        created_at: now,
        updated_at: now,
    };

    let req_patch: UpdateIngressReq = serde_json::from_value(serde_json::json!({
        "publicDomain": "movies.example.com",
        "externalAccessEnabled": false
    }))
    .unwrap();

    let patched = resolve_patched_ingress_config("radarr", &req_patch, Some(&existing), 7878, now)
        .expect("omitted listenPort and tlsEnabled should be preserved");
    assert_eq!(patched.public_domain, "movies.example.com");
    assert!(!patched.external_access_enabled);
    assert_eq!(patched.listen_port, 17878);
    assert!(patched.tls_enabled);

    let req_port_change: UpdateIngressReq = serde_json::from_value(serde_json::json!({
        "listenPort": 18999
    }))
    .unwrap();
    let err =
        resolve_patched_ingress_config("radarr", &req_port_change, Some(&existing), 7878, now)
            .expect_err("changing listenPort via ingress config must fail closed");
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(err.1, "PORT_RECONFIGURATION_UNSUPPORTED");
}

#[test]
fn test_service_control_rejects_foreign_units_and_unknown_managers() {
    let err =
        validate_service_control_request("sonarr", &control_req("stop", "systemd-unit", "sshd"))
            .expect_err("a package card must not stop an unrelated host unit");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    assert_eq!(err.1, "SERVICE_CONTROL_FORBIDDEN");
    let err = validate_service_control_request(
        "sonarr",
        &control_req("restart", "systemd", "aetherflow-runner"),
    )
    .expect_err("process override must stay within the card");
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    let err =
        validate_service_control_request("sonarr", &control_req("restart", "shell", "sonarr"))
            .expect_err("unknown managers are rejected");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    let err =
        validate_service_control_request("sonarr", &control_req("enable", "systemd", "sonarr"))
            .expect_err("only start/stop/restart are allowed");
    assert_eq!(err.0, StatusCode::BAD_REQUEST);
    let err = validate_service_control_request(
        "AetherFlow Frontend",
        &control_req("restart", "embedded", "aetherflow-frontend"),
    )
    .expect_err("embedded frontend has no daemon");
    assert_eq!(err.1, "EMBEDDED_SERVICE_CONTROL_UNSUPPORTED");
    let err = validate_service_control_request(
        "nextcloud",
        &control_req("restart", "systemd", "nextcloud"),
    )
    .expect_err("shared vhost controls stay blocked");
    assert_eq!(err.1, "SHARED_VHOST_CONTROL_UNSUPPORTED");
    assert_eq!(
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"))
            .unwrap(),
        "sonarr"
    );
}

#[test]
fn test_service_control_is_serialized_with_active_lifecycle_job() {
    // Regression: manual restarts during an update raced the installer's
    // own stop/replace/start sequence.
    let started_at = "hillclimb-control-lock";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: started_at.to_string(),
            package_id: "lidarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 25,
            last_line: String::new(),
            started_at: started_at.into(),
            expected_target_version: None,
        }
    ));
    let err =
        validate_service_control_request("lidarr", &control_req("restart", "systemd", "lidarr"))
            .expect_err("controls must wait for the lifecycle job");
    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(err.1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
    af_services::finish_package_job("lidarr", "update", true, "done", started_at);
    assert_eq!(
        validate_service_control_request("lidarr", &control_req("restart", "systemd", "lidarr"))
            .unwrap(),
        "lidarr"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_url_base_launch_contract_and_gateway_forwarding() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allocated_port = listener.local_addr().unwrap().port();
    let upstream = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut total = 0usize;
                while total < buf.len() {
                    let Ok(read) = stream.read(&mut buf[total..]).await else {
                        return;
                    };
                    if read == 0 {
                        break;
                    }
                    total += read;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&buf[..total]);
                let request_line = raw.lines().next().unwrap_or_default();
                let body = serde_json::json!({ "requestLine": request_line }).to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });

    let (root, connection) = lifecycle_status_fixture();
    let db_path = root.join("backend/data/aetherflow.sqlite");
    std::env::set_var("AF_DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");

    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let fake_systemctl = bin_dir.join("systemctl");
    std::fs::write(
        &fake_systemctl,
        "#!/bin/sh\ncase \"$1\" in show) printf 'ActiveState=active\\nSubState=running\\n';; is-active) echo active;; *) exit 0;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var(
        "PATH",
        format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );

    af_db::init_db().unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch("INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin');")
        .unwrap();
    drop(conn);

    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    let packages = vec![
        af_models::Package {
            name: "sonarr".into(),
            label: "Sonarr".into(),
            lock_file: "/install/.sonarr.lock".into(),
            service_type: "systemd".into(),
            service_name: "sonarr".into(),
            default_port: 8989,
            web_path: "/".into(),
            ..Default::default()
        },
        af_models::Package {
            name: "bazarr".into(),
            label: "Bazarr".into(),
            lock_file: "/install/.bazarr.lock".into(),
            service_type: "systemd".into(),
            service_name: "bazarr".into(),
            default_port: 6767,
            web_path: "/".into(),
            ..Default::default()
        },
    ];
    std::fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);

    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.bazarr.lock"), "installed").unwrap();

    let sonarr_xml = root.join("var/lib/sonarr/config.xml");
    std::fs::create_dir_all(sonarr_xml.parent().unwrap()).unwrap();
    std::fs::write(
        &sonarr_xml,
        format!(
            "<Config><Port>{allocated_port}</Port><UrlBase> /tv/sonarr/ </UrlBase><ApiKey>fixture-key</ApiKey></Config>"
        ),
    )
    .unwrap();

    let bazarr_yaml = root.join("var/lib/bazarr/config/config.yaml");
    std::fs::create_dir_all(bazarr_yaml.parent().unwrap()).unwrap();
    std::fs::write(
        &bazarr_yaml,
        "general:\n  ip: 127.0.0.1\n  port: 16767\n  base_url: /bazarr/../admin\n",
    )
    .unwrap();

    let vhosts = root.join("etc/apache2/sites-enabled");
    std::fs::create_dir_all(&vhosts).unwrap();
    std::fs::write(
        vhosts.join("aetherflow-ext-sonarr.conf"),
        "<VirtualHost *:443>\n    ServerName sonarr.example.test\n    SSLEngine On\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-sonarr.conf"),
        "<VirtualHost *:80>\n    ServerName sonarr.aether.local\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-bazarr.conf"),
        "<VirtualHost *:80>\n    ServerName bazarr.aether.local\n</VirtualHost>\n",
    )
    .unwrap();

    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "sonarr.example.test".into(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: i32::from(allocated_port),
        ..Default::default()
    })
    .unwrap();
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "bazarr".into(),
        external_access_enabled: false,
        tls_enabled: false,
        listen_port: 16767,
        ..Default::default()
    })
    .unwrap();

    af_services::clear_service_status_cache();
    af_services::mutators::clear_app_runtime_meta_cache();
    let (admin_token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let app = build_router().layer(axum::middleware::from_fn(
        crate::middlewares::app_subdomain_proxy_middleware,
    ));

    let fetch_json = |uri: &'static str, token: Option<&str>| {
        let app = app.clone();
        let auth = token.map(|t| format!("Bearer {t}"));
        async move {
            let mut req = axum::http::Request::builder()
                .uri(uri)
                .header(header::HOST, "localhost");
            if let Some(auth) = auth {
                req = req.header(header::AUTHORIZATION, auth);
            }
            let resp = app
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let bytes = axum::body::to_bytes(resp.into_body(), 262_144)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        }
    };

    // 1. Unauthenticated marketplace stays redacted and never exposes retained url_base.
    let redacted = fetch_json("/api/v1/public/marketplace", None).await;
    let redacted_sonarr = redacted
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "sonarr")
        .unwrap();
    assert_eq!(redacted_sonarr["web_path"], "/");
    assert!(redacted_sonarr.get("launch_url").is_none());
    assert!(redacted_sonarr.get("launch_scope").is_none());

    // 2. Both authenticated inventories expose the allocated port, retained URL base,
    //    and safe root fallback for malformed input.
    let authed_market = fetch_json("/api/v1/public/marketplace", Some(&admin_token)).await;
    let market_row = |id: &str| {
        authed_market
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()
    };
    assert_eq!(market_row("sonarr")["active_port"], allocated_port);
    assert_eq!(market_row("sonarr")["web_path"], "/tv/sonarr");
    assert_eq!(market_row("sonarr")["launch_scope"], "public");
    assert_eq!(
        market_row("sonarr")["launch_url"],
        "https://sonarr.example.test/tv/sonarr"
    );
    assert_eq!(market_row("bazarr")["web_path"], "/");
    assert_eq!(market_row("bazarr")["launch_scope"], "internal");
    assert_eq!(
        market_row("bazarr")["launch_url"],
        "http://bazarr.aether.local"
    );

    let authed_services = fetch_json("/api/v1/auth/services", Some(&admin_token)).await;
    assert_eq!(authed_services["Sonarr"]["active_port"], allocated_port);
    assert_eq!(authed_services["Sonarr"]["web_path"], "/tv/sonarr");
    assert_eq!(authed_services["Sonarr"]["launch_scope"], "public");
    assert_eq!(
        authed_services["Sonarr"]["launch_url"],
        "https://sonarr.example.test/tv/sonarr"
    );
    assert_eq!(authed_services["Bazarr"]["web_path"], "/");
    assert_eq!(authed_services["Bazarr"]["launch_scope"], "internal");
    assert_eq!(
        authed_services["Bazarr"]["launch_url"],
        "http://bazarr.aether.local"
    );

    // 3. Launching the resolved URL forwards the retained path to the allocated port.
    let parsed_launch =
        url::Url::parse(market_row("sonarr")["launch_url"].as_str().unwrap()).unwrap();
    assert_eq!(parsed_launch.host_str(), Some("sonarr.example.test"));
    assert_eq!(parsed_launch.path(), "/tv/sonarr");
    for gateway_host in ["sonarr.example.test", "sonarr.aether.local"] {
        let proxied = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(parsed_launch.path())
                    .header(header::HOST, gateway_host)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(proxied.status(), StatusCode::OK, "{gateway_host}");
        let bytes = axum::body::to_bytes(proxied.into_body(), 16_384)
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            observed["requestLine"], "GET /tv/sonarr HTTP/1.1",
            "{gateway_host}"
        );
    }

    // 4. Malformed retained UrlBase falls back safely to root in both inventories and forwarding.
    std::fs::write(
        &sonarr_xml,
        format!(
            "<Config><Port>{allocated_port}</Port><UrlBase>https://evil.example/hijack</UrlBase></Config>"
        ),
    )
    .unwrap();
    af_services::clear_service_status_cache();
    af_services::mutators::clear_app_runtime_meta_cache();

    let fallback_market = fetch_json("/api/v1/public/marketplace", Some(&admin_token)).await;
    let fallback_sonarr = fallback_market
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "sonarr")
        .unwrap();
    assert_eq!(fallback_sonarr["web_path"], "/");
    assert_eq!(fallback_sonarr["launch_url"], "https://sonarr.example.test");

    let fallback_services = fetch_json("/api/v1/auth/services", Some(&admin_token)).await;
    assert_eq!(fallback_services["Sonarr"]["web_path"], "/");
    assert_eq!(
        fallback_services["Sonarr"]["launch_url"],
        "https://sonarr.example.test"
    );

    let fallback_url = url::Url::parse(fallback_sonarr["launch_url"].as_str().unwrap()).unwrap();
    let proxied_root = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(fallback_url.path())
                .header(header::HOST, "sonarr.example.test")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proxied_root.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(proxied_root.into_body(), 16_384)
        .await
        .unwrap();
    let observed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(observed["requestLine"], "GET / HTTP/1.1");

    upstream.abort();
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn routine_service_control_failures_are_sanitized_and_correlated() {
    for timed_out in [false, true] {
        let detail = "SYNTHETIC_PRIVATE_DETAIL /private/review/secret.json";
        let error = if timed_out {
            anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, detail))
                .context("control failed")
        } else {
            anyhow::anyhow!(detail)
        };
        let response = service_control_failure_response(&error, "sonarr", "restart");
        assert_eq!(
            response.status(),
            if timed_out {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!body.to_string().contains("SYNTHETIC_PRIVATE_DETAIL"));
        assert!(!body.to_string().contains("/private/"));
        assert!(uuid::Uuid::parse_str(body["error_id"].as_str().unwrap()).is_ok());
        assert_eq!(
            body["code"],
            if timed_out {
                "SERVICE_CONTROL_TIMEOUT"
            } else {
                "SERVICE_CONTROL_FAILED"
            }
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn services_credentials_require_a_human_admin_for_http_views() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
    std::fs::write(
        root.join("var/lib/sonarr/config.xml"),
        "<Config><ApiKey>synthetic-service-credential</ApiKey><Port>18989</Port></Config>",
    )
    .unwrap();
    let package = af_models::Package {
        name: "sonarr".into(),
        label: "Sonarr".into(),
        service_name: "sonarr".into(),
        lock_file: "/install/.sonarr.lock".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    for (role, plugin, allowed) in [
        ("user", None, false),
        ("plugin", Some("status-reader"), false),
        ("admin", Some("status-reader"), false),
        ("admin", None, true),
    ] {
        let response = get_services(Extension(progress_test_user(role, plugin))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["Sonarr"].get("api_key").is_some(),
            allowed,
            "{role} {plugin:?}"
        );
        assert_eq!(
            body.to_string().contains("synthetic-service-credential"),
            allowed
        );
        assert_eq!(body["Sonarr"]["id"], "sonarr");
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn service_control_fails_closed_for_unreadable_or_unknown_journal() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let unavailable =
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"));
    blocker.execute_batch("ROLLBACK").unwrap();
    blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','unknown-receipt','update','unrecognized-phase','fixture')", []).unwrap();
    let unknown =
        validate_service_control_request("sonarr", &control_req("restart", "systemd", "sonarr"));
    assert_eq!(unavailable.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unknown.unwrap_err().1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_control_contention_returns_409_without_lock_details() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    let socket = short_test_socket_path(&format!(
        "c-{}.sock",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let guard = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    let request = |name: &str| {
        control_service_handler(
            Path(name.to_string()),
            Extension(AuthUser {
                user_id: 1,
                username: "fixture".into(),
                role: "admin".into(),
                jti: "fixture".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            }),
            HeaderMap::new(),
            Json(control_req("restart", "systemd", name)),
        )
    };
    // With no runner, the fallback must fail before invoking a real command.
    let local = request("aetherflow-frontend").await;
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let fake_runner = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                continue;
            } // runner availability probe
            let request = String::from_utf8_lossy(&buffer[..count]);
            let (status, response) = if request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .ends_with("/v1/self-update/status")
            {
                ("200 OK", af_models::RunnerResponse { success: true, output: serde_json::json!({"status":"succeeded","completed":true,"success":true,"job_unit":"","error":"","exit_code":null}).to_string(), error: String::new() })
            } else {
                assert!(request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .ends_with("/v1/systemctl"));
                (
                    "409 Conflict",
                    af_models::RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: "release lock contention at /private/fixture.lock".into(),
                    },
                )
            };
            let body = serde_json::to_string(&response).unwrap();
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
    });
    let remote = request("aetherflow-frontend").await;
    let core = request("aetherflow-api").await;
    fake_runner.abort();
    for response in [local, remote, core] {
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["code"], "LIFECYCLE_BUSY");
        assert!(payload["message"].as_str().unwrap().contains("Retry"));
        assert!(!String::from_utf8_lossy(&body).contains(".lock"));
    }
    drop(guard);
    std::fs::remove_file(socket).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
