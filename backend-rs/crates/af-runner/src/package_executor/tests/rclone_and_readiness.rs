use super::*;

#[test]
fn test_rclone_both_cli_variants_render_app_port_and_metrics() {
    let mut vars = HashMap::new();
    vars.insert("APP_PORT".to_string(), "19572".to_string());
    vars.insert("RCLONE_API_PORT".to_string(), "19573".to_string());
    vars.insert("MASTER_USER".to_string(), "admin".to_string());
    vars.insert("RCLONE_PASS".to_string(), "secret".to_string());

    // 1. Modern variant: rclone rcd
    let rcd_cmd = "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --rc-enable-metrics --config=/etc/rclone/rclone.conf";
    let rcd_rendered = interpolate_template(rcd_cmd, &vars);
    assert!(rcd_rendered.contains("--rc-addr=127.0.0.1:19572"));
    assert!(rcd_rendered.contains("--rc-enable-metrics"));
    assert!(!rcd_rendered.contains("{{APP_PORT}}"));
    assert!(!rcd_rendered.contains("5572"));

    // 2. Legacy fallback variant: rclone gui
    let gui_cmd = "/usr/bin/rclone gui --addr=127.0.0.1:{{APP_PORT}} --api-addr=127.0.0.1:{{RCLONE_API_PORT}} --user=${RCLONE_RC_USER} --pass=${RCLONE_RC_PASS} --enable-metrics --no-open-browser --config=/etc/rclone/rclone.conf";
    let gui_rendered = interpolate_template(gui_cmd, &vars);
    assert!(gui_rendered.contains("--addr=127.0.0.1:19572"));
    assert!(gui_rendered.contains("--api-addr=127.0.0.1:19573"));
    assert!(gui_rendered.contains("--user=${RCLONE_RC_USER}"));
    assert!(gui_rendered.contains("--pass=${RCLONE_RC_PASS}"));
    assert!(gui_rendered.contains("--enable-metrics"));
    assert!(!gui_rendered.contains("{{APP_PORT}}"));
    assert!(!gui_rendered.contains("{{RCLONE_API_PORT}}"));
    assert!(!gui_rendered.contains("5572"));

    // 3. Verify recipe systemd unit template contains {{RCLONE_EXEC_START}} placeholder
    let recipe = get_declarative_recipe("rclone").unwrap();
    let unit_step = recipe
        .install_steps
        .iter()
        .find_map(|s| match s {
            DeclarativeStep::WriteSystemdUnit {
                unit_name,
                content_template,
                ..
            } if unit_name == "rclone.service" => Some(content_template),
            _ => None,
        })
        .expect("rclone.service template must exist");

    // Verify template has {{RCLONE_EXEC_START}} and not hardcoded 5572
    assert!(unit_step.contains("ExecStart={{RCLONE_EXEC_START}}"));
    assert!(!unit_step.contains("127.0.0.1:5572"));

    // Simulate modern rcd substitution on unit template
    let root = create_isolated_test_dir("rclone-cli-mode");
    let rcd_start = detect_rclone_exec_start_for_root(&root);
    fs::remove_dir_all(root).unwrap();
    assert!(rcd_start.contains("{{APP_PORT}}"));
    let rcd_content = unit_step.replace("{{RCLONE_EXEC_START}}", &rcd_start);
    let rendered_rcd = interpolate_template(&rcd_content, &vars);
    assert!(rendered_rcd.contains("127.0.0.1:19572"));
    assert!(!rendered_rcd.contains("{{APP_PORT}}"));
    assert!(!rendered_rcd.contains("5572"));

    let root = create_isolated_test_dir("rclone-gui-mode");
    let binary = root.join("opt/AetherFlow/apps/rclone/rclone");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    for (help, expected_metrics) in [
        (
            "--addr --api-addr --rc-enable-metrics --enable-metrics --no-open-browser",
            "--rc-enable-metrics",
        ),
        (
            "--addr --api-addr --enable-metrics --no-open-browser",
            "--enable-metrics",
        ),
    ] {
        fs::write(
            &binary,
            format!("#!/bin/sh\n[ \"$1\" = gui ] && printf '%s\\n' '{help}'\n"),
        )
        .unwrap();
        fs::set_permissions(&binary, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let detected = detect_rclone_exec_start_for_root(&root);
        let rendered = interpolate_template(
            &unit_step.replace("{{RCLONE_EXEC_START}}", &detected),
            &vars,
        );
        assert!(rendered.contains("/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:19572 --api-addr=127.0.0.1:19573 "));
        assert!(rendered.contains(&format!(" {expected_metrics} ")));
        assert!(rendered.contains("--cache-dir=/var/lib/rclone/cache"));
        assert!(!rendered.contains("--user="));
        assert!(!rendered.contains("--pass="));
    }
    fs::remove_dir_all(root).unwrap();
}


#[tokio::test]
async fn test_rclone_authenticated_wait_for_http_ready_rcd_and_gui() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    let recipe = get_declarative_recipe("rclone").unwrap();

    // 1. Case 1 (rcd mode): /metrics returns 401 unauthenticated, 200 # HELP rclone_version_info with Basic Auth,
    // and /core/version returns 401 unauthenticated, 200 {"version":"1.65.0"} with Basic Auth -> passes
    {
        let server = start_local_http_server(|method, path, auth| {
                let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
                if path == "/metrics" {
                    if auth != Some(expected_auth) {
                        return (401, "text/plain", "Unauthorized\n".to_string());
                    }
                    return (
                        200,
                        "text/plain",
                        "# HELP rclone_version_info Rclone version\nrclone_version_info{version=\"v1.65.0\"} 1\n".to_string(),
                    );
                }
                if path == "/core/version" && method == "POST" {
                    if auth != Some(expected_auth) {
                        return (401, "application/json", "{\"error\":\"unauthorized\"}\n".to_string());
                    }
                    return (200, "application/json", "{\"version\":\"1.65.0\"}\n".to_string());
                }
                (404, "text/plain", "Not Found\n".to_string())
            }).await;

        // An existing unit can still select the legacy file while both copies are present.
        let root = create_isolated_test_dir("rclone-auth-rcd-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        for (logical, content) in [
            (
                "etc/aetherflow/rclone.env",
                "RCLONE_USER=admin\nRCLONE_PASS=mysecret\n",
            ),
            (
                "etc/rclone/rclone.env",
                "RCLONE_RC_USER=other\nRCLONE_RC_PASS=other\n",
            ),
            (
                "etc/systemd/system/rclone.service",
                "[Service]\nEnvironmentFile=-/etc/aetherflow/rclone.env\n",
            ),
        ] {
            let path = root.join(logical);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone RC HTTP listener".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "authenticated WaitForHttpReady for rclone rcd must succeed: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);

        // 1b: Failure with wrong credentials (server returns 401)
        let root_wrong = create_isolated_test_dir("rclone-auth-wrong-live");
        let env_cfg_wrong = PackageExecutionEnv::isolated(&root_wrong);
        let env_file_wrong = root_wrong.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file_wrong.parent().unwrap()).unwrap();
        fs::write(
            &env_file_wrong,
            "RCLONE_RC_USER=\"wrong\"\nRCLONE_RC_PASS=\"wrongpass\"\n",
        )
        .unwrap();

        let executor_wrong = DeclarativePackageExecutor::new(env_cfg_wrong);
        let res_wrong = executor_wrong
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res_wrong.is_err(),
            "wrong credentials WaitForHttpReady must fail on 401"
        );
        let _ = fs::remove_dir_all(&root_wrong);
    }

    // 2. Case 2 (unauthenticated /metrics exposure): /metrics returns 200 # HELP rclone_... WITHOUT credentials -> rejected (is_err())!
    {
        let server = start_local_http_server(|_method, path, _auth| {
                if path == "/metrics" {
                    return (
                        200,
                        "text/plain",
                        "# HELP rclone_version_info Rclone version\nrclone_version_info{version=\"v1.65.0\"} 1\n".to_string(),
                    );
                }
                (404, "text/plain", "Not Found\n".to_string())
            }).await;

        let root = create_isolated_test_dir("rclone-unauth-exposure-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone unauthenticated metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated /metrics exposure must be rejected with Err: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // 3. Case 3 (rcd with /metrics returning 405 Method Not Allowed or 404):
    // Supplies FULL set of variables created by the real recipe:
    // APP_PORT, RCLONE_API_PORT = APP_PORT + 1, RCLONE_WEB_MODE = "rcd", RCLONE_MODE = "rcd".
    // Also writes an active rclone.service unit without --api-addr.
    // Verifies single-port rcd readiness stays in single-port mode, rejects 405 on /metrics,
    // and succeeds when /metrics + /core/version (or /rc/noopauth) behave as a valid single-port rcd listener.
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (405, "text/plain", "405 Method Not Allowed\n".to_string());
            }
            if (path == "/core/version" || path == "/rc/noopauth") && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-auth-405-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        // Write active rclone.service unit without --api-addr (pure single-port rcd)
        let svc_file = root.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file.parent().unwrap()).unwrap();
        fs::write(
                &svc_file,
                format!(
                    "[Unit]\nDescription=Rclone RC Web GUI Service\n[Service]\nExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-addr=127.0.0.1:{}\n",
                    server.port
                ),
            ).unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg.clone());
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        // Supply RCLONE_API_PORT = APP_PORT + 1 as populated by recipe generator
        vars.insert("RCLONE_API_PORT".to_string(), (server.port + 1).to_string());
        vars.insert("RCLONE_WEB_MODE".to_string(), "rcd".to_string());
        vars.insert("RCLONE_MODE".to_string(), "rcd".to_string());

        // Assert that detect_rclone_separate_api_port stays None (single-port mode)
        let sep_port = detect_rclone_separate_api_port(&env_cfg, &vars, server.port);
        assert_eq!(
                sep_port, None,
                "single-port rcd unit without --api-addr must not detect separate api port even when RCLONE_API_PORT is present"
            );

        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone 405 rejection on /metrics in single-port rcd mode"
                .to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "single-port rcd with 405 on /metrics must NOT be accepted: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // 4. Case 4 (Split-port rclone gui mode, matching real Rclone 1.75.2 gui):
    // GUI listener on APP_PORT returns unauthenticated 200 OK <html>Rclone GUI</html> on both / and /metrics,
    // while the RC API listener on APP_PORT + 1 (--api-addr) returns 401 Unauthorized without credentials
    // and 200 OK with Basic Auth on BOTH /metrics and /core/version -> passes!
    // And if the RC API listener on APP_PORT + 1 returns 200 WITHOUT credentials, it is rejected (is_err())!
    {
        let server_gui = start_local_http_server(|_method, path, _auth| {
            if path == "/" || path == "/metrics" {
                return (200, "text/html", "<html>Rclone GUI</html>\n".to_string());
            }
            (200, "text/html", "<html>Rclone GUI</html>\n".to_string())
        })
        .await;

        let expected_auth = "Basic Z3VpX3VzZXI6Z3VpX3Bhc3M=";
        let server_api = start_local_http_server(move |method, path, auth| {
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        // 4a: Success with protected API server on --api-addr
        let root = create_isolated_test_dir("rclone-split-port-gui-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"gui_user\"\nRCLONE_RC_PASS=\"gui_pass\"\n",
        )
        .unwrap();

        // Write rclone.service with --api-addr
        let svc_file = root.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file.parent().unwrap()).unwrap();
        fs::write(
                &svc_file,
                format!(
                    "[Unit]\nDescription=Rclone GUI\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:{} --api-addr=127.0.0.1:{} --enable-metrics --no-open-browser\n",
                    server_gui.port, server_api.port
                ),
            ).unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server_gui.port.to_string());
        vars.insert("RCLONE_API_PORT".to_string(), server_api.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying split-port Rclone GUI readiness".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "split-port gui mode must succeed when RC API is protected: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);

        // 4b: RC API listener on --api-addr returns 200 WITHOUT credentials -> must be rejected (is_err())!
        let server_api_unauth = start_local_http_server(|method, path, _auth| {
            if path == "/metrics" && method == "GET" {
                return (401, "text/plain", "Unauthorized\n".to_string());
            }
            if path == "/core/version" && method == "POST" {
                // Unauthenticated request returns 200 -> auth bypass!
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root_bypass = create_isolated_test_dir("rclone-split-port-bypass-live");
        let env_cfg_bypass = PackageExecutionEnv::isolated(&root_bypass);
        let env_file_bypass = root_bypass.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file_bypass.parent().unwrap()).unwrap();
        fs::write(
            &env_file_bypass,
            "RCLONE_RC_USER=\"gui_user\"\nRCLONE_RC_PASS=\"gui_pass\"\n",
        )
        .unwrap();

        let svc_file_bypass = root_bypass.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file_bypass.parent().unwrap()).unwrap();
        fs::write(
                &svc_file_bypass,
                format!(
                    "[Unit]\nDescription=Rclone GUI\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:{} --api-addr=127.0.0.1:{} --enable-metrics --no-open-browser\n",
                    server_gui.port, server_api_unauth.port
                ),
            ).unwrap();

        let executor_bypass = DeclarativePackageExecutor::new(env_cfg_bypass);
        let mut vars_bypass = HashMap::new();
        vars_bypass.insert("APP_PORT".to_string(), server_gui.port.to_string());
        vars_bypass.insert(
            "RCLONE_API_PORT".to_string(),
            server_api_unauth.port.to_string(),
        );

        let res_bypass = executor_bypass
            .run_single_step(
                &recipe,
                &step,
                &mut vars_bypass,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res_bypass.is_err(),
            "RC API listener returning 200 without credentials must be rejected with Err: {:?}",
            res_bypass
        );
        let _ = fs::remove_dir_all(&root_bypass);
    }

    // 5. Case 5 (Non-rclone package "netdata" when /etc/rclone/rclone.env exists): no Authorization header sent -> passes
    {
        let seen_auth_headers = Arc::new(StdMutex::new(Vec::<Option<String>>::new()));
        let headers_tracker = seen_auth_headers.clone();
        let server = start_local_http_server(move |_method, path, auth| {
            headers_tracker
                .lock()
                .unwrap()
                .push(auth.map(|s| s.to_string()));
            if path == "/api/v1/info" {
                (
                    200,
                    "application/json",
                    "{\"version\":\"1.47.0\"}\n".to_string(),
                )
            } else {
                (200, "text/plain", "ok\n".to_string())
            }
        })
        .await;

        let root = create_isolated_test_dir("rclone-non-rclone-netdata-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        // Intentionally create /etc/rclone/rclone.env inside root
        let rclone_env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(rclone_env_file.parent().unwrap()).unwrap();
        fs::write(
            &rclone_env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let netdata_recipe =
            get_declarative_recipe("netdata").expect("netdata recipe must exist");
        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/api/v1/info".to_string(),
            progress_pct: 98,
            description: "Verifying Netdata HTTP listener readiness".to_string(),
        };

        let res = executor
            .run_single_step(
                &netdata_recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "readiness for netdata must succeed: {:?}",
            res
        );

        let recorded_headers = seen_auth_headers.lock().unwrap().clone();
        assert!(
            !recorded_headers.is_empty(),
            "netdata server must have received requests"
        );
        for auth in &recorded_headers {
            assert!(
                auth.is_none(),
                "non-rclone package probe must never send an Authorization header, got: {:?}",
                auth
            );
        }
        let _ = fs::remove_dir_all(&root);
    }
}

fn create_test_rclone_zip(staging_dir: &Path, reported_version: &str) -> (PathBuf, String) {
    let bin_path = staging_dir.join("rclone");
    let c_code = format!(
            "#include <stdio.h>\nint main(int argc, char** argv) {{ puts(\"rclone {}\"); return 0; }}\n",
            reported_version
        );
    let mut child = std::process::Command::new("gcc")
        .args(["-x", "c", "-", "-o", &bin_path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("gcc must be available for testing ELF binary verification");
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(c_code.as_bytes());
    }
    assert!(child.wait().unwrap().success());

    let zip_path = staging_dir.join("test_rclone.zip");
    let status = std::process::Command::new("zip")
        .args([
            "-j",
            &zip_path.to_string_lossy(),
            &bin_path.to_string_lossy(),
        ])
        .status()
        .expect("zip command must succeed");
    assert!(status.success());

    let zip_bytes = fs::read(&zip_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&zip_bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());

    (zip_path, sha256_hex)
}

#[tokio::test]
async fn test_rclone_install_rejects_sha256_mismatch() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-sha256-mismatch");
    let work_dir = create_isolated_test_dir("rclone-work-mismatch");
    let (zip_path, _real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    // Deliberately incorrect SHA-256 digest
    vars.insert(
        "RCLONE_ARCHIVE_SHA256".to_string(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    );

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "SHA-256 mismatch must fail closed: {:?}", res);

    let dest_bin = root.join("usr/local/bin/rclone");
    assert!(
        !dest_bin.exists(),
        "Binary must not be installed when SHA-256 verification fails"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_rejects_wrong_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-wrong-version");
    let work_dir = create_isolated_test_dir("rclone-work-wrong-version");
    // Binary reports v1.60.0 while target version is 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.60.0");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_err(),
        "Binary reporting wrong version (v1.60.0 vs target 1.75.2) must be rejected: {:?}",
        res
    );

    let dest_bin = root.join("usr/local/bin/rclone");
    assert!(
        !dest_bin.exists(),
        "Binary must not be installed when version check fails"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_succeeds_with_valid_sha256_and_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-install-ok");
    use std::os::unix::fs::PermissionsExt;
    let runtime_dir = root.join("opt/AetherFlow/apps/rclone");
    fs::create_dir_all(&runtime_dir).unwrap();
    let apps_dir = runtime_dir.parent().unwrap();
    for path in [apps_dir, runtime_dir.as_path()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let work_dir = create_isolated_test_dir("rclone-work-ok");
    // Binary reports v1.75.2 matching target 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_ok(),
        "Valid SHA-256 and matching version must succeed: {:?}",
        res
    );

    assert!(root.join(RCLONE_BIN.trim_start_matches('/')).is_file());
    assert!(root
        .join(RCLONE_BIN_OWNER.trim_start_matches('/'))
        .is_file());
    assert!(!root.join("usr/bin/rclone").exists());
    assert!(!root.join("usr/local/bin/rclone").exists());

    for path in [apps_dir, runtime_dir.as_path()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o711
        );
    }

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_readiness_rejects_exposed_core_version_as_auth_bypass() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Server where /metrics properly requires auth (returns 401 unauthenticated, 200 authenticated),
    // but /core/version returns 200 WITHOUT authentication (exposed RC endpoint).
    let server = start_local_http_server(|method, path, auth| {
        let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
        if path == "/metrics" && method == "GET" {
            if auth != Some(expected_auth) {
                return (401, "text/plain", "Unauthorized\n".to_string());
            }
            return (
                200,
                "text/plain",
                "# HELP rclone_version_info\n".to_string(),
            );
        }
        if path == "/core/version" && method == "POST" {
            // Exposure: returns 200 even unauthenticated!
            return (
                200,
                "application/json",
                "{\"version\":\"1.75.2\"}\n".to_string(),
            );
        }
        (404, "text/plain", "Not Found\n".to_string())
    })
    .await;

    let root = create_isolated_test_dir("rclone-exposed-core-version");
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let env_file = root.join("etc/rclone/rclone.env");
    fs::create_dir_all(env_file.parent().unwrap()).unwrap();
    fs::write(
        &env_file,
        "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
    )
    .unwrap();

    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();
    let mut vars = HashMap::new();
    vars.insert("APP_PORT".to_string(), server.port.to_string());
    let step = DeclarativeStep::WaitForHttpReady {
        path: "/metrics".to_string(),
        progress_pct: 98,
        description: "Verifying exposed core version rejection".to_string(),
    };

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "exposed /core/version returning 200 unauthenticated must be rejected as an authentication bypass: {:?}", res);
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_rclone_readiness_rejects_unauthenticated_404_or_500_on_metrics() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Test 1: /metrics returns 404 unauthenticated
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (404, "text/plain", "Not Found\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-unauth-404-metrics");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying unauthenticated 404 metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated 404 on /metrics must NOT be accepted as ready: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Test 2: /metrics returns 500 unauthenticated
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (500, "text/plain", "Internal Server Error\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-unauth-500-metrics");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying unauthenticated 500 metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated 500 on /metrics must NOT be accepted as ready: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_rclone_readiness_rejects_mock_or_dry_run_output_when_dry_run_false() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Case 1: Server returns "ok: curl 200" on unauthenticated /metrics
    {
        let server = start_local_http_server(|method, path, _auth| {
            if path == "/metrics" && method == "GET" {
                return (200, "text/plain", "ok: curl 200\n".to_string());
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-mock-metrics-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying mock output rejection on metrics".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(res.is_err(), "server returning 'ok: curl 200' on unauthenticated /metrics must be rejected when dry_run=false: {:?}", res);
        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Server returns "[dry-run] curl" on unauthenticated /core/version
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                return (200, "text/plain", "[dry-run] curl\n".to_string());
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-dryrun-version-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying [dry-run] output rejection on version".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(res.is_err(), "server returning '[dry-run] curl' on unauthenticated /core/version must be rejected when dry_run=false: {:?}", res);
        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_non_rclone_readiness_rejects_mock_or_dry_run_output_when_dry_run_false() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Case 1: Server returns "ok: curl 200" on GET /api/v1/info
    {
        let server = start_local_http_server(|_method, _path, _auth| {
            (200, "text/plain", "ok: curl 200\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("non-rclone-mock-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("netdata").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/api/v1/info".to_string(),
            progress_pct: 98,
            description: "Verifying mock output rejection for non-rclone".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "non-rclone returning 'ok: curl 200' must be rejected when dry_run=false: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Server returns "[dry-run] curl" on GET /api/v1/info
    {
        let server = start_local_http_server(|_method, _path, _auth| {
            (200, "text/plain", "[dry-run] curl\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("non-rclone-dryrun-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("netdata").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/api/v1/info".to_string(),
            progress_pct: 98,
            description: "Verifying [dry-run] output rejection for non-rclone".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "non-rclone returning '[dry-run] curl' must be rejected when dry_run=false: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn test_stale_rclone_web_unit_does_not_override_active_single_port_unit() {
    let root = create_isolated_test_dir("stale-rclone-web-unit");

    // Create active single-port rclone.service WITHOUT --api-addr
    let rclone_svc = root.join("etc/systemd/system/rclone.service");
    fs::create_dir_all(rclone_svc.parent().unwrap()).unwrap();
    fs::write(
            &rclone_svc,
            "[Unit]\nDescription=Rclone\n[Service]\nExecStart=/usr/bin/rclone rcd --rc-addr=127.0.0.1:5572\n",
        ).unwrap();

    // Create stale split-port rclone-web.service WITH --api-addr
    let stale_web_svc = root.join("etc/systemd/system/rclone-web.service");
    fs::write(
            &stale_web_svc,
            "[Unit]\nDescription=Stale Rclone Web\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:5572 --api-addr=127.0.0.1:5573\n",
        ).unwrap();

    let vars = HashMap::new();
    let detected = detect_rclone_separate_api_port_for_root(&root, &vars, 5572);
    assert_eq!(
        detected, None,
        "active rclone.service must not be overridden by stale rclone-web.service with --api-addr"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_rclone_rollback_preserves_preexisting_binary_and_symlink_on_failure() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-rollback-preserves");
    let work_dir = create_isolated_test_dir("rclone-work-preserves");

    // Pre-create pre-existing /usr/local/bin/rclone and /usr/bin/rclone symlink
    let usr_local_bin = root.join("usr/local/bin/rclone");
    fs::create_dir_all(usr_local_bin.parent().unwrap()).unwrap();
    fs::write(&usr_local_bin, b"original-rclone-binary-v1.60.0").unwrap();

    let usr_bin = root.join("usr/bin/rclone");
    fs::create_dir_all(usr_bin.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/usr/local/bin/rclone", &usr_bin).unwrap();

    // Stage zip with mismatched SHA-256
    let (zip_path, _real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary with sha mismatch".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert(
        "RCLONE_ARCHIVE_SHA256".to_string(),
        "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb".to_string(),
    );

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "SHA-256 mismatch must fail");

    // The pre-existing binary and symlink MUST remain completely intact!
    assert!(
        usr_local_bin.is_file(),
        "pre-existing /usr/local/bin/rclone must remain intact"
    );
    assert_eq!(
        fs::read(&usr_local_bin).unwrap(),
        b"original-rclone-binary-v1.60.0"
    );
    assert!(
        usr_bin.exists() || fs::symlink_metadata(&usr_bin).is_ok(),
        "pre-existing /usr/bin/rclone must exist"
    );
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(&usr_bin).unwrap(),
        PathBuf::from("/usr/local/bin/rclone")
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_upgrade_and_rollback_preserve_distro_and_operator_binaries() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-symlink-dest");
    let work_dir = create_isolated_test_dir("rclone-symlink-work");

    let operator = root.join("usr/local/bin/rclone");
    fs::create_dir_all(operator.parent().unwrap()).unwrap();
    fs::write(&operator, b"operator payload").unwrap();

    let distro = root.join("usr/bin/rclone");
    fs::create_dir_all(distro.parent().unwrap()).unwrap();
    fs::write(&distro, b"distro payload").unwrap();

    let managed = root.join(RCLONE_BIN.trim_start_matches('/'));
    let owner = root.join(RCLONE_BIN_OWNER.trim_start_matches('/'));
    fs::create_dir_all(managed.parent().unwrap()).unwrap();
    fs::write(&managed, b"prior managed payload").unwrap();
    fs::write(&owner, b"rclone\n").unwrap();

    // Stage zip with matching target version 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Upgrading the managed Rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    res.unwrap();
    assert_ne!(fs::read(&managed).unwrap(), b"prior managed payload");
    assert_eq!(fs::read(&distro).unwrap(), b"distro payload");
    assert_eq!(fs::read(&operator).unwrap(), b"operator payload");

    let _notes = journal.rollback(&executor.runner).await;
    assert_eq!(fs::read(&managed).unwrap(), b"prior managed payload");
    assert_eq!(fs::read(&distro).unwrap(), b"distro payload");
    assert_eq!(fs::read(&operator).unwrap(), b"operator payload");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_requires_dash_dash_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-dashdash-ver-root");
    let work_dir = create_isolated_test_dir("rclone-dashdash-ver-work");

    let bin_path = work_dir.join("rclone");
    let c_code = r#"#include <stdio.h>
#include <string.h>
int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        return 2; // fails on --version
    }
    if (argc > 1 && strcmp(argv[1], "version") == 0) {
        puts("rclone v1.75.2");
        return 0; // succeeds on version fallback
    }
    return 1;
}
"#;
    let mut child = std::process::Command::new("gcc")
        .args(["-x", "c", "-", "-o", &bin_path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("gcc must be available for testing ELF binary verification");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(c_code.as_bytes());
    }
    assert!(child.wait().unwrap().success());

    let zip_path = work_dir.join("test_rclone_subcmd.zip");
    let status = std::process::Command::new("zip")
        .args([
            "-j",
            &zip_path.to_string_lossy(),
            &bin_path.to_string_lossy(),
        ])
        .status()
        .expect("zip command must succeed");
    assert!(status.success());

    let zip_bytes = fs::read(&zip_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&zip_bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary with failing --version".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), sha256_hex);

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_err(),
        "Install must fail when --version fails, even if 'version' succeeds"
    );
    let err_str = format!("{:?}", res);
    assert!(
        err_str.contains("--version"),
        "Error must cite failed self-test '--version': {}",
        err_str
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

