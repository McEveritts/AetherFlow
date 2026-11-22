use super::*;

#[test]
fn test_single_package_update_response_flattens_contract_fields() {
    let rec = af_services::workers::PackageUpdateRecord {
        package_id: "radarr".to_string(),
        installed: true,
        installed_version: "5.14.0".to_string(),
        latest_version: "5.15.0".to_string(),
        update_available: true,
        checked_at: "2026-11-02T12:00:00Z".to_string(),
        release_url: "https://github.com/Radarr/Radarr/releases/tag/v5.15.0".to_string(),
        error: "github rate limit warning".to_string(),
        source_key: "github:Radarr/Radarr".to_string(),
    };
    let body = build_single_package_update_response("radarr", Some(rec));
    assert_eq!(body["package"], "radarr");
    assert_eq!(body["update_available"], true);
    assert_eq!(body["installed_version"], "5.14.0");
    assert_eq!(body["latest_version"], "5.15.0");
    assert_eq!(
        body["update_url"],
        "https://github.com/Radarr/Radarr/releases/tag/v5.15.0"
    );
    assert_eq!(body["checked_at"], "2026-11-02T12:00:00Z");
    assert_eq!(
        body["last_error"],
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(
        body["error"],
        "GitHub API rate limit reached; retaining last confirmed version"
    );
    assert_eq!(body["update"]["package_id"], "radarr");
}

#[test]
fn test_progress_reports_failed_outcome_after_job_clears_and_redacts_for_viewers() {
    let outcome = af_services::PackageJobOutcome {
        job_id: "test-job".into(),
        package_id: "sonarr".into(),
        action: "update".into(),
        status: "failed".into(),
        message: "Could not stop sonarr: exit status 5".into(),
        started_at: "2026-11-05T20:00:00.000Z".into(),
        finished_at: "2026-11-05T20:01:00Z".into(),
        ..Default::default()
    };
    let payload = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
    assert_eq!(payload["status"], "failed");
    assert_eq!(payload["action"], "update");
    assert_eq!(payload["message"], "Could not stop sonarr: exit status 5");
    assert_eq!(payload["started_at"], "2026-11-05T20:00:00.000Z");
    let idle = package_progress_payload("sonarr", None, None, false);
    assert_eq!(idle["status"], "idle");

    let ordinary = package_progress_payload("sonarr", None, Some(outcome), false);
    assert!(!ordinary.to_string().contains("exit status"));
    assert_eq!(ordinary["last_job"]["job_id"], "test-job");
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_inventory_requires_human_admin_for_lifecycle_diagnostics() {
    use tower::ServiceExt;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    let package = af_models::Package {
        name: "fixture".into(),
        label: "Fixture".into(),
        lock_file: "/install/.fixture.lock".into(),
        default_port: 12345,
        web_path: "/open".into(),
        ..Default::default()
    };
    let vhosts = root.join("etc/apache2/sites-enabled");
    std::fs::create_dir_all(&vhosts).unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.fixture.lock"), "installed").unwrap();
    std::fs::write(
        vhosts.join("aetherflow-app-fixture.conf"),
        "<VirtualHost *:80>\n    ServerName fixture.aether.local\n</VirtualHost>\n",
    )
    .unwrap();
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch(
            "INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin'), (2, 'viewer', 'user');
             INSERT INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status)
             VALUES ('inventory-reader', 1, 0, 1, 'running');",
        )
        .unwrap();
    drop(conn);
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "inventory-privilege-fixture".into(),
            package_id: "fixture".into(),
            expected_target_version: Some("2.0.0".into()),
            action: "update".into(),
            status: "updating".into(),
            progress: 42,
            started_at: chrono::Utc::now().to_rfc3339(),
            last_line: "PRIVATE_INSTALLER_DETAILS".into(),
        }
    ));
    af_services::finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(af_services::PackageJobFailure::Installer),
        "inventory-privilege-fixture",
        Some("private-fixture-stage".into()),
        Some(41),
        Some("PRIVATE_INSTALLER_DETAILS /home/fixture/internal-path".into()),
        Some("2.0.0".into()),
        Some("1.0.0".into()),
    )
    .unwrap();
    let (admin_token, admin_claims) =
        crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let (user_token, _) = crate::auth::create_standard_jwt(2, &HeaderMap::new()).unwrap();
    let mut cases = vec![
        ("human-admin".to_string(), admin_token, true, true),
        ("human-user".to_string(), user_token, true, false),
        (
            "invalid".to_string(),
            "invalid-token".to_string(),
            false,
            false,
        ),
    ];
    for (pid, permission, scope, authenticated) in [
        (
            "inventory-packages",
            "packages:read",
            "/api/v1/auth/packages",
            true,
        ),
        (
            "inventory-marketplace",
            "marketplace:read",
            "/api/v1/public/marketplace",
            true,
        ),
        (
            "inventory-metrics",
            "system:metrics:read",
            "/api/v1/auth/system/metrics",
            false,
        ),
    ] {
        let pdir = root.join("plugins").join(pid);
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(
            pdir.join("plugin.manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": pid,
                "name": pid,
                "version": "1.0.0",
                "permissions": [permission],
                "api_scopes": [format!("GET {scope}")],
                "backend": { "health_path": "/healthz" },
            }))
            .unwrap(),
        )
        .unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status) VALUES (?1, 1, 0, 1, 'running')",
                rusqlite::params![pid],
            )
            .unwrap();
        drop(conn);
        let (manifests, errs) = crate::plugins::discover_plugins();
        assert!(errs.is_empty(), "plugin discovery errors: {errs:?}");
        let manifest = manifests.into_iter().find(|m| m.id == pid).unwrap();
        let (token, _) = crate::plugins::mint_scoped_plugin_token(&manifest, Some(300)).unwrap();
        assert!(crate::plugins::decode_and_verify_plugin_token(&token).is_ok());
        cases.push((format!("dedicated {scope}"), token, authenticated, false));
        for plugin_id in [pid, ""] {
            let mut claims = admin_claims.clone();
            claims.plugin_id = plugin_id.into();
            claims.plugin_scopes = vec![scope.into()];
            claims.jti = uuid::Uuid::new_v4().to_string();
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(&crate::auth::jwt_secret_bytes()),
            )
            .unwrap();
            assert!(crate::auth::decode_session_claims(&token, false).is_ok());
            cases.push((format!("legacy {plugin_id:?} {scope}"), token, false, false));
        }
    }
    let router = build_router();
    for (label, token, authenticated, diagnostics_allowed) in cases {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(
            get_marketplace_auth_info(&headers),
            (authenticated, diagnostics_allowed),
            "{label}"
        );
        for require_auth in [false, true] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(if require_auth {
                            "/api/v1/public/marketplace?require_auth=1"
                        } else {
                            "/api/v1/public/marketplace"
                        })
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if require_auth && !authenticated {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
                continue;
            }
            assert_eq!(response.status(), StatusCode::OK, "{label}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            assert_eq!(response.headers()[header::VARY], "Authorization, Cookie");
            assert_eq!(
                response.headers()["x-aetherflow-inventory-authenticated"],
                if authenticated { "true" } else { "false" },
                "{label}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let app = &payload[0];
            assert_eq!(app["inventory_known"], authenticated, "{label}");
            if authenticated {
                assert_eq!(app["launch_scope"], "internal", "{label}");
                assert_eq!(
                    app["launch_url"], "http://fixture.aether.local/open",
                    "{label}"
                );
                assert_eq!(
                    app["last_job"]["job_id"], "inventory-privilege-fixture",
                    "{label}"
                );
                assert_eq!(app["last_job"]["status"], "failed", "{label}");
                assert_eq!(
                    app["last_job"]["expected_target_version"], "2.0.0",
                    "{label}"
                );
            }
            for field in ["failed_stage", "exit_code", "sanitized_summary"] {
                assert_eq!(
                    app["last_job"].get(field).is_some(),
                    diagnostics_allowed,
                    "{label} {field}"
                );
            }
            assert_eq!(
                payload.to_string().contains("PRIVATE_INSTALLER_DETAILS"),
                diagnostics_allowed,
                "{label}"
            );
            assert_eq!(
                payload.to_string().contains("/home/fixture/internal-path"),
                diagnostics_allowed,
                "{label}"
            );
        }
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn bulk_update_inventory_errors_are_unavailable_without_success_counts() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::fs::write(&automation, "{}").unwrap();
    let package = af_models::Package {
        name: "sonarr".into(),
        lock_file: "/install/.sonarr.lock".into(),
        ..Default::default()
    };
    let valid_catalog = serde_json::to_vec(&vec![package]).unwrap();
    for failure in ["catalog", "lock", "journal"] {
        std::fs::write(&catalog, &valid_catalog).unwrap();
        match failure {
            "catalog" => std::fs::write(&catalog, "{corrupt").unwrap(),
            "lock" => std::fs::create_dir_all(root.join("install/.sonarr.lock")).unwrap(),
            "journal" => blocker.execute_batch("BEGIN EXCLUSIVE").unwrap(),
            _ => unreachable!(),
        }
        let response = check_package_updates().await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{failure}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "STATUS_UNAVAILABLE");
        assert!(body.get("updates").is_none());
        assert!(body.get("updates_available").is_none());
        assert!(!body.to_string().contains(root.to_str().unwrap()));
        if failure == "lock" {
            std::fs::remove_dir(root.join("install/.sonarr.lock")).unwrap();
        }
        if failure == "journal" {
            blocker.execute_batch("ROLLBACK").unwrap();
        }
    }
    std::fs::write(&catalog, "[]").unwrap();
    let response = check_package_updates().await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["updates"], serde_json::json!([]));
    assert_eq!(body["updates_available"], 0);
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_sanitizes_users_and_plugins_but_keeps_admin_diagnostics() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "privileged-output-job".into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 42,
            last_line: "step_output=private-installer-output".into(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    for (role, plugin, raw_expected) in [
        ("user", None, false),
        ("plugin", Some("telemetry-client"), false),
        ("admin", Some("telemetry-client"), false),
        ("admin", None, true),
    ] {
        let user = progress_test_user(role, plugin);
        let response = package_progress(
            Path("sonarr".into()),
            Query(Default::default()),
            Extension(user.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["job_id"], "privileged-output-job");
        assert_eq!(payload["progress"], 42);
        assert_eq!(payload["status"], "updating");
        assert_eq!(
            payload.to_string().contains("private-installer-output"),
            raw_expected
        );
        if plugin.is_some() {
            assert_eq!(
                issue_ws_ticket(Extension(user), PeerIp(None), HeaderMap::new())
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    af_services::fail_package_job(
        "sonarr",
        "update",
        af_services::PackageJobFailure::Installer,
        "privileged-output-job",
    )
    .unwrap();
    let response = package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("admin", None)),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        outcome["message"],
        af_services::PackageJobFailure::Installer.summary()
    );
    assert!(!outcome.to_string().contains("private-installer-output"));
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_returns_superseded_receipt_by_job_and_package() {
    use super::super::marketplace::PackageProgressQuery;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    connection
        .execute_batch(
            "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at)
                 VALUES ('sonarr','new-job','update','updating','fixture');
             INSERT INTO package_lifecycle_history
                 (package_id,job_id,action,status,started_at,sanitized_summary)
                 VALUES ('sonarr','old-job','update','failed','fixture','private-fixture-detail');",
        )
        .unwrap();
    for (package, job_id, role, expected_status, expected_code) in [
        ("sonarr", Some("old-job"), "user", StatusCode::OK, "failed"),
        ("sonarr", Some("old-job"), "admin", StatusCode::OK, "failed"),
        (
            "sonarr",
            Some("new-job"),
            "user",
            StatusCode::OK,
            "updating",
        ),
        ("sonarr", None, "user", StatusCode::OK, "updating"),
        (
            "radarr",
            Some("old-job"),
            "user",
            StatusCode::NOT_FOUND,
            "PACKAGE_JOB_NOT_FOUND",
        ),
    ] {
        let response = package_progress(
            Path(package.into()),
            Query(PackageProgressQuery {
                job_id: job_id.map(str::to_owned),
            }),
            Extension(progress_test_user(role, None)),
        )
        .await;
        assert_eq!(response.status(), expected_status);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if expected_status == StatusCode::OK {
            assert_eq!(payload["status"], expected_code);
            assert_eq!(payload["job_id"], job_id.unwrap_or("new-job"));
        } else {
            assert_eq!(payload["code"], expected_code);
        }
        assert_eq!(
            payload.to_string().contains("private-fixture-detail"),
            role == "admin"
        );
    }
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_progress_yields_and_fails_closed_on_blocked_journal() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, blocker) = lifecycle_status_fixture();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut response = Box::pin(package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("user", None)),
    ));
    assert!(
        futures::poll!(&mut response).is_pending(),
        "journal status must not block the async runtime or return idle on read failure"
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), response)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["code"], "STATUS_UNAVAILABLE");
    assert!(af_runner::acquire_lifecycle_admission_lock(Some(&root)).is_ok());
    let mut admission = Box::pin(dispatch_package_lifecycle(
        "sonarr".into(),
        "install",
        "installing",
        false,
        AuthUser {
            user_id: 1,
            username: "isolated-admin".into(),
            role: "admin".into(),
            jti: "isolated-session".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        },
        HeaderMap::new(),
    ));
    assert!(
        futures::poll!(&mut admission).is_pending(),
        "admission status lookup must yield before reading the journal"
    );
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), admission)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    blocker.execute_batch("ROLLBACK").unwrap();
    blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','matching-receipt','update','completed','fixture')", []).unwrap();
    let response = package_progress(
        Path("sonarr".into()),
        Query(Default::default()),
        Extension(progress_test_user("user", None)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["job_id"], "matching-receipt");
    assert_eq!(payload["status"], "completed");
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_progress_ingestion_and_projections_redact_secrets() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    // Test emit_package_progress ingests and stores redacted line
    let job_id = "secret-prog-job";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }
    ));

    emit_package_progress(
        "sonarr",
        "update",
        "updating",
        50,
        "Executing script with user_password=\"secret_pass_123\" and db_secret=secret_db_456",
        "test-time",
        job_id,
    );

    let info = af_services::get_package_job_info("sonarr").unwrap();
    assert!(!info.last_line.contains("secret_pass_123"));
    assert!(!info.last_line.contains("secret_db_456"));
    assert!(info.last_line.contains("[REDACTED]"));

    for line in [
        r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
        "Authorization: [REDACTED] FRAGMENT_CANARY",
    ] {
        emit_package_progress(
            "sonarr",
            "update",
            "updating",
            50,
            line,
            "test-time",
            job_id,
        );
        let current = af_services::get_package_job_info("sonarr").unwrap();
        assert!(!current.last_line.contains("FRAGMENT_CANARY"));
        let projected = package_progress_payload("sonarr", Some(current), None, true);
        assert!(!projected.to_string().contains("FRAGMENT_CANARY"));
    }

    // Test finish_package_lifecycle ingests and stores redacted message and summary
    finish_package_lifecycle(
        "sonarr",
        "update",
        Some(af_services::PackageJobFailure::TargetVerification),
        95,
        "Target mismatch with github_token=secret_gh_tok_789 and api_key=secret_api_key_000",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v1.0.0"),
        &[],
    );

    let outcome = af_services::get_package_job_outcome("sonarr").unwrap();
    assert!(!outcome.message.contains("secret_gh_tok_789"));
    assert!(!outcome.message.contains("secret_api_key_000"));
    if let Some(ref summary) = outcome.sanitized_summary {
        assert!(!summary.contains("secret_gh_tok_789"));
        assert!(!summary.contains("secret_api_key_000"));
        assert!(summary.contains("[REDACTED]"));
    }

    // Test package_progress_payload redacts secrets for admin view
    let progress_json = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
    assert!(!progress_json.to_string().contains("secret_gh_tok_789"));
    assert!(!progress_json.to_string().contains("secret_api_key_000"));

    // Test Authorization: Basic, curl -u, --pass, and JSON boundary redaction
    let job_id2 = "secret-prog-job-2";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id2.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }
    ));
    emit_package_progress(
            "sonarr",
            "update",
            "updating",
            60,
            "Running curl -u admin:mysecret123 http://target.local with --pass pass_val_456 and Authorization: Basic dXNlcjpwYXNz and password={\"raw\":\"boundary_secret_789\"}",
            "test-time",
            job_id2,
        );
    let info2 = af_services::get_package_job_info("sonarr").unwrap();
    assert!(!info2.last_line.contains("mysecret123"));
    assert!(!info2.last_line.contains("pass_val_456"));
    assert!(!info2.last_line.contains("dXNlcjpwYXNz"));
    assert!(!info2.last_line.contains("boundary_secret_789"));
    assert!(info2.last_line.contains("curl -u [REDACTED]"));
    assert!(info2.last_line.contains("--pass [REDACTED]"));
    assert!(info2.last_line.contains("Basic [REDACTED]"));
    assert!(info2.last_line.contains("[REDACTED]"));

    finish_package_lifecycle(
            "sonarr",
            "update",
            Some(af_services::PackageJobFailure::Installer),
            60,
            "Failed running curl -u admin:mysecret123 http://target with --pass pass_val_456 and Basic dXNlcjpwYXNz",
            "test-time",
            job_id2,
            Some("v2.0.0"),
            None,
            &[],
        );
    let outcome2 = af_services::get_package_job_outcome("sonarr").unwrap();
    assert!(!outcome2.message.contains("mysecret123"));
    assert!(!outcome2.message.contains("pass_val_456"));
    assert!(!outcome2.message.contains("dXNlcjpwYXNz"));
    if let Some(ref sum) = outcome2.sanitized_summary {
        assert!(!sum.contains("mysecret123"));
        assert!(!sum.contains("pass_val_456"));
        assert!(!sum.contains("dXNlcjpwYXNz"));
    }
    let progress_json2 = package_progress_payload("sonarr", None, Some(outcome2), true);
    assert!(!progress_json2.to_string().contains("mysecret123"));
    assert!(!progress_json2.to_string().contains("pass_val_456"));
    assert!(!progress_json2.to_string().contains("dXNlcjpwYXNz"));

    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_public_unauthenticated_catalog_strips_all_private_fields() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let ledger = connection.path().unwrap();
    std::fs::rename(ledger, root.join("unavailable-ledger.sqlite")).unwrap();
    assert!(af_services::package_job_snapshot().is_err());

    let response = get_marketplace_apps_blocking(HeaderMap::new(), false);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-aetherflow-inventory-mode")
            .unwrap()
            .to_str()
            .unwrap(),
        "public_redacted"
    );
    assert_eq!(
        response
            .headers()
            .get("x-aetherflow-inventory-authenticated")
            .unwrap()
            .to_str()
            .unwrap(),
        "false"
    );

    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let apps = payload
        .as_array()
        .expect("public response must be an array");
    assert!(!apps.is_empty(), "public catalog should return packages");

    for app in apps {
        let obj = app.as_object().expect("each item must be a JSON object");
        // Public fields that may be present:
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("desc"));
        assert!(obj.contains_key("category"));
        assert_eq!(obj.get("status").unwrap(), "not_installed");
        assert_eq!(obj.get("inventory_known").unwrap(), false);
        assert_eq!(obj.get("inventory_authenticated").unwrap(), false);
        assert_eq!(obj.get("inventory_mode").unwrap(), "public_redacted");

        // Private inventory and ingress fields that MUST be omitted:
        assert!(
            !obj.contains_key("internal_domain"),
            "internal_domain must be omitted"
        );
        assert!(
            !obj.contains_key("external_access_enabled"),
            "external_access_enabled must be omitted"
        );
        assert!(
            !obj.contains_key("tls_enabled"),
            "tls_enabled must be omitted"
        );
        assert!(
            !obj.contains_key("latest_version"),
            "latest_version must be omitted"
        );
        assert!(
            !obj.contains_key("installed_version"),
            "installed_version must be omitted"
        );
        assert!(
            !obj.contains_key("checked_at"),
            "checked_at must be omitted"
        );
        assert!(
            !obj.contains_key("update_checked_at"),
            "update_checked_at must be omitted"
        );
        assert!(
            !obj.contains_key("update_url"),
            "update_url must be omitted"
        );
        assert!(
            !obj.contains_key("update_error"),
            "update_error must be omitted"
        );
        assert!(
            !obj.contains_key("update_available"),
            "update_available must be omitted"
        );
        assert!(
            !obj.contains_key("active_port"),
            "active_port must be omitted"
        );
        assert!(
            !obj.contains_key("public_domain"),
            "public_domain must be omitted"
        );
        assert!(!obj.contains_key("launch_url"));
        assert!(!obj.contains_key("launch_scope"));
        assert!(
            !obj.contains_key("active_job"),
            "active_job must be omitted"
        );
        assert!(!obj.contains_key("last_job"), "last_job must be omitted");
        assert!(
            !obj.contains_key("last_job_outcome"),
            "last_job_outcome must be omitted"
        );
        assert!(!obj.contains_key("progress"), "progress must be omitted");
        assert!(!obj.contains_key("log_line"), "log_line must be omitted");
        assert!(
            !obj.contains_key("started_at"),
            "started_at must be omitted"
        );
        assert!(!obj.contains_key("job_id"), "job_id must be omitted");
        assert!(
            !obj.contains_key("retained_data_present"),
            "retained_data_present must be omitted"
        );
    }

    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_catalog_exposes_retained_purge_only_for_authenticated_proven_idle_items() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    async fn settle_dispatched_job(response: axum::response::Response, package: &str) {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let job_id = body["job_id"].as_str().unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
            loop {
                if let Some(outcome) = af_services::get_package_job_outcome(package) {
                    if outcome.job_id == job_id {
                        break outcome;
                    }
                }
                interval.tick().await;
            }
        })
        .await
        .expect("dispatched lifecycle job did not finish");
        assert_eq!(outcome.status, "completed", "{outcome:?}");
    }
    async fn fetch_catalog_map(
        headers: HeaderMap,
    ) -> std::collections::HashMap<String, serde_json::Value> {
        let response = get_marketplace_apps_blocking(headers, false);
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        payload
            .as_array()
            .expect("marketplace response must be an array")
            .iter()
            .map(|item| (item["id"].as_str().unwrap().to_string(), item.clone()))
            .collect()
    }

    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("etc/Swizzin")).unwrap();
    std::fs::create_dir_all(root.join("etc/rclone")).unwrap();
    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    let hosts_file = root.join("etc/hosts");
    std::fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);
    std::env::set_var("AF_HOSTS_FILE", &hosts_file);

    let make_pkg = |name: &str, label: &str, port: i32| af_models::Package {
        name: name.into(),
        label: label.into(),
        service_name: name.into(),
        lock_file: format!("/install/.{name}.lock"),
        default_port: port,
        ..Default::default()
    };
    let catalog_pkgs = vec![
        make_pkg("rclone", "Rclone", 5572),
        make_pkg("sonarr", "Sonarr", 8989),
        make_pkg("radarr", "Radarr", 7878),
        make_pkg("bazarr", "Bazarr", 6767),
        make_pkg("lidarr", "Lidarr", 8686),
        make_pkg("prowlarr", "Prowlarr", 9696),
        make_pkg("jellyfin", "Jellyfin", 8096),
        make_pkg("ombi", "Ombi", 3579),
    ];
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&catalog_pkgs).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);

    // Seed admin user & auth header
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin')",
            [],
        )
        .unwrap();
        // Pre-fix retained ingress for radarr and jellyfin (jellyfin also gets a tampered receipt below)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
             INSERT INTO retained_app_ingress_configs VALUES ('radarr', '{\"appName\":\"radarr\",\"listenPort\":17878}');
             INSERT INTO retained_app_ingress_configs VALUES ('jellyfin', '{\"appName\":\"jellyfin\",\"listenPort\":18096}');
             INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,finished_at,retention_state)
             VALUES ('ombi','legacy-rm','remove','completed','2026-01-01T00:00:00Z','2026-01-01T00:01:00Z','');",
        )
        .unwrap();
    }
    let (admin_token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let mut admin_headers = HeaderMap::new();
    admin_headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {admin_token}").parse().unwrap(),
    );

    // Seed confined filesystem fixtures:
    // - rclone & sonarr installed
    // - prowlarr legacy Swizzin receipt only
    // - jellyfin tampered .retained claiming wrong package
    // - lidarr externally managed binary/config only
    std::fs::write(root.join("install/.rclone.lock"), b"installed\n").unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), b"installed\n").unwrap();
    std::fs::write(root.join("etc/Swizzin/.prowlarr.lock"), b"PORT=9696\n").unwrap();
    std::fs::write(
        root.join("install/.jellyfin.retained"),
        af_models::format_retained_package_receipt("sonarr", "2026-11-22T00:00:00Z"),
    )
    .unwrap();
    std::fs::write(root.join("usr/bin/lidarr"), b"distro-binary").unwrap();

    // Fake runner for ordinary remove + explicit purge on rclone
    let sock_path = short_test_socket_path(&format!(
        "afm-{}.sock",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    let _ = std::fs::remove_file(&sock_path);
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let runner_root = root.clone();
    let fake_runner = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buffer = [0u8; 8192];
            let Ok(count) = stream.read(&mut buffer).await else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let req_text = String::from_utf8_lossy(&buffer[..count]);
            let path = req_text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let body_str = req_text.split("\r\n\r\n").nth(1).unwrap_or("");
            let body = if path == "/v1/package" {
                let delete_data = serde_json::from_str::<serde_json::Value>(body_str)
                    .ok()
                    .and_then(|v| v.get("delete_data").and_then(|b| b.as_bool()))
                    .unwrap_or(false);
                let lock_path = runner_root.join("install/.rclone.lock");
                let retained_path = runner_root.join("install/.rclone.retained");
                if delete_data {
                    let _ = std::fs::remove_file(&retained_path);
                    let _ = std::fs::remove_file(&lock_path);
                } else {
                    let _ = std::fs::write(
                        &retained_path,
                        af_models::format_retained_package_receipt(
                            "rclone",
                            "2026-11-22T00:00:00Z",
                        ),
                    );
                    let _ = std::fs::remove_file(&lock_path);
                }
                "[PROGRESS:100] Package removal completed\n".to_string()
            } else if path.ends_with("/v1/self-update/status") {
                serde_json::to_string(&af_models::RunnerResponse {
                    success: true,
                    output: serde_json::json!({
                        "status": "succeeded",
                        "completed": true,
                        "success": true,
                        "job_unit": "",
                        "error": "",
                        "exit_code": null
                    })
                    .to_string(),
                    error: String::new(),
                })
                .unwrap()
            } else {
                serde_json::to_string(&af_models::RunnerResponse {
                    success: true,
                    output: "ok".to_string(),
                    error: String::new(),
                })
                .unwrap()
            };
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
        }
    });

    let remove_script = root.join("packages/package/remove/removepackage-rclone");
    std::fs::write(&remove_script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&remove_script, std::fs::Permissions::from_mode(0o755));
    }
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let admin = progress_test_user("admin", None);

    // 1. Ordinary uninstall of rclone creates retained ownership evidence.
    let retained_res = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(retained_res.status(), StatusCode::OK);
    settle_dispatched_job(retained_res, "rclone").await;

    // 2. Anonymous catalog omits retained_data_present for every item.
    let anon = fetch_catalog_map(HeaderMap::new()).await;
    for (id, app) in &anon {
        assert_eq!(app["inventory_authenticated"], false, "{id}");
        assert!(
            app.get("retained_data_present").is_none(),
            "anonymous catalog leaked retained_data_present for {id}: {app}"
        );
    }

    // 3. Authenticated catalog exposes retained_data_present ONLY for proven uninstalled idle items.
    let authed = fetch_catalog_map(admin_headers.clone()).await;
    assert_eq!(authed["rclone"]["status"], "uninstalled");
    assert_eq!(authed["rclone"]["inventory_authenticated"], true);
    assert_eq!(authed["rclone"]["inventory_known"], true);
    assert_eq!(authed["rclone"]["retained_data_present"], true);
    assert_eq!(authed["radarr"]["status"], "uninstalled");
    assert_eq!(authed["radarr"]["retained_data_present"], true);
    assert_eq!(authed["sonarr"]["status"], "installed");
    for fail_closed_id in ["sonarr", "bazarr", "lidarr", "prowlarr", "jellyfin", "ombi"] {
        assert!(
            authed[fail_closed_id]
                .get("retained_data_present")
                .is_none(),
            "{fail_closed_id} must fail closed: {}",
            authed[fail_closed_id]
        );
    }

    // 4. Active-job suppression hides retained_data_present while a job is running.
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "active-purge-attempt".into(),
            package_id: "rclone".into(),
            action: "remove".into(),
            status: "uninstalling".into(),
            progress: 10,
            last_line: "purging".into(),
            started_at: chrono::Utc::now().to_rfc3339(),
            expected_target_version: None,
        }
    ));
    let during_active = fetch_catalog_map(admin_headers.clone()).await;
    assert_eq!(during_active["rclone"]["status"], "uninstalling");
    assert!(
        during_active["rclone"]
            .get("retained_data_present")
            .is_none(),
        "active job must suppress retained_data_present: {}",
        during_active["rclone"]
    );

    // 5. Failed purge retry still retains batched lifecycle provenance even if .retained is removed.
    af_services::finish_package_job_with_recovery_and_retention(
        "rclone",
        "remove",
        false,
        Some(af_services::PackageJobFailure::Installer),
        "active-purge-attempt",
        None,
        Some(1),
        Some("simulated failure".into()),
        None,
        None,
        None,
        Some(af_runner::af_release::lifecycle::RETENTION_STATE_PURGED.to_string()),
    )
    .unwrap();
    let _ = std::fs::remove_file(root.join("install/.rclone.retained"));
    let after_failed_purge = fetch_catalog_map(admin_headers.clone()).await;
    assert_eq!(after_failed_purge["rclone"]["status"], "uninstalled");
    assert_eq!(
        after_failed_purge["rclone"]["retained_data_present"], true,
        "failed purge must keep prior retained lifecycle provenance"
    );

    // 6. Explicit purge via POST .../uninstall?purge=true clears retained_data_present,
    //    and subsequent ambiguous markerless state remains fail-closed.
    let purge_res = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        true,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(purge_res.status(), StatusCode::OK);
    settle_dispatched_job(purge_res, "rclone").await;

    let after_purge = fetch_catalog_map(admin_headers.clone()).await;
    assert_eq!(after_purge["rclone"]["status"], "uninstalled");
    assert!(
        after_purge["rclone"].get("retained_data_present").is_none(),
        "purged item must not advertise retained_data_present: {}",
        after_purge["rclone"]
    );

    std::fs::write(
        root.join("etc/rclone/rclone.conf"),
        b"[manual]\ntype = s3\n",
    )
    .unwrap();
    let after_ambiguous = fetch_catalog_map(admin_headers).await;
    assert!(
        after_ambiguous["rclone"]
            .get("retained_data_present")
            .is_none(),
        "ambiguous markerless state must fail closed: {}",
        after_ambiguous["rclone"]
    );
    let ambiguous_purge = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        true,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(ambiguous_purge.status(), StatusCode::CONFLICT);

    fake_runner.abort();
    let _ = std::fs::remove_file(&sock_path);
    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}
