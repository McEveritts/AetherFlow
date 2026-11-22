use super::lifecycle::resolve_plugin_executable;
use super::manifest::plugin_requires_admin;
use super::proxy::{collect_proxy_body, collect_proxy_response};
use super::registry::{allocate_plugin_port, read_registry_state};
use super::types::{ACTIVE_PROCESSES, PLUGIN_HEALTH};
use super::*;
use crate::auth::{jwt_secret_bytes, AuthUser};
use af_models::{PLUGIN_PORT_RANGE_END, PLUGIN_PORT_RANGE_START};
use axum::body::Body;
use axum::extract::{Extension, Path, Request};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

pub(crate) fn run_plugin_test_in_subprocess() -> bool {
    if std::env::var_os("AETHERFLOW_PLUGIN_TEST_ISOLATED").is_some() {
        return false;
    }
    let thread = std::thread::current();
    let test_name = thread.name().expect("named Rust test thread");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env("AETHERFLOW_PLUGIN_TEST_ISOLATED", "1")
        .status()
        .expect("start isolated plugin fixture");
    assert!(
        status.success(),
        "isolated plugin fixture failed: {test_name}"
    );
    true
}

#[tokio::test]
async fn proxy_body_collection_stops_at_limit_and_distinguishes_transport_errors() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let body = Body::from_stream(futures::stream::unfold(0, move |index| {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            assert!(
                index <= MAX_PLUGIN_PROXY_BODY_BYTES / 65536,
                "Must not poll stream past first over-limit chunk"
            );
            Some((Ok::<_, std::io::Error>(vec![0u8; 65536]), index + 1))
        }
    }));
    assert_eq!(
        collect_proxy_body(body).await.unwrap_err().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        MAX_PLUGIN_PROXY_BODY_BYTES / 65536 + 1
    );
    assert_eq!(
        collect_proxy_body(Body::from(vec![0u8; MAX_PLUGIN_PROXY_BODY_BYTES]))
            .await
            .unwrap()
            .len(),
        MAX_PLUGIN_PROXY_BODY_BYTES
    );
    let body = Body::from_stream(futures::stream::once(async {
        Err::<Vec<u8>, _>(std::io::Error::other("broken transport"))
    }));
    assert_eq!(
        collect_proxy_body(body).await.unwrap_err().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn upstream_response_limit_rejects_before_the_unfinished_body_ends() {
    use futures::StreamExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                let stream = futures::stream::iter(
                    (0..34).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 65536])),
                )
                .chain(futures::stream::pending());
                Body::from_stream(stream)
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let response = reqwest::get(format!("http://{address}/")).await.unwrap();
    let result =
        tokio::time::timeout(Duration::from_secs(2), collect_proxy_response(response)).await;
    server.abort();
    let rejected = result
        .expect("Must reject the first chunk beyond 2 MiB without waiting for EOF")
        .unwrap_err();
    assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(rejected.into_body(), 10000)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("PLUGIN_RESPONSE_TOO_LARGE"));
}

#[test]
fn test_manifest_validation_rejects_bad_ids_and_traversal() {
    let tmp = std::env::temp_dir().join(format!("af-plugin-test-{}", Uuid::new_v4()));
    let plugin_dir = tmp.join("valid-plugin");
    fs::create_dir_all(&plugin_dir).unwrap();

    let bad_id_manifest = RawPluginManifest {
        id: "../escape".to_string(),
        name: "Bad".to_string(),
        version: "0.1.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: vec!["system:metrics:read".to_string()],
        api_scopes: vec![],
        lifecycle_hooks: PluginLifecycleHooks::default(),
        backend: PluginBackendSpec::default(),
        frontend: PluginFrontendSpec::default(),
    };
    assert!(validate_plugin_manifest(&plugin_dir, bad_id_manifest).is_err());

    let traversal_hook_manifest = RawPluginManifest {
        id: "valid-plugin".to_string(),
        name: "Traversal".to_string(),
        version: "0.1.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: vec!["system:metrics:read".to_string()],
        api_scopes: vec![],
        lifecycle_hooks: PluginLifecycleHooks {
            on_start: "../../etc/passwd".to_string(),
            on_stop: String::new(),
        },
        backend: PluginBackendSpec::default(),
        frontend: PluginFrontendSpec::default(),
    };
    assert!(validate_plugin_manifest(&plugin_dir, traversal_hook_manifest).is_err());

    let forbidden_scope_manifest = RawPluginManifest {
        id: "valid-plugin".to_string(),
        name: "ForbiddenScope".to_string(),
        version: "0.1.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: vec!["system:metrics:read".to_string()],
        api_scopes: vec![RawScopeEntry::Simple("/api/v1/admin/users".to_string())],
        lifecycle_hooks: PluginLifecycleHooks::default(),
        backend: PluginBackendSpec::default(),
        frontend: PluginFrontendSpec::default(),
    };
    assert!(validate_plugin_manifest(&plugin_dir, forbidden_scope_manifest).is_err());

    let systemd_specifier_manifest = RawPluginManifest {
        id: "valid-plugin".to_string(),
        name: "Valid".to_string(),
        version: "0.1.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: vec![],
        api_scopes: vec![],
        lifecycle_hooks: PluginLifecycleHooks {
            on_start: "hooks/%i.sh".to_string(),
            on_stop: String::new(),
        },
        backend: PluginBackendSpec::default(),
        frontend: PluginFrontendSpec::default(),
    };
    assert!(validate_plugin_manifest(&plugin_dir, systemd_specifier_manifest).is_err());

    let control_char_name_manifest = RawPluginManifest {
        id: "valid-plugin".to_string(),
        name: "Bad\nINJECT=1".to_string(),
        version: "0.1.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: vec![],
        api_scopes: vec![],
        lifecycle_hooks: PluginLifecycleHooks::default(),
        backend: PluginBackendSpec::default(),
        frontend: PluginFrontendSpec::default(),
    };
    assert!(validate_plugin_manifest(&plugin_dir, control_char_name_manifest).is_err());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn destructive_plugin_scope_policy_rejects_explicit_and_overlapping_wildcards() {
    let destructive = [
        "/api/v1/admin/packages/demo/uninstall",
        "/api/admin/packages/*",
        "/api/v1/admin/services/aetherflow-api/control",
        "/api/admin/services/aetherflow-runner/control",
        "/api/v1/admin/system/update/run",
        "/api/v1/auth/deploy/demo",
        "/api/v1/auth/services/restart",
        "/api/v1/admin/*",
        "/api/v1/admin/pack*",
        "/api/v*",
        "/api/*",
    ];
    for permission in ["packages:write", "services:control", "system:admin"] {
        for route in destructive {
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                let scope = RawScopeEntry::Simple(format!("{method} {route}"));
                assert!(
                    normalize_scope_entry(&scope, &[permission.into()]).is_err(),
                    "{permission}: {method} {route}"
                );
            }
        }
    }
    for route in [
        "/api/v1/admin/services/restart/status",
        "/api/admin/system/update/status",
        "/api/v1/ingress/configs",
        "/api/v1/admin/*",
        "/api/v1/auth/*",
    ] {
        assert!(normalize_scope_entry(
            &RawScopeEntry::Simple(format!("GET {route}")),
            &["telemetry:read".into()],
        )
        .is_err());
    }
    assert!(normalize_scope_entry(
        &RawScopeEntry::Simple("GET /api/auth/services".into()),
        &["telemetry:read".into()],
    )
    .is_ok());
    for permission in ["system:read", "demo:write", "services:control"] {
        assert!(normalize_scope_entry(
            &RawScopeEntry::Simple("POST /api/v1/auth/notifications/1/read".into()),
            &[permission.into()],
        )
        .is_err());
    }
}

#[test]
fn destructive_plugin_request_policy_blocks_previously_minted_grants() {
    let mut claims = PluginTokenClaims {
        typ: PLUGIN_TOKEN_TYP.into(),
        iss: PLUGIN_TOKEN_ISSUER.into(),
        aud: PLUGIN_TOKEN_AUDIENCE.into(),
        sub: "plugin:fixture".into(),
        plugin_id: "fixture".into(),
        jti: "fixture".into(),
        iat: 1,
        exp: 2,
        epoch: 1,
        scopes: Vec::new(),
    };
    for path in [
        "/api/v1/admin/packages/demo/install",
        "/api/admin/packages/demo/uninstall",
        "/api/v1/admin/packages/demo/update",
        "/api/v1/admin/services/aetherflow-api/control",
        "/api/admin/services/demo/control",
        "/api/v1/admin/system/update/run",
        "/api/auth/deploy/demo",
    ] {
        for scope in [path, "/api/v1/admin/*", "/api/*"] {
            for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
                claims.scopes = vec![PluginScopeRule {
                    method: method.to_string(),
                    route: scope.into(),
                }];
                assert!(
                    !plugin_claims_allow_request(&claims, &method, path),
                    "{method} {path} from {scope}"
                );
            }
        }
    }
    for (path, allowed) in [
        ("/api/v1/auth/services", true),
        ("/api/v1/admin/services/restart/status", false),
        ("/api/admin/system/update/status", false),
        ("/api/v1/ingress/configs", false),
        ("/api/ingress/configs", false),
        ("/api/v1/auth/packages/demo/progress", true),
    ] {
        for method in [Method::GET, Method::HEAD] {
            claims.scopes = vec![PluginScopeRule {
                method: method.to_string(),
                route: "/api/*".into(),
            }];
            assert_eq!(
                plugin_claims_allow_request(&claims, &method, path),
                allowed,
                "{path}"
            );
        }
    }
    assert!(plugin_requires_admin(&["services:control".into()]));
    assert!(plugin_requires_admin(&["unknown:admin".into()]));
    assert!(!plugin_requires_admin(&["telemetry:read".into()]));
}

#[cfg(unix)]
#[tokio::test]
async fn managed_plugin_fails_closed_with_actionable_503_when_isolation_unavailable() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("fail-closed-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let plugin_dir = plugins_root.join("managed-fixture");
    let hooks_dir = plugin_dir.join("backend/hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
    fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&plugin_dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        plugin_dir.join("backend"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let forbidden_marker = tmp.join("api-user-executed.marker");
    let start_hook = hooks_dir.join("start.sh");
    fs::write(
        &start_hook,
        format!("#!/bin/bash\ntouch {:?}\n", forbidden_marker),
    )
    .unwrap();
    fs::set_permissions(&start_hook, fs::Permissions::from_mode(0o755)).unwrap();
    let stop_hook = hooks_dir.join("stop.sh");
    fs::write(
        &stop_hook,
        format!("#!/bin/bash\ntouch {:?}\n", forbidden_marker),
    )
    .unwrap();
    fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();

    let manifest_json = serde_json::json!({
        "id": "managed-fixture",
        "name": "Managed Fixture",
        "version": "1.0.0",
        "permissions": ["system:metrics:read"],
        "api_scopes": ["GET /api/v1/auth/system/metrics"],
        "lifecycle_hooks": {
            "on_start": "backend/hooks/start.sh",
            "on_stop": "backend/hooks/stop.sh"
        },
        "backend": { "health_path": "/healthz" }
    });
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        serde_json::to_vec_pretty(&manifest_json).unwrap(),
    )
    .unwrap();

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
    env::remove_var("PRIVILEGED_RUNNER_ENABLED");

    let admin = AuthUser {
        user_id: 1,
        username: "admin".into(),
        role: "admin".into(),
        jti: "op-1".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // 1. Start must fail closed with 503 PLUGIN_ISOLATION_UNAVAILABLE and never spawn locally
    let start_resp = control_plugin_handler(
        Path("managed-fixture".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "start".into(),
            port: Some(21444),
        }),
    )
    .await;
    assert_eq!(start_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(start_resp.into_body(), 8192)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("PLUGIN_ISOLATION_UNAVAILABLE"), "body={text}");
    assert!(
        text.contains("aetherflow-runner.service"),
        "actionable runner hint missing: {text}"
    );
    assert!(
        !forbidden_marker.exists(),
        "af-api MUST NOT fall back to spawning plugin hooks as the API user"
    );
    let reg = read_registry_state("managed-fixture");
    assert!(!reg.enabled);
    assert_eq!(
        reg.allocated_port, 0,
        "failed start must not persist custom port mutation"
    );
    assert_eq!(reg.status, "error");

    // 2. Stop with on_stop hook also fails closed without running hook as API user
    let stop_resp = control_plugin_handler(
        Path("managed-fixture".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "stop".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(stop_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!forbidden_marker.exists());

    // 3. Explicitly disabled PRIVILEGED_RUNNER_ENABLED=false also fails closed with 503
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");
    let disabled_resp = control_plugin_handler(
        Path("managed-fixture".into()),
        Extension(admin),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "start".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(disabled_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let disabled_body = axum::body::to_bytes(disabled_resp.into_body(), 8192)
        .await
        .unwrap();
    let disabled_text = String::from_utf8_lossy(&disabled_body);
    assert!(disabled_text.contains("PRIVILEGED_RUNNER_ENABLED"));
    assert!(!forbidden_marker.exists());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_scope_method_and_default_deny_enforcement() {
    let claims = PluginTokenClaims {
        typ: PLUGIN_TOKEN_TYP.to_string(),
        iss: PLUGIN_TOKEN_ISSUER.to_string(),
        aud: PLUGIN_TOKEN_AUDIENCE.to_string(),
        sub: "plugin:demo".to_string(),
        plugin_id: "demo".to_string(),
        jti: "plg-demo-1".to_string(),
        iat: 1000,
        exp: 2000,
        epoch: 1,
        scopes: vec![PluginScopeRule {
            method: "GET".to_string(),
            route: "/api/v1/auth/system/metrics".to_string(),
        }],
    };

    assert!(plugin_claims_allow_request(
        &claims,
        &Method::GET,
        "/api/v1/auth/system/metrics"
    ));
    assert!(!plugin_claims_allow_request(
        &claims,
        &Method::POST,
        "/api/v1/auth/system/metrics"
    ));
    assert!(!plugin_claims_allow_request(
        &claims,
        &Method::GET,
        "/api/v1/auth/session"
    ));
    assert!(!plugin_claims_allow_request(
        &claims,
        &Method::POST,
        "/api/v1/auth/refresh"
    ));
    assert!(!plugin_claims_allow_request(
        &claims,
        &Method::GET,
        "/api/v1/admin/users"
    ));
}

#[test]
fn test_credential_domain_separation_and_mutating_scope_permission_gate() {
    // Read-only permissions cannot request POST scopes
    let read_only_perms = vec!["system:metrics:read".to_string()];
    let post_scope = RawScopeEntry::Simple("POST /api/v1/auth/system/metrics".to_string());
    assert!(normalize_scope_entry(&post_scope, &read_only_perms).is_err());

    // Write permissions allow explicit POST scope on non-denied route
    let write_perms = vec!["notifications:write".to_string()];
    let valid_post = RawScopeEntry::Simple("POST /api/v1/auth/notifications/1/read".to_string());
    let rules = normalize_scope_entry(&valid_post, &write_perms).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].method, "POST");

    // Operator session tokens signed with raw JWT_SECRET cannot validate as plugin tokens
    let fake_session = crate::auth::SessionClaims {
        user_id: 1,
        sub: "1".to_string(),
        iss: "aetherflow".to_string(),
        iat: Utc::now().timestamp(),
        auth_time: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 900,
        jti: "op-session-1".to_string(),
        cfp: String::new(),
        ver: 0,
        plugin_id: String::new(),
        plugin_scopes: Vec::new(),
    };
    let op_jwt = encode(
        &Header::new(Algorithm::HS256),
        &fake_session,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )
    .unwrap();
    assert!(decode_and_verify_plugin_token(&op_jwt).is_err());
}

pub(crate) fn test_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) fn ensure_shared_test_db() -> &'static PathBuf {
    static DB_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DB_PATH.get_or_init(|| {
        let db_dir = std::env::temp_dir().join(format!("af-plugin-shared-db-{}", Uuid::new_v4()));
        fs::create_dir_all(&db_dir).unwrap();
        let db_path = db_dir.join("test.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            std::env::set_var(key, &db_path);
        }
        af_db::init_db().expect("initialize the isolated plugin test database");
        db_path
    })
}

#[tokio::test]
async fn plugin_listing_uses_cached_health_and_redacts_operator_details() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    let db = ensure_shared_test_db();
    let root = db.parent().unwrap().join("list-plugins");
    let plugin = root.join("test-plugin");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.manifest.json"),
        r#"{
        "id": "test-plugin", "name": "Fixture", "version": "1.0.0", "sdk": "rust",
        "backend": {"health_path": "/healthz"}
    }"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("rejected-plugin")).unwrap();
    fs::write(root.join("rejected-plugin/plugin.manifest.json"), "invalid").unwrap();
    env::set_var("AETHERFLOW_PLUGINS_DIR", &root);
    update_registry_state(
        "test-plugin",
        true,
        21099,
        "running",
        "private diagnostic",
        false,
    );
    PLUGIN_HEALTH
        .lock()
        .unwrap()
        .insert("test-plugin".into(), (21099, true));

    let writer = af_db::get_conn().unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    for role in ["user", "admin"] {
        let user = AuthUser {
            user_id: 1,
            username: "fixture".into(),
            role: role.into(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            list_plugins_handler(Extension(user)),
        )
        .await
        .expect("plugin listing does not wait on the writer");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let plugin = &result["plugins"][0];
        assert_eq!(plugin["id"], "test-plugin");
        assert_eq!(plugin["healthy"], true);
        assert_eq!(plugin.get("allocated_port").is_some(), role == "admin");
        assert_eq!(plugin.get("last_error").is_some(), role == "admin");
        assert_eq!(
            result["rejected"].as_array().unwrap().is_empty(),
            role != "admin"
        );
    }
    writer.execute_batch("ROLLBACK").unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn managed_plugin_lifecycle_delegates_to_runner_with_rotation_restart_and_rollback() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("runner-delegated-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("runner-tokens");
    let plugin_dir = plugins_root.join("isolated-demo");
    let hooks_dir = plugin_dir.join("backend/hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
    fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&plugin_dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        plugin_dir.join("backend"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let start_hook = hooks_dir.join("start.sh");
    fs::write(&start_hook, "#!/bin/bash\nexit 0\n").unwrap();
    fs::set_permissions(&start_hook, fs::Permissions::from_mode(0o755)).unwrap();
    let stop_hook = hooks_dir.join("stop.sh");
    fs::write(&stop_hook, "#!/bin/bash\nexit 0\n").unwrap();
    fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();

    let manifest_json = serde_json::json!({
        "id": "isolated-demo",
        "name": "Isolated Demo",
        "version": "1.0.0",
        "permissions": ["system:metrics:read"],
        "api_scopes": ["GET /api/v1/auth/system/metrics"],
        "lifecycle_hooks": {
            "on_start": "backend/hooks/start.sh",
            "on_stop": "backend/hooks/stop.sh"
        },
        "backend": { "health_path": "/healthz" }
    });
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        serde_json::to_vec_pretty(&manifest_json).unwrap(),
    )
    .unwrap();

    let unit_state = tmp.join("unit.state");
    let args_log = tmp.join("systemd-run.args");
    let fail_flag = tmp.join("fail-start.flag");
    let fake_sdrun = tmp.join("fake-systemd-run");
    fs::write(
        &fake_sdrun,
        format!(
            r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$@" >> {args:?}
if [[ -f {fail:?} ]]; then
  echo "simulated systemd-run failure" >&2
  exit 1
fi
echo active > {state:?}
"#,
            args = args_log,
            fail = fail_flag,
            state = unit_state
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

    let fake_sdctl = tmp.join("fake-systemctl");
    fs::write(
        &fake_sdctl,
        format!(
            r#"#!/bin/bash
set -euo pipefail
case "${{1:-}}" in
  show)
st="inactive"
if [[ -f {state:?} ]]; then st="$(cat {state:?})"; fi
echo "ActiveState=$st"
echo "SubState=running"
echo "MainPID=0"
echo "UID=62444"
echo "GID=62444"
;;
  stop)
echo inactive > {state:?}
;;
  reset-failed)
;;
esac
"#,
            state = unit_state
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

    let sock_path = env::temp_dir().join(format!(
        "af-plg-{}.sock",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let runner_app = af_runner::build_runner_router();
    let runner_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            let svc = TowerToHyperService::new(runner_app.clone());
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");

    let admin = AuthUser {
        user_id: 1,
        username: "admin".into(),
        role: "admin".into(),
        jti: "op-2".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // 1. Start succeeds through af-runner and stages a valid runtime token outside DATA_DIR
    let start_resp = control_plugin_handler(
        Path("isolated-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "start".into(),
            port: Some(21222),
        }),
    )
    .await;
    assert_eq!(start_resp.status(), StatusCode::OK);

    let runtime_id_1 = ACTIVE_PROCESSES
        .lock()
        .unwrap()
        .get("isolated-demo")
        .unwrap()
        .runtime_id
        .to_string();
    let token_path_1 = tokens_root
        .join("isolated-demo")
        .join(&runtime_id_1)
        .join("runtime.token");
    let token_1 = fs::read_to_string(&token_path_1).unwrap();
    assert!(decode_and_verify_plugin_token(&token_1).is_ok());
    assert!(
        !fs::read_to_string(&args_log).unwrap().contains(&token_1),
        "runtime token must never appear in systemd-run argv"
    );

    // 2. revoke_tokens bumps epoch, invalidates token_1, and rotates staged token immediately
    let revoke_resp = control_plugin_handler(
        Path("isolated-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "revoke_tokens".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(revoke_resp.status(), StatusCode::OK);
    assert!(decode_and_verify_plugin_token(&token_1).is_err());
    let token_2 = fs::read_to_string(&token_path_1).unwrap();
    assert_ne!(token_1, token_2);
    assert!(decode_and_verify_plugin_token(&token_2).is_ok());

    // 3. Restart rotates runtime_id and invalidates prior runtime token
    let restart_resp = control_plugin_handler(
        Path("isolated-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "restart".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(restart_resp.status(), StatusCode::OK);
    let runtime_id_2 = ACTIVE_PROCESSES
        .lock()
        .unwrap()
        .get("isolated-demo")
        .unwrap()
        .runtime_id
        .to_string();
    assert_ne!(runtime_id_1, runtime_id_2);
    assert!(decode_and_verify_plugin_token(&token_2).is_err());

    // 4. Stop clears runner unit, wipes token dir, and disables plugin
    let stop_resp = control_plugin_handler(
        Path("isolated-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "stop".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(stop_resp.status(), StatusCode::OK);
    assert!(!tokens_root.join("isolated-demo").exists());
    assert!(!read_registry_state("isolated-demo").enabled);

    // 5. Rollback when runner fails to launch transient unit
    fs::write(&fail_flag, "1").unwrap();
    let failed_start = control_plugin_handler(
        Path("isolated-demo".into()),
        Extension(admin),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "start".into(),
            port: Some(21333),
        }),
    )
    .await;
    assert_eq!(failed_start.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let reg_after_fail = read_registry_state("isolated-demo");
    assert!(!reg_after_fail.enabled);
    assert_eq!(reg_after_fail.status, "error");
    assert_eq!(
        reg_after_fail.allocated_port, 21222,
        "failed start must restore previous allocated port"
    );
    assert!(!ACTIVE_PROCESSES
        .lock()
        .unwrap()
        .contains_key("isolated-demo"));

    runner_task.abort();
    let _ = fs::remove_file(&sock_path);
    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn external_plugin_backend_preserves_lifecycle_without_runner() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("external-plugin-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let plugin_dir = plugins_root.join("external-only");
    fs::create_dir_all(&plugin_dir).unwrap();
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        r#"{
            "id": "external-only",
            "name": "External Backend",
            "version": "1.0.0",
            "runtime_status": "external",
            "permissions": ["system:metrics:read"],
            "api_scopes": ["GET /api/v1/auth/system/metrics"],
            "backend": { "health_path": "/healthz" }
        }"#,
    )
    .unwrap();

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");

    let (manifests, rejected) = discover_plugins_in_dir(&plugins_root);
    assert!(rejected.is_empty());
    let manifest = manifests
        .into_iter()
        .find(|m| m.id == "external-only")
        .unwrap();

    let started = start_plugin_instance(&manifest).await.unwrap();
    assert!(started.enabled);
    assert_eq!(started.status, "running");
    assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&started.allocated_port));

    let (token, _) = mint_scoped_plugin_token(&manifest, Some(120)).unwrap();
    assert!(decode_and_verify_plugin_token(&token).is_ok());

    let stopped = stop_plugin_instance(&manifest).await.unwrap();
    assert!(!stopped.enabled);
    assert_eq!(stopped.status, "stopped");
    assert!(decode_and_verify_plugin_token(&token).is_err());

    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn external_plugin_reuses_listening_preferred_port_while_preserving_guards() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("external-port-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");

    for id in ["external-listening", "other-external"] {
        let plugin_dir = plugins_root.join(id);
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("plugin.manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "name": id,
                "version": "1.0.0",
                "runtime_status": "external",
                "permissions": ["system:metrics:read"],
                "api_scopes": ["GET /api/v1/auth/system/metrics"],
                "backend": { "health_path": "/healthz" }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    let mut bound = None;
    for candidate in (21500..=PLUGIN_PORT_RANGE_END).chain(PLUGIN_PORT_RANGE_START..21500) {
        if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", candidate)).await {
            bound = Some((candidate, listener));
            break;
        }
    }
    let (ext_port, listener) = bound.expect("bind loopback port in plugin range");
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/healthz",
            axum::routing::get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        );
        let _ = axum::serve(listener, app).await;
    });

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");

    let (manifests, rejected) = discover_plugins_in_dir(&plugins_root);
    assert!(rejected.is_empty(), "rejected={rejected:?}");
    let ext_manifest = manifests
        .iter()
        .find(|m| m.id == "external-listening")
        .unwrap()
        .clone();
    let other_manifest = manifests
        .iter()
        .find(|m| m.id == "other-external")
        .unwrap()
        .clone();

    // 1. Explicitly selected already-listening external port is honored and healthy.
    let started = start_plugin_instance_with_port(&ext_manifest, Some(ext_port))
        .await
        .unwrap();
    assert!(started.enabled);
    assert!(started.healthy);
    assert_eq!(started.allocated_port, ext_port);

    // 2. Stopping and re-starting without an explicit port honors the registered port.
    let stopped = stop_plugin_instance(&ext_manifest).await.unwrap();
    assert!(!stopped.enabled);
    assert_eq!(stopped.allocated_port, ext_port);

    let restarted = start_plugin_instance(&ext_manifest).await.unwrap();
    assert!(restarted.enabled);
    assert!(restarted.healthy);
    assert_eq!(restarted.allocated_port, ext_port);

    // 3. Another plugin cannot claim the same port registered to external-listening.
    let other_started = start_plugin_instance_with_port(&other_manifest, Some(ext_port))
        .await
        .unwrap();
    assert_ne!(other_started.allocated_port, ext_port);
    assert!(
        (PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&other_started.allocated_port)
    );

    // 4. Out-of-range preferred ports are never returned for external launches.
    let in_range_port = allocate_plugin_port("external-out-of-range", 19999, true).unwrap();
    assert_ne!(in_range_port, 19999);
    assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&in_range_port));

    // 5. Managed launches still enforce free-port binding and skip already-listening ports.
    let managed_port = allocate_plugin_port("external-listening", ext_port, false).unwrap();
    assert_ne!(managed_port, ext_port);
    assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&managed_port));

    let _ = stop_plugin_instance(&other_manifest).await;
    let _ = stop_plugin_instance(&ext_manifest).await;
    server.abort();
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[test]
fn resolve_plugin_executable_supports_sdk_template_manifest_path_and_backend_rs() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = env::temp_dir().join(format!("af-plugin-bin-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();

    let make_exec = |rel: &str| {
        let p = tmp.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    };

    let mut manifest = ValidatedPluginManifest {
        id: "bin-test".to_string(),
        name: "bin-test".to_string(),
        version: "1.0.0".to_string(),
        sdk: "rust".to_string(),
        contract_version: "v1".to_string(),
        runtime_status: "managed".to_string(),
        description: String::new(),
        author: String::new(),
        permissions: Vec::new(),
        granted_scopes: Vec::new(),
        lifecycle_hooks: PluginLifecycleHooks::default(),
        backend: PluginBackendSpec {
            manifest_path: "backend/Cargo.toml".to_string(),
            binary_name: "my-plugin-bin".to_string(),
            ..Default::default()
        },
        frontend: PluginFrontendSpec::default(),
        plugin_dir: tmp.clone(),
    };

    // 1. Fallback order from lowest to highest priority when manifest_path = "backend/Cargo.toml":
    // root <bin> -> bin/<bin> -> backend-rs/target/debug -> backend-rs/target/release -> backend/target/debug -> backend/target/release.
    let root_bin = make_exec("my-plugin-bin");
    assert_eq!(resolve_plugin_executable(&manifest).unwrap().0, root_bin);

    let bin_dir_bin = make_exec("bin/my-plugin-bin");
    assert_eq!(resolve_plugin_executable(&manifest).unwrap().0, bin_dir_bin);

    let debug_rs_bin = make_exec("backend-rs/target/debug/my-plugin-bin");
    assert_eq!(
        resolve_plugin_executable(&manifest).unwrap().0,
        debug_rs_bin
    );

    let release_rs_bin = make_exec("backend-rs/target/release/my-plugin-bin");
    assert_eq!(
        resolve_plugin_executable(&manifest).unwrap().0,
        release_rs_bin
    );

    let sdk_debug_bin = make_exec("backend/target/debug/my-plugin-bin");
    assert_eq!(
        resolve_plugin_executable(&manifest).unwrap().0,
        sdk_debug_bin
    );

    let sdk_release_bin = make_exec("backend/target/release/my-plugin-bin");
    assert_eq!(
        resolve_plugin_executable(&manifest).unwrap().0,
        sdk_release_bin
    );

    // Clearing binary_name skips candidate resolution.
    manifest.backend.binary_name.clear();
    assert!(resolve_plugin_executable(&manifest).is_none());

    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[tokio::test]
async fn reconcile_startup_and_graceful_shutdown_preserve_enabled_and_reap_orphans() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("reconcile-shutdown-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("tokens");
    let state_dir = tmp.join("units");
    fs::create_dir_all(&state_dir).unwrap();

    for id in ["auto-demo", "orphan-demo"] {
        let pdir = plugins_root.join(id);
        let hdir = pdir.join("backend/hooks");
        fs::create_dir_all(&hdir).unwrap();
        fs::set_permissions(&pdir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(pdir.join("backend"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&hdir, fs::Permissions::from_mode(0o755)).unwrap();
        let sh = hdir.join("start.sh");
        fs::write(&sh, "#!/bin/bash\nexit 0\n").unwrap();
        fs::set_permissions(&sh, fs::Permissions::from_mode(0o755)).unwrap();
        let manifest = serde_json::json!({
            "id": id,
            "name": id,
            "version": "1.0.0",
            "lifecycle_hooks": { "on_start": "backend/hooks/start.sh" },
            "backend": { "health_path": "/healthz" }
        });
        fs::write(
            pdir.join("plugin.manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }
    fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();

    let fake_sdrun = tmp.join("fake-sdrun");
    fs::write(
        &fake_sdrun,
        format!(
            r#"#!/bin/bash
set -euo pipefail
unit=""
for arg in "$@"; do
  case "$arg" in
--unit=*) unit="${{arg#--unit=}}" ;;
  esac
done
echo active > {dir:?}/"$unit"
"#,
            dir = state_dir
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

    let fake_sdctl = tmp.join("fake-sdctl");
    fs::write(
        &fake_sdctl,
        format!(
            r#"#!/bin/bash
set -euo pipefail
cmd="${{1:-}}"
unit="${{@: -1}}"
case "$cmd" in
  show)
st="inactive"
if [[ -f {dir:?}/"$unit" ]]; then st="$(cat {dir:?}/"$unit")"; fi
echo "ActiveState=$st"
echo "SubState=running"
echo "MainPID=0"
echo "UID=62555"
echo "GID=62555"
;;
  stop)
echo inactive > {dir:?}/"$unit"
;;
  reset-failed)
;;
esac
"#,
            dir = state_dir
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

    // Simulate a stale orphaned unit for disabled plugin `orphan-demo`, while `auto-demo` is enabled in DB.
    fs::write(
        state_dir.join("aetherflow-plugin-orphan-demo.service"),
        "active\n",
    )
    .unwrap();
    update_registry_state("auto-demo", true, 21401, "running", "", false);
    update_registry_state("orphan-demo", false, 21402, "stopped", "", false);

    let sock_path = env::temp_dir().join(format!(
        "af-plg-{}.sock",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let runner_app = af_runner::build_runner_router();
    let runner_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            let svc = TowerToHyperService::new(runner_app.clone());
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");

    reconcile_managed_plugins_on_startup().await;

    assert_eq!(
        fs::read_to_string(state_dir.join("aetherflow-plugin-auto-demo.service"))
            .unwrap()
            .trim(),
        "active"
    );
    assert_eq!(
        fs::read_to_string(state_dir.join("aetherflow-plugin-orphan-demo.service"))
            .unwrap()
            .trim(),
        "inactive",
        "disabled plugin's orphaned unit must be reaped on startup"
    );
    assert!(ACTIVE_PROCESSES.lock().unwrap().contains_key("auto-demo"));

    // Graceful shutdown stops active unit via runner while preserving enabled=true in SQLite
    shutdown_managed_plugins().await;
    assert_eq!(
        fs::read_to_string(state_dir.join("aetherflow-plugin-auto-demo.service"))
            .unwrap()
            .trim(),
        "inactive"
    );
    assert!(!ACTIVE_PROCESSES.lock().unwrap().contains_key("auto-demo"));
    assert!(
        read_registry_state("auto-demo").enabled,
        "graceful shutdown must preserve enabled=true so next startup auto-starts the plugin"
    );
    assert!(!tokens_root.join("auto-demo").exists());

    runner_task.abort();
    let _ = fs::remove_file(&sock_path);
    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn plugin_registry_db_errors_fail_with_500_instead_of_200_or_silent_defaults() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("plugin-db-error-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let plugin_dir = plugins_root.join("db-err-demo");
    fs::create_dir_all(&plugin_dir).unwrap();
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        r#"{
            "id": "db-err-demo",
            "name": "DB Error Demo",
            "version": "1.0.0",
            "runtime_status": "external",
            "permissions": ["system:metrics:read"],
            "api_scopes": ["GET /api/v1/auth/system/metrics"],
            "backend": { "health_path": "/healthz" }
        }"#,
    )
    .unwrap();
    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);

    let conn = af_db::get_conn().unwrap();
    conn.execute("DROP TABLE plugins_registry", []).unwrap();
    drop(conn);

    let admin = AuthUser {
        user_id: 1,
        username: "admin".into(),
        role: "admin".into(),
        jti: "op-db-err".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // 1. list_plugins_handler must return 500 PLUGIN_REGISTRY_ERROR (never 200 with fake stopped plugins)
    let list_resp = list_plugins_handler(Extension(admin.clone())).await;
    assert_eq!(list_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let list_body = axum::body::to_bytes(list_resp.into_body(), 4096)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&list_body).contains("PLUGIN_REGISTRY_ERROR"));

    // 2. control_plugin_handler revoke_tokens must return 500 when token_epoch cannot be persisted
    let revoke_resp = control_plugin_handler(
        Path("db-err-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        Json(PluginControlRequest {
            action: "revoke_tokens".into(),
            port: None,
        }),
    )
    .await;
    assert_eq!(revoke_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // 3. serve_plugin_ui_handler must return 500 PLUGIN_REGISTRY_ERROR (never 403 PLUGIN_DISABLED)
    let ui_resp =
        serve_plugin_ui_handler(Path("db-err-demo".into()), Extension(admin.clone())).await;
    assert_eq!(ui_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // 4. mint_plugin_token_handler must return 500 PLUGIN_REGISTRY_ERROR (never 409 PLUGIN_NOT_ENABLED)
    let mint_resp = mint_plugin_token_handler(
        Path("db-err-demo".into()),
        Extension(admin.clone()),
        HeaderMap::new(),
        None,
    )
    .await;
    assert_eq!(mint_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // 5. proxy_plugin_root_handler must return 500 PLUGIN_REGISTRY_ERROR (never 503 PLUGIN_STOPPED)
    let proxy_req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let proxy_resp =
        proxy_plugin_root_handler(Path("db-err-demo".into()), Extension(admin), proxy_req).await;
    assert_eq!(proxy_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // 6. allocate_plugin_port must fail closed instead of allocating with an empty used_ports set
    assert!(allocate_plugin_port("db-err-demo", 21050, false).is_err());

    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn default_sandboxed_plugin_ui_uses_wildcard_postmessage_target_origin() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("plugin-ui-postmsg-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let plugin_dir = plugins_root.join("ui-demo");
    fs::create_dir_all(&plugin_dir).unwrap();
    fs::write(
        plugin_dir.join("plugin.manifest.json"),
        r#"{
            "id": "ui-demo",
            "name": "UI Demo",
            "version": "1.0.0",
            "runtime_status": "external",
            "permissions": ["system:metrics:read"],
            "api_scopes": ["GET /api/v1/auth/system/metrics"],
            "backend": { "health_path": "/healthz" }
        }"#,
    )
    .unwrap();
    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    update_registry_state("ui-demo", true, 21455, "running", "", false);

    let user = AuthUser {
        user_id: 1,
        username: "viewer".into(),
        role: "user".into(),
        jti: "op-ui-demo".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let resp = serve_plugin_ui_handler(Path("ui-demo".into()), Extension(user)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp
        .headers()
        .get("Content-Security-Policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("sandbox allow-scripts"), "csp={csp}");
    let body = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        !html.contains("window.location.origin"),
        "sandboxed iframe with opaque null origin must not pass window.location.origin to postMessage"
    );
    assert!(html.contains("window.parent.postMessage({ type: 'AF_PLUGIN_READY', pluginId }, '*');"));
    assert!(html.contains("method: 'GET'\n      }, '*');"));

    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[tokio::test]
async fn startup_reconciliation_skips_orphan_reaping_on_registry_db_error() {
    if run_plugin_test_in_subprocess() {
        return;
    }
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = test_env_lock().lock().await;
    let db = ensure_shared_test_db();
    let tmp = db
        .parent()
        .unwrap()
        .join(format!("reconcile-db-err-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("tokens");
    let state_dir = tmp.join("units");
    fs::create_dir_all(&state_dir).unwrap();

    let pdir = plugins_root.join("active-demo");
    let hdir = pdir.join("backend/hooks");
    fs::create_dir_all(&hdir).unwrap();
    fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&pdir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(pdir.join("backend"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&hdir, fs::Permissions::from_mode(0o755)).unwrap();
    let sh = hdir.join("start.sh");
    fs::write(&sh, "#!/bin/bash\nexit 0\n").unwrap();
    fs::set_permissions(&sh, fs::Permissions::from_mode(0o755)).unwrap();
    let manifest = serde_json::json!({
        "id": "active-demo",
        "name": "Active Demo",
        "version": "1.0.0",
        "lifecycle_hooks": { "on_start": "backend/hooks/start.sh" },
        "backend": { "health_path": "/healthz" }
    });
    fs::write(
        pdir.join("plugin.manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fake_sdctl = tmp.join("fake-sdctl");
    fs::write(
        &fake_sdctl,
        format!(
            r#"#!/bin/bash
set -euo pipefail
cmd="${{1:-}}"
unit="${{@: -1}}"
case "$cmd" in
  show)
st="inactive"
if [[ -f {dir:?}/"$unit" ]]; then st="$(cat {dir:?}/"$unit")"; fi
echo "ActiveState=$st"
echo "SubState=running"
echo "MainPID=0"
echo "UID=62555"
echo "GID=62555"
;;
  stop)
echo inactive > {dir:?}/"$unit"
;;
  reset-failed)
;;
esac
"#,
            dir = state_dir
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

    let unit_state_path = state_dir.join("aetherflow-plugin-active-demo.service");
    fs::write(&unit_state_path, "active\n").unwrap();

    // Break plugins_registry so startup reconciliation cannot read registry state.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE plugins_registry", []).unwrap();
    }

    let sock_path = env::temp_dir().join(format!(
        "af-plg-{}.sock",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let runner_app = af_runner::build_runner_router();
    let runner_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            let svc = TowerToHyperService::new(runner_app.clone());
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");

    reconcile_managed_plugins_on_startup().await;

    assert_eq!(
        fs::read_to_string(&unit_state_path).unwrap().trim(),
        "active",
        "DB read error during startup reconciliation must skip orphan reaping rather than stopping an active plugin"
    );

    runner_task.abort();
    let _ = fs::remove_file(&sock_path);
    let _ = fs::remove_dir_all(&tmp);
}
