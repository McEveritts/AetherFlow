use af_models::{
    PluginRunnerStartRequest, PluginRunnerStatusRequest, PluginRunnerStatusResponse,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest,
};
use axum::http::StatusCode;
use axum::{Extension, Json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::RunnerPeerCred;

use super::isolation::{
    build_plugin_start_systemd_run_args, collect_control_plane_inaccessible_paths,
    verify_isolated_identity, write_staged_plugin_token, UnitShowProps,
};
use super::manifest::{
    load_verified_plugin_spec, validate_plugin_id, validate_plugin_token, validate_port,
};
use super::*;

fn write_fixture_plugin(root: &Path, plugin_id: &str, with_stop_hook: bool) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let plugin_dir = root.join(plugin_id);
    let hooks_dir = plugin_dir.join("backend/hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
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

    let mut hooks = serde_json::json!({
        "on_start": "backend/hooks/start.sh"
    });
    if with_stop_hook {
        let stop_hook = hooks_dir.join("stop.sh");
        fs::write(&stop_hook, "#!/bin/bash\nexit 0\n").unwrap();
        fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();
        hooks["on_stop"] = serde_json::json!("backend/hooks/stop.sh");
    }

    let manifest = serde_json::json!({
        "id": plugin_id,
        "name": "Fixture Plugin",
        "version": "1.2.3",
        "lifecycle_hooks": hooks,
        "backend": {
            "health_path": "/healthz"
        }
    });
    let manifest_path = plugin_dir.join("plugin.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
    plugin_dir
}

#[test]
fn request_debug_redacts_plugin_tokens() {
    let start_req = PluginRunnerStartRequest {
        plugin_id: "demo-plugin".into(),
        port: 21001,
        runtime_id: Uuid::new_v4().to_string(),
        api_base_url: "http://127.0.0.1:8080".into(),
        initial_token: "super-secret-jwt-value".into(),
    };
    let rendered = format!("{start_req:?}");
    assert!(!rendered.contains("super-secret-jwt-value"));
    assert!(rendered.contains("[REDACTED]"));

    let rotate_req = PluginRunnerTokenRotateRequest {
        plugin_id: "demo-plugin".into(),
        runtime_id: Uuid::new_v4().to_string(),
        token: "another-secret-jwt-value".into(),
    };
    let rendered_rot = format!("{rotate_req:?}");
    assert!(!rendered_rot.contains("another-secret-jwt-value"));
    assert!(rendered_rot.contains("[REDACTED]"));
}

#[test]
fn validates_loopback_api_base_url_and_rejects_external_or_malformed_inputs() {
    assert_eq!(
        validate_loopback_api_base_url("http://127.0.0.1:8080/").unwrap(),
        "http://127.0.0.1:8080"
    );
    assert_eq!(
        validate_loopback_api_base_url("http://[::1]:8080").unwrap(),
        "http://[::1]:8080"
    );
    assert_eq!(
        validate_loopback_api_base_url("http://localhost:18080").unwrap(),
        "http://localhost:18080"
    );
    for bad in [
        "",
        "http://169.254.169.254:80",
        "http://example.com:8080",
        "http://127.0.0.1:8080/api",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080?x=1",
        "http://127.0.0.1:0",
        "file:///etc/passwd",
        "http://127.0.0.1:8080\nINJECT=1",
    ] {
        assert!(
            validate_loopback_api_base_url(bad).is_err(),
            "expected rejection for {bad:?}"
        );
    }
}

#[test]
fn rejects_invalid_ids_ports_tokens_and_symlink_manifests() {
    assert!(validate_plugin_id("../escape").is_err());
    assert!(validate_plugin_id("sdk-template-rust").is_err());
    assert!(validate_plugin_id("BadUpper").is_err());
    assert!(validate_port(8080).is_err());
    assert!(validate_port(20999).is_err());
    assert!(validate_port(22000).is_err());
    assert!(validate_plugin_token("").is_err());
    assert!(validate_plugin_token("abc\ndef").is_err());
    assert!(validate_plugin_token("abc def").is_err());
    assert!(validate_plugin_token("abc;id").is_err());
    assert!(validate_plugin_token("eyJhbGciOiJIUzI1NiJ9.payload.sig_1-2").is_ok());
}

#[cfg(unix)]
#[test]
fn systemd_run_args_enforce_isolation_and_keep_credentials_out_of_argv() {
    let tmp = env::temp_dir().join(format!("af-runner-plugin-args-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("tokens");
    let plugin_dir = write_fixture_plugin(&plugins_root, "telemetry-fixture", true);
    let sibling_dir = write_fixture_plugin(&plugins_root, "other-plugin", false);

    let _env_guard = crate::ENV_TEST_MUTEX.blocking_lock();
    let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);

    let spec = load_verified_plugin_spec("telemetry-fixture").unwrap();
    let runtime_id = Uuid::new_v4().to_string();
    let token_secret = "eyJhbGciOiJIUzI1NiJ9.fixture_secret_payload.signature123";
    let runtime_token_dir = write_staged_plugin_token(
        &tokens_root,
        "telemetry-fixture",
        &runtime_id,
        token_secret,
        false,
    )
    .unwrap();

    let args = build_plugin_start_systemd_run_args(
        "aetherflow-plugin-telemetry-fixture.service",
        &spec,
        21042,
        &runtime_id,
        "http://127.0.0.1:8080",
        &runtime_token_dir,
        &tokens_root,
    )
    .unwrap();

    if let Some(v) = prev_plugins {
        env::set_var("AETHERFLOW_PLUGINS_DIR", v);
    } else {
        env::remove_var("AETHERFLOW_PLUGINS_DIR");
    }

    let joined = args.join("\n");
    assert!(args.iter().any(|a| a == "--property=DynamicUser=yes"));
    assert!(args.iter().any(|a| a == "--property=SupplementaryGroups="));
    assert!(args.iter().any(|a| a == "--property=ProtectSystem=strict"));
    assert!(args.iter().any(|a| a == "--property=ProtectHome=yes"));
    assert!(args.iter().any(|a| a == "--property=PrivateTmp=yes"));
    assert!(args.iter().any(|a| a == "--property=PrivateDevices=yes"));
    assert!(args.iter().any(|a| a == "--property=NoNewPrivileges=yes"));
    assert!(args
        .iter()
        .any(|a| a == "--property=CapabilityBoundingSet="));
    assert!(args.iter().any(|a| a == "--property=ProtectProc=invisible"));
    assert!(args
        .iter()
        .any(|a| a == "--property=StateDirectory=aetherflow-plugin-telemetry-fixture"));
    assert!(args
        .iter()
        .any(|a| a == "--property=StateDirectoryMode=0700"));
    assert!(args
        .iter()
        .any(|a| a == "--property=InaccessiblePaths=-/var/lib/aetherflow"));
    assert!(args
        .iter()
        .any(|a| a == "--property=InaccessiblePaths=-/etc/aetherflow"));
    assert!(args
        .iter()
        .any(|a| a == "--property=InaccessiblePaths=-/run/aetherflow"));
    assert!(args
        .iter()
        .any(|a| a == "--property=InaccessiblePaths=-/var/log/aetherflow"));
    let default_inaccessible = collect_control_plane_inaccessible_paths(
        &fs::canonicalize(&plugin_dir).unwrap(),
        Some(&runtime_token_dir),
        Path::new(DEFAULT_PLUGIN_TOKENS_ROOT),
    );
    assert!(
        default_inaccessible
            .iter()
            .any(|p| p == DEFAULT_PLUGIN_TOKENS_ROOT),
        "default tokens root must be masked in InaccessiblePaths: {default_inaccessible:?}"
    );
    assert!(args.iter().any(|a| a
        == &format!(
            "--property=InaccessiblePaths=-{}",
            fs::canonicalize(&sibling_dir).unwrap().display()
        )));
    assert!(args.iter().any(|a| a
        == &format!(
            "--property=BindReadOnlyPaths={}:{PLUGIN_APP_MOUNT_POINT}",
            fs::canonicalize(&plugin_dir).unwrap().display()
        )));
    assert!(args.iter().any(|a| a
        == &format!(
            "--property=BindReadOnlyPaths={}:{PLUGIN_TOKEN_MOUNT_POINT}",
            runtime_token_dir.display()
        )));
    assert!(args.iter().any(|a| a
        == &format!(
            "--property=ExecStop=/bin/bash {PLUGIN_APP_MOUNT_POINT}/backend/hooks/stop.sh"
        )));
    assert!(args
        .iter()
        .any(|a| a
            == &format!("--setenv=AETHERFLOW_PLUGIN_TOKEN_FILE={PLUGIN_TOKEN_FILE_IN_SANDBOX}")));
    assert!(
        !joined.contains(token_secret),
        "Plugin runtime token MUST NEVER appear in systemd-run argv!"
    );
    assert!(
        !joined.contains("AETHERFLOW_PLUGIN_TOKEN="),
        "Raw AETHERFLOW_PLUGIN_TOKEN env var must not be passed in argv!"
    );
    assert_eq!(
        fs::read_to_string(runtime_token_dir.join("runtime.token")).unwrap(),
        token_secret
    );
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[test]
fn staged_token_replacement_is_atomic_private_and_rejects_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let tmp = env::temp_dir().join(format!("af-runner-token-stage-{}", Uuid::new_v4()));
    let tokens_root = tmp.join("tokens");
    let rid = Uuid::new_v4().to_string();

    let runtime_dir =
        write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.one.sig", false)
            .unwrap();
    assert_eq!(
        fs::metadata(&tokens_root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(tokens_root.join("demo-plugin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let token_path = runtime_dir.join("runtime.token");
    assert_eq!(
        fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
        0o444
    );

    let mut old_reader = fs::File::open(&token_path).unwrap();
    write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.two.sig", true).unwrap();
    let mut old_val = String::new();
    std::io::Read::read_to_string(&mut old_reader, &mut old_val).unwrap();
    assert_eq!(old_val, "token.one.sig");
    assert_eq!(fs::read_to_string(&token_path).unwrap(), "token.two.sig");

    // Symlink at token_path is atomically replaced without modifying symlink target.
    let sentinel = tmp.join("sentinel");
    fs::write(&sentinel, "untouched").unwrap();
    fs::remove_file(&token_path).unwrap();
    symlink(&sentinel, &token_path).unwrap();
    write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.three.sig", true).unwrap();
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "untouched");
    assert!(!fs::symlink_metadata(&token_path).unwrap().is_symlink());

    // Symlink root directory is rejected fail-closed.
    let link_root = tmp.join("linked-root");
    symlink(&tokens_root, &link_root).unwrap();
    assert!(
        write_staged_plugin_token(&link_root, "demo-plugin", &rid, "token.four.sig", false)
            .is_err()
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn verify_isolated_identity_rejects_root_and_api_caller_uid_gid() {
    let peer = Some(RunnerPeerCred {
        uid: 1001,
        gid: 1001,
        pid: Some(4242),
    });
    assert!(verify_isolated_identity(
        &UnitShowProps {
            uid: Some(0),
            gid: Some(61234),
            ..Default::default()
        },
        peer,
        true
    )
    .is_err());
    assert!(verify_isolated_identity(
        &UnitShowProps {
            uid: Some(1001),
            gid: Some(61234),
            ..Default::default()
        },
        peer,
        true
    )
    .is_err());
    assert!(verify_isolated_identity(
        &UnitShowProps {
            uid: Some(61234),
            gid: Some(1001),
            ..Default::default()
        },
        peer,
        true
    )
    .is_err());
    assert!(verify_isolated_identity(
        &UnitShowProps {
            uid: None,
            gid: None,
            ..Default::default()
        },
        peer,
        true
    )
    .is_err());
    assert!(verify_isolated_identity(
        &UnitShowProps {
            uid: Some(61234),
            gid: Some(61234),
            ..Default::default()
        },
        peer,
        true
    )
    .is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn handler_start_rotate_status_stop_and_identity_fail_closed_with_shims() {
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let tmp = env::temp_dir().join(format!("af-runner-plugin-e2e-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("tokens");
    let state_file = tmp.join("unit.state");
    let args_log = tmp.join("systemd-run.log");
    let _plugin_dir = write_fixture_plugin(&plugins_root, "fixture-demo", true);

    let fake_systemd_run = tmp.join("fake-systemd-run");
    fs::write(
        &fake_systemd_run,
        format!(
            "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" >> {:?}\necho active > {:?}\n",
            args_log, state_file
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();

    let uid_file = tmp.join("unit.uid");
    fs::write(&uid_file, "62100\n").unwrap();
    let fake_systemctl = tmp.join("fake-systemctl");
    fs::write(
        &fake_systemctl,
        format!(
            r#"#!/bin/bash
set -euo pipefail
cmd="${{1:-}}"
case "$cmd" in
  show)
    st="inactive"
    if [[ -f {state:?} ]]; then st="$(cat {state:?})"; fi
    uid="$(cat {uid:?})"
    echo "ActiveState=$st"
    echo "SubState=running"
    echo "MainPID=0"
    echo "UID=$uid"
    echo "GID=$uid"
    ;;
  stop)
    echo inactive > {state:?}
    ;;
  reset-failed)
    ;;
esac
"#,
            state = state_file,
            uid = uid_file
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
    let prev_tokens = env::var_os("AETHERFLOW_PLUGIN_TOKENS_ROOT");
    let prev_sdrun = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
    let prev_sdctl = env::var_os("AETHERFLOW_SYSTEMCTL_BIN");
    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_systemd_run);
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_systemctl);

    let rid = Uuid::new_v4().to_string();
    let peer = Some(Extension(RunnerPeerCred {
        uid: 1001,
        gid: 1001,
        pid: Some(123),
    }));

    // 1. Start succeeds when unit reports independent DynamicUser UID/GID (62100 != 1001)
    let (code, Json(resp)) = handle_plugin_start(
        peer,
        Json(PluginRunnerStartRequest {
            plugin_id: "fixture-demo".into(),
            port: 21055,
            runtime_id: rid.clone(),
            api_base_url: "http://127.0.0.1:8080".into(),
            initial_token: "hdr.initial_secret.sig".into(),
        }),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "resp={resp:?}");
    assert!(resp.success);
    let parsed: PluginRunnerStatusResponse = serde_json::from_str(&resp.output).unwrap();
    assert!(parsed.active);
    assert_eq!(parsed.uid, Some(62100));
    let logged_argv = fs::read_to_string(&args_log).unwrap();
    assert!(!logged_argv.contains("hdr.initial_secret.sig"));

    // 2. Token rotation updates staged runtime.token atomically
    let (rot_code, Json(rot_resp)) =
        handle_plugin_token_rotate(Json(PluginRunnerTokenRotateRequest {
            plugin_id: "fixture-demo".into(),
            runtime_id: rid.clone(),
            token: "hdr.rotated_secret.sig".into(),
        }))
        .await;
    assert_eq!(rot_code, StatusCode::OK, "rot_resp={rot_resp:?}");
    assert_eq!(
        fs::read_to_string(
            tokens_root
                .join("fixture-demo")
                .join(&rid)
                .join("runtime.token")
        )
        .unwrap(),
        "hdr.rotated_secret.sig"
    );

    // 3. Status reports active
    let (st_code, Json(st_resp)) = handle_plugin_status(Json(PluginRunnerStatusRequest {
        plugin_id: "fixture-demo".into(),
        runtime_id: Some(rid.clone()),
    }))
    .await;
    assert_eq!(st_code, StatusCode::OK);
    let st_parsed: PluginRunnerStatusResponse = serde_json::from_str(&st_resp.output).unwrap();
    assert!(st_parsed.active);

    // 4. Stop clears active unit and wipes token directory
    let (stop_code, Json(stop_resp)) = handle_plugin_stop(Json(PluginRunnerStopRequest {
        plugin_id: "fixture-demo".into(),
        port: 21055,
        runtime_id: Some(rid.clone()),
        api_base_url: "http://127.0.0.1:8080".into(),
        run_stop_hook: true,
    }))
    .await;
    assert_eq!(stop_code, StatusCode::OK, "stop_resp={stop_resp:?}");
    assert!(!tokens_root.join("fixture-demo").exists());

    // 5. If unit ever reports API caller UID (1001), runner stops it and fails closed!
    fs::write(&uid_file, "1001\n").unwrap();
    let (bad_code, Json(bad_resp)) = handle_plugin_start(
        Some(Extension(RunnerPeerCred {
            uid: 1001,
            gid: 1001,
            pid: Some(123),
        })),
        Json(PluginRunnerStartRequest {
            plugin_id: "fixture-demo".into(),
            port: 21055,
            runtime_id: Uuid::new_v4().to_string(),
            api_base_url: "http://127.0.0.1:8080".into(),
            initial_token: "hdr.blocked_secret.sig".into(),
        }),
    )
    .await;
    assert_eq!(bad_code, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!bad_resp.success);
    assert!(bad_resp.error.contains("matches API caller OS uid"));
    assert!(!tokens_root.join("fixture-demo").exists());
    assert_eq!(fs::read_to_string(&state_file).unwrap().trim(), "inactive");

    for (k, v) in [
        ("AETHERFLOW_PLUGINS_DIR", prev_plugins),
        ("AETHERFLOW_PLUGIN_TOKENS_ROOT", prev_tokens),
        ("AETHERFLOW_SYSTEMD_RUN_BIN", prev_sdrun),
        ("AETHERFLOW_SYSTEMCTL_BIN", prev_sdctl),
    ] {
        if let Some(val) = v {
            env::set_var(k, val);
        } else {
            env::remove_var(k);
        }
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[tokio::test]
async fn handler_reports_503_when_isolation_unavailable_and_runs_oneshot_stop_hook() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    let tmp = env::temp_dir().join(format!("af-runner-plugin-503-{}", Uuid::new_v4()));
    let plugins_root = tmp.join("plugins");
    let tokens_root = tmp.join("tokens");
    let _plugin_dir = write_fixture_plugin(&plugins_root, "stop-fixture", true);

    // Symlinked on_start must be rejected fail-closed.
    let bad_dir = write_fixture_plugin(&plugins_root, "symlink-fixture", false);
    let outside = tmp.join("outside.sh");
    fs::write(&outside, "#!/bin/bash\nexit 0\n").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
    let bad_start = bad_dir.join("backend/hooks/start.sh");
    fs::remove_file(&bad_start).unwrap();
    symlink(&outside, &bad_start).unwrap();

    let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
    let prev_tokens = env::var_os("AETHERFLOW_PLUGIN_TOKENS_ROOT");
    let prev_sdrun = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
    let prev_sdctl = env::var_os("AETHERFLOW_SYSTEMCTL_BIN");
    env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
    env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);

    // 1. Missing systemd-run binary -> 503 SERVICE_UNAVAILABLE with actionable message
    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", tmp.join("missing-sdrun"));
    let (code, Json(resp)) = handle_plugin_start(
        None,
        Json(PluginRunnerStartRequest {
            plugin_id: "stop-fixture".into(),
            port: 21060,
            runtime_id: Uuid::new_v4().to_string(),
            api_base_url: "http://127.0.0.1:8080".into(),
            initial_token: "hdr.tok.sig".into(),
        }),
    )
    .await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.error.contains("systemd-run"));

    // 2. Non-root without override -> 503 SERVICE_UNAVAILABLE
    if unsafe { libc::geteuid() } != 0 {
        env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN");
        env::remove_var("AETHERFLOW_SYSTEMCTL_BIN");
        let (nr_code, Json(nr_resp)) = handle_plugin_start(
            None,
            Json(PluginRunnerStartRequest {
                plugin_id: "stop-fixture".into(),
                port: 21060,
                runtime_id: Uuid::new_v4().to_string(),
                api_base_url: "http://127.0.0.1:8080".into(),
                initial_token: "hdr.tok.sig".into(),
            }),
        )
        .await;
        assert_eq!(nr_code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            nr_resp.error.contains("DynamicUser=yes")
                || nr_resp.error.contains("systemd-run")
                || nr_resp.error.contains("systemctl"),
            "nr_resp={nr_resp:?}"
        );
    }

    // 3. Symlinked on_start hook rejected with 400 BAD_REQUEST; inactive stop runs isolated oneshot stop unit
    let stop_args_log = tmp.join("stop-hook-args.log");
    let fake_sdrun = tmp.join("fake-sdrun");
    fs::write(
        &fake_sdrun,
        format!(
            "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > {:?}\n",
            stop_args_log
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

    let fake_sdctl = tmp.join("fake-sdctl");
    fs::write(
        &fake_sdctl,
        "#!/bin/bash\nset -euo pipefail\nif [[ \"${1:-}\" == \"show\" ]]; then echo ActiveState=inactive; echo SubState=dead; fi\n",
    )
    .unwrap();
    fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

    env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
    env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);

    let (sym_code, Json(sym_resp)) = handle_plugin_start(
        None,
        Json(PluginRunnerStartRequest {
            plugin_id: "symlink-fixture".into(),
            port: 21061,
            runtime_id: Uuid::new_v4().to_string(),
            api_base_url: "http://127.0.0.1:8080".into(),
            initial_token: "hdr.tok.sig".into(),
        }),
    )
    .await;
    assert_eq!(sym_code, StatusCode::BAD_REQUEST, "sym_resp={sym_resp:?}");
    assert!(sym_resp.error.contains("Symbolic link"));

    let (stop_code, Json(stop_resp)) = handle_plugin_stop(Json(PluginRunnerStopRequest {
        plugin_id: "stop-fixture".into(),
        port: 21060,
        runtime_id: None,
        api_base_url: "http://127.0.0.1:8080".into(),
        run_stop_hook: true,
    }))
    .await;
    assert_eq!(stop_code, StatusCode::OK, "stop_resp={stop_resp:?}");
    let stop_argv = fs::read_to_string(&stop_args_log).unwrap();
    assert!(stop_argv.contains("--unit=aetherflow-plugin-stop-fixture-stop.service"));
    assert!(stop_argv.contains("--property=DynamicUser=yes"));
    assert!(stop_argv.contains("--property=Type=oneshot"));
    assert!(stop_argv.contains("--property=InaccessiblePaths=-/var/lib/aetherflow"));
    assert!(stop_argv.contains("/run/aetherflow-plugin-app/backend/hooks/stop.sh"));

    for (k, v) in [
        ("AETHERFLOW_PLUGINS_DIR", prev_plugins),
        ("AETHERFLOW_PLUGIN_TOKENS_ROOT", prev_tokens),
        ("AETHERFLOW_SYSTEMD_RUN_BIN", prev_sdrun),
        ("AETHERFLOW_SYSTEMCTL_BIN", prev_sdctl),
    ] {
        if let Some(val) = v {
            env::set_var(k, val);
        } else {
            env::remove_var(k);
        }
    }
    let _ = fs::remove_dir_all(&tmp);
}
