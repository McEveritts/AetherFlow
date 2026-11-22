use af_models::{
    plugin_stop_hook_unit_name, plugin_systemd_unit_name, PluginRunnerStartRequest,
    PluginRunnerStatusRequest, PluginRunnerStatusResponse, PluginRunnerStopRequest,
    PluginRunnerTokenRotateRequest, RunnerResponse,
};
use axum::http::StatusCode;
use axum::{Extension, Json};
use std::fs;
use std::time::Duration;
use tokio::process::Command;

use crate::RunnerPeerCred;

use super::isolation::{
    build_plugin_start_systemd_run_args, build_plugin_stop_hook_systemd_run_args,
    cleanup_plugin_tokens, ensure_host_mountpoints, query_unit_properties, stop_and_reset_unit,
    verify_isolated_identity, write_staged_plugin_token,
};
use super::manifest::{
    load_verified_plugin_spec, validate_loopback_api_base_url, validate_plugin_id,
    validate_plugin_token, validate_port, validate_runtime_id,
};
use super::{
    ensure_systemd_isolation_ready, plugin_lock, resolve_plugin_tokens_root,
    using_custom_systemd_run_override, PluginRunnerError,
};

pub async fn handle_plugin_start(
    peer: Option<Extension<RunnerPeerCred>>,
    Json(req): Json<PluginRunnerStartRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_start_inner(peer.map(|Extension(c)| c), req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_start_inner(
    peer: Option<RunnerPeerCred>,
    req: PluginRunnerStartRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let port = validate_port(req.port)?;
    let runtime_id = validate_runtime_id(&req.runtime_id)?;
    let api_base_url = validate_loopback_api_base_url(&req.api_base_url)?;
    validate_plugin_token(&req.initial_token)?;

    let (systemd_run, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let spec = load_verified_plugin_spec(&plugin_id)?;
    if spec.start_target.is_none() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no managed backend executable or on_start hook",
            spec.id
        )));
    }
    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let tokens_root = resolve_plugin_tokens_root()?;

    ensure_host_mountpoints()?;

    // Ensure no stale unit instance remains before staging the fresh runtime.
    let _ = stop_and_reset_unit(&systemctl, &unit_name).await;

    let runtime_token_dir = write_staged_plugin_token(
        &tokens_root,
        &plugin_id,
        &runtime_id,
        &req.initial_token,
        false,
    )?;

    let args = match build_plugin_start_systemd_run_args(
        &unit_name,
        &spec,
        port,
        &runtime_id,
        &api_base_url,
        &runtime_token_dir,
        &tokens_root,
    ) {
        Ok(args) => args,
        Err(err) => {
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(err);
        }
    };

    let launch_res = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(&systemd_run)
            .args(&args)
            .kill_on_drop(true)
            .output(),
    )
    .await;

    match launch_res {
        Ok(Ok(out)) if out.status.success() => {}
        Ok(Ok(out)) => {
            let detail = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            let sanitized = detail.trim();
            let lower = sanitized.to_ascii_lowercase();
            if lower.contains("failed to connect to bus")
                || lower.contains("system has not been booted with systemd")
                || lower.contains("interactive authentication required")
            {
                return Err(PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: systemd manager rejected transient unit '{unit_name}': {sanitized}"
                )));
            }
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to start isolated plugin unit '{unit_name}': {sanitized}"
            )));
        }
        Ok(Err(err)) => {
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to execute systemd-run for '{unit_name}': {err}"
            )));
        }
        Err(_) => {
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(PluginRunnerError::Runtime(format!(
                "Timed out launching isolated plugin unit '{unit_name}'"
            )));
        }
    }

    let props = match query_unit_properties(&systemctl, &unit_name).await {
        Ok(props) => props,
        Err(err) => {
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(err);
        }
    };

    let strict_identity = !using_custom_systemd_run_override();
    if let Err(err) = verify_isolated_identity(&props, peer, strict_identity) {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        cleanup_plugin_tokens(&tokens_root, &plugin_id);
        return Err(err);
    }

    let active = matches!(props.active_state.as_str(), "active" | "activating");
    if !active {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        cleanup_plugin_tokens(&tokens_root, &plugin_id);
        return Err(PluginRunnerError::Runtime(format!(
            "Isolated plugin unit '{unit_name}' failed to enter active state (state={} sub={})",
            props.active_state, props.sub_state
        )));
    }

    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active,
        sub_state: props.sub_state,
        runtime_id: Some(runtime_id),
        uid: props.uid,
        gid: props.gid,
    })
}

pub async fn handle_plugin_stop(
    Json(req): Json<PluginRunnerStopRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_stop_inner(req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_stop_inner(
    req: PluginRunnerStopRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let port = if req.port == 0 {
        0
    } else {
        validate_port(req.port)?
    };
    let runtime_id = match req.runtime_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_runtime_id(raw)?),
        _ => None,
    };
    let api_base_url = if req.api_base_url.trim().is_empty() {
        "http://127.0.0.1:8080".to_string()
    } else {
        validate_loopback_api_base_url(&req.api_base_url)?
    };

    let (systemd_run, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let tokens_root = resolve_plugin_tokens_root()?;

    let pre_props = query_unit_properties(&systemctl, &unit_name).await.ok();
    let was_active = pre_props.as_ref().is_some_and(|p| {
        matches!(
            p.active_state.as_str(),
            "active" | "activating" | "reloading"
        )
    });

    let stop_result = if was_active {
        // Active managed units execute their validated `ExecStop=` hook inside the same
        // DynamicUser/StateDirectory sandbox before systemd sweeps the control group.
        stop_and_reset_unit(&systemctl, &unit_name).await
    } else {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        if req.run_stop_hook {
            if let Ok(spec) = load_verified_plugin_spec(&plugin_id) {
                if spec.stop_hook_rel.is_some() {
                    ensure_host_mountpoints()?;
                    let stop_unit = plugin_stop_hook_unit_name(&plugin_id).ok_or_else(|| {
                        PluginRunnerError::InvalidRequest("Invalid plugin id".to_string())
                    })?;
                    let existing_token_dir = runtime_id
                        .as_deref()
                        .map(|rid| tokens_root.join(&plugin_id).join(rid))
                        .filter(|p| {
                            fs::symlink_metadata(p)
                                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
                        });
                    let stop_args = build_plugin_stop_hook_systemd_run_args(
                        &stop_unit,
                        &spec,
                        port,
                        runtime_id.as_deref(),
                        &api_base_url,
                        existing_token_dir.as_deref(),
                        &tokens_root,
                    )?;
                    let run_res = tokio::time::timeout(
                        Duration::from_secs(10),
                        Command::new(&systemd_run)
                            .args(&stop_args)
                            .kill_on_drop(true)
                            .output(),
                    )
                    .await;
                    if run_res.is_err() {
                        let _ = stop_and_reset_unit(&systemctl, &stop_unit).await;
                    } else {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            Command::new(&systemctl)
                                .args(["reset-failed", &stop_unit])
                                .kill_on_drop(true)
                                .output(),
                        )
                        .await;
                    }
                }
            }
        }
        Ok(())
    };

    cleanup_plugin_tokens(&tokens_root, &plugin_id);
    stop_result?;

    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active: false,
        sub_state: "dead".to_string(),
        runtime_id: None,
        uid: None,
        gid: None,
    })
}

pub async fn handle_plugin_status(
    Json(req): Json<PluginRunnerStatusRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_status_inner(req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_status_inner(
    req: PluginRunnerStatusRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let runtime_id = match req.runtime_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_runtime_id(raw)?),
        _ => None,
    };
    let (_, systemctl) = ensure_systemd_isolation_ready()?;
    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;

    let props = query_unit_properties(&systemctl, &unit_name).await?;
    let active = matches!(props.active_state.as_str(), "active" | "activating");
    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active,
        sub_state: props.sub_state,
        runtime_id: if active { runtime_id } else { None },
        uid: props.uid,
        gid: props.gid,
    })
}

pub async fn handle_plugin_token_rotate(
    Json(req): Json<PluginRunnerTokenRotateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_token_rotate_inner(req).await {
        Ok(()) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "rotated".to_string(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_token_rotate_inner(
    req: PluginRunnerTokenRotateRequest,
) -> Result<(), PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let runtime_id = validate_runtime_id(&req.runtime_id)?;
    validate_plugin_token(&req.token)?;

    let (_, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let props = query_unit_properties(&systemctl, &unit_name).await?;
    if !matches!(props.active_state.as_str(), "active" | "activating") {
        return Err(PluginRunnerError::Runtime(format!(
            "Cannot rotate token: isolated plugin unit '{unit_name}' is not active"
        )));
    }
    let tokens_root = resolve_plugin_tokens_root()?;
    let _ = write_staged_plugin_token(&tokens_root, &plugin_id, &runtime_id, &req.token, true)?;
    Ok(())
}
