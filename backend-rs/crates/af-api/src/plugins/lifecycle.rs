use super::manifest::{discover_plugins, validate_relative_plugin_subpath};
use super::registry::{
    allocate_plugin_port, read_registry_state, try_read_registry_state, try_update_registry_state,
    update_registry_state,
};
use super::tokens::{revoke_all_tokens_for_plugin, sign_plugin_token};
use super::types::{
    ActivePluginRuntime, PluginLifecycleError, PluginRegistryState, PluginRuntimeView,
    ValidatedPluginManifest, ACTIVE_PROCESSES, PLUGIN_HEALTH, PLUGIN_LIFECYCLE, PROXY_HTTP_CLIENT,
};
use af_models::{
    plugin_systemd_unit_name, PluginRunnerStartRequest, PluginRunnerStatusRequest,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest, PLUGIN_PORT_RANGE_END,
    PLUGIN_PORT_RANGE_START,
};
use af_runner::{
    dispatch_plugin_start, dispatch_plugin_status, dispatch_plugin_stop,
    dispatch_plugin_token_rotate,
};
use rusqlite::params;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

pub(super) fn resolve_plugin_executable(
    manifest: &ValidatedPluginManifest,
) -> Option<(PathBuf, Vec<String>)> {
    let bin = manifest.backend.binary_name.trim();
    if !bin.is_empty() {
        let mut candidates = Vec::with_capacity(8);

        // 1. Honor explicit Cargo manifest directory from `backend.manifest_path`
        // (e.g. `backend/Cargo.toml` -> `backend/target/{release,debug}/<bin>`).
        let manifest_path_trimmed = manifest.backend.manifest_path.trim();
        if !manifest_path_trimmed.is_empty() {
            if let Some(parent) = std::path::Path::new(manifest_path_trimmed).parent() {
                let parent_str = parent.to_string_lossy().trim_matches('/').to_string();
                if parent_str.is_empty() || parent_str == "." {
                    candidates.push(format!("target/release/{bin}"));
                    candidates.push(format!("target/debug/{bin}"));
                } else {
                    candidates.push(format!("{parent_str}/target/release/{bin}"));
                    candidates.push(format!("{parent_str}/target/debug/{bin}"));
                }
            }
        }

        // 2. Canonical Rust plugin workspace target & packaged binary layouts.
        for default_rel in [
            format!("backend-rs/target/release/{bin}"),
            format!("backend-rs/target/debug/{bin}"),
            format!("backend/target/release/{bin}"),
            format!("backend/target/debug/{bin}"),
            format!("bin/{bin}"),
            bin.to_string(),
        ] {
            if !candidates.contains(&default_rel) {
                candidates.push(default_rel);
            }
        }

        for rel in candidates {
            if let Ok(path) = validate_relative_plugin_subpath(&manifest.plugin_dir, &rel, true) {
                if path.is_file() {
                    return Some((path, Vec::new()));
                }
            }
        }
    }
    if !manifest.lifecycle_hooks.on_start.trim().is_empty() {
        if let Ok(hook_path) = validate_relative_plugin_subpath(
            &manifest.plugin_dir,
            &manifest.lifecycle_hooks.on_start,
            true,
        ) {
            if hook_path.is_file() && cfg!(unix) {
                return Some((
                    PathBuf::from("/bin/bash"),
                    vec![hook_path.to_string_lossy().into_owned()],
                ));
            }
        }
    }
    None
}

fn resolve_api_base_url() -> Result<String, PluginLifecycleError> {
    let api_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let raw = env::var("AETHERFLOW_INTERNAL_API_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("http://127.0.0.1:{api_port}"));
    af_runner::plugins::validate_loopback_api_base_url(&raw).map_err(PluginLifecycleError::from)
}

fn privileged_runner_explicitly_disabled() -> bool {
    env::var("PRIVILEGED_RUNNER_ENABLED")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
}

fn check_plugin_isolation_available() -> Result<(), PluginLifecycleError> {
    if privileged_runner_explicitly_disabled() {
        return Err(PluginLifecycleError::IsolationUnavailable(
            "Managed plugin isolation is unavailable because PRIVILEGED_RUNNER_ENABLED is disabled. Enable PRIVILEGED_RUNNER_ENABLED=true with aetherflow-runner.service on a systemd-managed Linux host (af-api refuses to spawn managed plugins as the API OS user), or configure this plugin as an external backend."
                .to_string(),
        ));
    }
    if !af_runner::is_runner_available() {
        let sock = af_runner::resolve_runner_socket_path();
        return Err(PluginLifecycleError::IsolationUnavailable(format!(
            "Managed plugin isolation is unavailable because aetherflow-runner.service is not reachable at '{sock}'. Start aetherflow-runner.service on a systemd-managed Linux host (af-api refuses to spawn managed plugins as the API OS user), or configure this plugin as an external backend."
        )));
    }
    Ok(())
}

pub async fn probe_plugin_health(port: u16, health_path: &str) -> Result<bool, String> {
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return Err(format!(
            "Port {} is outside allowed plugin loopback range",
            port
        ));
    }
    let clean_path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{}", health_path)
    };
    let url = format!("http://127.0.0.1:{}{}", port, clean_path);
    match PROXY_HTTP_CLIENT.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(conn) = af_db::get_conn() {
                let _ = conn.execute(
                    "UPDATE plugins_registry SET last_health_at = CURRENT_TIMESTAMP, last_error = '' WHERE allocated_port = ?1",
                    params![port as i64],
                );
            }
            Ok(true)
        }
        Ok(resp) => Err(format!("Health check returned HTTP {}", resp.status())),
        Err(e) => Err(format!("Health probe unreachable: {}", e)),
    }
}

// The lifecycle lock serializes status reaping and token rotation with stop/restart.
async fn monitor_plugin(
    manifest: ValidatedPluginManifest,
    port: u16,
    runtime_id: Uuid,
    mut epoch: i64,
) {
    let mut rotated_at = std::time::Instant::now();
    let mut consecutive_status_errors: u8 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let healthy = probe_plugin_health(port, &manifest.backend.health_path)
            .await
            .unwrap_or(false);
        let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
        let still_current = ACTIVE_PROCESSES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&manifest.id)
            .is_some_and(|runtime| runtime.runtime_id == runtime_id);
        if !still_current {
            return;
        }

        let status_req = PluginRunnerStatusRequest {
            plugin_id: manifest.id.clone(),
            runtime_id: Some(runtime_id.to_string()),
        };
        match dispatch_plugin_status(&status_req).await {
            Ok(status) if !status.active => {
                ACTIVE_PROCESSES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&manifest.id);
                PLUGIN_HEALTH
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&manifest.id);
                let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                    plugin_id: manifest.id.clone(),
                    port,
                    runtime_id: Some(runtime_id.to_string()),
                    api_base_url: resolve_api_base_url()
                        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                    run_stop_hook: false,
                })
                .await;
                update_registry_state(
                    &manifest.id,
                    false,
                    port,
                    "error",
                    "Plugin process exited",
                    true,
                );
                revoke_all_tokens_for_plugin(&manifest.id);
                return;
            }
            Ok(_) => {
                consecutive_status_errors = 0;
            }
            Err(error) => {
                consecutive_status_errors = consecutive_status_errors.saturating_add(1);
                tracing::warn!(
                    plugin = %manifest.id,
                    %error,
                    failures = consecutive_status_errors,
                    "Managed plugin isolation status check failed"
                );
                if consecutive_status_errors >= 3 && !healthy {
                    ACTIVE_PROCESSES
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&manifest.id);
                    PLUGIN_HEALTH
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&manifest.id);
                    update_registry_state(
                        &manifest.id,
                        false,
                        port,
                        "error",
                        "Managed plugin isolation runner became unreachable",
                        true,
                    );
                    revoke_all_tokens_for_plugin(&manifest.id);
                    return;
                }
                continue;
            }
        }

        PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(manifest.id.clone(), (port, healthy));
        let state = read_registry_state(&manifest.id);
        if state.enabled
            && (state.token_epoch != epoch || rotated_at.elapsed() >= Duration::from_secs(180))
        {
            match sign_plugin_token(&manifest, state.token_epoch, None, Some(runtime_id)) {
                Ok((token, _)) => {
                    let rotate_req = PluginRunnerTokenRotateRequest {
                        plugin_id: manifest.id.clone(),
                        runtime_id: runtime_id.to_string(),
                        token,
                    };
                    match dispatch_plugin_token_rotate(&rotate_req).await {
                        Ok(()) => {
                            epoch = state.token_epoch;
                            rotated_at = std::time::Instant::now();
                        }
                        Err(error) => {
                            tracing::warn!(
                                plugin = %manifest.id,
                                %error,
                                "Isolated plugin token rotation failed"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        plugin = %manifest.id,
                        %error,
                        "Failed to sign rotated plugin token"
                    );
                }
            }
        }
    }
}

async fn stop_tracked_runtime_without_hook(plugin_id: &str) {
    let maybe_runtime = ACTIVE_PROCESSES
        .lock()
        .ok()
        .and_then(|mut map| map.remove(plugin_id));
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(plugin_id);
    if let Some(mut runtime) = maybe_runtime {
        if let Some(monitor) = runtime.monitor.take() {
            monitor.abort();
            let _ = monitor.await;
        }
        if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                plugin_id: plugin_id.to_string(),
                port: runtime.port,
                runtime_id: Some(runtime.runtime_id.to_string()),
                api_base_url: resolve_api_base_url()
                    .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                run_stop_hook: false,
            })
            .await;
        }
    }
}

pub async fn start_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    start_plugin_instance_with_port(manifest, None).await
}

pub async fn start_plugin_instance_with_port(
    manifest: &ValidatedPluginManifest,
    preferred_port: Option<u16>,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    let spawned_managed = resolve_plugin_executable(manifest).is_some();
    let existing = try_read_registry_state(&manifest.id).map_err(PluginLifecycleError::Runtime)?;

    if spawned_managed {
        if let Err(err) = check_plugin_isolation_available() {
            let msg = err.to_string();
            update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                false,
            );
            return Err(err);
        }
    }

    stop_tracked_runtime_without_hook(&manifest.id).await;
    let port = allocate_plugin_port(
        &manifest.id,
        preferred_port.unwrap_or(existing.allocated_port),
        !spawned_managed,
    )
    .map_err(PluginLifecycleError::Runtime)?;

    let api_base_url = if spawned_managed {
        resolve_api_base_url()?
    } else {
        String::new()
    };

    let state = try_update_registry_state(&manifest.id, true, port, "running", "", true)
        .map_err(PluginLifecycleError::Runtime)?;
    if !state.enabled || state.allocated_port != port || state.token_epoch == existing.token_epoch {
        return Err(PluginLifecycleError::Runtime(
            "Could not enable plugin registry entry".into(),
        ));
    }

    if spawned_managed {
        let runtime_id = Uuid::new_v4();
        plugin_systemd_unit_name(&manifest.id).ok_or_else(|| {
            PluginLifecycleError::InvalidInput("Invalid plugin identifier".to_string())
        })?;
        let (initial_token, _) =
            sign_plugin_token(manifest, state.token_epoch, None, Some(runtime_id))
                .map_err(PluginLifecycleError::Runtime)?;

        // Register runtime_id prior to launching the isolated systemd unit so immediate
        // startup API calls with the scoped token validate cleanly.
        ACTIVE_PROCESSES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                manifest.id.clone(),
                ActivePluginRuntime {
                    port,
                    runtime_id,
                    monitor: None,
                },
            );

        let start_req = PluginRunnerStartRequest {
            plugin_id: manifest.id.clone(),
            port,
            runtime_id: runtime_id.to_string(),
            api_base_url,
            initial_token,
        };
        if let Err(runner_err) = dispatch_plugin_start(&start_req).await {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            let lifecycle_err = PluginLifecycleError::from(runner_err);
            let msg = lifecycle_err.to_string();
            update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            revoke_all_tokens_for_plugin(&manifest.id);
            return Err(lifecycle_err);
        }

        let monitor = tokio::spawn(monitor_plugin(
            manifest.clone(),
            port,
            runtime_id,
            state.token_epoch,
        ));
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = procs.get_mut(&manifest.id) {
            if entry.runtime_id == runtime_id {
                entry.monitor = Some(monitor);
            } else {
                monitor.abort();
            }
        } else {
            monitor.abort();
        }
    }

    let max_attempts = if spawned_managed { 30 } else { 1 };
    let mut healthy = false;
    for attempt in 0..max_attempts {
        if probe_plugin_health(port, &manifest.backend.health_path)
            .await
            .unwrap_or(false)
        {
            healthy = true;
            break;
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(manifest.id.clone(), (port, healthy));
    let state = read_registry_state(&manifest.id);
    Ok(build_runtime_view(manifest, &state, healthy))
}

pub async fn stop_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    let existing = try_read_registry_state(&manifest.id).map_err(PluginLifecycleError::Runtime)?;
    let has_managed_exec = resolve_plugin_executable(manifest).is_some();
    let has_stop_hook = !manifest.lifecycle_hooks.on_stop.trim().is_empty();

    // Pause the background monitor before running stop/on_stop, while preserving
    // runtime_id in ACTIVE_PROCESSES so an isolated on_stop hook can still call the API.
    let (active_monitor, active_runtime_id, active_port) = {
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = procs.get_mut(&manifest.id) {
            (
                entry.monitor.take(),
                Some(entry.runtime_id),
                Some(entry.port),
            )
        } else {
            (None, None, None)
        }
    };
    if let Some(monitor) = active_monitor {
        monitor.abort();
        let _ = monitor.await;
    }

    let needs_isolated_stop =
        active_runtime_id.is_some() || has_stop_hook || (has_managed_exec && existing.enabled);

    if needs_isolated_stop {
        if let Err(err) = check_plugin_isolation_available() {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            revoke_all_tokens_for_plugin(&manifest.id);
            let msg = err.to_string();
            let _ = update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            return Err(err);
        }

        let stop_req = PluginRunnerStopRequest {
            plugin_id: manifest.id.clone(),
            port: active_port.unwrap_or(existing.allocated_port),
            runtime_id: active_runtime_id.map(|id| id.to_string()),
            api_base_url: resolve_api_base_url()
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            run_stop_hook: has_stop_hook,
        };
        if let Err(runner_err) = dispatch_plugin_stop(&stop_req).await {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            revoke_all_tokens_for_plugin(&manifest.id);
            let lifecycle_err = PluginLifecycleError::from(runner_err);
            let msg = lifecycle_err.to_string();
            let _ = update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            return Err(lifecycle_err);
        }
    }

    ACTIVE_PROCESSES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&manifest.id);
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&manifest.id);
    revoke_all_tokens_for_plugin(&manifest.id);
    let existing = try_read_registry_state(&manifest.id).map_err(PluginLifecycleError::Runtime)?;
    let state = try_update_registry_state(
        &manifest.id,
        false,
        existing.allocated_port,
        "stopped",
        "",
        true,
    )
    .map_err(PluginLifecycleError::Runtime)?;
    if state.enabled || state.token_epoch == existing.token_epoch {
        return Err(PluginLifecycleError::Runtime(
            "Could not disable plugin registry entry".into(),
        ));
    }
    Ok(build_runtime_view(manifest, &state, false))
}

pub async fn restart_plugin_instance_with_port(
    manifest: &ValidatedPluginManifest,
    preferred_port: Option<u16>,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    if resolve_plugin_executable(manifest).is_some() {
        check_plugin_isolation_available()?;
    }
    stop_plugin_instance(manifest).await?;
    start_plugin_instance_with_port(manifest, preferred_port).await
}

/// Reconciles managed plugins after API startup: auto-starts enabled managed plugins in fresh
/// isolated systemd units and reaps orphaned units belonging to disabled managed plugins.
pub async fn reconcile_managed_plugins_on_startup() {
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let (manifests, _) = discover_plugins();
    for manifest in manifests {
        if resolve_plugin_executable(&manifest).is_none() {
            continue;
        }
        let state = match try_read_registry_state(&manifest.id) {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(
                    plugin = %manifest.id,
                    %error,
                    "Failed to read plugin registry state during startup reconciliation; skipping reconciliation"
                );
                continue;
            }
        };
        if state.enabled || state.status == "running" {
            let preferred = (PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END)
                .contains(&state.allocated_port)
                .then_some(state.allocated_port);
            if let Err(err) = start_plugin_instance_with_port(&manifest, preferred).await {
                tracing::warn!(
                    plugin = %manifest.id,
                    %err,
                    "Failed to auto-start managed plugin during startup reconciliation"
                );
            }
        } else if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            if let Ok(status) = dispatch_plugin_status(&PluginRunnerStatusRequest {
                plugin_id: manifest.id.clone(),
                runtime_id: None,
            })
            .await
            {
                if status.active {
                    let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                        plugin_id: manifest.id.clone(),
                        port: state.allocated_port,
                        runtime_id: None,
                        api_base_url: resolve_api_base_url()
                            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                        run_stop_hook: false,
                    })
                    .await;
                }
            }
        }
    }
}

/// Gracefully tears down active managed plugin systemd units during API shutdown while
/// preserving their `enabled` preference in SQLite so the next startup reconciles them cleanly.
pub async fn shutdown_managed_plugins() {
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let active: Vec<(String, u16, Uuid, Option<tokio::task::JoinHandle<()>>)> = {
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if procs.is_empty() {
            return;
        }
        procs
            .drain()
            .map(|(id, mut r)| (id, r.port, r.runtime_id, r.monitor.take()))
            .collect()
    };
    let (manifests, _) = discover_plugins();
    let stop_hooks: HashSet<String> = manifests
        .into_iter()
        .filter(|m| !m.lifecycle_hooks.on_stop.trim().is_empty())
        .map(|m| m.id)
        .collect();
    let api_base_url =
        resolve_api_base_url().unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    for (plugin_id, port, runtime_id, monitor) in active {
        if let Some(handle) = monitor {
            handle.abort();
            let _ = handle.await;
        }
        PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&plugin_id);
        revoke_all_tokens_for_plugin(&plugin_id);
        if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                plugin_id: plugin_id.clone(),
                port,
                runtime_id: Some(runtime_id.to_string()),
                api_base_url: api_base_url.clone(),
                run_stop_hook: stop_hooks.contains(&plugin_id),
            })
            .await;
        }
    }
}

pub(super) fn build_runtime_view(
    manifest: &ValidatedPluginManifest,
    state: &PluginRegistryState,
    healthy: bool,
) -> PluginRuntimeView {
    PluginRuntimeView {
        id: manifest.id.clone(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        sdk: manifest.sdk.clone(),
        contract_version: manifest.contract_version.clone(),
        runtime_status: manifest.runtime_status.clone(),
        description: manifest.description.clone(),
        author: manifest.author.clone(),
        permissions: manifest.permissions.clone(),
        granted_scopes: manifest.granted_scopes.clone(),
        enabled: state.enabled,
        status: state.status.clone(),
        healthy,
        allocated_port: state.allocated_port,
        health_path: manifest.backend.health_path.clone(),
        ui_url: format!("/api/v1/auth/plugins/{}/ui", manifest.id),
        proxy_base_url: format!("/api/v1/auth/plugins/{}/proxy", manifest.id),
        slot: manifest.frontend.slot.clone(),
        capabilities: if manifest.frontend.capabilities.is_empty() {
            vec![
                "sandbox-iframe".to_string(),
                "postmessage-bridge".to_string(),
                "scoped-proxy".to_string(),
            ]
        } else {
            manifest.frontend.capabilities.clone()
        },
        last_health_at: state.last_health_at.clone(),
        last_error: state.last_error.clone(),
    }
}
