use super::lifecycle::{
    build_runtime_view, restart_plugin_instance_with_port, start_plugin_instance_with_port,
    stop_plugin_instance,
};
use super::manifest::{
    discover_plugins, find_validated_plugin, plugin_requires_admin,
    validate_relative_plugin_subpath,
};
use super::registry::{try_read_registry_state, try_update_registry_state};
use super::tokens::{mint_scoped_plugin_token, revoke_all_tokens_for_plugin, sign_plugin_token};
use super::types::{
    PluginLifecycleError, PluginRegistryState, ValidatedPluginManifest, ACTIVE_PROCESSES,
    PLUGIN_HEALTH, PLUGIN_LIFECYCLE,
};
use crate::auth::{api_error, AuthUser};
use af_models::{PluginRunnerTokenRotateRequest, PLUGIN_PORT_RANGE_END, PLUGIN_PORT_RANGE_START};
use af_runner::dispatch_plugin_token_rotate;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use std::fs;

pub async fn list_plugins_handler(Extension(user): Extension<AuthUser>) -> Response {
    let admin = user.role == "admin";
    tokio::task::spawn_blocking(move || {
        let (manifests, rejected) = discover_plugins();
        let health = PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut views = Vec::with_capacity(manifests.len());
        for manifest in &manifests {
            let state = match try_read_registry_state(&manifest.id) {
                Ok(state) => state,
                Err(error) => {
                    tracing::warn!(plugin = %manifest.id, %error, "Failed to read plugin registry state");
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "PLUGIN_REGISTRY_ERROR",
                        "Failed to read plugin registry state",
                    );
                }
            };
            let healthy = state.enabled
                && health.get(&manifest.id) == Some(&(state.allocated_port, true));
            let view = build_runtime_view(manifest, &state, healthy);
            let mut value = serde_json::json!(view);
            if !admin {
                if let Some(fields) = value.as_object_mut() {
                    fields.remove("allocated_port");
                    fields.remove("last_error");
                }
            }
            views.push(value);
        }
        let rejected: Vec<_> = rejected
            .into_iter()
            .filter(|_| admin)
            .map(|(id, error)| serde_json::json!({ "id": id, "error": error }))
            .collect();
        Json(serde_json::json!({ "plugins": views, "rejected": rejected })).into_response()
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PLUGIN_DISCOVERY_ERROR",
            "Plugin discovery failed",
        )
    })
}

#[derive(Debug, Deserialize)]
pub struct PluginControlRequest {
    pub action: String,
    #[serde(default)]
    pub port: Option<u16>,
}

pub async fn control_plugin_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<PluginControlRequest>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    if let Some(custom_port) = req.port {
        if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&custom_port) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_PLUGIN_PORT",
                format!(
                    "Plugin port must be within loopback range {}..{}",
                    PLUGIN_PORT_RANGE_START, PLUGIN_PORT_RANGE_END
                ),
            );
        }
    }

    let action = req.action.trim().to_lowercase();
    let result = match action.as_str() {
        "start" | "enable" => start_plugin_instance_with_port(&manifest, req.port).await,
        "stop" | "disable" => stop_plugin_instance(&manifest).await,
        "restart" => restart_plugin_instance_with_port(&manifest, req.port).await,
        "revoke_tokens" => {
            revoke_all_tokens_for_plugin(&manifest.id);
            let existing = match try_read_registry_state(&manifest.id) {
                Ok(state) => state,
                Err(err) => return PluginLifecycleError::Runtime(err).into_api_response(),
            };
            let updated = match try_update_registry_state(
                &manifest.id,
                existing.enabled,
                existing.allocated_port,
                &existing.status,
                "",
                true,
            ) {
                Ok(state) if state.token_epoch != existing.token_epoch => state,
                Ok(_) => {
                    return PluginLifecycleError::Runtime(
                        "Failed to bump plugin token epoch".to_string(),
                    )
                    .into_api_response()
                }
                Err(err) => return PluginLifecycleError::Runtime(err).into_api_response(),
            };
            let active_rid = ACTIVE_PROCESSES
                .lock()
                .ok()
                .and_then(|procs| procs.get(&manifest.id).map(|r| r.runtime_id));
            if let Some(runtime_id) = active_rid {
                if updated.enabled {
                    if let Ok((token, _)) =
                        sign_plugin_token(&manifest, updated.token_epoch, None, Some(runtime_id))
                    {
                        let _ = dispatch_plugin_token_rotate(&PluginRunnerTokenRotateRequest {
                            plugin_id: manifest.id.clone(),
                            runtime_id: runtime_id.to_string(),
                            token,
                        })
                        .await;
                    }
                }
            }
            let healthy = PLUGIN_HEALTH
                .lock()
                .ok()
                .and_then(|h| h.get(&manifest.id).copied())
                .is_some_and(|(p, ok)| p == updated.allocated_port && ok);
            Ok(build_runtime_view(&manifest, &updated, healthy))
        }
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ACTION",
                "Allowed plugin actions: start, stop, restart, enable, disable, revoke_tokens",
            )
        }
    };

    match result {
        Ok(view) => {
            let ip = crate::ws::extract_client_ip(&headers);
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                &format!("plugin_{}", action),
                "plugin",
                &manifest.id,
                &format!("port={}", view.allocated_port),
                &ip,
                ua,
            );
            Json(serde_json::json!({
                "message": format!("Plugin '{}' action '{}' completed", manifest.id, action),
                "plugin": view,
            }))
            .into_response()
        }
        Err(err) => err.into_api_response(),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct MintPluginTokenRequest {
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

pub async fn mint_plugin_token_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: Option<Json<MintPluginTokenRequest>>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    if let Err(error) = try_read_registry_state(&manifest.id) {
        tracing::warn!(plugin = %manifest.id, %error, "Failed to read plugin registry state before token mint");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PLUGIN_REGISTRY_ERROR",
            "Failed to read plugin registry state",
        );
    }

    let ttl = body.and_then(|b| b.0.ttl_seconds);
    match mint_scoped_plugin_token(&manifest, ttl) {
        Ok((token, claims)) => {
            let ip = crate::ws::extract_client_ip(&headers);
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                "plugin_token_mint",
                "plugin",
                &manifest.id,
                &claims.jti,
                &ip,
                ua,
            );
            Json(serde_json::json!({
                "token": token,
                "token_type": claims.typ,
                "audience": claims.aud,
                "plugin_id": manifest.id,
                "jti": claims.jti,
                "expires_at": claims.exp,
                "scopes": claims.scopes,
            }))
            .into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, "PLUGIN_NOT_ENABLED", err),
    }
}

pub async fn serve_plugin_ui_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    if plugin_requires_admin(&manifest.permissions) {
        if let Err(response) = crate::auth::require_admin(&auth_user) {
            return *response;
        }
    }

    let state = match try_read_registry_state(&manifest.id) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(plugin = %manifest.id, %error, "Failed to read plugin registry state before serving UI");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PLUGIN_REGISTRY_ERROR",
                "Failed to read plugin registry state",
            );
        }
    };
    if !state.enabled {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_DISABLED",
            "Plugin must be enabled before mounting its UI",
        );
    }

    // Check if plugin provides a custom HTML bundle file inside its directory
    let custom_html = if !manifest.frontend.bundle.trim().is_empty() {
        validate_relative_plugin_subpath(&manifest.plugin_dir, &manifest.frontend.bundle, true)
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
    } else {
        validate_relative_plugin_subpath(&manifest.plugin_dir, "frontend/dist/index.html", true)
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
    };

    let html = custom_html.unwrap_or_else(|| render_default_sandboxed_plugin_ui(&manifest, &state));

    let mut resp = html.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-ancestors 'self'; sandbox allow-scripts",
        ),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    resp
}

fn render_default_sandboxed_plugin_ui(
    manifest: &ValidatedPluginManifest,
    state: &PluginRegistryState,
) -> String {
    let scopes_label = if manifest.granted_scopes.is_empty() {
        "none (default-deny)".to_string()
    } else {
        manifest
            .granted_scopes
            .iter()
            .map(|s| format!("{} {}", s.method, s.route))
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{name} ({version})</title>
<style>
  body {{
    margin: 0;
    padding: 16px;
    background: #050811;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
  }}
  .card {{
    border: 1px solid rgba(99, 102, 241, 0.25);
    background: rgba(15, 23, 42, 0.75);
    border-radius: 12px;
    padding: 16px;
  }}
  .badge {{
    display: inline-block;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(16, 185, 129, 0.15);
    color: #6ee7b7;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }}
  button {{
    margin-top: 12px;
    background: #4f46e5;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }}
  pre {{
    margin-top: 12px;
    padding: 10px;
    background: #020617;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    font-size: 11px;
    overflow-x: auto;
  }}
</style>
</head>
<body>
  <div class="card" data-plugin-id="{id}">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>{name} <span style="opacity:0.6;">v{version}</span></strong>
      <span class="badge">Sandboxed Capability Bridge · Port {port}</span>
    </div>
    <p style="font-size:12px;color:#94a3b8;margin:8px 0;">{desc}</p>
    <div style="font-size:11px;color:#64748b;">Granted Scopes: <code>{scopes}</code></div>
    <button id="probe-btn" type="button">Probe Plugin /status via Host Bridge</button>
    <pre id="output">Waiting for host capability handshake...</pre>
  </div>
  <script>
    const pluginId = {id_json};
    const out = document.getElementById('output');
    window.addEventListener('message', (event) => {{
      const msg = event.data || {{}};
      if (msg.type === 'AF_PLUGIN_INIT') {{
        out.textContent = JSON.stringify({{ status: 'handshake_complete', capabilities: msg.capabilities || [] }}, null, 2);
      }} else if (msg.type === 'AF_PLUGIN_PROXY_RESPONSE') {{
        out.textContent = JSON.stringify(msg.payload, null, 2);
      }}
    }});
    document.getElementById('probe-btn').addEventListener('click', () => {{
      window.parent.postMessage({{
        type: 'AF_PLUGIN_PROXY_REQUEST',
        pluginId,
        path: 'status',
        method: 'GET'
      }}, window.location.origin);
    }});
    window.parent.postMessage({{ type: 'AF_PLUGIN_READY', pluginId }}, window.location.origin);
  </script>
</body>
</html>"#,
        id = html_escape(&manifest.id),
        name = html_escape(&manifest.name),
        version = html_escape(&manifest.version),
        port = state.allocated_port,
        desc = html_escape(&manifest.description),
        scopes = html_escape(&scopes_label),
        id_json = serde_json::to_string(&manifest.id).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
