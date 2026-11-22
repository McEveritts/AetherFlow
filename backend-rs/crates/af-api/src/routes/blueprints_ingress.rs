use super::health::privileged_runner_is_enabled;
use super::marketplace::load_authoritative_app_ingress_config;
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_models::AppIngressConfig;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rusqlite::params;
use serde::Deserialize;

pub(super) async fn get_blueprints(Extension(auth_user): Extension<AuthUser>) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    crate::auth::blocking_response(|| match af_services::get_all_blueprints() {
        Ok(blueprints) => Json(serde_json::json!({
            "blueprints": blueprints
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(%error, "Failed to load application blueprints");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load application blueprints",
            )
        }
    })
    .await
}

pub(super) async fn get_app_blueprint(
    Extension(auth_user): Extension<AuthUser>,
    Path(app_name): Path<String>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    crate::auth::blocking_response(move || match af_services::get_all_blueprints() {
        Ok(all) => {
            if let Some(bp) = all.into_iter().find(|b| b.blueprint.app_name == app_name) {
                Json(bp).into_response()
            } else {
                api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found")
            }
        }
        Err(error) => {
            tracing::warn!(app = %app_name, %error, "Failed to load application blueprint");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load application blueprint",
            )
        }
    })
    .await
}

pub(super) async fn sync_app_blueprint(
    Path(app_name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    if af_services::get_blueprint(&app_name).is_none() {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found");
    }
    // Keep the app mutation guard until host synchronization or rollback finishes,
    // including when the HTTP client disconnects.
    let sync = tokio::spawn(async move {
        let guarded_app = app_name.clone();
        af_services::mutators::with_blueprint_mutation(&guarded_app, async move {
            Ok(sync_app_blueprint_admitted(Path(app_name), Extension(auth_user), headers).await)
        })
        .await
    })
    .await;
    match sync {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => blueprint_sync_failure_response(&error),
        Err(error) => blueprint_sync_failure_response(&anyhow::Error::new(error)),
    }
}

pub(super) fn blueprint_sync_failure_response(error: &anyhow::Error) -> Response {
    let error_id = uuid::Uuid::new_v4().to_string();
    tracing::error!(%error_id, detail = %format!("{error:#}"), "blueprint synchronization failed");
    let (status, code, message) = if af_runner::is_lifecycle_busy(error) {
        (StatusCode::CONFLICT, "LIFECYCLE_BUSY", "Application configuration is reserved by another lifecycle operation; retry after it completes")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "BLUEPRINT_SYNC_FAILED", "Blueprint synchronization could not be completed; inspect authorized diagnostics before retrying")
    };
    (
        status,
        Json(serde_json::json!({"code":code,"message":message,"error_id":error_id})),
    )
        .into_response()
}

pub(super) fn blueprint_sync_partial_failure_response(
    error: &anyhow::Error,
    failed_phase: &'static str,
    result: af_services::BlueprintSetupResult,
) -> Response {
    let error_id = uuid::Uuid::new_v4().to_string();
    tracing::error!(
        %error_id,
        failed_phase,
        app = %result.app_name,
        config_applied = result.config_applied,
        ingress_synced = result.ingress_synced,
        hosts_synced = result.hosts_synced,
        network_dns_synced = result.network_dns_synced,
        detail = %format!("{error:#}"),
        "blueprint synchronization failed"
    );
    let partial_commit = result.config_applied
        || result.ingress_synced
        || result.hosts_synced
        || result.network_dns_synced;
    let message = match (failed_phase, partial_commit) {
        ("config", _) => "Blueprint application configuration failed before ingress or DNS changes were committed; inspect authorized diagnostics before retrying",
        ("ingress", true) => "Blueprint ingress synchronization failed after applying application configuration; durable ingress was restored where possible and retrying is safe after resolving diagnostics",
        ("ingress", false) => "Blueprint ingress synchronization failed; inspect authorized diagnostics before retrying",
        ("hosts", true) => "Blueprint local hosts synchronization failed after prior phases committed; retrying is safe once host DNS writes succeed",
        ("hosts", false) => "Blueprint local hosts synchronization failed; inspect authorized diagnostics before retrying",
        ("network_dns", true) => "Blueprint network DNS synchronization failed after prior phases committed; retrying is safe once DNS providers are available",
        ("network_dns", false) => "Blueprint network DNS synchronization failed; inspect authorized diagnostics before retrying",
        (_, true) => "Blueprint synchronization failed after committing prior phases; inspect authorized diagnostics before retrying",
        (_, false) => "Blueprint synchronization could not be completed; inspect authorized diagnostics before retrying",
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "code": "BLUEPRINT_SYNC_FAILED",
            "message": message,
            "error_id": error_id,
            "failed_phase": failed_phase,
            "partial_commit": partial_commit,
            "retryable": true,
            "result": result,
        })),
    )
        .into_response()
}

pub(super) async fn sync_app_blueprint_admitted(
    Path(app_name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let Some(bp) = af_services::get_blueprint(&app_name) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found");
    };
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "blueprint_sync",
        "blueprint",
        &bp.app_name,
        "",
        &ip,
        ua,
    );

    let lookup_app = bp.app_name.clone();
    let (existing_ing, previous_active) =
        match tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let existing = load_authoritative_app_ingress_config(&lookup_app)?;
            let active = af_db::get_app_ingress_config(&lookup_app)?;
            Ok((existing, active))
        })
        .await
        {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(error)) => return blueprint_sync_failure_response(&error),
            Err(error) => return blueprint_sync_failure_response(&anyhow::Error::new(error)),
        };

    let configured_port = af_services::mutators::get_app_runtime_meta(&bp.app_name).configured_port;
    let allocated_port = existing_ing
        .as_ref()
        .map(|c| c.listen_port)
        .filter(|&p| p > 0)
        .unwrap_or(if configured_port > 0 {
            configured_port
        } else {
            bp.default_port
        });
    let base_domain = af_services::resolve_base_domain();
    let public_domain = existing_ing
        .as_ref()
        .map(|c| c.public_domain.trim().to_string())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            if base_domain.is_empty() || allocated_port <= 0 {
                String::new()
            } else {
                af_services::format_app_public_domain(&bp.app_name, &base_domain)
            }
        });
    let external_access_enabled = existing_ing
        .as_ref()
        .map(|c| c.external_access_enabled)
        .unwrap_or(false);
    let tls_enabled = existing_ing
        .as_ref()
        .map(|c| c.tls_enabled)
        .unwrap_or(!public_domain.is_empty());
    let internal_domain = if !bp.internal_domain.trim().is_empty() {
        bp.internal_domain.trim().to_ascii_lowercase()
    } else {
        format!("{}.aether.local", bp.app_name.trim().to_ascii_lowercase())
    };

    let mut result = af_services::BlueprintSetupResult {
        app_name: bp.app_name.clone(),
        service_name: bp.service_name.clone(),
        allocated_port,
        default_port: bp.default_port,
        port_reassigned: allocated_port != bp.default_port && allocated_port > 0,
        internal_domain: internal_domain.clone(),
        public_domain: public_domain.clone(),
        external_access_enabled,
        config_applied: false,
        mutated_files: Vec::new(),
        unprivileged_skips: Vec::new(),
        warnings: Vec::new(),
        ingress_synced: false,
        hosts_synced: false,
        network_dns_synced: false,
    };

    let config_summary = match af_services::mutators::apply_blueprint_host_config(
        &bp.app_name,
        u16::try_from(allocated_port).unwrap_or(0),
    )
    .await
    {
        Ok(summary) => summary,
        Err(error) => {
            return blueprint_sync_partial_failure_response(
                &anyhow::Error::msg(error),
                "config",
                result,
            );
        }
    };
    result.config_applied = config_summary.config_applied;
    result.mutated_files = config_summary.mutated_files;
    result.unprivileged_skips = config_summary.unprivileged_skips;
    result.warnings = config_summary.warnings;

    if allocated_port > 0 {
        let now = Utc::now();
        let ingress_cfg = AppIngressConfig {
            app_name: bp.app_name.clone(),
            public_domain: public_domain.clone(),
            external_access_enabled,
            listen_port: allocated_port,
            tls_enabled,
            created_at: existing_ing.as_ref().map(|c| c.created_at).unwrap_or(now),
            updated_at: now,
        };
        let persisted_cfg = ingress_cfg.clone();
        let db_write = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            af_db::set_app_ingress_config(&persisted_cfg)?;
            af_db::invalidate_ingress_cache();
            Ok(())
        })
        .await
        .map_err(anyhow::Error::new)
        .and_then(|res| res);
        if let Err(error) = db_write {
            return blueprint_sync_partial_failure_response(&error, "ingress", result);
        }

        let publish_cfg = ingress_cfg.clone();
        let publish_internal = internal_domain.clone();
        let publish = tokio::task::spawn_blocking(move || {
            apply_ingress_vhost_policy(&publish_cfg, &publish_internal)
        })
        .await
        .map_err(anyhow::Error::new)
        .and_then(|res| res);
        match publish {
            Ok(true) => {
                if ingress_cfg.tls_enabled {
                    af_services::mutators::trigger_apache_cert_sync().await;
                }
                result.ingress_synced = true;
            }
            Ok(false) => {
                result.warnings.push(
                    "Apache ingress publication skipped because managed Apache is unavailable; durable ingress settings were saved"
                        .to_string(),
                );
            }
            Err(error) => {
                let rollback_app = bp.app_name.clone();
                let rollback_prev = previous_active.clone();
                let rollback_internal = internal_domain.clone();
                let rollback = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                    restore_ingress_config(&rollback_app, rollback_prev.as_ref())?;
                    if let Some(previous) = rollback_prev {
                        if let Err(vhost_err) = sync_ingress_vhost(&previous, &rollback_internal) {
                            tracing::error!(
                                app = %rollback_app,
                                %vhost_err,
                                "Could not reapply previous Apache vhost during blueprint sync rollback"
                            );
                        }
                    }
                    Ok(())
                })
                .await;
                if !matches!(rollback, Ok(Ok(()))) {
                    tracing::error!(?rollback, "Blueprint ingress database rollback failed");
                    result.warnings.push(
                        "Durable ingress rollback failed after Apache publication error"
                            .to_string(),
                    );
                }
                return blueprint_sync_partial_failure_response(&error, "ingress", result);
            }
        }
    }

    let mut dns_domains = Vec::new();
    if !internal_domain.is_empty() {
        dns_domains.push(internal_domain.clone());
    }
    if !public_domain.is_empty() && !dns_domains.contains(&public_domain) {
        dns_domains.push(public_domain.clone());
    }
    result.hosts_synced = if dns_domains.is_empty() {
        true
    } else {
        match af_services::mutators::sync_local_dns_domains(&dns_domains).await {
            Ok(()) => true,
            Err(error) if af_services::mutators::is_unprivileged_host_write_error(&error) => {
                if !result.unprivileged_skips.contains(&error) {
                    result.unprivileged_skips.push(error.clone());
                }
                result.warnings.push(format!(
                    "Local DNS hosts sync skipped in unprivileged API process: {}",
                    error
                ));
                false
            }
            Err(error) => {
                return blueprint_sync_partial_failure_response(
                    &anyhow::Error::msg(error),
                    "hosts",
                    result,
                );
            }
        }
    };
    if let Err(error) = af_services::mutators::sync_network_dns_providers().await {
        return blueprint_sync_partial_failure_response(
            &anyhow::Error::msg(error),
            "network_dns",
            result,
        );
    }
    result.network_dns_synced = true;

    if !result.unprivileged_skips.is_empty() && !result.ingress_synced && !result.config_applied {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "BLUEPRINT_HOST_WRITE_SKIPPED",
                "message": "Blueprint host configuration writes were skipped due to unprivileged filesystem restrictions and no database/ingress sync occurred",
                "failed_phase": "hosts",
                "partial_commit": false,
                "retryable": true,
                "unprivileged_skips": result.unprivileged_skips,
                "warnings": result.warnings,
                "result": result,
            })),
        )
            .into_response();
    }

    let message = if result.unprivileged_skips.is_empty() && result.warnings.is_empty() {
        "Blueprint synchronized successfully"
    } else if !result.unprivileged_skips.is_empty() {
        "Blueprint synchronized with warnings (some host writes were skipped in unprivileged mode)"
    } else {
        "Blueprint synchronized with warnings"
    };

    Json(serde_json::json!({
        "message": message,
        "result": result,
    }))
    .into_response()
}

pub(super) async fn get_ingress_configs(Extension(user): Extension<AuthUser>) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    crate::auth::blocking_response(|| match af_db::get_all_app_ingress_configs() {
        Ok(configs) => Json(serde_json::json!({ "configs": configs })).into_response(),
        Err(error) => {
            tracing::warn!(%error, "Failed to load ingress configurations");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load ingress configurations",
            )
        }
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateIngressReq {
    #[serde(default)]
    pub(super) public_domain: Option<String>,
    #[serde(default)]
    pub(super) external_access_enabled: Option<bool>,
    #[serde(default)]
    pub(super) listen_port: Option<i32>,
    #[serde(default)]
    pub(super) tls_enabled: Option<bool>,
}

pub(super) fn resolve_patched_ingress_config(
    clean_app: &str,
    req: &UpdateIngressReq,
    existing: Option<&AppIngressConfig>,
    blueprint_default_port: i32,
    now: chrono::DateTime<Utc>,
) -> Result<AppIngressConfig, (StatusCode, &'static str, &'static str)> {
    let current_effective_port = existing
        .map(|ex| ex.listen_port)
        .filter(|&p| p > 0)
        .unwrap_or(blueprint_default_port);

    if let Some(requested_port) = req.listen_port {
        if !(0..=65535).contains(&requested_port) {
            return Err((
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "listenPort must be between 0 and 65535",
            ));
        }
        if requested_port > 0
            && current_effective_port > 0
            && requested_port != current_effective_port
        {
            return Err((
                StatusCode::CONFLICT,
                "PORT_RECONFIGURATION_UNSUPPORTED",
                "Changing listenPort via ingress configuration is not supported without native service rebinding and readiness verification",
            ));
        }
        if requested_port > 0 && current_effective_port <= 0 {
            return Err((
                StatusCode::CONFLICT,
                "PORT_RECONFIGURATION_UNSUPPORTED",
                "This application does not support custom ingress listenPort assignment",
            ));
        }
    }

    let clean_public_domain = match req.public_domain.as_ref() {
        Some(raw_domain) => {
            if raw_domain.trim().is_empty() {
                String::new()
            } else {
                let norm = af_db::normalize_base_domain(raw_domain);
                if norm.is_empty() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "INVALID_DOMAIN",
                        "Invalid publicDomain",
                    ));
                }
                norm
            }
        }
        None => existing
            .map(|ex| ex.public_domain.clone())
            .unwrap_or_default(),
    };

    let listen_port = req
        .listen_port
        .filter(|&p| p > 0)
        .unwrap_or(current_effective_port);

    let external_access_enabled = req
        .external_access_enabled
        .or_else(|| existing.map(|ex| ex.external_access_enabled))
        .unwrap_or(false);

    if !(1..=65535).contains(&listen_port) {
        return Err((
            StatusCode::BAD_REQUEST,
            "INVALID_PORT",
            "No valid native listen port is configured for this application",
        ));
    }
    if external_access_enabled && clean_public_domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "INVALID_DOMAIN",
            "A public domain is required to enable external access",
        ));
    }

    let tls_enabled = req
        .tls_enabled
        .or_else(|| existing.map(|ex| ex.tls_enabled))
        .unwrap_or(!clean_public_domain.is_empty());

    Ok(AppIngressConfig {
        app_name: clean_app.to_string(),
        public_domain: clean_public_domain,
        external_access_enabled,
        listen_port,
        tls_enabled,
        created_at: existing.map(|c| c.created_at).unwrap_or(now),
        updated_at: now,
    })
}

pub(super) fn is_valid_ingress_app_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub(super) async fn update_app_ingress_config(
    Path(app_name): Path<String>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<UpdateIngressReq>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    let clean_app = app_name.trim().to_lowercase();
    if clean_app.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "App name is required",
        );
    }
    if !is_valid_ingress_app_slug(&clean_app) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid application name; must be a DNS-safe lowercase slug",
        );
    }
    // Keep the app mutation guard until host synchronization or rollback finishes,
    // including when the HTTP client disconnects.
    let update = tokio::spawn(async move {
        let guarded_app = clean_app.clone();
        af_services::mutators::with_blueprint_mutation(&guarded_app, async move {
            upsert_app_ingress_config(clean_app, req).await
        })
        .await
    })
    .await;
    match update {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if af_runner::is_lifecycle_busy(&error) => {
            blueprint_sync_failure_response(&error)
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "Ingress update failed");
            api_error(
                StatusCode::BAD_GATEWAY,
                "INGRESS_SYNC_FAILED",
                "Ingress configuration could not be synchronized",
            )
        }
        Err(error) => {
            tracing::error!(%error, "Ingress update worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Ingress configuration could not be updated",
            )
        }
    }
}

pub(super) async fn upsert_app_ingress_config(
    clean_app: String,
    req: UpdateIngressReq,
) -> anyhow::Result<Response> {
    let staged = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        af_db::invalidate_ingress_cache();
        let previous = af_db::get_app_ingress_config(&clean_app)?;
        let blueprint = af_services::get_blueprint(&clean_app);
        let runtime_port = af_services::mutators::get_app_runtime_meta(&clean_app).configured_port;
        let native_port = if runtime_port > 0 {
            runtime_port
        } else {
            blueprint
                .as_ref()
                .map_or(0, |blueprint| blueprint.default_port)
        };
        let cfg = match resolve_patched_ingress_config(
            &clean_app,
            &req,
            previous.as_ref(),
            native_port,
            Utc::now(),
        ) {
            Ok(cfg) => cfg,
            Err((status, code, message)) => return Ok(Err(api_error(status, code, message))),
        };
        let internal = blueprint
            .map(|blueprint| blueprint.internal_domain)
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| format!("{clean_app}.aether.local"));
        let port_changed = previous
            .as_ref()
            .is_some_and(|old| old.listen_port != cfg.listen_port);
        af_db::set_app_ingress_config(&cfg)?;
        Ok(Ok((cfg, previous, internal, port_changed)))
    })
    .await??;
    let (cfg, previous, internal, port_changed) = match staged {
        Ok(staged) => staged,
        Err(response) => return Ok(response),
    };

    let app = cfg.app_name.clone();
    let runtime = tokio::runtime::Handle::current();
    let sync_cfg = cfg.clone();
    let sync_internal = internal.clone();
    let sync = async {
        if port_changed {
            // The mutator handles its host port work in a blocking task and
            // reuses the app admission held by this update.
            af_services::mutators::apply_blueprint_app_config(&app, cfg.listen_port)
                .await
                .map_err(anyhow::Error::msg)?;
        }
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            apply_ingress_vhost_policy(&sync_cfg, &sync_internal)?;
            let mut domains = vec![sync_internal];
            if !sync_cfg.public_domain.is_empty() && !domains.contains(&sync_cfg.public_domain) {
                domains.push(sync_cfg.public_domain);
            }
            if let Err(error) =
                runtime.block_on(af_services::mutators::sync_local_dns_domains(&domains))
            {
                tracing::warn!(%error, "Internal DNS synchronization failed during ingress update");
            }
            if let Err(error) =
                runtime.block_on(af_services::mutators::sync_network_dns_providers())
            {
                tracing::warn!(%error, "Network DNS synchronization failed during ingress update");
            }
            Ok(())
        })
        .await?
    }
    .await;

    if let Err(error) = sync {
        let rollback = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            restore_ingress_config(&app, previous.as_ref())?;
            if let Some(previous) = previous {
                if let Err(error) = sync_ingress_vhost(&previous, &internal) {
                    tracing::error!(app = %app, %error, "Could not reapply previous Apache vhost");
                }
            }
            Ok(())
        })
        .await;
        if !matches!(rollback, Ok(Ok(()))) {
            tracing::error!(?rollback, "Ingress database rollback failed");
            return Ok(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INGRESS_ROLLBACK_FAILED",
                "Ingress configuration could not be restored",
            ));
        }
        return Err(error);
    }
    if cfg.tls_enabled {
        af_services::mutators::trigger_apache_cert_sync().await;
    }
    Ok(Json(serde_json::json!({
        "message": "Ingress configuration updated successfully",
        "config": cfg,
    }))
    .into_response())
}

pub(super) fn apache_ingress_is_managed() -> bool {
    privileged_runner_is_enabled()
        || af_services::mutators::resolve_config_path("/etc/apache2/sites-available").is_dir()
        || std::path::Path::new(&af_runner::runner_socket_path()).exists()
}

pub(super) fn sync_ingress_vhost(cfg: &AppIngressConfig, internal: &str) -> Result<bool, String> {
    af_services::mutators::sync_apache_app_vhost(
        &cfg.app_name,
        cfg.listen_port,
        internal,
        &cfg.public_domain,
        cfg.external_access_enabled,
    )
}

pub(super) fn apply_ingress_vhost_policy(
    cfg: &AppIngressConfig,
    internal: &str,
) -> Result<bool, anyhow::Error> {
    let apache_managed = apache_ingress_is_managed();
    match sync_ingress_vhost(cfg, internal) {
        Ok(true) => Ok(true),
        Ok(false) if !apache_managed => Ok(false),
        Err(error) if !apache_managed => {
            tracing::warn!(
                app = %cfg.app_name,
                %error,
                "Apache unavailable during unmanaged ingress update"
            );
            Ok(false)
        }
        Ok(false) => anyhow::bail!("Managed Apache did not apply ingress configuration"),
        Err(error) => {
            anyhow::bail!("Managed Apache failed to apply ingress configuration: {error}")
        }
    }
}

pub(super) fn restore_ingress_config(
    app: &str,
    previous: Option<&AppIngressConfig>,
) -> anyhow::Result<()> {
    if let Some(previous) = previous {
        af_db::get_conn()?
            .execute(
                "UPDATE app_ingress_configs SET public_domain = ?2, external_access_enabled = ?3,
             listen_port = ?4, tls_enabled = ?5, updated_at = ?6 WHERE app_name = ?1",
                params![
                    app,
                    previous.public_domain,
                    previous.external_access_enabled,
                    previous.listen_port,
                    previous.tls_enabled,
                    previous.updated_at.to_rfc3339()
                ],
            )
            .and_then(|changed| {
                if changed == 1 {
                    Ok(())
                } else {
                    Err(rusqlite::Error::QueryReturnedNoRows)
                }
            })?;
        af_db::invalidate_ingress_cache();
    } else {
        af_db::delete_app_ingress_config(app)?;
    }
    Ok(())
}
