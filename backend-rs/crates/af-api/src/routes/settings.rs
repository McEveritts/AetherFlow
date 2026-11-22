use super::blueprints_ingress::{
    apply_ingress_vhost_policy, blueprint_sync_failure_response, restore_ingress_config,
    sync_ingress_vhost,
};
use crate::auth::{api_error, AuthUser};
use af_models::AppIngressConfig;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub ai_model: String,
    #[serde(default)]
    pub local_provider: String,
    #[serde(default)]
    pub local_model: String,
    pub system_prompt: String,
    pub language: String,
    pub timezone: String,
    pub update_channel: String,
    pub default_dashboard: String,
    pub setup_completed: bool,
    pub base_domain: String,
    pub gemini_api_key: String,
    pub openai_api_key: String,
    pub lm_studio_endpoint: String,
    pub ollama_endpoint: String,
    pub anthropic_api_key: String,
    pub anthropic_endpoint: String,
}

pub(super) fn is_masked_secret(raw: &str) -> bool {
    let value = raw.trim();
    value.starts_with("****") || value == af_db::SECRET_MASK
}

pub(super) fn mask_secret(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let dec = match af_db::decrypt_key(raw) {
        Ok(value) if !value.starts_with("enc:v1:") => value,
        _ => return "****".to_string(),
    };
    if dec.chars().count() > 4 {
        let last4: String = dec
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", last4)
    } else {
        "****".to_string()
    }
}

pub(super) fn redact_settings_for_role(payload: &mut SettingsPayload, role: &str) {
    if role != "admin" {
        payload.gemini_api_key.clear();
        payload.openai_api_key.clear();
        payload.anthropic_api_key.clear();
        payload.lm_studio_endpoint.clear();
        payload.ollama_endpoint.clear();
        payload.anthropic_endpoint.clear();
    }
}

pub(super) async fn get_settings(Extension(user): Extension<AuthUser>) -> Response {
    crate::auth::blocking_response(move || get_settings_for_role(&user.role)).await
}

pub(super) fn get_settings_for_role(role: &str) -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let row = conn.query_row(
        "SELECT COALESCE(ai_model, 'gemini-4-argon'), COALESCE(system_prompt, ''), COALESCE(language, 'en'), \
         COALESCE(timezone, 'UTC'), COALESCE(update_channel, 'stable'), COALESCE(default_dashboard, 'overview'), \
         COALESCE(setup_completed, 0), COALESCE(base_domain, ''), COALESCE(gemini_api_key, ''), \
         COALESCE(openai_api_key, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''), \
         COALESCE(anthropic_api_key, ''), COALESCE(anthropic_endpoint, ''), \
         COALESCE(local_provider, ''), COALESCE(local_model, '') FROM settings WHERE id = 1",
        [],
        |r| {
            let base_domain: String = r.get(7)?;
            let gemini_raw: String = r.get(8)?;
            let openai_raw: String = r.get(9)?;
            let anthropic_raw: String = r.get(12)?;
            Ok(SettingsPayload {
                ai_model: r.get(0)?,
                system_prompt: r.get(1)?,
                language: r.get(2)?,
                timezone: r.get(3)?,
                update_channel: r.get(4)?,
                default_dashboard: r.get(5)?,
                setup_completed: r.get(6)?,
                base_domain,
                gemini_api_key: mask_secret(&gemini_raw),
                openai_api_key: mask_secret(&openai_raw),
                lm_studio_endpoint: r.get(10)?,
                ollama_endpoint: r.get(11)?,
                anthropic_api_key: mask_secret(&anthropic_raw),
                anthropic_endpoint: r.get(13)?,
                local_provider: r.get(14)?,
                local_model: r.get(15)?,
            })
        },
    );

    drop(conn);
    match row {
        Ok(mut payload) => {
            if payload.base_domain.is_empty() {
                payload.base_domain = af_services::resolve_base_domain();
            }
            redact_settings_for_role(&mut payload, role);
            Json(payload).into_response()
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Json(SettingsPayload::default()).into_response()
        }
        Err(error) => {
            tracing::warn!(%error, "Failed to load settings");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            )
        }
    }
}

pub(super) static ADMIN_SETTINGS_WRITE_LOCK: Lazy<std::sync::Arc<tokio::sync::Mutex<()>>> =
    Lazy::new(|| std::sync::Arc::new(tokio::sync::Mutex::new(())));

#[cfg(test)]
pub(super) type BaseDomainSyncPauseHook = (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<tokio::sync::Notify>,
);

#[cfg(test)]
pub(super) static BASE_DOMAIN_SYNC_STAGE_HOOK: Lazy<
    std::sync::Mutex<Option<BaseDomainSyncPauseHook>>,
> = Lazy::new(|| std::sync::Mutex::new(None));

pub(super) async fn update_settings(
    Extension(user): Extension<AuthUser>,
    Json(mut req): Json<SettingsPayload>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    req.ai_model = req.ai_model.trim().to_owned();
    req.local_provider = req.local_provider.trim().to_owned();
    req.local_model = req.local_model.trim().to_owned();
    if (!req.local_provider.is_empty()
        && !matches!(
            req.local_provider.as_str(),
            "lm-studio" | "ollama" | "anthropic-local"
        ))
        || (!req.local_model.is_empty()
            && !crate::intelligence::is_valid_local_model_id(&req.local_model))
        || crate::intelligence::is_forbidden_model_alias(&req.ai_model)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AI_SETTINGS",
            "Use a local runtime and an installed model identifier, not a provider alias",
        );
    }
    for endpoint in [
        &mut req.lm_studio_endpoint,
        &mut req.ollama_endpoint,
        &mut req.anthropic_endpoint,
    ] {
        if !endpoint.trim().is_empty() {
            match af_services::validate_server_url(endpoint) {
                Ok(clean) => *endpoint = clean,
                Err(_) => {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ENDPOINT",
                        "Invalid or disallowed AI endpoint URL",
                    )
                }
            }
        } else {
            endpoint.clear();
        }
    }
    fn endpoint_origin_tuple(raw: &str) -> Option<(String, String, u16)> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let parsed = url::Url::parse(trimmed).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let port = parsed.port_or_known_default()?;
        Some((parsed.scheme().to_ascii_lowercase(), host, port))
    }

    fn is_loopback_ai_endpoint_url(raw: &str) -> bool {
        let Ok(parsed) = url::Url::parse(raw.trim()) else {
            return false;
        };
        let Some(host) = parsed.host_str() else {
            return false;
        };
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
    }

    let channel = if req.update_channel == "nightly" {
        "nightly"
    } else if req.update_channel == "experimental" {
        "experimental"
    } else {
        "stable"
    };
    let norm_domain = if req.base_domain.trim().is_empty() {
        String::new()
    } else {
        let n = af_db::normalize_base_domain(&req.base_domain);
        if n.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_DOMAIN",
                "Invalid base domain",
            );
        }
        n
    };

    // Serialize all PUT /admin/settings writes (including fast-path and blank saves)
    // against in-flight base-domain syncs without requiring the privileged runner for
    // unrelated saves.
    let settings_guard = ADMIN_SETTINGS_WRITE_LOCK.clone().lock_owned().await;

    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let (prev_anth_endpoint, prev_anth_key, prev_base_domain_raw): (String, String, String) = match conn
        .query_row(
            "SELECT COALESCE(anthropic_endpoint, ''), COALESCE(anthropic_api_key, ''), COALESCE(base_domain, '') FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ) {
        Ok(values) => values,
        Err(rusqlite::Error::QueryReturnedNoRows) => Default::default(),
        Err(error) => {
            tracing::warn!(%error, "Could not inspect current settings state");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SETTINGS_SAVE_FAILED",
                "Settings could not be saved",
            );
        }
    };
    let db_prev_base_domain = af_db::normalize_base_domain(&prev_base_domain_raw);
    let pending_sync = match af_db::get_pending_base_domain_sync(&conn) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "Could not inspect pending base-domain synchronization state");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SETTINGS_SAVE_FAILED",
                "Settings could not be saved",
            );
        }
    };
    let effective_prev_anth = if prev_anth_endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        prev_anth_endpoint.trim()
    };
    let effective_next_anth = if req.anthropic_endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        req.anthropic_endpoint.trim()
    };
    let retaining_anth_key =
        is_masked_secret(&req.anthropic_api_key) && !prev_anth_key.trim().is_empty();
    let supplying_fresh_anth_key =
        !req.anthropic_api_key.trim().is_empty() && !is_masked_secret(&req.anthropic_api_key);
    let will_have_anth_key = supplying_fresh_anth_key || retaining_anth_key;

    if retaining_anth_key
        && endpoint_origin_tuple(effective_prev_anth) != endpoint_origin_tuple(effective_next_anth)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "ENDPOINT_KEY_REBIND_DENIED",
            "Changing anthropic_endpoint while an API key is stored requires supplying a fresh API key in the same request",
        );
    }
    if will_have_anth_key
        && !req.anthropic_endpoint.trim().is_empty()
        && !req.anthropic_endpoint.trim().starts_with("https://")
        && !is_loopback_ai_endpoint_url(&req.anthropic_endpoint)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INSECURE_AI_ENDPOINT",
            "Non-loopback AI endpoints carrying an API key must use https://",
        );
    }

    let sync_needed =
        !norm_domain.is_empty() && (norm_domain != db_prev_base_domain || pending_sync.is_some());
    if !sync_needed {
        let saved = (|| -> anyhow::Result<()> {
            let transaction =
                conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_settings_in_tx(&transaction, &req, channel, &norm_domain)?;
            if norm_domain.is_empty() {
                if let Some(ref pending) = pending_sync {
                    if !db_prev_base_domain.is_empty()
                        && !pending
                            .source_base_domains
                            .iter()
                            .any(|existing| existing == &db_prev_base_domain)
                    {
                        let mut sources = pending.source_base_domains.clone();
                        sources.push(db_prev_base_domain.clone());
                        af_db::set_pending_base_domain_sync(
                            &transaction,
                            &pending.previous_base_domain,
                            &pending.target_base_domain,
                            &sources,
                        )?;
                    }
                } else if !db_prev_base_domain.is_empty() {
                    af_db::set_pending_base_domain_sync(
                        &transaction,
                        &db_prev_base_domain,
                        "",
                        std::slice::from_ref(&db_prev_base_domain),
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = saved {
            tracing::warn!(%error, "Settings update was rolled back");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SETTINGS_SAVE_FAILED",
                "Settings could not be saved",
            );
        }

        drop(conn);
        af_db::invalidate_ingress_cache();
        af_db::get_base_domain();
        drop(settings_guard);

        req.gemini_api_key.clear();
        req.openai_api_key.clear();
        req.anthropic_api_key.clear();
        req.base_domain = norm_domain;
        req.update_channel = channel.to_string();

        return Json(serde_json::json!({
            "message": "Settings saved successfully",
            "data": req,
        }))
        .into_response();
    }

    drop(conn);
    let sync_req = req.clone();
    let sync_domain = norm_domain.clone();
    let sync_channel = channel;
    // Keep settings write serialization and lifecycle admission active until host
    // synchronization or rollback finishes, including when the HTTP client disconnects.
    let synchronized = tokio::spawn(async move {
        let _settings_guard = settings_guard;
        af_services::mutators::with_blueprint_admission(async move {
            Ok(synchronize_base_domain_update(sync_req, sync_channel, sync_domain).await)
        })
        .await
    })
    .await;
    match synchronized {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(failure))) => return base_domain_sync_failure_response(failure),
        Ok(Err(error)) => return blueprint_sync_failure_response(&error),
        Err(error) => return blueprint_sync_failure_response(&anyhow::Error::new(error)),
    }

    req.gemini_api_key.clear();
    req.openai_api_key.clear();
    req.anthropic_api_key.clear();
    req.base_domain = norm_domain;
    req.update_channel = channel.to_string();

    Json(serde_json::json!({
        "message": "Settings saved successfully",
        "data": req,
    }))
    .into_response()
}

pub(super) fn persist_settings_in_tx(
    transaction: &rusqlite::Connection,
    req: &SettingsPayload,
    channel: &str,
    norm_domain: &str,
) -> anyhow::Result<()> {
    let updated = transaction.execute(
        "UPDATE settings SET ai_model = ?1, system_prompt = ?2, language = ?3, timezone = ?4, \
         update_channel = ?5, default_dashboard = ?6, setup_completed = ?7, base_domain = ?8, \
         lm_studio_endpoint = ?9, ollama_endpoint = ?10, anthropic_endpoint = ?11, \
         local_provider = ?12, local_model = ?13, \
         updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![
            req.ai_model,
            req.system_prompt,
            req.language,
            req.timezone,
            channel,
            req.default_dashboard,
            req.setup_completed,
            norm_domain,
            req.lm_studio_endpoint,
            req.ollama_endpoint,
            req.anthropic_endpoint,
            req.local_provider,
            req.local_model,
        ],
    )?;
    anyhow::ensure!(updated == 1, "Settings row is missing");
    for (column, value) in [
        ("gemini_api_key", &req.gemini_api_key),
        ("openai_api_key", &req.openai_api_key),
        ("anthropic_api_key", &req.anthropic_api_key),
    ] {
        if !is_masked_secret(value) {
            let encrypted = if value.is_empty() {
                String::new()
            } else {
                af_db::encrypt_key(value)?
            };
            transaction.execute(
                &format!("UPDATE settings SET {column} = ?1 WHERE id = 1"),
                params![encrypted],
            )?;
        }
    }
    Ok(())
}

pub(super) fn env_fallback_base_domain() -> String {
    env::var("AETHERFLOW_BASE_DOMAIN")
        .or_else(|_| env::var("AETHERFLOW_DOMAIN"))
        .map(|d| af_db::normalize_base_domain(&d))
        .unwrap_or_default()
}

pub(crate) fn is_generated_public_domain(
    app_name: &str,
    public_domain: &str,
    base_domain: &str,
) -> bool {
    let current = af_db::normalize_base_domain(public_domain);
    let expected = af_services::format_app_public_domain(app_name, base_domain);
    !current.is_empty() && !expected.is_empty() && current == expected
}

pub(super) fn should_auto_update_active_domain(
    app_name: &str,
    public_domain: &str,
    source_base_domains: &[String],
    target_base_domain: &str,
) -> bool {
    let trimmed = public_domain.trim();
    if trimmed.is_empty() {
        return true;
    }
    source_base_domains
        .iter()
        .any(|source| is_generated_public_domain(app_name, trimmed, source))
        || is_generated_public_domain(app_name, trimmed, target_base_domain)
}

pub(super) fn should_auto_update_retained_domain(
    app_name: &str,
    public_domain: &str,
    source_base_domains: &[String],
    target_base_domain: &str,
) -> bool {
    let trimmed = public_domain.trim();
    if trimmed.is_empty() {
        return false;
    }
    !is_generated_public_domain(app_name, trimmed, target_base_domain)
        && source_base_domains
            .iter()
            .any(|source| is_generated_public_domain(app_name, trimmed, source))
}

pub(super) struct PlannedActiveIngressUpdate {
    app_name: String,
    internal_domain: String,
    has_blueprint: bool,
    previous_active: Option<AppIngressConfig>,
    next_config: AppIngressConfig,
}

pub(super) struct PlannedRetainedIngressUpdate {
    app_key: String,
    app_name: String,
    has_blueprint: bool,
    next_config: AppIngressConfig,
}

pub(super) enum BaseDomainSyncFailure {
    Persistence(anyhow::Error),
    LifecycleBusy(anyhow::Error),
    Phase {
        failed_phase: &'static str,
        partial_commit: bool,
        error: anyhow::Error,
    },
}

pub(super) fn base_domain_sync_failure_response(failure: BaseDomainSyncFailure) -> Response {
    match failure {
        BaseDomainSyncFailure::Persistence(error) => {
            tracing::warn!(%error, "Settings update was rolled back");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SETTINGS_SAVE_FAILED",
                "Settings could not be saved",
            )
        }
        BaseDomainSyncFailure::LifecycleBusy(error) => blueprint_sync_failure_response(&error),
        BaseDomainSyncFailure::Phase {
            failed_phase,
            partial_commit,
            error,
        } => {
            if af_runner::is_lifecycle_busy(&error) {
                return blueprint_sync_failure_response(&error);
            }
            let error_id = uuid::Uuid::new_v4().to_string();
            tracing::error!(
                %error_id,
                failed_phase,
                partial_commit,
                detail = %format!("{error:#}"),
                "base-domain synchronization failed"
            );
            let message = if partial_commit {
                "Base-domain synchronization failed after committing partial changes; retrying with the same base domain is safe once diagnostics are resolved"
            } else {
                "Base-domain synchronization could not be completed; inspect authorized diagnostics before retrying"
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
                })),
            )
                .into_response()
        }
    }
}

pub(super) fn restore_base_domain_after_sync_failure(
    restore_domain: &str,
    prior_pending: Option<&af_db::PendingBaseDomainSync>,
    target_committed: bool,
) -> anyhow::Result<()> {
    let mut conn = af_db::get_conn()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE settings SET base_domain = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![restore_domain],
    )?;
    if !target_committed {
        match prior_pending {
            Some(pending) => af_db::set_pending_base_domain_sync(
                &tx,
                &pending.previous_base_domain,
                &pending.target_base_domain,
                &pending.source_base_domains,
            )?,
            None => af_db::clear_pending_base_domain_sync(&tx)?,
        }
    }
    tx.commit()?;
    drop(conn);
    af_db::invalidate_ingress_cache();
    af_db::get_base_domain();
    Ok(())
}

pub(super) async fn apply_planned_active_ingress_update(
    item: PlannedActiveIngressUpdate,
) -> Result<(), (&'static str, anyhow::Error)> {
    let apply_one = async {
        let save_cfg = item.next_config.clone();
        tokio::task::spawn_blocking(move || af_db::set_app_ingress_config(&save_cfg))
            .await
            .map_err(|error| ("ingress", anyhow::Error::new(error)))?
            .map_err(|error| ("ingress", error))?;

        let mut native_mutated = false;
        if item.has_blueprint {
            match af_services::mutators::apply_blueprint_host_config(
                &item.app_name,
                u16::try_from(item.next_config.listen_port).unwrap_or(0),
            )
            .await
            {
                Ok(summary) => {
                    native_mutated = summary.config_applied;
                }
                Err(error) => {
                    let rollback_app = item.app_name.clone();
                    let rollback_prev = item.previous_active.clone();
                    if let Err(rollback_err) = tokio::task::spawn_blocking(move || {
                        restore_ingress_config(&rollback_app, rollback_prev.as_ref())
                    })
                    .await
                    .map_err(anyhow::Error::new)
                    .and_then(|res| res)
                    {
                        tracing::error!(
                            app = %item.app_name,
                            %rollback_err,
                            "Could not restore ingress row after native config failure"
                        );
                    }
                    return Err(("config", anyhow::Error::msg(error)));
                }
            }
        }

        let vhost_cfg = item.next_config.clone();
        let vhost_internal = item.internal_domain.clone();
        let vhost_result = tokio::task::spawn_blocking(move || {
            apply_ingress_vhost_policy(&vhost_cfg, &vhost_internal)
        })
        .await
        .map_err(anyhow::Error::new)
        .and_then(|res| res);
        if let Err(error) = vhost_result {
            let rollback_app = item.app_name.clone();
            let rollback_prev = item.previous_active.clone();
            let rollback_internal = item.internal_domain.clone();
            if let Err(rollback_err) = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                restore_ingress_config(&rollback_app, rollback_prev.as_ref())?;
                if let Some(previous) = rollback_prev {
                    if let Err(vhost_err) = sync_ingress_vhost(&previous, &rollback_internal) {
                        tracing::error!(
                            app = %rollback_app,
                            %vhost_err,
                            "Could not reapply previous Apache vhost during base-domain rollback"
                        );
                    }
                }
                Ok(())
            })
            .await
            .map_err(anyhow::Error::new)
            .and_then(|res| res)
            {
                tracing::error!(
                    app = %item.app_name,
                    %rollback_err,
                    "Could not restore ingress state after Apache failure"
                );
            }
            if native_mutated {
                return Err(("ingress_partial", error));
            }
            return Err(("ingress", error));
        }
        Ok::<(), (&'static str, anyhow::Error)>(())
    };

    if item.has_blueprint {
        match af_services::mutators::with_blueprint_mutation(&item.app_name, async {
            Ok(apply_one.await)
        })
        .await
        {
            Ok(inner) => inner,
            Err(error) => Err(("preflight", error)),
        }
    } else {
        apply_one.await
    }
}

pub(super) async fn synchronize_base_domain_update(
    req: SettingsPayload,
    channel: &'static str,
    norm_domain: String,
) -> Result<(), BaseDomainSyncFailure> {
    let plan_domain = norm_domain.clone();
    let (
        db_prev_base_domain,
        origin_base_domain,
        prior_pending,
        source_base_domains,
        active_updates,
        retained_updates,
    ) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        af_db::invalidate_ingress_cache();
        let conn = af_db::get_conn()?;
        let db_prev_raw: String = conn
            .query_row(
                "SELECT COALESCE(base_domain, '') FROM settings WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let db_prev = af_db::normalize_base_domain(&db_prev_raw);
        let pending = af_db::get_pending_base_domain_sync(&conn)?;
        drop(conn);

        let env_base = env_fallback_base_domain();
        let origin_base = if let Some(ref pending) = pending {
            if !pending.previous_base_domain.is_empty() {
                pending.previous_base_domain.clone()
            } else if !db_prev.is_empty() && db_prev != plan_domain {
                db_prev.clone()
            } else {
                env_base.clone()
            }
        } else if !db_prev.is_empty() {
            db_prev.clone()
        } else {
            env_base.clone()
        };

        let mut source_base_domains = Vec::new();
        for candidate in [Some(origin_base.as_str()), Some(db_prev.as_str())]
            .into_iter()
            .flatten()
            .chain(
                pending
                    .iter()
                    .flat_map(|item| item.source_base_domains.iter().map(String::as_str)),
            )
            .chain(
                [
                    pending
                        .as_ref()
                        .map(|item| item.target_base_domain.as_str()),
                    if db_prev.is_empty() {
                        Some(env_base.as_str())
                    } else {
                        None
                    },
                ]
                .into_iter()
                .flatten(),
            )
        {
            if !candidate.is_empty()
                && !source_base_domains
                    .iter()
                    .any(|existing| existing == candidate)
            {
                source_base_domains.push(candidate.to_string());
            }
        }

        let now = Utc::now();
        let active_configs = af_db::get_all_app_ingress_configs()?;
        let retained_configs = af_db::get_all_retained_app_ingress_configs()?;
        let packages = af_services::get_packages()?;

        let mut handled_apps = std::collections::HashSet::new();
        let mut retained_apps = std::collections::HashSet::new();
        let mut active_updates = Vec::new();
        let mut retained_updates = Vec::new();

        for cfg in active_configs {
            handled_apps.insert(cfg.app_name.trim().to_ascii_lowercase());
            if !should_auto_update_active_domain(
                &cfg.app_name,
                &cfg.public_domain,
                &source_base_domains,
                &plan_domain,
            ) {
                continue;
            }
            let blueprint = af_services::get_blueprint(&cfg.app_name);
            let listen_port = if cfg.listen_port > 0 {
                cfg.listen_port
            } else {
                let runtime_port =
                    af_services::mutators::get_app_runtime_meta(&cfg.app_name).configured_port;
                if runtime_port > 0 {
                    runtime_port
                } else {
                    blueprint.as_ref().map_or(0, |bp| bp.default_port)
                }
            };
            if listen_port <= 0 {
                continue;
            }
            let was_empty = cfg.public_domain.trim().is_empty();
            let next_public_domain =
                af_services::format_app_public_domain(&cfg.app_name, &plan_domain);
            if next_public_domain.is_empty() {
                continue;
            }
            let internal_domain = blueprint
                .as_ref()
                .map(|bp| bp.internal_domain.trim().to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .unwrap_or_else(|| af_services::resolve_app_internal_domain(&cfg.app_name));
            let next_config = AppIngressConfig {
                app_name: cfg.app_name.clone(),
                public_domain: next_public_domain,
                external_access_enabled: cfg.external_access_enabled,
                listen_port,
                tls_enabled: if was_empty { true } else { cfg.tls_enabled },
                created_at: cfg.created_at,
                updated_at: now,
            };
            active_updates.push(PlannedActiveIngressUpdate {
                app_name: cfg.app_name.clone(),
                internal_domain,
                has_blueprint: blueprint.is_some(),
                previous_active: Some(cfg),
                next_config,
            });
        }

        for (app_key, retained_cfg) in retained_configs {
            retained_apps.insert(app_key.trim().to_ascii_lowercase());
            if !should_auto_update_retained_domain(
                &retained_cfg.app_name,
                &retained_cfg.public_domain,
                &source_base_domains,
                &plan_domain,
            ) {
                continue;
            }
            let next_public_domain =
                af_services::format_app_public_domain(&retained_cfg.app_name, &plan_domain);
            if next_public_domain.is_empty() {
                continue;
            }
            let mut next_config = retained_cfg.clone();
            next_config.public_domain = next_public_domain;
            next_config.updated_at = now;
            retained_updates.push(PlannedRetainedIngressUpdate {
                app_key,
                has_blueprint: af_services::get_blueprint(&retained_cfg.app_name).is_some(),
                app_name: retained_cfg.app_name,
                next_config,
            });
        }

        for p in packages {
            let pkg_key = p.name.trim().to_ascii_lowercase();
            if p.status != "installed"
                || handled_apps.contains(&pkg_key)
                || retained_apps.contains(&pkg_key)
            {
                continue;
            }
            let runtime_port = af_services::mutators::get_app_runtime_meta(&p.name).configured_port;
            let listen_port = if runtime_port > 0 {
                runtime_port
            } else {
                p.default_port
            };
            if listen_port <= 0 {
                continue;
            }
            let pub_dom = af_services::format_app_public_domain(&p.name, &plan_domain);
            if pub_dom.is_empty() {
                continue;
            }
            let blueprint = af_services::get_blueprint(&p.name);
            let internal_domain = blueprint
                .as_ref()
                .map(|bp| bp.internal_domain.trim().to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .unwrap_or_else(|| af_services::resolve_app_internal_domain(&p.name));
            let next_config = AppIngressConfig {
                app_name: p.name.clone(),
                public_domain: pub_dom,
                external_access_enabled: false,
                listen_port,
                tls_enabled: true,
                created_at: now,
                updated_at: now,
            };
            active_updates.push(PlannedActiveIngressUpdate {
                app_name: p.name,
                internal_domain,
                has_blueprint: blueprint.is_some(),
                previous_active: None,
                next_config,
            });
        }

        Ok((
            db_prev,
            origin_base,
            pending,
            source_base_domains,
            active_updates,
            retained_updates,
        ))
    })
    .await
    .map_err(|error| BaseDomainSyncFailure::Phase {
        failed_phase: "preflight",
        partial_commit: false,
        error: anyhow::Error::new(error),
    })?
    .map_err(|error| BaseDomainSyncFailure::Phase {
        failed_phase: "preflight",
        partial_commit: false,
        error,
    })?;

    let prior_partial_commit = prior_pending
        .as_ref()
        .is_some_and(|pending| !pending.target_base_domain.is_empty());

    // Preflight lifecycle reservations for all affected apps before any DB or host write.
    let mut checked_apps = std::collections::HashSet::new();
    let preflight_targets: Vec<(String, bool)> = active_updates
        .iter()
        .map(|item| (item.app_name.clone(), item.has_blueprint))
        .chain(
            retained_updates
                .iter()
                .map(|item| (item.app_name.clone(), item.has_blueprint)),
        )
        .collect();
    for (app_name, has_blueprint) in preflight_targets {
        if !checked_apps.insert(app_name.trim().to_ascii_lowercase()) {
            continue;
        }
        let check = if has_blueprint {
            af_services::mutators::with_blueprint_mutation(&app_name, async { Ok(()) }).await
        } else {
            let check_app = app_name.clone();
            tokio::task::spawn_blocking(move || {
                af_db::check_app_ingress_reservation(&check_app)
                    .map_err(|error| error.context(af_runner::LifecycleBusy))
            })
            .await
            .map_err(anyhow::Error::new)
            .and_then(|res| res)
        };
        if let Err(error) = check {
            if af_runner::is_lifecycle_busy(&error) {
                return Err(BaseDomainSyncFailure::LifecycleBusy(error));
            }
            return Err(BaseDomainSyncFailure::Phase {
                failed_phase: "preflight",
                partial_commit: prior_partial_commit,
                error,
            });
        }
    }

    // Stage settings.base_domain and durable pending sync state so native config
    // mutators and DNS sync observe the target base domain and crashes remain retryable.
    let stage_origin = origin_base_domain.clone();
    let stage_target = norm_domain.clone();
    let mut stage_sources = source_base_domains;
    if !stage_target.is_empty()
        && !stage_sources
            .iter()
            .any(|existing| existing == &stage_target)
    {
        stage_sources.push(stage_target.clone());
    }
    let staged = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE settings SET base_domain = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            params![stage_target],
        )?;
        anyhow::ensure!(updated == 1, "Settings row is missing");
        af_db::set_pending_base_domain_sync(&tx, &stage_origin, &stage_target, &stage_sources)?;
        tx.commit()?;
        drop(conn);
        af_db::invalidate_ingress_cache();
        af_db::get_base_domain();
        Ok(())
    })
    .await
    .map_err(anyhow::Error::new)
    .and_then(|res| res);
    if let Err(error) = staged {
        return Err(BaseDomainSyncFailure::Persistence(error));
    }

    #[cfg(test)]
    {
        let stage_hook = BASE_DOMAIN_SYNC_STAGE_HOOK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((entered, release)) = stage_hook {
            entered.notify_one();
            release.notified().await;
        }
    }

    let restore_domain = if prior_pending.as_ref().is_some_and(|pending| {
        !pending.target_base_domain.is_empty()
            && (db_prev_base_domain == norm_domain
                || db_prev_base_domain == pending.target_base_domain)
    }) {
        origin_base_domain.clone()
    } else {
        db_prev_base_domain.clone()
    };

    let mut target_committed = false;
    let mut sync_error: Option<(&'static str, anyhow::Error)> = None;

    for item in active_updates {
        match Box::pin(apply_planned_active_ingress_update(item)).await {
            Ok(()) => {
                target_committed = true;
            }
            Err(("ingress_partial", error)) => {
                target_committed = true;
                sync_error = Some(("ingress", error));
                break;
            }
            Err((phase, error)) => {
                sync_error = Some((phase, error));
                break;
            }
        }
    }

    if sync_error.is_none() {
        if let Err(error) = af_services::mutators::sync_network_dns_providers().await {
            sync_error = Some(("network_dns", anyhow::Error::msg(error)));
        }
    }

    let partial_commit = prior_partial_commit || target_committed;
    if let Some((failed_phase, error)) = sync_error {
        let restore_for_task = restore_domain.clone();
        let restore_pending = prior_pending.clone();
        if let Err(restore_err) = tokio::task::spawn_blocking(move || {
            restore_base_domain_after_sync_failure(
                &restore_for_task,
                restore_pending.as_ref(),
                target_committed,
            )
        })
        .await
        .map_err(anyhow::Error::new)
        .and_then(|res| res)
        {
            tracing::error!(
                %restore_err,
                "Could not restore settings.base_domain after synchronization failure"
            );
        }
        return Err(BaseDomainSyncFailure::Phase {
            failed_phase,
            partial_commit,
            error,
        });
    }

    let final_domain = norm_domain.clone();
    let finalized = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = af_db::get_conn()?;
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        persist_settings_in_tx(&transaction, &req, channel, &final_domain)?;
        for retained in retained_updates {
            af_db::update_retained_app_ingress_config_in_tx(
                &transaction,
                &retained.app_key,
                &retained.next_config,
            )?;
        }
        af_db::clear_pending_base_domain_sync(&transaction)?;
        transaction.commit()?;
        drop(conn);
        af_db::invalidate_ingress_cache();
        af_db::get_base_domain();
        Ok(())
    })
    .await
    .map_err(anyhow::Error::new)
    .and_then(|res| res);
    if let Err(error) = finalized {
        let restore_for_task = restore_domain.clone();
        let restore_pending = prior_pending.clone();
        let _ = tokio::task::spawn_blocking(move || {
            restore_base_domain_after_sync_failure(
                &restore_for_task,
                restore_pending.as_ref(),
                target_committed,
            )
        })
        .await;
        return Err(BaseDomainSyncFailure::Persistence(error));
    }

    af_services::mutators::trigger_apache_cert_sync().await;
    Ok(())
}
