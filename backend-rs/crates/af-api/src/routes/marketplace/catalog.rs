use super::receipts::{sanitize_package_update_record, sanitize_url_or_source_key_for_api};
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_models::{AppIngressConfig, MarketplaceApp};
use axum::extract::{Extension, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize)]
pub(in crate::routes) struct MarketplaceQuery {
    #[serde(default)]
    require_auth: Option<String>,
}

pub(in crate::routes) fn parse_require_auth(query: &MarketplaceQuery) -> bool {
    matches!(
        query.require_auth.as_deref().map(str::trim),
        Some("1") | Some("true") | Some("yes")
    )
}

pub(in crate::routes) async fn get_marketplace_apps(
    Query(query): Query<MarketplaceQuery>,
    peer: Option<Extension<crate::auth::PeerPrincipal>>,
    headers: HeaderMap,
) -> Response {
    let require_auth = parse_require_auth(&query);
    let peer_authenticated = peer.is_some();
    let mut response = tokio::task::spawn_blocking(move || {
        get_marketplace_apps_blocking_for_peer(headers, require_auth, peer_authenticated)
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Marketplace status unavailable",
        )
    });
    // The same URL serves public catalog metadata and credential-dependent inventory.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().append(
        header::VARY,
        HeaderValue::from_static("Authorization, Cookie"),
    );
    response
}

pub(crate) fn get_marketplace_auth_info(headers: &HeaderMap) -> (bool, bool) {
    let Some(token) = crate::auth::resolve_raw_token(headers) else {
        return (false, false);
    };
    if let Ok(plugin_claims) = crate::plugins::decode_and_verify_plugin_token(&token) {
        let is_authed = crate::plugins::plugin_claims_allow_request(
            &plugin_claims,
            &axum::http::Method::GET,
            "/api/v1/public/marketplace",
        ) || crate::plugins::plugin_claims_allow_request(
            &plugin_claims,
            &axum::http::Method::GET,
            "/api/v1/auth/packages",
        );
        return (is_authed, false);
    }
    if let Ok(claims) = crate::auth::decode_session_claims(&token, false) {
        if !claims.plugin_id.is_empty() || !claims.plugin_scopes.is_empty() {
            return (false, false);
        }
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let client_ip = extract_client_ip(headers);
        if !crate::auth::matches_client_fingerprint(&claims.cfp, &client_ip, ua) {
            return (false, false);
        }
        let caller_strict_fp = crate::auth::legacy_client_fingerprint(&client_ip, ua);
        let Ok(conn) = af_db::get_read_conn() else {
            return (false, false);
        };
        let Ok(subj) = crate::auth::verify_active_session_on_conn(
            &conn,
            claims.user_id,
            &claims.jti,
            claims.ver,
            chrono::Utc::now().timestamp(),
            crate::auth::RotationGrace::StrictFingerprint(&caller_strict_fp),
        ) else {
            return (false, false);
        };
        let is_admin = subj.role.trim().eq_ignore_ascii_case("admin");
        return (true, is_admin);
    }
    (false, false)
}

#[cfg(test)]
pub(in crate::routes) fn get_marketplace_apps_blocking(
    headers: HeaderMap,
    require_auth: bool,
) -> Response {
    get_marketplace_apps_blocking_for_peer(headers, require_auth, false)
}

fn get_marketplace_apps_blocking_for_peer(
    headers: HeaderMap,
    require_auth: bool,
    peer_authenticated: bool,
) -> Response {
    let (is_authenticated, diagnostics_allowed) = if peer_authenticated {
        (true, true)
    } else {
        get_marketplace_auth_info(&headers)
    };
    if require_auth && !is_authenticated {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required for marketplace inventory",
        );
    }
    if !is_authenticated {
        let Ok(pkgs) = af_services::get_package_catalog() else {
            return marketplace_unavailable();
        };
        let public_apps: Vec<serde_json::Value> = pkgs
            .into_iter()
            .map(|p| {
                let mut map = serde_json::Map::new();
                map.insert("id".to_string(), serde_json::Value::String(p.name));
                map.insert("name".to_string(), serde_json::Value::String(p.label));
                map.insert("desc".to_string(), serde_json::Value::String(p.description));
                map.insert("hits".to_string(), serde_json::json!(p.hits));
                map.insert(
                    "category".to_string(),
                    serde_json::Value::String(p.category),
                );
                map.insert(
                    "status".to_string(),
                    serde_json::Value::String("not_installed".to_string()),
                );
                if p.default_port > 0 {
                    map.insert(
                        "default_port".to_string(),
                        serde_json::json!(p.default_port),
                    );
                }
                if !p.web_path.is_empty() {
                    map.insert(
                        "web_path".to_string(),
                        serde_json::Value::String(p.web_path),
                    );
                }
                map.insert(
                    "inventory_known".to_string(),
                    serde_json::Value::Bool(false),
                );
                map.insert(
                    "inventory_authenticated".to_string(),
                    serde_json::Value::Bool(false),
                );
                map.insert(
                    "inventory_mode".to_string(),
                    serde_json::Value::String(
                        af_models::INVENTORY_MODE_PUBLIC_REDACTED.to_string(),
                    ),
                );
                serde_json::Value::Object(map)
            })
            .collect();

        return (
            [
                (
                    axum::http::header::HeaderName::from_static("x-aetherflow-inventory-mode"),
                    axum::http::HeaderValue::from_static(af_models::INVENTORY_MODE_PUBLIC_REDACTED),
                ),
                (
                    axum::http::header::HeaderName::from_static(
                        "x-aetherflow-inventory-authenticated",
                    ),
                    axum::http::HeaderValue::from_static("false"),
                ),
            ],
            Json(public_apps),
        )
            .into_response();
    }

    let Ok(jobs) = af_services::package_job_snapshot() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Lifecycle status could not be confirmed; retry shortly",
        );
    };
    let Ok(pkgs) = af_services::get_packages_with_jobs(&jobs) else {
        return marketplace_unavailable();
    };
    let ingress_map: HashMap<String, AppIngressConfig> = match af_db::get_all_app_ingress_configs()
    {
        Ok(configs) => configs
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "Failed to load app ingress configs for marketplace");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load marketplace ingress configuration",
            );
        }
    };
    let retained_packages = match af_services::retained_lifecycle_packages() {
        Ok(packages) => packages,
        Err(error) => {
            tracing::warn!(%error, "Failed to load retained lifecycle packages for marketplace");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load marketplace retained lifecycle state",
            );
        }
    };
    let retained_ingress_keys: std::collections::HashSet<String> =
        match af_db::list_retained_app_ingress_names() {
            Ok(names) => names
                .into_iter()
                .map(|name| {
                    af_models::resolve_package_lock_name(&name.trim().to_ascii_lowercase())
                        .to_string()
                })
                .filter(|name| !name.is_empty())
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "Failed to load retained ingress state for marketplace");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Could not load marketplace retained ingress state",
                );
            }
        };
    let base_domain = af_services::resolve_base_domain();

    let mut apps = Vec::with_capacity(pkgs.len());
    for p in pkgs {
        let mut active_port = p.default_port;
        let internal_domain = af_services::resolve_app_internal_domain(&p.name);
        let mut public_domain = String::new();
        let mut external_access = false;
        let mut tls_enabled = true;

        if let Some(ing) = ingress_map.get(&p.name) {
            if ing.listen_port > 0 {
                active_port = ing.listen_port;
            }
            public_domain = ing.public_domain.clone();
            external_access = ing.external_access_enabled;
            tls_enabled = ing.tls_enabled;
        }
        if public_domain.is_empty() && !base_domain.is_empty() && active_port > 0 {
            public_domain = af_services::format_app_public_domain(&p.name, &base_domain);
        }
        let retained_data_present = package_has_retained_purge_evidence(
            &p,
            &jobs,
            &retained_packages,
            &retained_ingress_keys,
        );

        let mut app = MarketplaceApp {
            id: p.name.clone(),
            name: p.label,
            desc: p.description,
            hits: p.hits,
            category: p.category,
            status: p.status,
            default_port: p.default_port,
            active_port,
            internal_domain,
            public_domain,
            external_access_enabled: external_access,
            tls_enabled,
            web_path: p.web_path,
            bind_scope: af_services::service_bind_scope_for_id(&p.name).to_owned(),
            web_scheme: af_services::service_web_scheme_for_id(&p.name, active_port).to_owned(),
            launch_url: p.launch_url,
            launch_scope: p.launch_scope,
            progress: 0,
            started_at: None,
            job_id: None,
            log_line: String::new(),
            installed_version: sanitize_url_or_source_key_for_api(&p.installed_version),
            latest_version: sanitize_url_or_source_key_for_api(&p.latest_version),
            update_available: p.update_available,
            update_checked_at: p.update_checked_at,
            update_url: sanitize_url_or_source_key_for_api(&p.update_url),
            update_error: sanitize_url_or_source_key_for_api(
                &af_services::workers::public_update_error(&p.update_error),
            ),
            inventory_known: true,
            inventory_authenticated: true,
            inventory_mode: af_models::INVENTORY_MODE_AUTHENTICATED.to_string(),
            retained_data_present,
            last_job: jobs
                .outcomes
                .get(&p.name)
                .map(|outcome| af_models::MarketplaceJobOutcome {
                    job_id: outcome.job_id.clone(),
                    action: outcome.action.clone(),
                    status: outcome.status.clone(),
                    started_at: outcome.started_at.clone(),
                    finished_at: outcome.finished_at.clone(),
                    expected_target_version: outcome
                        .expected_target_version
                        .as_deref()
                        .map(sanitize_url_or_source_key_for_api),
                    achieved_version: outcome
                        .achieved_version
                        .as_deref()
                        .map(sanitize_url_or_source_key_for_api),
                    failed_stage: if diagnostics_allowed {
                        outcome
                            .failed_stage
                            .as_deref()
                            .map(sanitize_url_or_source_key_for_api)
                    } else {
                        None
                    },
                    exit_code: if diagnostics_allowed {
                        outcome.exit_code
                    } else {
                        None
                    },
                    sanitized_summary: if diagnostics_allowed {
                        outcome.sanitized_summary.as_deref().map(|summary| {
                            sanitize_url_or_source_key_for_api(&af_services::redact_secrets(
                                summary,
                            ))
                        })
                    } else {
                        None
                    },
                }),
        };

        if let Some(job) = jobs.active.get(&p.name).cloned() {
            app.progress = job.progress;
            app.job_id = Some(job.job_id);
            app.started_at = Some(job.started_at);
            app.log_line = sanitize_url_or_source_key_for_api(
                af_services::package_job_progress_summary(&job.status),
            );
        }

        apps.push(app);
    }

    (
        [
            (
                axum::http::header::HeaderName::from_static("x-aetherflow-inventory-mode"),
                axum::http::HeaderValue::from_static(af_models::INVENTORY_MODE_AUTHENTICATED),
            ),
            (
                axum::http::header::HeaderName::from_static("x-aetherflow-inventory-authenticated"),
                axum::http::HeaderValue::from_static("true"),
            ),
        ],
        Json(apps),
    )
        .into_response()
}

pub(in crate::routes) fn package_has_retained_purge_evidence(
    pkg: &af_models::Package,
    jobs: &af_services::PackageJobSnapshot,
    retained_packages: &std::collections::HashSet<String>,
    retained_ingress_keys: &std::collections::HashSet<String>,
) -> bool {
    if jobs.active.contains_key(&pkg.name)
        || !matches!(
            pkg.status.as_str(),
            "uninstalled" | "not_installed" | "retired"
        )
    {
        return false;
    }
    let explicit_lock = (!pkg.lock_file.trim().is_empty()).then_some(pkg.lock_file.as_str());
    let Ok(receipts) = af_models::inspect_package_receipts(&pkg.name, explicit_lock, None) else {
        return false;
    };
    if receipts.has_any_receipt() {
        return false;
    }
    if receipts.has_retained_receipt() {
        return true;
    }
    let lock_key =
        af_models::resolve_package_lock_name(&pkg.name.trim().to_ascii_lowercase()).to_string();
    !lock_key.is_empty()
        && (retained_packages.contains(&lock_key) || retained_ingress_keys.contains(&lock_key))
}

pub(in crate::routes) fn marketplace_unavailable() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Failed to load package catalog configuration",
    )
}

pub(in crate::routes) fn package_progress_payload(
    id: &str,
    active: Option<af_services::PackageJobInfo>,
    outcome: Option<af_services::PackageJobOutcome>,
    diagnostics_allowed: bool,
) -> serde_json::Value {
    if let Some(mut job) = active {
        if !diagnostics_allowed {
            job.last_line = af_services::package_job_progress_summary(&job.status).into();
        } else {
            job.last_line =
                sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&job.last_line));
        }
        return serde_json::to_value(job).unwrap_or_default();
    }
    if let Some(mut outcome) = outcome {
        // Authenticated view: include the terminal failure message so clients
        // can report why a job failed after the active entry is gone.
        if !diagnostics_allowed {
            outcome.message = af_services::package_job_progress_summary(&outcome.status).into();
            outcome.failed_stage = None;
            outcome.exit_code = None;
            outcome.sanitized_summary = None;
            outcome.recovery_state = None;
        } else {
            outcome.message =
                sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&outcome.message));
            outcome.sanitized_summary = outcome
                .sanitized_summary
                .map(|s| sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&s)));
            outcome.failed_stage = outcome
                .failed_stage
                .map(|s| sanitize_url_or_source_key_for_api(&s));
            outcome.expected_target_version = outcome
                .expected_target_version
                .map(|v| sanitize_url_or_source_key_for_api(&v));
            outcome.achieved_version = outcome
                .achieved_version
                .map(|v| sanitize_url_or_source_key_for_api(&v));
        }
        return serde_json::json!({
            "package_id": id,
            "job_id": outcome.job_id,
            "action": outcome.action,
            "status": outcome.status,
            "progress": if outcome.status == "completed" { 100 } else { 0 },
            "last_line": outcome.message,
            "message": outcome.message,
            "started_at": outcome.started_at,
            "finished_at": outcome.finished_at,
            "last_job": outcome,
        });
    }
    serde_json::json!({
        "package_id": id,
        "status": "idle",
        "progress": 0,
    })
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::routes) struct PackageProgressQuery {
    pub(in crate::routes) job_id: Option<String>,
}

pub(in crate::routes) async fn package_progress(
    Path(id): Path<String>,
    Query(query): Query<PackageProgressQuery>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let diagnostics_allowed = crate::ws::package_diagnostics_allowed(&auth_user);
    tokio::task::spawn_blocking(move || {
        let Ok(jobs) = af_services::package_job_snapshot() else {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Lifecycle status could not be confirmed; retry shortly",
            );
        };
        let matches_job = |id: &str| query.job_id.as_deref().is_none_or(|expected| id == expected);
        let active = jobs.active.get(&id).filter(|job| matches_job(&job.job_id)).cloned();
        let mut outcome = jobs.outcomes.get(&id).filter(|job| matches_job(&job.job_id)).cloned();
        if let Some(job_id) = query.job_id.filter(|_| active.is_none() && outcome.is_none()) {
            match af_services::get_package_job_history_outcome(&id, &job_id) {
                Ok(Some(receipt)) => outcome = Some(receipt),
                Ok(None) => return api_error(
                    StatusCode::NOT_FOUND,
                    "PACKAGE_JOB_NOT_FOUND",
                    "The package operation receipt is unavailable. Check the current package state.",
                ),
                Err(_) => return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STATUS_UNAVAILABLE",
                    "Lifecycle status could not be confirmed; retry shortly",
                ),
            }
        }
        Json(package_progress_payload(&id, active, outcome, diagnostics_allowed))
        .into_response()
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Lifecycle status could not be confirmed; retry shortly",
        )
    })
}

pub(in crate::routes) async fn check_package_updates() -> Response {
    let records = match af_services::workers::refresh_all_package_updates().await {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(error = %error, "package update check inventory unavailable");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Application inventory could not be confirmed; retry the update check shortly",
            );
        }
    };
    let updates_available = records.iter().filter(|r| r.update_available).count();
    let pkg_repo_urls: HashMap<String, String> = af_services::get_packages()
        .unwrap_or_default()
        .into_iter()
        .map(|p| {
            (
                p.name,
                sanitize_url_or_source_key_for_api(&p.update_repo_url),
            )
        })
        .collect();

    let updates: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            let sanitized = sanitize_package_update_record(r);
            let mut val = serde_json::to_value(&sanitized).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let repo_url = pkg_repo_urls
                    .get(&sanitized.package_id)
                    .cloned()
                    .unwrap_or_default();
                if !repo_url.is_empty() {
                    obj.insert(
                        "update_repo_url".to_string(),
                        serde_json::Value::String(repo_url),
                    );
                }
                if !sanitized.source_key.is_empty() {
                    obj.insert(
                        "update_source_key".to_string(),
                        serde_json::Value::String(sanitized.source_key.clone()),
                    );
                }
                if !sanitized.release_url.is_empty() {
                    obj.insert(
                        "update_url".to_string(),
                        serde_json::Value::String(sanitized.release_url.clone()),
                    );
                }
            }
            val
        })
        .collect();

    Json(serde_json::json!({
        "message": "Package update check completed",
        "updates": updates,
        "updates_available": updates_available,
    }))
    .into_response()
}

pub(in crate::routes) async fn check_single_package_update(Path(id): Path<String>) -> Response {
    let Ok(pkgs) = af_services::get_packages() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load package catalog configuration",
        );
    };
    let Some(pkg) = pkgs.into_iter().find(|p| p.name == id) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Package not found");
    };
    let record = af_services::workers::refresh_package_update_by_id(&pkg.name).await;
    let record = record.map(sanitize_package_update_record);
    Json(build_single_package_update_response(&pkg.name, record)).into_response()
}

pub(in crate::routes) fn build_single_package_update_response(
    pkg_name: &str,
    mut record: Option<af_services::workers::PackageUpdateRecord>,
) -> serde_json::Value {
    if let Some(record) = record.as_mut() {
        record.error = af_services::workers::public_update_error(&record.error);
        *record = sanitize_package_update_record(record.clone());
    }
    let update_available = record.as_ref().map(|r| r.update_available).unwrap_or(false);
    let installed_version = record.as_ref().map(|r| r.installed_version.clone());
    let latest_version = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.latest_version));
    let update_url = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.release_url));
    let release_url = update_url.clone();
    let update_source_key = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.source_key));
    let update_repo_url = af_services::get_packages()
        .ok()
        .and_then(|pkgs| pkgs.into_iter().find(|p| p.name == pkg_name))
        .map(|p| sanitize_url_or_source_key_for_api(&p.update_repo_url))
        .filter(|u| !u.is_empty());
    let checked_at = record.as_ref().map(|r| r.checked_at.clone());
    let last_error = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.error))
        .filter(|e| !e.trim().is_empty());
    serde_json::json!({
        "message": "Package update check completed",
        "package": pkg_name,
        "update_available": update_available,
        "installed_version": installed_version,
        "latest_version": latest_version,
        "update_url": update_url,
        "release_url": release_url,
        "update_repo_url": update_repo_url,
        "update_source_key": update_source_key,
        "checked_at": checked_at,
        "last_error": last_error,
        "error": last_error,
        "update": record,
    })
}
