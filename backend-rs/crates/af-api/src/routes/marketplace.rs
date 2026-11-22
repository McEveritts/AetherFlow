use super::*;

#[derive(Debug, Default, Deserialize)]
pub(super) struct MarketplaceQuery {
    #[serde(default)]
    require_auth: Option<String>,
}

fn parse_require_auth(query: &MarketplaceQuery) -> bool {
    matches!(
        query.require_auth.as_deref().map(str::trim),
        Some("1") | Some("true") | Some("yes")
    )
}

pub(super) async fn get_marketplace_apps(
    Query(query): Query<MarketplaceQuery>,
    headers: HeaderMap,
) -> Response {
    let require_auth = parse_require_auth(&query);
    let mut response =
        tokio::task::spawn_blocking(move || get_marketplace_apps_blocking(headers, require_auth))
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

pub(super) fn get_marketplace_auth_info(headers: &HeaderMap) -> (bool, bool) {
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
        if crate::auth::is_session_token_revoked_beyond_grace(&claims.jti, claims.user_id) {
            return (false, false);
        }
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
        let Ok(conn) = af_db::get_read_conn() else {
            return (false, false);
        };
        let Ok(subj) = crate::auth::load_active_human_subject(&conn, claims.user_id) else {
            return (false, false);
        };
        if claims.ver < subj.sessions_revoked_after {
            return (false, false);
        }
        if crate::auth::table_exists(&conn, "active_sessions").unwrap_or(false) {
            let resolved_jti = crate::auth::resolve_current_session_jti(&claims.jti);
            let session_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3))",
                    rusqlite::params![claims.user_id, claims.jti, resolved_jti],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if !session_exists {
                return (false, false);
            }
        }
        let is_admin = subj.role.trim().eq_ignore_ascii_case("admin");
        return (true, is_admin);
    }
    (false, false)
}

pub(super) fn get_marketplace_apps_blocking(headers: HeaderMap, require_auth: bool) -> Response {
    let (is_authenticated, diagnostics_allowed) = get_marketplace_auth_info(&headers);
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
    let ingress_map: HashMap<String, AppIngressConfig> = af_db::get_all_app_ingress_configs()
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.app_name.clone(), c))
        .collect();
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

fn marketplace_unavailable() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Failed to load package catalog configuration",
    )
}

pub(super) fn package_progress_payload(
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
pub(super) struct PackageProgressQuery {
    pub(super) job_id: Option<String>,
}

pub(super) async fn package_progress(
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PackageActionQuery {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PackageTargetPayload {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

fn extract_expected_target_version(bytes: &[u8]) -> Result<Option<String>, StatusCode> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let val: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let obj = val.as_object().ok_or(StatusCode::BAD_REQUEST)?;

    if let Some(target_val) = obj.get("expected_target_version") {
        if !target_val.is_null() && !target_val.is_string() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(target_val) = obj.get("target_version") {
        if !target_val.is_null() && !target_val.is_string() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let parsed: PackageTargetPayload =
        serde_json::from_value(serde_json::Value::Object(obj.clone()))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let res = parsed
        .expected_target_version
        .or(parsed.target_version)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(res)
}

pub(super) async fn install_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => {
            return api_error(
                code,
                "BAD_REQUEST",
                "Malformed JSON or invalid expected_target_version",
            )
        }
    };
    let clean_id = id.trim_start_matches("package-");
    let has_legacy_upgrade = match af_services::package_has_legacy_upgrade_receipt(clean_id) {
        Ok(present) => present,
        Err(err) => {
            return api_error(
                StatusCode::CONFLICT,
                "UNSAFE_INSTALLATION_LOCK",
                format!("Unsafe installation lock detected: {err}"),
            );
        }
    };
    let action = if af_services::is_package_installed(clean_id) || has_legacy_upgrade {
        "reinstall"
    } else {
        "install"
    };
    dispatch_package_lifecycle_with_target(
        id,
        action,
        "installing",
        false,
        target,
        auth_user,
        headers,
    )
    .await
}

pub(crate) async fn reinstall_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => {
            return api_error(
                code,
                "BAD_REQUEST",
                "Malformed JSON or invalid expected_target_version",
            )
        }
    };
    dispatch_package_lifecycle_with_target(
        id,
        "reinstall",
        "installing",
        false,
        target,
        auth_user,
        headers,
    )
    .await
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct UninstallQuery {
    #[serde(default)]
    pub(super) purge: Option<String>,
}

/// Removal is data-preserving unless the caller explicitly asks for a purge
/// with `?purge=true`. Any other value is rejected rather than guessed.
pub(super) fn parse_uninstall_purge(query: &UninstallQuery) -> Result<bool, String> {
    match query.purge.as_deref().map(str::trim) {
        None | Some("") | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => Err(format!(
            "Invalid purge value {:?}; use purge=true for an explicit data purge",
            other
        )),
    }
}

pub(super) async fn uninstall_package(
    Path(id): Path<String>,
    Query(query): Query<UninstallQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let purge = match parse_uninstall_purge(&query) {
        Ok(purge) => purge,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message),
    };
    dispatch_package_lifecycle_with_target(
        id,
        "remove",
        "uninstalling",
        purge,
        None,
        auth_user,
        headers,
    )
    .await
}

pub(super) async fn update_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => {
            return api_error(
                code,
                "BAD_REQUEST",
                "Malformed JSON or invalid expected_target_version",
            )
        }
    };
    dispatch_package_lifecycle_with_target(
        id, "update", "updating", false, target, auth_user, headers,
    )
    .await
}

/// Appends diagnostic lines to the active job record if present.
pub(crate) fn append_package_job_output(job_id: &str, line: &str) {
    let sanitized_line = af_services::redact_secrets(line);
    if let Ok(snapshot) = af_services::package_job_snapshot() {
        for (_pkg_id, info) in snapshot.active {
            if info.job_id == job_id {
                let mut updated = info.clone();
                if !updated.last_line.is_empty() {
                    updated.last_line.push_str("; ");
                }
                updated.last_line.push_str(&sanitized_line);
                let _ = af_services::set_package_job_info(updated);
                break;
            }
        }
    }
}

pub(super) fn is_lock_file_present(lock_file: &str, fs_root_override: Option<&str>) -> bool {
    af_models::inspect_canonical_package_receipt(
        "",
        Some(lock_file),
        fs_root_override
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(std::path::Path::new),
    )
    .unwrap_or(false)
}

pub(super) fn verified_prior_state_recovery(
    action: &str,
    prior_installed: bool,
    recovery_eligible: bool,
    receipt_restore_error: Option<&str>,
    post_restore_failures: &[String],
    lock_file: &str,
    fs_root_override: Option<&str>,
) -> bool {
    matches!(action, "reinstall" | "update" | "install")
        && prior_installed
        && recovery_eligible
        && receipt_restore_error.is_none()
        && post_restore_failures.is_empty()
        && is_lock_file_present(lock_file, fs_root_override)
}

/// Ends a lifecycle job: records the terminal outcome (so polling clients can
/// distinguish failure from success) and broadcasts the terminal event.
#[allow(clippy::too_many_arguments)]
pub(super) fn finish_package_lifecycle(
    pkg_id: &str,
    action: &str,
    failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
) {
    finish_package_lifecycle_with_recovery(
        pkg_id,
        action,
        failure,
        progress,
        message,
        started_at,
        job_id,
        expected_target_version,
        achieved_version,
        stopped_units,
        false,
    );
}

/// Ends a lifecycle job with optional verified prior-state recovery confirmation
/// for failed in-place operations. Any inactive pre-stopped service forces
/// `prior_state_recovered` back to `false` (fail-closed).
#[allow(clippy::too_many_arguments)]
pub(super) fn finish_package_lifecycle_with_recovery(
    pkg_id: &str,
    action: &str,
    failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
    prior_state_recovered: bool,
) {
    finish_package_lifecycle_with_recovery_and_retention(
        pkg_id,
        action,
        failure,
        progress,
        message,
        started_at,
        job_id,
        expected_target_version,
        achieved_version,
        stopped_units,
        prior_state_recovered,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_package_lifecycle_with_recovery_and_retention(
    pkg_id: &str,
    action: &str,
    mut failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
    mut prior_state_recovered: bool,
    retention_state: Option<&str>,
) {
    let mut message_buf = message.to_string();

    if !stopped_units.is_empty() {
        let mut inactive_units = Vec::new();
        for unit in stopped_units {
            let (status, _, _) = af_services::get_systemd_unit_info(unit);
            if status != "running" && status != "idle" {
                inactive_units.push(format!("{unit} ({status})"));
            }
        }
        if !inactive_units.is_empty() {
            prior_state_recovered = false;
            let inactive_diagnostic = format!(
                "Application stopped services failed to resume: {}",
                inactive_units.join(", ")
            );
            append_package_job_output(job_id, &inactive_diagnostic);
            if failure.is_none() {
                failure = Some(af_services::PackageJobFailure::ServiceRestore);
                message_buf = format!(
                    "Application completed but stopped services failed to resume: {}",
                    inactive_units.join(", ")
                );
            } else {
                if !message_buf.is_empty() {
                    message_buf.push_str("; ");
                }
                message_buf.push_str(&inactive_diagnostic);
            }
        }
    }

    let sanitized_msg = af_services::redact_secrets(&message_buf);
    let message = sanitized_msg.as_str();
    let succeeded = failure.is_none();
    let recovery_state = if !succeeded
        && prior_state_recovered
        && matches!(action, "reinstall" | "update" | "install")
    {
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED.to_string())
    } else {
        None
    };
    let (failed_stage, exit_code, sanitized_summary) = if !succeeded {
        if failure == Some(af_services::PackageJobFailure::TargetVerification) {
            (
                Some("target_certification_after_install_commit".to_string()),
                Some(1),
                Some(af_services::sanitize_diagnostic_summary(message, 280)),
            )
        } else {
            let (st, ec, su) = af_services::parse_diagnostic_markers(message);
            (
                st.or_else(|| failure.as_ref().map(|f| f.category().to_string())),
                ec,
                su.or_else(|| {
                    if !message.trim().is_empty() {
                        Some(af_services::sanitize_diagnostic_summary(message, 280))
                    } else {
                        None
                    }
                }),
            )
        }
    } else {
        (None, None, None)
    };

    let outcome = af_services::finish_package_job_with_recovery_and_retention(
        pkg_id,
        action,
        succeeded,
        failure,
        job_id,
        failed_stage,
        exit_code,
        sanitized_summary,
        expected_target_version.map(|s| s.to_string()),
        achieved_version.map(|s| s.to_string()),
        recovery_state,
        retention_state.map(|s| s.to_string()),
    );
    let Some(outcome) = outcome else {
        return;
    };

    let mut ws_payload = serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": outcome.status,
        "progress": if succeeded { 100 } else { progress.min(95) },
        "line": message,
        "started_at": started_at,
        "job_id": outcome.job_id,
        "finished_at": outcome.finished_at,
    });
    if let Some(target) = expected_target_version {
        ws_payload["expected_target_version"] = serde_json::json!(target);
    }
    if let Some(achieved) = achieved_version {
        ws_payload["achieved_version"] = serde_json::json!(achieved);
    }
    broadcast_ws_message(&ws_payload);
}

pub(super) struct SystemUpdateLifecycleBlock {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    error_id: Option<String>,
}

impl std::fmt::Display for SystemUpdateLifecycleBlock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl IntoResponse for SystemUpdateLifecycleBlock {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "code": self.code, "message": self.message, "error_id": self.error_id,
            })),
        )
            .into_response()
    }
}

/// Discover authoritative runner receipts; do not rely on API process memory.
pub(super) async fn system_update_lifecycle_block_with<QueryFn, QueryFut>(
    query_status: QueryFn,
) -> Option<SystemUpdateLifecycleBlock>
where
    QueryFn: FnOnce() -> QueryFut,
    QueryFut: std::future::Future<Output = anyhow::Result<af_models::SelfUpdateJobStatus>>,
{
    match query_status().await {
        Ok(status) if status.completed && matches!(status.status.as_str(), "succeeded" | "failed") && (status.job_unit.is_empty() || status.validate_invariants(None).is_ok()) => None,
        Ok(_) => Some(SystemUpdateLifecycleBlock {
            status: StatusCode::CONFLICT,
            code: "SYSTEM_UPDATE_IN_PROGRESS",
            message: "An AetherFlow system update is in progress or requires recovery; retry after it completes",
            error_id: None,
        }),
        Err(error) => {
            let error_id = uuid::Uuid::new_v4().to_string();
            tracing::error!(%error_id, detail = %format!("{error:#}"), "system update observation failed");
            Some(SystemUpdateLifecycleBlock {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "STATUS_UNAVAILABLE",
                message: "AetherFlow system update status is unavailable; retry after it can be verified",
                error_id: Some(error_id),
            })
        },
    }
}

pub(super) async fn system_update_lifecycle_block() -> Option<SystemUpdateLifecycleBlock> {
    system_update_lifecycle_block_with(|| async {
        af_runner::dispatch_self_update_status_request(&af_models::SelfUpdateStatusRequest {
            job_unit: String::new(),
        })
        .await
    })
    .await
}

pub(super) fn allocate_or_resolve_app_port(app_name: &str, default_port: i32) -> i32 {
    allocate_or_resolve_app_port_with(
        app_name,
        default_port,
        load_authoritative_app_ingress_config,
        af_db::get_reserved_ports_excluding,
    )
}

pub(super) fn allocate_or_resolve_app_port_with<LoadExistingFn, LoadReservedFn>(
    app_name: &str,
    default_port: i32,
    mut load_existing: LoadExistingFn,
    mut load_reserved: LoadReservedFn,
) -> i32
where
    LoadExistingFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    LoadReservedFn: FnMut(&str) -> anyhow::Result<std::collections::BTreeSet<i32>>,
{
    match load_existing(app_name) {
        Ok(Some(existing)) if existing.listen_port > 0 => return existing.listen_port,
        Ok(_) => {}
        Err(_) => return 0,
    }
    let Ok(reserved) = load_reserved(app_name) else {
        return 0;
    };
    let bp = af_services::get_blueprint(app_name);
    let candidate = bp.as_ref().map(|b| b.default_port).unwrap_or(default_port);
    if !(1024..=65535).contains(&candidate) {
        return 0;
    }
    if !reserved.contains(&candidate)
        && std::net::TcpListener::bind(("127.0.0.1", candidate as u16)).is_ok()
    {
        return candidate;
    }
    // These applications do not expose a configurable native listen port.
    if matches!(app_name, "plex" | "calibreweb") {
        return 0;
    }
    let [start, end] = bp
        .as_ref()
        .map(|b| b.fallback_port_range)
        .filter(|[start, end]| (1024..=65535).contains(start) && (*start..=65535).contains(end))
        .unwrap_or(af_models::MARKETPLACE_FALLBACK_PORT_RANGE);
    for port in start..=end {
        if !reserved.contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok()
        {
            return port;
        }
    }
    0
}

pub(super) fn emit_package_progress(
    pkg_id: &str,
    action: &str,
    status: &str,
    progress: i32,
    line: &str,
    started_at: &str,
    job_id: &str,
) {
    let target = af_services::get_package_job_info(pkg_id).and_then(|j| j.expected_target_version);
    let sanitized_line = af_services::redact_secrets(line);
    let info = af_services::PackageJobInfo {
        job_id: job_id.to_string(),
        package_id: pkg_id.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        progress,
        last_line: sanitized_line.clone(),
        started_at: started_at.to_string(),
        expected_target_version: target.clone(),
    };
    let Some(info) = af_services::set_package_job_info(info) else {
        return;
    };
    let progress = info.progress;
    let mut payload = serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": status,
        "job_id": job_id,
        "progress": progress,
        "line": sanitized_line,
        "started_at": started_at,
    });
    if let Some(target_ver) = target {
        payload["expected_target_version"] = serde_json::json!(target_ver);
    }
    broadcast_ws_message(&payload);
}

fn is_oneshot_service_unit(unit: &str) -> bool {
    let lower = unit
        .trim()
        .trim_end_matches(".service")
        .to_ascii_lowercase();
    matches!(lower.as_str(), "recyclarr" | "scrutiny-collector")
}

fn is_restart_eligible_unit(unit: &str) -> bool {
    !is_oneshot_service_unit(unit)
}

pub(super) async fn pre_stop_units_for_package_update_with<
    ResolveFn,
    StatusFn,
    ControlFn,
    ControlFut,
>(
    action: &str,
    clean_id: &str,
    fs_root_override: &str,
    mut resolve_units: ResolveFn,
    mut query_status: StatusFn,
    mut control_unit: ControlFn,
) -> Result<Vec<String>, (String, String)>
where
    ResolveFn: FnMut(&str) -> Vec<String>,
    StatusFn: FnMut(&str) -> String,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut stopped_units: Vec<String> = Vec::new();
    let is_reinstall = action == "reinstall"
        || (action == "install" && af_services::is_package_installed(clean_id));
    if (action == "update" || is_reinstall)
        && af_services::should_pre_stop_on_update(clean_id)
        && fs_root_override.trim().is_empty()
    {
        let mut units = resolve_units(clean_id);
        let mut seen = std::collections::HashSet::new();
        units.retain(|unit| seen.insert(unit.clone()));
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut units);
        let mut running_units = Vec::new();
        for unit_name in units {
            let is_oneshot = is_oneshot_service_unit(&unit_name);
            match query_status(&unit_name).as_str() {
                "running" => running_units.push(unit_name),
                "restarting" if is_oneshot => running_units.push(unit_name),
                "stopped" | "failed" | "idle" | "not-found" => {}
                observation => {
                    return Err((
                        unit_name,
                        format!(
                            "Required service state is unconfirmed ({observation}); update was not started"
                        ),
                    ))
                }
            }
        }
        for unit_name in running_units {
            if is_restart_eligible_unit(&unit_name) {
                stopped_units.push(unit_name.clone());
            }
            if let Err(error) = control_unit(unit_name.clone(), "stop").await {
                let mut errors = vec![error.to_string()];
                for stopped_unit in
                    af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units)
                {
                    if let Err(restore_error) = control_unit(stopped_unit.clone(), "start").await {
                        errors.push(format!(
                            "Required restoration of {stopped_unit} failed: {restore_error}"
                        ));
                    }
                }
                return Err((unit_name, errors.join("; ")));
            }
        }
    }
    Ok(stopped_units)
}

pub(super) fn load_authoritative_app_ingress_config(
    app_name: &str,
) -> anyhow::Result<Option<AppIngressConfig>> {
    af_db::invalidate_ingress_cache();
    let conn = af_db::get_read_conn()?;
    af_db::load_lifecycle_ingress(&conn, app_name)
}

fn resolve_existing_update_port_with<LoadIngressFn>(
    pkg_id: &str,
    mut load_ingress_config: LoadIngressFn,
) -> Result<i32, String>
where
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
{
    let mut canonical_app = pkg_id
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(".service")
        .to_string();
    if canonical_app == "af-maintainerr" {
        canonical_app = "maintainerr".to_string();
    }
    if let Some(blueprint) = af_services::get_blueprint(&canonical_app) {
        if blueprint.default_port <= 0 {
            return Ok(0);
        }
        if !blueprint.app_name.is_empty() {
            canonical_app = blueprint.app_name;
        }
    }

    let existing_config = load_ingress_config(&canonical_app).map_err(|error| {
        format!(
            "cannot read existing configured port for {}: {}",
            canonical_app, error
        )
    })?;
    let Some(existing_config) = existing_config else {
        return Err(format!(
            "missing persisted ingress port mapping for {} update",
            canonical_app
        ));
    };
    if !(1024..=65535).contains(&existing_config.listen_port) {
        return Err(format!(
            "invalid persisted listen port {} for {} update",
            existing_config.listen_port, canonical_app
        ));
    }
    Ok(existing_config.listen_port)
}

pub(super) fn resolve_package_lifecycle_port_with<
    RuntimePortFn,
    LoadIngressFn,
    AllocateInstallPortFn,
>(
    action: &str,
    clean_id: &str,
    pkg_default_port: i32,
    mut query_runtime_port: RuntimePortFn,
    mut load_ingress_config: LoadIngressFn,
    mut allocate_install_port: AllocateInstallPortFn,
) -> Result<i32, String>
where
    RuntimePortFn: FnMut(&str) -> i32,
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    AllocateInstallPortFn: FnMut(&str, i32) -> i32,
{
    if action == "update" {
        if !af_services::should_pre_stop_on_update(clean_id)
            && af_services::resolve_service_control_scope(clean_id) != "shared-vhost"
        {
            return resolve_existing_update_port_with(clean_id, load_ingress_config);
        }
        // Read native configuration before stopping the application. An update
        // must keep its port even while that port is owned by the old process.
        let configured_port = query_runtime_port(clean_id);
        let ingress = load_ingress_config(clean_id).map_err(|error| {
            format!("cannot read existing configured port for {clean_id}: {error}")
        })?;
        let ingress_port = ingress.map(|config| config.listen_port).unwrap_or(0);
        let resolved_port = if (1024..=65535).contains(&configured_port) {
            configured_port
        } else if (1024..=65535).contains(&ingress_port) {
            ingress_port
        } else if pkg_default_port <= 0 {
            0
        } else {
            return Err(format!(
                "existing configured port for {clean_id} update is unavailable"
            ));
        };
        Ok(resolved_port)
    } else if action == "install" || action == "reinstall" {
        if action == "reinstall" || af_services::is_package_installed(clean_id) {
            let configured_port = query_runtime_port(clean_id);
            if (1024..=65535).contains(&configured_port) {
                return Ok(configured_port);
            }
            if let Ok(Some(ingress)) = load_ingress_config(clean_id) {
                if (1024..=65535).contains(&ingress.listen_port) {
                    return Ok(ingress.listen_port);
                }
            }
            if let Ok(Some(receipt_port)) = af_services::package_receipt_port(clean_id) {
                if (1024..=65535).contains(&receipt_port)
                    && af_db::get_reserved_ports_excluding(clean_id)
                        .is_ok_and(|reserved| !reserved.contains(&receipt_port))
                {
                    return Ok(receipt_port);
                }
            }
        }
        let allocated_port = allocate_install_port(clean_id, pkg_default_port);
        if pkg_default_port > 0 && allocated_port <= 0 {
            return Err("No supported listen port is available for this application".to_string());
        }
        Ok(allocated_port)
    } else {
        Ok(pkg_default_port)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_package_lifecycle_dispatch_gate_with<
    RuntimePortFn,
    LoadIngressFn,
    AllocateInstallPortFn,
    ResolveUnitsFn,
    StatusFn,
    ControlFn,
    ControlFut,
    DispatchFn,
    DispatchFut,
>(
    action: &str,
    clean_id: &str,
    pkg_default_port: i32,
    fs_root_override: &str,
    query_runtime_port: RuntimePortFn,
    load_ingress_config: LoadIngressFn,
    allocate_install_port: AllocateInstallPortFn,
    resolve_units: ResolveUnitsFn,
    query_status: StatusFn,
    control_unit: ControlFn,
    mut dispatch_package: DispatchFn,
) -> Result<(i32, Vec<String>, anyhow::Result<()>), String>
where
    RuntimePortFn: FnMut(&str) -> i32,
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    AllocateInstallPortFn: FnMut(&str, i32) -> i32,
    ResolveUnitsFn: FnMut(&str) -> Vec<String>,
    StatusFn: FnMut(&str) -> String,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    DispatchFn: FnMut(i32) -> DispatchFut,
    DispatchFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let allocated_port = resolve_package_lifecycle_port_with(
        action,
        clean_id,
        pkg_default_port,
        query_runtime_port,
        load_ingress_config,
        allocate_install_port,
    )?;

    let stopped_units = pre_stop_units_for_package_update_with(
        action,
        clean_id,
        fs_root_override,
        resolve_units,
        query_status,
        control_unit,
    )
    .await
    .map_err(|(failed_unit, error_message)| {
        format!("Could not stop {}: {}", failed_unit, error_message)
    })?;

    let execution_result = dispatch_package(allocated_port).await;
    Ok((allocated_port, stopped_units, execution_result))
}

#[derive(Debug, Clone)]
pub(crate) struct PackageLifecycleFailure {
    pub(crate) kind: af_services::PackageJobFailure,
    pub(crate) message: String,
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    af_runner::af_release::lifecycle::versions_match_target(achieved, expected)
}

pub fn target_version_matches(expected: &str, achieved: &str) -> bool {
    versions_match_target(achieved, expected)
}

pub(super) fn resolve_candidate_receipt_paths(pkg_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let fs_root = std::env::var("AETHERFLOW_FS_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("AF_PACKAGE_ROOT")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .map(PathBuf::from);

    let resolve = |rel: &str| -> PathBuf {
        let rel_trimmed = rel.trim_start_matches(['/', '\\']);
        if let Some(ref root) = fs_root {
            root.join(rel_trimmed)
        } else {
            PathBuf::from(rel)
        }
    };

    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && pkg_name.eq_ignore_ascii_case("filebot") {
            let p = resolve("/opt/filebot-node/.af-version");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        if prefix == "/opt" && pkg_name.eq_ignore_ascii_case("listenarr") {
            let p = resolve("/opt/Listenarr/.af-version");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = resolve(&candidate);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if pkg_name.eq_ignore_ascii_case("piped") {
        for extra in [
            "/opt/piped/.af-components.json",
            "/var/lib/piped/.af-components.json",
        ] {
            let p = resolve(extra);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
        if let Some(bp) = af_services::get_blueprint(candidate_name) {
            let cfg = bp.config_file_path.trim();
            if !cfg.is_empty() {
                let p = resolve(cfg);
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    paths
}

fn open_dir_nofollow_stepwise_ext(
    dir_path: &std::path::Path,
    create_missing: bool,
) -> Result<Option<OwnedFd>, String> {
    if !dir_path.is_absolute() {
        return Err(format!(
            "Directory path {} is not absolute",
            dir_path.display()
        ));
    }

    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("Failed to open root directory '/': {}", err));
    }
    let mut curr_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    let mut current_path = PathBuf::from("/");
    for comp in dir_path.components() {
        match comp {
            std::path::Component::Prefix(_) => {
                return Err(format!(
                    "Unsupported prefix component in path {}",
                    dir_path.display()
                ));
            }
            std::path::Component::RootDir => {
                continue;
            }
            std::path::Component::CurDir => {
                continue;
            }
            std::path::Component::ParentDir => {
                return Err(format!(
                    "Directory path {} contains invalid '..' parent directory component",
                    dir_path.display()
                ));
            }
            std::path::Component::Normal(part) => {
                current_path.push(part);
                let part_bytes = part.as_bytes();
                let part_cstr = std::ffi::CString::new(part_bytes)
                    .map_err(|e| format!("Invalid directory component {:?}: {}", part, e))?;

                let next_fd = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    let raw = err.raw_os_error();
                    if raw == Some(libc::ENOENT) {
                        if !create_missing {
                            return Ok(None);
                        }
                        let mkdir_res = unsafe {
                            libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755)
                        };
                        if mkdir_res != 0 {
                            let mk_err = std::io::Error::last_os_error();
                            if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                return Err(format!(
                                    "Failed to create directory component {}: {}",
                                    current_path.display(),
                                    mk_err
                                ));
                            }
                        }
                        let opened_fd = unsafe {
                            libc::openat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW
                                    | libc::O_CLOEXEC,
                            )
                        };
                        if opened_fd < 0 {
                            let open_err = std::io::Error::last_os_error();
                            return Err(format!(
                                "Failed to open directory component {}: {}",
                                current_path.display(),
                                open_err
                            ));
                        }
                        curr_fd = unsafe { OwnedFd::from_raw_fd(opened_fd) };
                        continue;
                    }
                    if raw == Some(libc::ELOOP) || raw == Some(libc::ENOTDIR) {
                        let mut comp_st: libc::stat = unsafe { std::mem::zeroed() };
                        let stat_res = unsafe {
                            libc::fstatat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                &mut comp_st,
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        };
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                            return Err(format!(
                                "Candidate receipt ancestor {} is not a directory",
                                current_path.display()
                            ));
                        }
                        if raw == Some(libc::ELOOP) {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        return Err(format!(
                            "Candidate receipt ancestor {} is not a directory",
                            current_path.display()
                        ));
                    }
                    return Err(format!(
                        "Failed to open directory component {}: {}",
                        current_path.display(),
                        err
                    ));
                }
                curr_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
            }
        }
    }

    Ok(Some(curr_fd))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptSnapshotEntry {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl std::ops::Deref for ReceiptSnapshotEntry {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for ReceiptSnapshotEntry {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for ReceiptSnapshotEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

impl From<&[u8]> for ReceiptSnapshotEntry {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

pub(super) fn snapshot_candidate_receipts(
    pkg_name: &str,
) -> Result<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>, String> {
    let paths = resolve_candidate_receipt_paths(pkg_name);
    let mut snapshots = Vec::new();
    for path in paths {
        let parent = path.parent().ok_or_else(|| {
            format!(
                "Candidate receipt {} has no parent directory",
                path.display()
            )
        })?;

        let file_name = path
            .file_name()
            .ok_or_else(|| format!("Candidate receipt {} has no file name", path.display()))?;
        let file_cstr = std::ffi::CString::new(file_name.as_bytes())
            .map_err(|e| format!("Invalid receipt filename {}: {}", path.display(), e))?;

        let is_version_or_components = matches!(
            file_name.to_str(),
            Some(".af-version") | Some(".af-components.json")
        );
        let max_size: i64 = if is_version_or_components {
            64 * 1024
        } else {
            1024 * 1024
        };
        let limit_label = if is_version_or_components {
            "64 KiB"
        } else {
            "1 MiB"
        };

        // 1. Open parent using open_dir_nofollow_stepwise_ext(parent, false)
        let dir_fd = match open_dir_nofollow_stepwise_ext(parent, false) {
            Ok(Some(fd)) => fd,
            Ok(None) => {
                snapshots.push((path, None));
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        };

        // 2. Stat candidate receipt entry relative to dir_fd with AT_SYMLINK_NOFOLLOW
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to stat receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if st.st_size > max_size || st.st_size < 0 {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        // 3. Open receipt file relative to dir_fd
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to open receipt {}: {}",
                path.display(),
                err
            ));
        }

        // 4. Verify libc::fstat matches (st.st_dev, st.st_ino) and S_IFREG and <= max_size
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        let fstat_res = unsafe { libc::fstat(fd, &mut opened_st) };
        if fstat_res != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!(
                "Failed to stat opened receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (opened_st.st_dev, opened_st.st_ino) != (st.st_dev, st.st_ino) {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} changed during open",
                path.display()
            ));
        }

        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if opened_st.st_size > max_size || opened_st.st_size < 0 {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        let mode = (opened_st.st_mode & 0o7777) as u32;
        let uid = opened_st.st_uid as u32;
        let gid = opened_st.st_gid as u32;

        // 5. Read bounded at most max_size
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        file.by_ref()
            .take((max_size as u64) + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("Failed to read receipt {}: {}", path.display(), e))?;

        if buf.len() > max_size as usize {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        snapshots.push((
            path,
            Some(ReceiptSnapshotEntry {
                bytes: buf,
                mode,
                uid,
                gid,
            }),
        ));
    }
    Ok(snapshots)
}

pub(super) fn restore_candidate_receipts(
    snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (path, prev_entry_opt) in snapshots {
        let parent = match path.parent() {
            Some(p) => p,
            None => {
                errors.push(format!("Receipt path has no parent: {}", path.display()));
                continue;
            }
        };

        let file_name = match path.file_name() {
            Some(name) => name,
            None => {
                errors.push(format!("Receipt path has no file name: {}", path.display()));
                continue;
            }
        };
        let file_cstr = match std::ffi::CString::new(file_name.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!(
                    "Invalid receipt filename {}: {}",
                    path.display(),
                    e
                ));
                continue;
            }
        };

        let dir_fd = if prev_entry_opt.is_some() {
            match open_dir_nofollow_stepwise_ext(parent, true) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    errors.push(format!(
                        "Failed to create or open parent directory for receipt {}",
                        path.display()
                    ));
                    continue;
                }
                Err(e) => {
                    errors.push(format!(
                        "Refusing to restore receipt {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            }
        } else {
            match open_dir_nofollow_stepwise_ext(parent, false) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    errors.push(format!(
                        "Refusing to remove uncertified receipt {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            }
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            errors.push(format!(
                "Refusing to overwrite directory at receipt path {}",
                path.display()
            ));
            continue;
        }

        if let Some(entry) = prev_entry_opt {
            let tmp_name = format!(
                ".af-tmp-receipt-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            );
            let tmp_cstr = match std::ffi::CString::new(tmp_name.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("Invalid temporary receipt filename: {}", e));
                    continue;
                }
            };

            let tmp_fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if tmp_fd < 0 {
                let err = std::io::Error::last_os_error();
                errors.push(format!(
                    "Failed to create temporary receipt for {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let write_res = (|| -> Result<(), std::io::Error> {
                let mut written = 0;
                while written < entry.bytes.len() {
                    let res = unsafe {
                        libc::write(
                            tmp_fd,
                            entry.bytes[written..].as_ptr() as *const libc::c_void,
                            entry.bytes.len() - written,
                        )
                    };
                    if res < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    written += res as usize;
                }
                Ok(())
            })();

            if let Err(e) = write_res {
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to write temporary receipt for {}: {}",
                    path.display(),
                    e
                ));
                continue;
            }

            let chown_res =
                unsafe { libc::fchown(tmp_fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
            if chown_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore ownership for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let chmod_res = unsafe { libc::fchmod(tmp_fd, (entry.mode & 0o7777) as libc::mode_t) };
            if chmod_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore mode for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let sync_res = unsafe { libc::fsync(tmp_fd) };
            if sync_res != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to fsync temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            unsafe { libc::close(tmp_fd) };

            let rename_res = unsafe {
                libc::renameat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    dir_fd.as_raw_fd(),
                    file_cstr.as_ptr(),
                )
            };
            if rename_res != 0 {
                let err = std::io::Error::last_os_error();
                let _ = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to atomically restore receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        } else {
            let unlink_res = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), file_cstr.as_ptr(), 0) };
            if unlink_res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    errors.push(format!(
                        "Failed to remove uncertified receipt {}: {}",
                        path.display(),
                        err
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}

pub(super) async fn finalize_post_script_lifecycle_with<
    ApplyFut,
    SaveIngressFn,
    ControlFn,
    ControlFut,
    RefreshFut,
>(
    stopped_units: &[String],
    apply_blueprint: ApplyFut,
    mut control_unit: ControlFn,
    query_status: impl Fn(&str) -> String,
    refresh_update: RefreshFut,
    save_ingress: SaveIngressFn,
) -> Result<Option<String>, PackageLifecycleFailure>
where
    ApplyFut: std::future::Future<Output = Result<Option<AppIngressConfig>, String>>,
    SaveIngressFn: FnOnce(&AppIngressConfig) -> anyhow::Result<()>,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    RefreshFut: std::future::Future<Output = Option<String>>,
{
    let ingress = apply_blueprint.await;
    let mut service_failures = Vec::new();
    for unit in af_runner::af_release::lifecycle::ordered_units_for_start(stopped_units) {
        if let Err(error) = control_unit(unit.clone(), "start").await {
            service_failures.push(format!("Failed to restart stopped unit {unit}: {error}"));
        }
    }
    let achieved_version = refresh_update.await;
    for unit in stopped_units {
        let status = query_status(unit);
        if status != "running" && status != "idle" {
            service_failures.push(format!(
                "Application service failed to remain active after execution: {unit} ({status})"
            ));
        }
    }

    let ingress = ingress.map_err(|error| {
        let mut message =
            format!("Required blueprint configuration synchronization failed: {error}");
        let kind = if service_failures.is_empty() {
            af_services::PackageJobFailure::Configuration
        } else {
            message.push_str(&format!("; {}", service_failures.join("; ")));
            af_services::PackageJobFailure::ConfigurationAndServiceRestore
        };
        PackageLifecycleFailure { kind, message }
    })?;
    if !service_failures.is_empty() {
        return Err(PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::ServiceRestore,
            message: service_failures.join("; "),
        });
    }

    // Commit only after all phases that can trigger runtime rollback. A
    // failed transaction leaves both active and retained ingress intact.
    if let Some(config) = ingress {
        save_ingress(&config).map_err(|error| PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::Configuration,
            message: format!("Failed to persist ingress configuration: {error}"),
        })?;
    }
    Ok(achieved_version)
}

fn is_incomplete_rollback_error(err_msg: &str) -> bool {
    af_runner::package_lifecycle::is_incomplete_rollback_error(err_msg)
}

#[cfg(test)]
pub(super) async fn restore_pre_stopped_units_after_installer_failure_with<ControlFn, ControlFut>(
    clean_id: &str,
    stopped_units: &[String],
    installer_error: &str,
    mut control_unit: ControlFn,
) -> (af_services::PackageJobFailure, String)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut restore_errors: Vec<String> = Vec::new();
    if af_services::should_pre_stop_on_update(clean_id) && !stopped_units.is_empty() {
        if is_incomplete_rollback_error(installer_error) {
            restore_errors.push(
                "Refusing to restart pre-stopped service after incomplete rollback".to_string(),
            );
        } else {
            for unit in af_runner::af_release::lifecycle::ordered_units_for_start(stopped_units) {
                if let Err(restore_err) = control_unit(unit.clone(), "start").await {
                    restore_errors.push(format!(
                        "Failed to restore stopped unit {}: {}",
                        unit, restore_err
                    ));
                }
            }
        }
    }
    if restore_errors.is_empty() {
        (
            af_services::PackageJobFailure::Installer,
            installer_error.to_string(),
        )
    } else {
        (
            af_services::PackageJobFailure::ServiceRestore,
            format!("{}; {}", installer_error, restore_errors.join("; ")),
        )
    }
}

fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rest.rfind('#') {
        let before = &rest[..idx];
        let after = &rest[idx + 1..];
        if before.ends_with("?q") || before.ends_with("&q") {
            return (rest, None);
        }
        if before.ends_with("cred") && after.contains('@') {
            return (rest, None);
        }
        (before, Some(after))
    } else {
        (rest, None)
    }
}

fn sanitize_git_repo_remote(remote: &str) -> String {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    static HEX_12_QUERY_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"^\?q#[0-9a-fA-F]{12}$").unwrap());

    // Mask cred#<12-hex> and ?q#<12-hex> so Url::parse does not treat '#' as URL fragment delimiter
    let masked = if trimmed.contains("cred#") || trimmed.contains("?q#") {
        let m1 = regex::Regex::new(r"cred#([0-9a-fA-F]{12})@")
            .unwrap()
            .replace_all(trimmed, "cred__AFTOKEN__$1@")
            .into_owned();
        regex::Regex::new(r"\?q#([0-9a-fA-F]{12})")
            .unwrap()
            .replace_all(&m1, "?q__AFTOKEN__$1")
            .into_owned()
    } else {
        trimmed.to_string()
    };

    if let Ok(mut parsed) = reqwest::Url::parse(&masked) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        if let Some(q) = parsed.query() {
            let full_q = format!("?{q}");
            if !full_q.starts_with("?q__AFTOKEN__") && !HEX_12_QUERY_RE.is_match(&full_q) {
                parsed.set_query(None);
            }
        }
        parsed.set_fragment(None);

        let user = parsed.username().to_string();
        let pass = parsed.password().map(|p| p.to_string());

        if pass.is_some() {
            let _ = parsed.set_password(None);
            if (scheme == "http" || scheme == "https") && !user.starts_with("cred__AFTOKEN__") {
                let _ = parsed.set_username("");
            }
        } else if !user.is_empty()
            && (scheme == "http" || scheme == "https")
            && !user.starts_with("cred__AFTOKEN__")
        {
            let _ = parsed.set_username("");
        }

        let mut out = parsed.to_string();
        if !masked.ends_with('/') && out.ends_with('/') && parsed.path() == "/" {
            out.pop();
        }
        // Unmask
        out = out.replace("cred__AFTOKEN__", "cred#");
        out = out.replace("?q__AFTOKEN__", "?q#");
        out
    } else if trimmed.contains(':') {
        let (without_frag, _) = split_git_repo_remote_and_branch(trimmed);
        let (without_q, query_part) = if let Some((base, q)) = without_frag.split_once('?') {
            let full_q = format!("?{q}");
            if HEX_12_QUERY_RE.is_match(&full_q) {
                (base, format!("?{q}"))
            } else {
                (base, String::new())
            }
        } else {
            (without_frag, String::new())
        };

        if let Some((user_host, path)) = without_q.split_once(':') {
            if let Some((user, host)) = user_host.split_once('@') {
                let clean_user = if let Some((u, _pass)) = user.split_once(':') {
                    u
                } else {
                    user
                };
                format!("{clean_user}@{host}:{path}{query_part}")
            } else {
                format!("{user_host}:{path}{query_part}")
            }
        } else {
            format!("{without_q}{query_part}")
        }
    } else {
        trimmed.to_string()
    }
}

pub fn sanitize_url_or_source_key_for_api(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.contains('|') {
        let parts: Vec<String> = trimmed
            .split('|')
            .map(sanitize_url_or_source_key_for_api)
            .collect();
        return parts.join("|");
    }

    if let Some(rest) = trimmed.strip_prefix("git-repo:") {
        let (remote, branch) = split_git_repo_remote_and_branch(rest);
        let sanitized_remote = sanitize_git_repo_remote(remote);
        return match branch {
            Some(b) => format!("git-repo:{sanitized_remote}#{b}"),
            None => format!("git-repo:{sanitized_remote}"),
        };
    }

    static URL_USERINFO_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/?#@\s]+@").unwrap());
    static SENSITIVE_QUERY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?i)([?&;])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.-])?pass(?:[_.-][A-Za-z0-9]*)*\b)=([^&#|\s]+)"#).unwrap()
    });

    let stripped = URL_USERINFO_RE.replace_all(trimmed, "$1");

    // If reqwest::Url::parse succeeds on a display URL, strip credentials, query string, and fragment.
    if let Ok(mut parsed) = reqwest::Url::parse(&stripped) {
        let scheme = parsed.scheme();
        if (scheme == "http"
            || scheme == "https"
            || scheme == "ssh"
            || scheme == "git"
            || scheme == "ftp")
            && parsed.has_host()
        {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            let mut out = parsed.to_string();
            let base_before = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
            if !trimmed.ends_with('/')
                && out.ends_with('/')
                && !base_before.ends_with('/')
                && parsed.path() == "/"
            {
                out.pop();
            }
            return out;
        }
    }

    // SCP-style remotes: e.g. git@github.com:org/repo.git?token=x#frag or user:pass@host:path?q#frag
    if !trimmed.contains("://") {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let without_q = without_frag.split('?').next().unwrap_or(without_frag);
        if let Some((userinfo, host_path)) = without_q.split_once('@') {
            if host_path.contains(':') || trimmed.starts_with("git@") {
                let clean_user = userinfo.split(':').next().unwrap_or(userinfo);
                return format!("{clean_user}@{host_path}");
            }
        }
    }

    let query_sanitized = SENSITIVE_QUERY_RE.replace_all(&stripped, "$1$2=[REDACTED]");
    let sanitized = af_runner::package_lifecycle::sanitize_lifecycle_field(&query_sanitized);
    URL_USERINFO_RE.replace_all(&sanitized, "$1").into_owned()
}

pub fn sanitize_package_update_record(
    mut record: af_services::workers::PackageUpdateRecord,
) -> af_services::workers::PackageUpdateRecord {
    record.release_url = sanitize_url_or_source_key_for_api(&record.release_url);
    record.source_key = sanitize_url_or_source_key_for_api(&record.source_key);
    record.installed_version = sanitize_url_or_source_key_for_api(&record.installed_version);
    record.latest_version = sanitize_url_or_source_key_for_api(&record.latest_version);
    record.error = sanitize_url_or_source_key_for_api(&af_services::workers::public_update_error(
        &record.error,
    ));
    record
}

pub(crate) struct RunnerLifecycleSnapshotHandle {
    package_id: String,
    job_id: String,
    active: bool,
}

impl RunnerLifecycleSnapshotHandle {
    pub(crate) fn new(package_id: String, job_id: String) -> Self {
        Self {
            package_id,
            job_id,
            active: true,
        }
    }

    pub(crate) async fn restore(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        af_runner::dispatch_package_lifecycle_snapshot_restore(&self.package_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub(crate) async fn discard(&mut self, preserve_backup: bool) {
        if !self.active {
            return;
        }
        self.active = false;
        if let Err(err) = af_runner::dispatch_package_lifecycle_snapshot_discard_for_job(
            &self.package_id,
            &self.job_id,
            preserve_backup,
        )
        .await
        {
            tracing::warn!(
                package = %self.package_id,
                job_id = %self.job_id,
                preserve_backup,
                error = %err,
                "Failed to discard runner lifecycle snapshot"
            );
        }
    }
}

impl Drop for RunnerLifecycleSnapshotHandle {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let pkg = self.package_id.clone();
        let job = self.job_id.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = af_runner::dispatch_package_lifecycle_snapshot_discard_for_job(
                    &pkg, &job, true,
                )
                .await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_ext_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    mut runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    mut runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    mut control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    // Step 1: Quiesce (stop) quiesce_units BEFORE restore_candidate_receipts runs
    let mut quiesce_failures: Vec<String> = Vec::new();
    if af_services::should_pre_stop_on_update(clean_id) && !quiesce_units.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let mut ordered_quiesce: Vec<String> = quiesce_units
            .iter()
            .filter(|unit| seen.insert((*unit).clone()))
            .cloned()
            .collect();
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut ordered_quiesce);
        for unit in &ordered_quiesce {
            if let Err(e) = control_unit(unit.clone(), "stop").await {
                let err_str = e.to_string();
                let err_lower = err_str.to_ascii_lowercase();
                let is_absent_err = err_lower.contains("not loaded")
                    || err_lower.contains("not-found")
                    || err_lower.contains("not found")
                    || err_lower.contains("no such file")
                    || err_lower.contains("could not be found")
                    || err_lower.contains("exit status: 5")
                    || err_lower.contains("exit code 5");

                if is_absent_err
                    && matches!(
                        query_status(unit).as_str(),
                        "stopped" | "idle" | "not-found"
                    )
                {
                    tracing::info!(
                        unit = %unit,
                        error = %e,
                        "Absent unit not loaded during stop before restoration, confirmed quiescent"
                    );
                } else {
                    tracing::error!(unit = %unit, error = %e, "Failed to quiesce unit before receipt restoration");
                    quiesce_failures.push(format!(
                        "Failed to quiesce unit '{unit}' before receipt restoration: {e}"
                    ));
                }
            }
        }
    }

    if !quiesce_failures.is_empty() {
        if let Some(ref mut rt) = runtime_snapshot {
            rt.preserve_on_drop = true;
        }
        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(true).await;
        }
        return (
            Some("Skipped candidate receipt restoration because service quiescence failed (incomplete-rollback)".to_string()),
            quiesce_failures,
        );
    }

    // Incomplete rollback did not recover runtime. Leave candidate receipts on
    // disk so a NEW runtime is not paired with a rewound .af-version.
    let mut restart_failures: Vec<String> = Vec::new();
    if refuse_restart {
        if let Some(ref mut rt) = runtime_snapshot {
            rt.preserve_on_drop = true;
        }
        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(true).await;
        }
        if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
            restart_failures.push(
                "Refusing to restart pre-stopped service after incomplete rollback".to_string(),
            );
        }
        return (
            Some("Skipped candidate receipt restoration after incomplete rollback".to_string()),
            restart_failures,
        );
    }

    let receipt_restore_error = if let Some(ref mut rs) = runner_snapshot {
        if let Err(rt_err) = rs.restore().await {
            if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                restart_failures.push(
                    "Refusing to restart pre-stopped service after runtime restoration failure"
                        .to_string(),
                );
            }
            return (Some(rt_err), restart_failures);
        }
        None
    } else {
        // Step 2: Restore runtime snapshot if present
        if let Some(ref mut rt) = runtime_snapshot {
            if let Err(rt_err) = rt.restore() {
                if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after runtime restoration failure"
                            .to_string(),
                    );
                }
                return (Some(rt_err), restart_failures);
            }
        }

        if !blueprint_snapshots.is_empty() {
            if let Err(bp_err) =
                af_runner::package_lifecycle::restore_candidate_receipts(blueprint_snapshots)
            {
                if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after receipt restoration failure"
                            .to_string(),
                    );
                }
                return (Some(bp_err), restart_failures);
            }
        }

        // Step 3: Restore candidate receipts
        if !receipt_snapshots.is_empty() {
            restore_candidate_receipts(receipt_snapshots).err()
        } else {
            None
        }
    };

    // Step 4: Restart restart_units AFTER restore_candidate_receipts completes
    if receipt_restore_error.is_some() {
        if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
            restart_failures.push(
                "Refusing to restart pre-stopped service after receipt restoration failure"
                    .to_string(),
            );
        }
        return (receipt_restore_error, restart_failures);
    }

    if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
        for unit in af_runner::af_release::lifecycle::ordered_units_for_start(restart_units) {
            if let Err(e) = control_unit(unit.clone(), "start").await {
                tracing::error!(unit = %unit, error = %e, "Application service restart failed after receipt restoration");
                restart_failures.push(format!("{unit}: {e}"));
            }
        }

        // Step 5: Verify restart_units active
        for unit in restart_units {
            let st = query_status(unit);
            if st != "running"
                && st != "idle"
                && !restart_failures.iter().any(|f| f.starts_with(unit))
            {
                restart_failures.push(format!("{unit} is {st}"));
            }
        }
    }

    (receipt_restore_error, restart_failures)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
        clean_id,
        quiesce_units,
        restart_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_with<ControlFn, ControlFut, StatusFn>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    quiesce_and_restore_candidate_receipts_and_runtime_with(
        clean_id,
        quiesce_units,
        restart_units,
        receipt_snapshots,
        refuse_restart,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
pub(super) static CANDIDATE_QUIESCE_RECORDER: std::sync::Mutex<Option<Vec<String>>> =
    std::sync::Mutex::new(None);

#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_ext(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
) -> (Option<String>, Vec<String>) {
    let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
    let mut quiesce_units = stopped_units.to_vec();
    for u in all_controllable {
        if !quiesce_units.contains(&u) {
            quiesce_units.push(u);
        }
    }
    af_runner::af_release::lifecycle::sort_units_for_stop(&mut quiesce_units);
    let restart_units: Vec<String> = stopped_units
        .iter()
        .filter(|u| is_restart_eligible_unit(u))
        .cloned()
        .collect();
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
        clean_id,
        &quiesce_units,
        &restart_units,
        receipt_snapshots,
        blueprint_snapshots,
        refuse_restart,
        runtime_snapshot,
        runner_snapshot,
        |unit, ctl_action| async move {
            #[cfg(test)]
            {
                if let Ok(mut lock) = CANDIDATE_QUIESCE_RECORDER.lock() {
                    if let Some(ref mut vec) = *lock {
                        vec.push(format!("{ctl_action} {unit}"));
                    }
                }
            }
            if std::env::var("AETHERFLOW_FS_ROOT")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return Ok(());
            }
            af_services::control_service_with_manager(&unit, ctl_action, "systemd-unit").await
        },
        |unit| {
            if std::env::var("AETHERFLOW_FS_ROOT")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return "running".to_string();
            }
            af_services::get_systemd_unit_info(unit).0
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
) -> (Option<String>, Vec<String>) {
    quiesce_and_restore_candidate_receipts_and_runtime_ext(
        clean_id,
        stopped_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
) -> (Option<String>, Vec<String>) {
    quiesce_and_restore_candidate_receipts_and_runtime(
        clean_id,
        stopped_units,
        receipt_snapshots,
        refuse_restart,
        None,
    )
    .await
}

pub(crate) fn should_rollback_post_certification_failure(
    action: &str,
    kind: af_services::PackageJobFailure,
) -> bool {
    matches!(action, "install" | "reinstall" | "update")
        && matches!(
            kind,
            af_services::PackageJobFailure::Configuration
                | af_services::PackageJobFailure::ServiceRestore
                | af_services::PackageJobFailure::ConfigurationAndServiceRestore
        )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_post_certification_finalization_failure_ext_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    action: &str,
    mut required_err: PackageLifecycleFailure,
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (PackageLifecycleFailure, Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    if should_rollback_post_certification_failure(action, required_err.kind) {
        let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
        let mut quiesce_units = stopped_units.to_vec();
        for u in all_controllable {
            if !quiesce_units.contains(&u) {
                quiesce_units.push(u);
            }
        }
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut quiesce_units);
        let restart_units: Vec<String> = stopped_units
            .iter()
            .filter(|u| is_restart_eligible_unit(u))
            .cloned()
            .collect();
        let (receipt_restore_error, restart_failures) =
            quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
                clean_id,
                &quiesce_units,
                &restart_units,
                receipt_snapshots,
                blueprint_snapshots,
                refuse_restart,
                runtime_snapshot,
                runner_snapshot,
                control_unit,
                query_status,
            )
            .await;
        if let Some(ref r_err) = receipt_restore_error {
            required_err
                .message
                .push_str(&format!("; receipt restoration error: {}", r_err));
        }
        if !restart_failures.is_empty() {
            required_err.message.push_str(&format!(
                "; post-restoration restart failures: {}",
                restart_failures.join("; ")
            ));
        }
        if required_err.kind == af_services::PackageJobFailure::Configuration
            && (receipt_restore_error.is_some() || !restart_failures.is_empty())
        {
            required_err.kind = af_services::PackageJobFailure::ConfigurationAndServiceRestore;
        }
        (required_err, receipt_restore_error, restart_failures)
    } else {
        (required_err, None, Vec::new())
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn handle_post_certification_finalization_failure_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    action: &str,
    required_err: PackageLifecycleFailure,
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (PackageLifecycleFailure, Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    handle_post_certification_finalization_failure_ext_with(
        action,
        required_err,
        clean_id,
        stopped_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn dispatch_package_lifecycle(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    delete_data: bool,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle_with_target(
        pkg_id,
        action,
        status_label,
        delete_data,
        None,
        auth_user,
        headers,
    )
    .await
}

pub(super) async fn dispatch_package_lifecycle_with_target(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    delete_data: bool,
    mut expected_target_version: Option<String>,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    if delete_data && action != "remove" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Data purge is only valid for package removal",
        );
    }
    #[allow(clippy::result_large_err)]
    let (pkgs, admission_guard) = match tokio::task::spawn_blocking(|| {
        let guard = af_runner::acquire_lifecycle_admission_lock(None).map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                "LIFECYCLE_ADMISSION_UNAVAILABLE",
                format!("Cannot reserve application lifecycle admission: {}", error),
            )
        })?;
        af_services::package_job_snapshot()
            .and_then(|_| af_services::reconcile_package_jobs_under_admission())
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STATUS_UNAVAILABLE",
                    "Lifecycle status could not be reconciled; retry shortly",
                )
            })?;
        af_services::get_packages()
            .map(|packages| (packages, guard))
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STATUS_UNAVAILABLE",
                    "Package catalog and lifecycle status could not be confirmed; retry shortly",
                )
            })
    })
    .await
    {
        Ok(Ok(admission)) => admission,
        Ok(Err(response)) => return response,
        _ => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Package catalog and lifecycle status could not be confirmed; retry shortly",
            )
        }
    };
    let Some(pkg) = pkgs.into_iter().find(|p| p.name == pkg_id) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Package not found");
    };

    if matches!(
        pkg.status.as_str(),
        "installing" | "uninstalling" | "updating"
    ) {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package is already modifying state",
        );
    }

    if action == "update" && pkg.status != "installed" {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package must be installed before it can be updated",
        );
    }

    if action == "remove" && delete_data {
        let fs_root_override = env::var("AETHERFLOW_FS_ROOT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let root_path = fs_root_override.as_deref().map(std::path::Path::new);
        let conn_guard = af_db::get_read_conn().ok();
        let inspection = af_runner::inspect_package_purge_state_with_conn(
            &pkg.name,
            (!pkg.lock_file.trim().is_empty()).then_some(pkg.lock_file.as_str()),
            root_path,
            conn_guard.as_deref(),
        );
        match inspection {
            Ok(insp) => match insp.eligibility {
                af_runner::PackagePurgeEligibility::Installed
                | af_runner::PackagePurgeEligibility::RetainedProven => {}
                af_runner::PackagePurgeEligibility::AmbiguousMarkerless => {
                    return api_error(
                        StatusCode::CONFLICT,
                        "AMBIGUOUS_RETAINED_OWNERSHIP",
                        af_runner::format_ambiguous_purge_error(&insp),
                    );
                }
                af_runner::PackagePurgeEligibility::NotPresent => {
                    return api_error(
                        StatusCode::CONFLICT,
                        "PACKAGE_NOT_INSTALLED",
                        format!(
                            "Package '{}' is not installed and has no recognized retained AetherFlow installation to purge",
                            pkg.name
                        ),
                    );
                }
            },
            Err(err) => {
                return api_error(StatusCode::CONFLICT, "UNSAFE_INSTALLATION_LOCK", err);
            }
        }
    }

    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }

    let script_prefix = if action == "remove" {
        "removepackage-"
    } else {
        "installpackage-"
    };
    let script_name = format!("{}{}", script_prefix, pkg.name);
    let Some(_script_path) = af_runner::resolve_package_script_path(action, &script_name) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Provisioning script is missing or unreadable on the server",
        );
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let audit_action = if delete_data {
        "package_purge".to_string()
    } else {
        format!("package_{}", action)
    };
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        &audit_action,
        "package",
        &pkg.name,
        &pkg.label,
        &ip,
        ua,
    );

    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }

    let clean_id = pkg.name.clone();
    let is_retired = pkg.update_source == "retired" || pkg.name == "readarr";
    let is_pinned = pkg.update_source.eq_ignore_ascii_case("pinned");
    let is_vendor = pkg.update_source.eq_ignore_ascii_case("vendor");

    if let Some(ref target) = expected_target_version {
        if !af_runner::af_release::lifecycle::is_valid_target_version_token(target) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid target version token format",
            );
        }
    }

    if (is_vendor || clean_id.eq_ignore_ascii_case("listenarr")) && action != "remove" {
        if let Err(reason) = af_runner::validate_package_target_policy(
            &pkg.name,
            &pkg.update_source,
            &pkg.update_package,
            action,
            expected_target_version.as_deref(),
        ) {
            return api_error(StatusCode::CONFLICT, "CONFLICT", reason);
        }
    }

    let pinned_target = if is_pinned {
        if pkg.name == "threadfin" {
            match af_runner::validate_threadfin_target_policy(if action == "remove" {
                None
            } else {
                expected_target_version.as_deref()
            }) {
                Ok((resolved_ver, _)) => Some(resolved_ver),
                Err(err) => {
                    return api_error(StatusCode::CONFLICT, "CONFLICT", err.to_string());
                }
            }
        } else {
            let trimmed = pkg.update_package.trim();
            if action != "remove" {
                if let Err(reason) = af_runner::validate_package_target_policy(
                    &pkg.name,
                    &pkg.update_source,
                    &pkg.update_package,
                    action,
                    expected_target_version.as_deref(),
                ) {
                    return api_error(StatusCode::CONFLICT, "CONFLICT", reason);
                }
            }
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    } else {
        None
    };

    if is_retired {
        if let Some(ref explicit_target) = expected_target_version {
            if !af_runner::af_release::lifecycle::versions_match_target(
                explicit_target,
                "0.4.18.2805",
            ) && !af_runner::af_release::lifecycle::versions_match_target(
                "0.4.18.2805",
                explicit_target,
            ) {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Retired package can only target pinned version 0.4.18.2805",
                );
            }
        }
    }

    if action == "remove" {
        expected_target_version = None;
    } else if action == "update" {
        if is_retired && expected_target_version.is_none() {
            expected_target_version = Some("0.4.18.2805".to_string());
        } else if let Some(ref pinned_ver) = pinned_target {
            if expected_target_version.is_none() {
                expected_target_version = Some(pinned_ver.clone());
            }
        }

        af_services::workers::ensure_app_updates_columns();
        let db_update: Option<(String, String, bool, String, String, String)> = if let Ok(conn) =
            af_db::get_conn()
        {
            conn.query_row(
                "SELECT COALESCE(installed_version, ''), COALESCE(latest_version, ''), COALESCE(update_available, 0), COALESCE(checked_at, ''), COALESCE(last_error, ''), COALESCE(source_key, '') FROM app_updates WHERE package_name = ?1",
                rusqlite::params![&clean_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok()
        } else {
            None
        };

        let Some((installed, latest, update_available, checked_at, err, source_key)) = db_update
        else {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        };

        let db_latest = latest.trim();
        if db_latest.is_empty() {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        }

        if is_retired
            && !af_runner::af_release::lifecycle::versions_match_target(db_latest, "0.4.18.2805")
            && !af_runner::af_release::lifecycle::versions_match_target("0.4.18.2805", db_latest)
        {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Retired package can only target pinned version 0.4.18.2805",
            );
        }
        if let Some(ref pinned_ver) = pinned_target {
            if af_runner::af_release::lifecycle::strip_version_prefix(db_latest)
                != af_runner::af_release::lifecycle::strip_version_prefix(pinned_ver)
            {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    format!(
                        "Pinned package '{}' can only target version {}",
                        pkg.name, pinned_ver
                    ),
                );
            }
        }

        let github_api_base = std::env::var("AETHERFLOW_GITHUB_API_BASE_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.github.com".to_string());
        let expected_source_key =
            af_services::workers::canonical_update_source_key(&github_api_base, &pkg);

        if source_key.trim().is_empty() || source_key.trim() != expected_source_key {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: package update source is unconfirmed or mismatched",
            );
        }

        let has_valid_checked_at = !checked_at.trim().is_empty()
            && chrono::DateTime::parse_from_rfc3339(checked_at.trim()).is_ok();
        let db_installed = installed.trim();
        let installed_confirmed = !db_installed.is_empty()
            && !db_installed.eq_ignore_ascii_case("unknown")
            && !err.to_ascii_lowercase().contains("installed version");
        let has_provenance = has_valid_checked_at && installed_confirmed && update_available;

        if !installed_confirmed {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: installed version could not be confirmed",
            );
        }
        if !has_provenance {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version lacks prior confirmation provenance",
            );
        }

        if !err.trim().is_empty() {
            let Some(ref explicit_target) = expected_target_version else {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Cannot start update: upstream update check reported error",
                );
            };
            if !af_runner::af_release::lifecycle::versions_match_target(explicit_target, db_latest)
                && !af_runner::af_release::lifecycle::versions_match_target(
                    db_latest,
                    explicit_target,
                )
            {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Explicit target version conflicts with confirmed upstream latest version",
                );
            }
        } else {
            if let Some(ref explicit_target) = expected_target_version {
                if !af_runner::af_release::lifecycle::versions_match_target(
                    explicit_target,
                    db_latest,
                ) && !af_runner::af_release::lifecycle::versions_match_target(
                    db_latest,
                    explicit_target,
                ) {
                    return api_error(
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        "Explicit target version conflicts with confirmed upstream latest version",
                    );
                }
            } else {
                expected_target_version = Some(db_latest.to_string());
            }
        }

        if expected_target_version
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        }
    } else {
        // Install or Reinstall: do not block on app_updates errors or missing records
        if is_retired && expected_target_version.is_none() {
            expected_target_version = Some("0.4.18.2805".to_string());
        } else if let Some(ref pinned_ver) = pinned_target {
            if expected_target_version.is_none() {
                expected_target_version = Some(pinned_ver.clone());
            }
        }
    }

    // This value is also the job identity clients use to match a terminal
    // outcome to the job they started; jobs for one package are sequential.
    let job_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    if !af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.clone(),
        package_id: pkg.name.clone(),
        action: action.to_string(),
        status: status_label.to_string(),
        progress: 5,
        last_line: format!("Starting {} for {}...", action, pkg.label),
        started_at: started_at.clone(),
        expected_target_version: expected_target_version.clone(),
    }) {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package is already modifying state",
        );
    }
    drop(admission_guard);
    emit_package_progress(
        &pkg.name,
        action,
        status_label,
        5,
        &format!("Starting {} for {}...", action, pkg.label),
        &started_at,
        &job_id,
    );

    let response_job_id = job_id.clone();
    let response_started_at = started_at.clone();
    let pkg_label = pkg.label.clone();
    let pkg_default_port = pkg.default_port;
    let pkg_lock_file = pkg.lock_file.clone();
    let job_lease = af_services::take_package_job_lease(&clean_id, &job_id);

    tokio::spawn(af_runner::PACKAGE_JOB_ID.scope(job_id.clone(), async move {
        let _job_lease = job_lease;
        let _lifecycle_guard = match af_services::PACKAGE_LIFECYCLE_MUTEX.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                emit_package_progress(
                    &clean_id,
                    action,
                    status_label,
                    5,
                    &format!(
                        "Queued: waiting for another lifecycle operation to finish before {} {}...",
                        action, pkg_label
                    ),
                    &started_at,
                    &job_id,
                );
                af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await
            }
        };
        let fs_root_override_raw = env::var("AETHERFLOW_FS_ROOT").unwrap_or_default();
        let fs_root_override =
            Option::from(fs_root_override_raw.clone()).filter(|root| !root.trim().is_empty());
        let prior_installed = is_lock_file_present(&pkg_lock_file, fs_root_override.as_deref());

        // Re-check under the lifecycle mutex: a system update may have been
        // launched while this job was queued (run_update holds this mutex
        // while launching, so the check cannot race with the launch).
        if let Some(message) = system_update_lifecycle_block().await {
            let prior_state_recovered = verified_prior_state_recovery(
                action,
                prior_installed,
                true,
                None,
                &[],
                &pkg_lock_file,
                fs_root_override.as_deref(),
            );
            finish_package_lifecycle_with_recovery(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::Preparation),
                5,
                &message.to_string(),
                &started_at,
                &job_id,
                expected_target_version.as_deref(),
                None,
                &[],
                prior_state_recovered,
            );
            return;
        }
        emit_package_progress(
            &clean_id,
            action,
            status_label,
            10,
            &format!("Preparing environment for {}...", pkg_label),
            &started_at,
            &job_id,
        );

        let can_run_bash =
            cfg!(unix) && fs_root_override.is_none() && std::path::Path::new("/bin/bash").exists();

        let expected_target_for_runner = expected_target_version.clone();
        #[allow(clippy::type_complexity)]
        let captured_receipt_snapshots: std::sync::Arc<
            std::sync::Mutex<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let snapshots_slot = captured_receipt_snapshots.clone();
        let captured_blueprint_snapshots: std::sync::Arc<
            std::sync::Mutex<Vec<af_runner::package_lifecycle::FileSnapshot>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let blueprint_snapshots_slot = captured_blueprint_snapshots.clone();
        let captured_runtime_snapshot: std::sync::Arc<
            std::sync::Mutex<Option<af_runner::package_lifecycle::PackageRuntimeSnapshot>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let runtime_snapshot_slot = captured_runtime_snapshot.clone();
        let captured_runner_snapshot: std::sync::Arc<
            std::sync::Mutex<Option<RunnerLifecycleSnapshotHandle>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let runner_snapshot_slot = captured_runner_snapshot.clone();
        let (allocated_port, stopped_units, execution_result) =
            match run_package_lifecycle_dispatch_gate_with(
                action,
                &clean_id,
                pkg_default_port,
                &fs_root_override_raw,
                |app_id| af_services::mutators::get_app_runtime_meta(app_id).configured_port,
                load_authoritative_app_ingress_config,
                allocate_or_resolve_app_port,
                |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
                |unit_name| af_services::get_systemd_unit_info(unit_name).0,
                |unit_name, control_action| async move {
                    af_services::control_service_with_manager(
                        &unit_name,
                        control_action,
                        "systemd-unit",
                    )
                    .await
                },
                |resolved_port| {
                    let clean_id = clean_id.clone();
                    let pkg_label = pkg_label.clone();
                    let script_name = script_name.clone();
                    let pkg_lock_file = pkg_lock_file.clone();
                    let started_at = started_at.clone();
                    let job_id = job_id.clone();
                    let fs_root_override = fs_root_override.clone();
                    let runner_target = expected_target_for_runner.clone();
                    let snapshots_slot = snapshots_slot.clone();
                    let blueprint_snapshots_slot = blueprint_snapshots_slot.clone();
                    let runtime_snapshot_slot = runtime_snapshot_slot.clone();
                    let runner_snapshot_slot = runner_snapshot_slot.clone();
                    async move {
                        if matches!(action, "install" | "reinstall" | "update") {
                            let mut capture_units =
                                af_services::resolve_controllable_service_units(&clean_id, "stop");
                            if let Ok(pkgs) = af_services::get_packages() {
                                if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_id) {
                                    let svc = p.service_name.trim().to_string();
                                    if !svc.is_empty()
                                        && !matches!(
                                            svc.as_str(),
                                            "apache2"
                                                | "nginx"
                                                | "apache2.service"
                                                | "nginx.service"
                                        )
                                        && !capture_units.contains(&svc)
                                    {
                                        capture_units.push(svc);
                                    }
                                }
                            }
                            let use_runner = can_run_bash && af_runner::is_runner_available();
                            if use_runner {
                                match af_runner::dispatch_package_lifecycle_snapshot_capture(
                                    &clean_id,
                                    &capture_units,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        *runner_snapshot_slot.lock().unwrap() =
                                            Some(RunnerLifecycleSnapshotHandle::new(
                                                clean_id.clone(),
                                                job_id.clone(),
                                            ));
                                    }
                                    Err(err) => {
                                        return Err(anyhow::anyhow!("Preparation: {err}"));
                                    }
                                }
                            } else {
                                match snapshot_candidate_receipts(&clean_id) {
                                    Ok(s) => *snapshots_slot.lock().unwrap() = s,
                                    Err(err) => {
                                        return Err(anyhow::anyhow!("Preparation: {err}"));
                                    }
                                }
                                let env_cfg = af_runner::PackageExecutionEnv {
                                    fs_root: fs_root_override
                                        .as_ref()
                                        .map(|s| PathBuf::from(s.trim()))
                                        .or_else(|| af_runner::PackageExecutionEnv::default().fs_root),
                                    ..af_runner::PackageExecutionEnv::default()
                                };
                                match af_runner::package_lifecycle::snapshot_blueprint_targets(
                                    &clean_id,
                                    &env_cfg,
                                ) {
                                    Ok(bp_snaps) => {
                                        *blueprint_snapshots_slot.lock().unwrap() = bp_snaps;
                                    }
                                    Err(err) => {
                                        return Err(anyhow::anyhow!("Preparation: {err}"));
                                    }
                                }
                                match af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
                                    &clean_id,
                                    &capture_units,
                                    &env_cfg,
                                    false,
                                ) {
                                    Ok(rt_snap) => {
                                        *runtime_snapshot_slot.lock().unwrap() = Some(rt_snap);
                                    }
                                    Err(err) => {
                                        return Err(anyhow::anyhow!("Preparation: {err}"));
                                    }
                                }
                            }
                        }
                        emit_package_progress(
                            &clean_id,
                            action,
                            status_label,
                            25,
                            &format!("Executing {} script for {}...", action, pkg_label),
                            &started_at,
                            &job_id,
                        );

                        if can_run_bash && af_runner::is_runner_available() {
                            af_runner::dispatch_package_action_with_target(
                                action,
                                &clean_id,
                                &script_name,
                                resolved_port,
                                delete_data,
                                runner_target,
                                |line| {
                                    let (pct, msg) = af_runner::parse_progress_line(&line)
                                        .map(|(p, m)| (p as i32, m))
                                        .unwrap_or_else(|| (60, line));
                                    let display_msg = if msg.is_empty() {
                                        format!("Running {} for {}...", action, pkg_label)
                                    } else {
                                        msg
                                    };
                                    emit_package_progress(
                                        &clean_id,
                                        action,
                                        status_label,
                                        pct,
                                        &display_msg,
                                        &started_at,
                                        &job_id,
                                    );
                                },
                            )
                            .await
                        } else if can_run_bash {
                            Err(anyhow::anyhow!(
                                "AetherFlow runner service is unavailable; refusing to execute privileged package operation in-process"
                            ))
                        } else {
                            emit_package_progress(
                                &clean_id,
                                action,
                                status_label,
                                60,
                                &format!("Applying package state changes for {}...", pkg_label),
                                &started_at,
                                &job_id,
                            );
                            if !pkg_lock_file.is_empty() {
                                let root_path = fs_root_override.as_deref().map(std::path::Path::new);
                                let lock_paths = af_models::resolve_package_lock_paths(
                                    &clean_id,
                                    Some(&pkg_lock_file),
                                    root_path,
                                );
                                if action == "remove" {
                                    let had_canonical = af_models::inspect_receipt_file(
                                        &lock_paths.canonical,
                                        root_path,
                                    )
                                    .unwrap_or(false);
                                    let had_legacy = lock_paths.legacy_swizzin.as_ref().is_some_and(
                                        |legacy_path| {
                                            af_models::inspect_receipt_file(legacy_path, root_path)
                                                .unwrap_or(false)
                                        },
                                    );
                                    let had_retained = !lock_paths.retained.as_os_str().is_empty()
                                        && af_models::inspect_receipt_file(
                                            &lock_paths.retained,
                                            root_path,
                                        )
                                        .unwrap_or(false);
                                    if !delete_data {
                                        if (had_canonical || had_legacy || had_retained)
                                            && !lock_paths.retained.as_os_str().is_empty()
                                        {
                                            if let Some(parent) = lock_paths.retained.parent() {
                                                let _ = fs::create_dir_all(parent);
                                            }
                                            let payload = af_models::format_retained_package_receipt(
                                                &clean_id,
                                                &chrono::Utc::now().to_rfc3339(),
                                            );
                                            let _ = fs::write(&lock_paths.retained, payload);
                                        }
                                    } else if had_retained {
                                        let _ = fs::remove_file(&lock_paths.retained);
                                    }
                                    let _ = fs::remove_file(&lock_paths.canonical);
                                    if had_legacy {
                                        if let Some(ref legacy_path) = lock_paths.legacy_swizzin {
                                            let _ = fs::remove_file(legacy_path);
                                        }
                                    }
                                } else if fs_root_override.is_some() {
                                    if let Some(parent) = lock_paths.canonical.parent() {
                                        let _ = fs::create_dir_all(parent);
                                    }
                                    let _ = fs::write(&lock_paths.canonical, b"installed\n");
                                    if !lock_paths.retained.as_os_str().is_empty()
                                        && af_models::inspect_receipt_file(
                                            &lock_paths.retained,
                                            root_path,
                                        )
                                        .unwrap_or(false)
                                    {
                                        let _ = fs::remove_file(&lock_paths.retained);
                                    }
                                    if let Some(ref legacy_path) = lock_paths.legacy_swizzin {
                                        if af_models::inspect_receipt_file(legacy_path, root_path)
                                            .unwrap_or(false)
                                        {
                                            let _ = fs::remove_file(legacy_path);
                                        }
                                    }
                                }
                            }
                            Ok(())
                        }
                    }
                },
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error_message) => {
                    finish_package_lifecycle(
                        &clean_id,
                        action,
                        Some(af_services::PackageJobFailure::Preparation),
                        10,
                        &error_message,
                        &started_at,
                        &job_id,
                        expected_target_version.as_deref(),
                        None,
                        &[],
                    );
                    return;
                }
            };

        let receipt_snapshots = captured_receipt_snapshots.lock().unwrap().clone();
        let blueprint_snapshots = captured_blueprint_snapshots.lock().unwrap().clone();
        let mut runtime_snapshot = captured_runtime_snapshot.lock().unwrap().take();
        let mut runner_snapshot = captured_runner_snapshot.lock().unwrap().take();

        if let Err(error) = execution_result {
            af_services::mutators::clear_app_runtime_meta_cache();
            let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
            let err_str = error.to_string();
            let is_prep_err = err_str.starts_with("Preparation: ");
            let refuse_restart = is_incomplete_rollback_error(&err_str);
            let snapshot_captured =
                runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
            if refuse_restart {
                if let Some(ref mut snapshot) = runtime_snapshot {
                    snapshot.preserve_on_drop = true;
                }
            }
            let (receipt_restore_error, restart_failures) =
                if matches!(action, "install" | "reinstall" | "update") {
                    quiesce_and_restore_candidate_receipts_and_runtime_ext(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        &blueprint_snapshots,
                        refuse_restart,
                        if refuse_restart {
                            None
                        } else {
                            runtime_snapshot.as_mut()
                        },
                        runner_snapshot.as_mut(),
                    )
                    .await
                } else {
                    let mut restart_failures = Vec::new();
                    if refuse_restart {
                        restart_failures.push("Refusing to restart pre-stopped service after incomplete rollback".to_string());
                    } else if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
                        for unit in af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units) {
                            if let Err(e) = af_services::control_service_with_manager(&unit, "start", "systemd-unit").await {
                                restart_failures.push(format!("{unit}: {e}"));
                            }
                        }
                    }
                    (None, restart_failures)
                };

            let prior_state_recovered = verified_prior_state_recovery(
                action,
                prior_installed,
                !refuse_restart && (is_prep_err || snapshot_captured),
                receipt_restore_error.as_deref(),
                &restart_failures,
                &pkg_lock_file,
                fs_root_override.as_deref(),
            );

            let failure_kind = if is_prep_err {
                af_services::PackageJobFailure::Preparation
            } else if restart_failures.is_empty() {
                af_services::PackageJobFailure::Installer
            } else {
                af_services::PackageJobFailure::ServiceRestore
            };
            let clean_err = err_str.strip_prefix("Preparation: ").unwrap_or(&err_str);
            let mut failure_message = if restart_failures.is_empty() {
                clean_err.to_string()
            } else {
                format!("{clean_err}; {}", restart_failures.join("; "))
            };
            if let Some(ref r_err) = receipt_restore_error {
                tracing::error!(
                    package = %clean_id,
                    error = %r_err,
                    "Failed to restore candidate receipts after script execution failure"
                );
                append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
                failure_message.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            if let Some(ref mut rs) = runner_snapshot {
                rs.discard(false).await;
            }
            if runtime_snapshot.is_some() {
                let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            }

            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle_with_recovery(
                &clean_id,
                action,
                Some(failure_kind),
                60,
                &failure_message,
                &started_at,
                &job_id,
                expected_target_version.as_deref(),
                None,
                &stopped_units,
                prior_state_recovered,
            );
            return;
        }

        let mut achieved_ver: Option<String> = None;

        if matches!(action, "install" | "reinstall" | "update") {
            let mut restart_failures: Vec<String> = Vec::new();
            if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
                for unit in af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units) {
                    if let Err(e) = af_services::control_service_with_manager(&unit, "start", "systemd-unit").await {
                        tracing::error!(unit, error = %e, "Application service restoration failed after script execution");
                        restart_failures.push(format!("{unit}: {e}"));
                    }
                }
                for unit in &stopped_units {
                    let (st, _, _) = af_services::get_systemd_unit_info(unit);
                    if st != "running" && st != "idle"
                        && !restart_failures.iter().any(|f| f.starts_with(unit)) {
                            restart_failures.push(format!("{unit} is {st}"));
                        }
                }
            }

            if !restart_failures.is_empty() {
                let snapshot_captured =
                    runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
                let (receipt_restore_error, post_restore_failures) =
                    quiesce_and_restore_candidate_receipts_and_runtime_ext(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        &blueprint_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
                        runner_snapshot.as_mut(),
                    )
                    .await;
                let prior_state_recovered = verified_prior_state_recovery(
                    action,
                    prior_installed,
                    snapshot_captured,
                    receipt_restore_error.as_deref(),
                    &post_restore_failures,
                    &pkg_lock_file,
                    fs_root_override.as_deref(),
                );
                if let Some(ref r_err) = receipt_restore_error {
                    tracing::error!(
                        package = %clean_id,
                        error = %r_err,
                        "Failed to restore candidate receipts after service restart failure"
                    );
                    append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
                }
                for pf in post_restore_failures {
                    if !restart_failures.contains(&pf) {
                        restart_failures.push(pf);
                    }
                }

                let mut msg = format!(
                    "Application service restart failed after execution: {}",
                    restart_failures.join("; ")
                );
                if let Some(ref r_err) = receipt_restore_error {
                    msg.push_str(&format!("; receipt restoration error: {}", r_err));
                }

                if let Some(ref mut rs) = runner_snapshot {
                    rs.discard(false).await;
                }
                if runtime_snapshot.is_some() {
                    let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
                }

                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle_with_recovery(
                    &clean_id,
                    action,
                    Some(af_services::PackageJobFailure::ServiceRestore),
                    95,
                    &msg,
                    &started_at,
                    &job_id,
                    expected_target_version.as_deref(),
                    achieved_ver.as_deref(),
                    &stopped_units,
                    prior_state_recovered,
                );
                return;
            }

            let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
            let pkgs = af_services::get_packages().unwrap_or_default();
            achieved_ver = if let Some(pkg) = pkgs.into_iter().find(|p| p.name == clean_id) {
                af_services::workers::probe_installed_package_version_strict(&pkg)
                    .await
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            } else {
                None
            };

            let target_match_failed = if action == "update" || expected_target_version.is_some() {
                let target = expected_target_version.as_deref().unwrap_or("");
                let matches_target = match achieved_ver.as_deref() {
                    Some(achieved) if !achieved.trim().is_empty() => {
                        if !target.is_empty() {
                            versions_match_target(achieved, target)
                        } else {
                            true
                        }
                    }
                    _ => false,
                };
                !matches_target
            } else {
                false
            };

            if target_match_failed {
                let snapshot_captured =
                    runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
                let (receipt_restore_error, post_restore_failures) =
                    quiesce_and_restore_candidate_receipts_and_runtime_ext(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        &blueprint_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
                        runner_snapshot.as_mut(),
                    )
                    .await;
                let prior_state_recovered = verified_prior_state_recovery(
                    action,
                    prior_installed,
                    snapshot_captured,
                    receipt_restore_error.as_deref(),
                    &post_restore_failures,
                    &pkg_lock_file,
                    fs_root_override.as_deref(),
                );
                if let Some(ref r_err) = receipt_restore_error {
                    tracing::error!(
                        package = %clean_id,
                        error = %r_err,
                        "Failed to restore candidate receipts after target certification failure"
                    );
                    append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
                }

                let mut msg = format!(
                    "Target certification failed after installer execution (runtime state may be partially committed): expected {}, achieved {}",
                    expected_target_version.as_deref().unwrap_or(""),
                    achieved_ver.as_deref().unwrap_or("none")
                );
                if !post_restore_failures.is_empty() {
                    msg.push_str(&format!("; service restart after receipt restoration failed: {}", post_restore_failures.join("; ")));
                }
                if let Some(ref r_err) = receipt_restore_error {
                    msg.push_str(&format!("; receipt restoration error: {}", r_err));
                }

                if let Some(ref mut rs) = runner_snapshot {
                    rs.discard(false).await;
                }
                if runtime_snapshot.is_some() {
                    let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
                }

                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle_with_recovery(
                    &clean_id,
                    action,
                    Some(af_services::PackageJobFailure::TargetVerification),
                    95,
                    &msg,
                    &started_at,
                    &job_id,
                    expected_target_version.as_deref(),
                    achieved_ver.as_deref(),
                    &stopped_units,
                    prior_state_recovered,
                );
                return;
            }

            emit_package_progress(
                &clean_id,
                action,
                status_label,
                85,
                &format!("Synchronizing blueprint & ingress for {}...", pkg_label),
                &started_at,
                &job_id,
            );

            let finalization = finalize_post_script_lifecycle_with(
                &stopped_units,
                af_services::mutators::apply_lifecycle_blueprint_app_config(&clean_id, allocated_port),
                |unit_name, ctrl_action| async move {
                    af_services::control_service_with_manager(
                        &unit_name,
                        ctrl_action,
                        "systemd-unit",
                    )
                    .await
                },
                |unit| af_services::get_systemd_unit_info(unit).0,
                async {
                    let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
                    let pkgs = af_services::get_packages().unwrap_or_default();
                    let version = if let Some(pkg) = pkgs.into_iter().find(|p| p.name == clean_id) {
                        af_services::workers::probe_installed_package_version_strict(&pkg)
                            .await
                            .ok()
                            .filter(|s| !s.trim().is_empty())
                    } else {
                        None
                    };
                    if !stopped_units.is_empty() {
                        af_services::clear_service_status_cache();
                    }
                    version
                },
                |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, &job_id, action),
            )
            .await;
            if let Err(required_err) = finalization {
                let snapshot_captured =
                    runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
                let rollback_attempted =
                    should_rollback_post_certification_failure(action, required_err.kind);
                let (required_err, receipt_restore_error, post_restore_failures) =
                    handle_post_certification_finalization_failure_ext_with(
                        action,
                        required_err,
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        &blueprint_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
                        runner_snapshot.as_mut(),
                        |unit, ctl_action| async move {
                            #[cfg(test)]
                            {
                                if let Ok(mut lock) = CANDIDATE_QUIESCE_RECORDER.lock() {
                                    if let Some(ref mut vec) = *lock {
                                        vec.push(format!("{ctl_action} {unit}"));
                                    }
                                }
                            }
                            if std::env::var("AETHERFLOW_FS_ROOT")
                                .map(|s| !s.trim().is_empty())
                                .unwrap_or(false)
                            {
                                return Ok(());
                            }
                            af_services::control_service_with_manager(&unit, ctl_action, "systemd-unit").await
                        },
                        |unit| {
                            if std::env::var("AETHERFLOW_FS_ROOT")
                                .map(|s| !s.trim().is_empty())
                                .unwrap_or(false)
                            {
                                return "running".to_string();
                            }
                            af_services::get_systemd_unit_info(unit).0
                        },
                    )
                    .await;
                let prior_state_recovered = verified_prior_state_recovery(
                    action,
                    prior_installed,
                    rollback_attempted && snapshot_captured,
                    receipt_restore_error.as_deref(),
                    &post_restore_failures,
                    &pkg_lock_file,
                    fs_root_override.as_deref(),
                );
                if let Some(r_err) = receipt_restore_error {
                    tracing::error!(
                        package = %clean_id,
                        error = %r_err,
                        "Failed to restore candidate receipts after service restoration failure"
                    );
                    append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
                }
                if let Some(ref mut rs) = runner_snapshot {
                    rs.discard(false).await;
                }
                if runtime_snapshot.is_some() {
                    let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
                }

                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle_with_recovery(
                    &clean_id,
                    action,
                    Some(required_err.kind),
                    90,
                    &required_err.message,
                    &started_at,
                    &job_id,
                    expected_target_version.as_deref(),
                    None,
                    &stopped_units,
                    prior_state_recovered,
                );
                return;
            }

            if achieved_ver.is_none() {
                achieved_ver = finalization.ok().flatten();
            }
            if achieved_ver.is_none() {
                if let Ok(conn) = af_db::get_conn() {
                    if let Ok(ver) = conn.query_row(
                        "SELECT installed_version FROM app_updates WHERE package_name = ?1",
                        rusqlite::params![&clean_id],
                        |r| r.get::<_, String>(0),
                    ) {
                        let trimmed = ver.trim();
                        if !trimmed.is_empty() {
                            achieved_ver = Some(trimmed.to_string());
                        }
                    }
                }
            }
        } else if action == "remove" {
            let retained = af_db::get_conn().and_then(|mut conn| {
                af_db::synchronize_lifecycle_ingress(
                    &mut conn,
                    &clean_id,
                    action,
                    &job_id,
                    0,
                    delete_data,
                    "",
                )
            });
            if let Err(error) = retained {
                finish_package_lifecycle(
                    &clean_id,
                    action,
                    Some(af_services::PackageJobFailure::Retention),
                    90,
                    &format!(
                        "Package removed but reinstall settings could not be retained: {}",
                        error
                    ),
                    &started_at,
                    &job_id,
                    None,
                    None,
                    &stopped_units,
                );
                return;
            }
            if let Err(dns_err) = af_services::mutators::sync_network_dns_providers().await {
                if let Some(ref mut rs) = runner_snapshot {
            rs.discard(false).await;
        }
        if runtime_snapshot.is_some() {
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
        }

        af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle(
                    &clean_id,
                    action,
                    Some(af_services::PackageJobFailure::Configuration),
                    95,
                    &format!(
                        "[STAGE:dns_cleanup] Package removed but local DNS reconciliation failed: {}",
                        dns_err
                    ),
                    &started_at,
                    &job_id,
                    None,
                    None,
                    &stopped_units,
                );
                return;
            }
        }

        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(false).await;
        }
        if runtime_snapshot.is_some() {
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
        }

        af_services::clear_service_status_cache();
        af_services::mutators::clear_app_runtime_meta_cache();

        finish_package_lifecycle_with_recovery_and_retention(
            &clean_id,
            action,
            None,
            100,
            &format!("Completed {} for {}", action, pkg_label),
            &started_at,
            &job_id,
            expected_target_version.as_deref(),
            achieved_ver.as_deref(),
            // Final service verification already ran before ingress persistence.
            &[],
            false,
            (action == "remove").then_some(if delete_data {
                af_runner::af_release::lifecycle::RETENTION_STATE_PURGED
            } else {
                af_runner::af_release::lifecycle::RETENTION_STATE_RETAINED
            }),
        );
    }));

    let msg = match action {
        "install" | "reinstall" => "Installation started successfully",
        "remove" => "Uninstallation started successfully",
        _ => "Update started successfully",
    };

    Json(serde_json::json!({
        "message": msg,
        "package": pkg_id,
        "status": status_label,
        "action": action,
        "started_at": response_started_at,
        "job_id": response_job_id,
        "purge": delete_data,
    }))
    .into_response()
}

pub(super) async fn check_package_updates() -> Response {
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

pub(super) async fn check_single_package_update(Path(id): Path<String>) -> Response {
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

pub(super) fn build_single_package_update_response(
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
