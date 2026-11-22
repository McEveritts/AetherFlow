use super::job_runner::{spawn_package_lifecycle_job, PackageLifecycleJobContext};
use super::lifecycle::{emit_package_progress, system_update_lifecycle_block};
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use std::env;

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

pub(in crate::routes) async fn dispatch_package_lifecycle_with_target(
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
    let is_apt = pkg.update_source.eq_ignore_ascii_case("apt");

    if let Some(ref target) = expected_target_version {
        if !af_runner::af_release::lifecycle::is_valid_target_version_token(target) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid target version token format",
            );
        }
    }

    if is_apt && action != "remove" {
        if let Err(reason) = af_runner::validate_package_target_policy(
            &pkg.name,
            &pkg.update_source,
            &pkg.update_package,
            action,
            expected_target_version.as_deref(),
        ) {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", reason);
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
                if is_apt
                    && !af_runner::af_release::lifecycle::validate_exact_apt_version(db_latest)
                {
                    return api_error(
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        format!(
                            "Cannot start update: confirmed APT latest version '{}' for '{}' is not an exact Debian version",
                            db_latest, pkg.name
                        ),
                    );
                }
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

    spawn_package_lifecycle_job(PackageLifecycleJobContext {
        job_lease,
        job_id,
        started_at,
        clean_id,
        action,
        status_label,
        delete_data,
        expected_target_version,
        script_name,
        pkg_label,
        pkg_default_port,
        pkg_lock_file,
    });

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
