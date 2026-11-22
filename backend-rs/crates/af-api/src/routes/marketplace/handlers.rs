use super::dispatch::dispatch_package_lifecycle_with_target;
use crate::auth::{api_error, AuthUser};
use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PackageActionQuery {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::routes) struct PackageTargetPayload {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

pub(in crate::routes) fn extract_expected_target_version(
    bytes: &[u8],
) -> Result<Option<String>, StatusCode> {
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

pub(in crate::routes) async fn install_package(
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
pub(in crate::routes) struct UninstallQuery {
    #[serde(default)]
    pub(in crate::routes) purge: Option<String>,
}

/// Removal is data-preserving unless the caller explicitly asks for a purge
/// with `?purge=true`. Any other value is rejected rather than guessed.
pub(in crate::routes) fn parse_uninstall_purge(query: &UninstallQuery) -> Result<bool, String> {
    match query.purge.as_deref().map(str::trim) {
        None | Some("") | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => Err(format!(
            "Invalid purge value {:?}; use purge=true for an explicit data purge",
            other
        )),
    }
}

pub(in crate::routes) async fn uninstall_package(
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

pub(in crate::routes) async fn update_package(
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
