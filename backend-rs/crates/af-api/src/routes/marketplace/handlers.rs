use super::dispatch::dispatch_package_lifecycle_with_target;
use crate::auth::{api_error, AuthUser, PeerPrincipal};
use crate::peers::errors::PeerError;
use crate::peers::scopes::is_jellyfin_update_package_id;
use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
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
    peer_principal: Option<Extension<PeerPrincipal>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(Extension(peer)) = peer_principal {
        if !peer.access.marketplace.allows_write() && !is_jellyfin_update_package_id(&id) {
            let err = PeerError::peer_scope_denied(
                &peer.local_server,
                "package_update",
                "Grant scope updates:write authorizes Jellyfin updates only; marketplace:write is required for other packages",
            );
            let mut resp = err.clone().into_response();
            resp.extensions_mut().insert(err);
            return resp;
        }
    }
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

#[cfg(test)]
mod peer_update_scope_tests {
    use super::*;
    use af_db::peers::{AccessLevel, AccessMap};
    use axum::body::to_bytes;

    fn test_admin() -> AuthUser {
        AuthUser {
            user_id: 7,
            username: "peer-manager".to_string(),
            role: "admin".to_string(),
            jti: "peer-grant:test".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    fn test_peer(access: AccessMap) -> PeerPrincipal {
        PeerPrincipal {
            link_id: "link-1".to_string(),
            link_name: "manager-a".to_string(),
            local_server: "managed-b".to_string(),
            grant_id: "grant-1".to_string(),
            run_as_user_id: 7,
            run_as_username: "peer-manager".to_string(),
            access,
            origin_operator: Some("alice".to_string()),
            request_id: "req-pkg-scope-1".to_string(),
        }
    }

    #[tokio::test]
    async fn updates_write_only_allows_jellyfin_and_ffmpeg_and_rejects_other_packages() {
        let mut updates_only = AccessMap::none();
        updates_only.updates = AccessLevel::Write;

        // Non-Jellyfin packages must be rejected with 403 PEER_SCOPE_DENIED and attached PeerError.
        for pkg in ["sonarr", "plex", "radarr", "jellyfin-plugin"] {
            let resp = update_package(
                Path(pkg.to_string()),
                Query(PackageActionQuery::default()),
                Extension(test_admin()),
                Some(Extension(test_peer(updates_only.clone()))),
                HeaderMap::new(),
                axum::body::Bytes::from_static(b"not-json"),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "pkg={pkg}");
            assert!(
                matches!(
                    resp.extensions().get::<PeerError>(),
                    Some(PeerError::PeerScopeDenied(_))
                ),
                "response must attach PeerError::PeerScopeDenied for audit attribution: pkg={pkg}"
            );
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
            assert_eq!(body["code"], "PEER_SCOPE_DENIED", "pkg={pkg}: {body}");
            assert_eq!(body["step"], "package_update", "pkg={pkg}: {body}");
        }

        // Jellyfin & jellyfin-ffmpeg* pass the PeerPrincipal scope check (reaching JSON validation -> 400).
        for pkg in [
            "jellyfin",
            "Jellyfin",
            "jellyfin-ffmpeg",
            "jellyfin-ffmpeg8",
        ] {
            let resp = update_package(
                Path(pkg.to_string()),
                Query(PackageActionQuery::default()),
                Extension(test_admin()),
                Some(Extension(test_peer(updates_only.clone()))),
                HeaderMap::new(),
                axum::body::Bytes::from_static(b"not-json"),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "updates:write must allow {pkg} past peer scope guard"
            );
        }

        // marketplace:write allows non-Jellyfin packages past the PeerPrincipal scope guard.
        let mut marketplace_write = AccessMap::none();
        marketplace_write.marketplace = AccessLevel::Write;
        let mp_resp = update_package(
            Path("sonarr".to_string()),
            Query(PackageActionQuery::default()),
            Extension(test_admin()),
            Some(Extension(test_peer(marketplace_write))),
            HeaderMap::new(),
            axum::body::Bytes::from_static(b"not-json"),
        )
        .await;
        assert_eq!(
            mp_resp.status(),
            StatusCode::BAD_REQUEST,
            "marketplace:write must allow non-Jellyfin packages past peer scope guard"
        );

        // Local human admin (no PeerPrincipal) is unaffected for any package.
        let local_resp = update_package(
            Path("sonarr".to_string()),
            Query(PackageActionQuery::default()),
            Extension(test_admin()),
            None,
            HeaderMap::new(),
            axum::body::Bytes::from_static(b"not-json"),
        )
        .await;
        assert_eq!(local_resp.status(), StatusCode::BAD_REQUEST);
    }
}
