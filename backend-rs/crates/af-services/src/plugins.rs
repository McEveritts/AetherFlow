//! Native Rust Plugin Route Scope Verifier (`af-services::plugins`)

/// Verifies whether `request_path` is authorized by at least one scope in `allowed_scopes`.
/// Enforces exact or segment-boundary prefix matching (`/api/v1/public/marketplace` matches
/// `/api/v1/public/marketplace` and `/api/v1/public/marketplace/items`, but NOT
/// `/api/v1/public/marketplace_admin`).
pub fn verify_plugin_route_scope(allowed_scopes: &[String], request_path: &str) -> bool {
    let raw_path = request_path.split('?').next().unwrap_or("").trim();
    if !raw_path.starts_with("/api/v1/")
        || raw_path.contains("..")
        || raw_path.contains('\\')
        || raw_path.contains("//")
    {
        return false;
    }
    let norm_path = if raw_path.len() > 1 {
        raw_path.trim_end_matches('/')
    } else {
        raw_path
    };

    for raw_scope in allowed_scopes {
        let scope = raw_scope.trim();
        if !scope.starts_with("/api/v1/") || scope.contains("..") {
            continue;
        }

        if let Some(prefix) = scope.strip_suffix("/*") {
            let clean_prefix = prefix.trim_end_matches('/');
            if clean_prefix.len() < "/api/v1".len() {
                continue;
            }
            if norm_path == clean_prefix {
                return true;
            }
            if let Some(rest) = norm_path.strip_prefix(clean_prefix) {
                if rest.starts_with('/') {
                    return true;
                }
            }
        } else if scope.ends_with('*') {
            continue;
        } else {
            let clean_scope = scope.trim_end_matches('/');
            if norm_path == clean_scope {
                return true;
            }
            if let Some(rest) = norm_path.strip_prefix(clean_scope) {
                if rest.starts_with('/') {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_plugin_route_scope_boundaries() {
        let scopes = vec![
            "/api/v1/public/marketplace".to_string(),
            "/api/v1/auth/system/*".to_string(),
        ];

        // Exact & sub-path match for exact scope
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace/"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace/featured?limit=10"
        ));

        // Segment boundary check: must NOT match sibling prefix
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace_admin"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace-internal"
        ));

        // Wildcard prefix match
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/metrics"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/hardware"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system_other"
        ));

        // Disallowed routes & traversal attempts
        assert!(!verify_plugin_route_scope(&scopes, "/api/v1/admin/users"));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/../admin/users"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/public/marketplace"
        ));
    }
}
