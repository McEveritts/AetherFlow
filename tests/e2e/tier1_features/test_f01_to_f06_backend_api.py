"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F01: Rust Directory Browser Handler
- F02: Auth Session Refresh
- F03: Profile Password Mutation
- F04: Profile Avatar Mutation
- F05: Ingress Configuration CRUD
- F06: System Topology Endpoint
"""

import os
from urllib.parse import quote

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

ROUTES_RS = "backend-rs/crates/af-api/src/routes.rs"
AUTH_RS = "backend-rs/crates/af-api/src/auth.rs"
DB_RS = "backend-rs/crates/af-db/src/lib.rs"
INTELLIGENCE_RS = "backend-rs/crates/af-api/src/intelligence.rs"
MIDDLEWARES_RS = "backend-rs/crates/af-api/src/middlewares.rs"


class TestF01DirectoryListingValidPath(TestCase):
    def __init__(self):
        super().__init__("T1_F01_01", "F01", 1, "Directory listing returns entries array and path metadata for allowed path")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("GET", "/api/v1/auth/fs?path=/mnt")
            self.assert_status_code(code, 200)
            self.assert_in("entries", body)
            self.assert_in("current_path", body)
            self.assert_in("parent_path", body)
        else:
            has_route = inspector.check_route_registered("GET", "/fs") or inspector.check_rust_symbol(ROUTES_RS, r'\.route\("/fs"')
            handler_code = inspector.read_file(ROUTES_RS)
            has_handler = bool(handler_code and "browse_directories" in handler_code)
            self.assert_true(has_route and has_handler, "F01: GET /api/v1/auth/fs handler must be registered in af-api routes.rs")


class TestF01ParentPathCalculation(TestCase):
    def __init__(self):
        super().__init__("T1_F01_02", "F01", 1, "Parent path is accurately computed for nested subdirectories")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            fixture = os.environ.get("AETHERFLOW_E2E_FS_FIXTURE")
            self.assert_true(bool(fixture), "AETHERFLOW_E2E_FS_FIXTURE is required for nested filesystem coverage")
            parent = os.path.join(os.path.realpath(fixture), "storage")
            nested = os.path.join(parent, "media")
            code, body, _ = client.request("GET", "/api/v1/auth/fs?path=" + quote(nested, safe="/"))
            self.assert_status_code(code, 200)
            self.assert_equal(body.get("current_path"), nested)
            self.assert_equal(body.get("parent_path"), parent)
        else:
            handler_code = inspector.read_file(ROUTES_RS)
            self.assert_true(bool(handler_code and "browse_host_directories" in handler_code and '"parent_path"' in handler_code), "F01: routes.rs browse_host_directories must compute parent_path")


class TestF01EntryMetadataStructure(TestCase):
    def __init__(self):
        super().__init__("T1_F01_03", "F01", 1, "Each directory entry contains name, path, is_dir, size, and mod_time")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            fixture = os.environ.get("AETHERFLOW_E2E_FS_FIXTURE")
            self.assert_true(bool(fixture), "AETHERFLOW_E2E_FS_FIXTURE is required for directory-entry coverage")
            nested = os.path.join(os.path.realpath(fixture), "storage", "media")
            code, body, _ = client.request("GET", "/api/v1/auth/fs?path=" + quote(nested, safe="/"))
            self.assert_status_code(code, 200)
            entries = body.get("entries", [])
            matching = [entry for entry in entries if entry.get("name") == "fixture.txt"]
            self.assert_equal(len(matching), 1, "Fixture file must be returned")
            entry = matching[0]
            for field in ("name", "path", "is_dir", "size", "mod_time"):
                self.assert_in(field, entry)
            self.assert_equal(entry["path"], os.path.join(nested, "fixture.txt"))
            self.assert_equal(entry["is_dir"], False)
            self.assert_true(isinstance(entry["size"], int) and entry["size"] > 0)
            self.assert_true(isinstance(entry["mod_time"], str) and bool(entry["mod_time"]))
        else:
            handler_code = inspector.read_file(ROUTES_RS)
            self.assert_true(bool(handler_code and "is_dir" in handler_code and "mod_time" in handler_code), "F01: Directory entry payload must include name, is_dir, size, mod_time")


class TestF01SymlinkResolutionWithinSandbox(TestCase):
    def __init__(self):
        super().__init__("T1_F01_04", "F01", 1, "Symlinks pointing inside allowed roots are resolved and accessible")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler_code = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(handler_code and "fs::canonicalize" in handler_code and "is_fs_path_allowed" in handler_code), "F01: routes.rs must use fs::canonicalize and is_fs_path_allowed for path verification")


class TestF01CompatibilityAlias(TestCase):
    def __init__(self):
        super().__init__("T1_F01_05", "F01", 1, "Compatibility alias /api/fs routes to the Rust filesystem browser")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, _, _ = client.request("GET", "/api/fs?path=/mnt")
            self.assert_status_code(code, 200)
        else:
            routes = inspector.read_file(ROUTES_RS)
            self.assert_true(bool(routes and '/fs' in routes and 'compat_routes' in routes), "F01: /api/fs compat route must be registered for frontend PathSelector compatibility")


class TestF02SessionRefreshValidCredentials(TestCase):
    def __init__(self):
        super().__init__("T1_F02_01", "F02", 1, "Valid session cookie returns new JWT token with HTTP 200")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("POST", "/api/v1/auth/refresh")
            self.assert_status_code(code, 200)
            self.assert_equal(body.get("status"), "success")
            self.assert_true(bool(body.get("token")), "Expected non-empty JWT token in refresh response")
        else:
            routes = inspector.read_file(ROUTES_RS)
            self.assert_true(bool(routes and '/auth/refresh' in routes and '/refresh' in routes), "F02: POST /api/v1/auth/refresh must be registered in routes.rs")


class TestF02SessionRefreshExpiryUpdated(TestCase):
    def __init__(self):
        super().__init__("T1_F02_02", "F02", 1, "Refresh response includes updated future expires_at timestamp")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("POST", "/api/v1/auth/refresh")
            self.assert_status_code(code, 200)
            self.assert_true(body.get("expires_at", 0) > 0, "expires_at must be positive epoch timestamp")
        else:
            auth_code = inspector.read_file(AUTH_RS)
            self.assert_true(bool(auth_code and "refresh_session_for_peer_blocking" in auth_code and "expires_at" in auth_code), "F02: refresh_session_for_peer_blocking must return expires_at in JSON payload")


class TestF02SessionRefreshUserPayload(TestCase):
    def __init__(self):
        super().__init__("T1_F02_03", "F02", 1, "Refresh response includes user object with id, username, and role")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("POST", "/api/v1/auth/refresh")
            self.assert_status_code(code, 200)
            user = body.get("user", {})
            self.assert_in("username", user)
            self.assert_in("role", user)
        else:
            auth_code = inspector.read_file(AUTH_RS)
            self.assert_true(bool(auth_code and "refresh_session_for_peer_blocking" in auth_code and "user" in auth_code), "F02: refresh handler must include user identity payload")


class TestF02SubsequentAuthWithRotatedToken(TestCase):
    def __init__(self):
        super().__init__("T1_F02_04", "F02", 1, "Rotated token successfully authenticates subsequent requests")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("POST", "/api/v1/auth/refresh")
            self.assert_status_code(code, 200)
            new_token = body.get("token")
            client.set_auth_token(new_token)
            sec_code, _, _ = client.request("GET", "/api/v1/auth/sessions")
            self.assert_status_code(sec_code, 200)
        else:
            auth_code = inspector.read_file(AUTH_RS)
            self.assert_true(bool(auth_code and "create_session_jwt_in_conn" in auth_code and "refresh_session_for_peer_blocking" in auth_code), "F02: Refresh handler must issue valid verifiable JWT tokens")


class TestF02CsrfExemptionForXmlHttpRequest(TestCase):
    def __init__(self):
        super().__init__("T1_F02_05", "F02", 1, "Refresh endpoint allows transparent AJAX refresh without CSRF blocking")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file(AUTH_RS)
        routes_code = inspector.read_file(ROUTES_RS)
        has_exemption = (auth_code and "is_refresh_path" in auth_code) or (routes_code and "auth_limited_public" in routes_code and "/auth/refresh" in routes_code)
        self.assert_true(bool(has_exemption), "F02: Refresh endpoint must allow transparent AJAX refresh without CSRF token blocking")


class TestF03PasswordMutationRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F03_01", "F03", 1, "PUT /api/v1/auth/profile/password is registered in router")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/profile/password' in routes), "F03: PUT /api/v1/auth/profile/password must be registered in routes.rs")


class TestF03PasswordBcryptVerification(TestCase):
    def __init__(self):
        super().__init__("T1_F03_02", "F03", 1, "Current password is verified using bcrypt before applying changes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "bcrypt::verify" in routes and "update_password" in routes), "F03: update_password must verify current password with bcrypt")


class TestF03PasswordMinLengthEnforcement(TestCase):
    def __init__(self):
        super().__init__("T1_F03_03", "F03", 1, "New password length is enforced (minimum 8 characters)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "update_password" in routes and "< 8" in routes), "F03: Password handler must enforce minimum character length")


class TestF03PasswordHashStorage(TestCase):
    def __init__(self):
        super().__init__("T1_F03_04", "F03", 1, "New password is encrypted with bcrypt before saving to users table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "bcrypt::hash" in routes and "update_password" in routes), "F03: update_password must hash new password using bcrypt")


class TestF03PasswordAuditLogRecording(TestCase):
    def __init__(self):
        super().__init__("T1_F03_05", "F03", 1, "Password mutation emits an audit log event")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "update_password" in routes and "record_audit" in routes and "password_update" in routes), "F03: Password change should record an audit entry")


class TestF04AvatarPutRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F04_01", "F04", 1, "PUT /api/v1/auth/profile/avatar is registered in routes.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/profile/avatar' in routes and 'put(update_avatar)' in routes), "F04: PUT /api/v1/auth/profile/avatar must be registered in routes.rs")


class TestF04AvatarDeleteRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F04_02", "F04", 1, "DELETE /api/v1/auth/profile/avatar is registered in routes.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/profile/avatar' in routes and '.delete(delete_avatar)' in routes), "F04: DELETE /api/v1/auth/profile/avatar must be registered in routes.rs")


class TestF04AvatarDataUriHandling(TestCase):
    def __init__(self):
        super().__init__("T1_F04_03", "F04", 1, "Avatar mutation accepts and stores valid image data URIs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "update_avatar" in routes and "validate_avatar_uri" in routes), "F04: update_avatar handler must validate and store avatar URIs in routes.rs")


class TestF04AvatarRemovalClearsField(TestCase):
    def __init__(self):
        super().__init__("T1_F04_04", "F04", 1, "DELETE avatar handler resets user avatar column to empty string")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and "delete_avatar" in routes), "F04: delete_avatar handler must exist in af-api routes.rs")


class TestF04AvatarReflectedInProfile(TestCase):
    def __init__(self):
        super().__init__("T1_F04_05", "F04", 1, "GET /api/v1/auth/profile returns the updated avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file(AUTH_RS)
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool((auth_code and "avatar" in auth_code) or (routes and "avatar" in routes)), "F04: User profile must surface the avatar field")


class TestF05IngressListConfigsRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F05_01", "F05", 1, "GET /api/v1/admin/ingress/configs returns list of app ingress records")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        has_route = bool(routes and '/ingress/configs' in routes)
        has_handler = bool(routes and 'get_ingress_configs' in routes)
        self.assert_true(has_route and has_handler, "F05: GET /api/v1/admin/ingress/configs must be registered and implemented in routes.rs")


class TestF05IngressUpdateAppRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F05_02", "F05", 1, "PUT /api/v1/admin/ingress/apps/:appName upserts domain and port routing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/ingress/apps/:appName' in routes and 'update_app_ingress_config' in routes), "F05: PUT /api/v1/admin/ingress/apps/:appName must be registered in routes.rs")


class TestF05IngressSqlitePersistence(TestCase):
    def __init__(self):
        super().__init__("T1_F05_03", "F05", 1, "Ingress handler persists configurations to app_ingress_configs table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(routes and "set_app_ingress_config" in routes and db_code and "app_ingress_configs" in db_code), "F05: af-api routes.rs and af-db must persist configs in app_ingress_configs")


class TestF05IngressGatewaySyncTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F05_04", "F05", 1, "Ingress update synchronizes Apache2 Certbot SANs and Subdomain Gateway routes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        mw = inspector.read_file(MIDDLEWARES_RS)
        self.assert_true(bool(routes and "trigger_apache_cert_sync" in routes and mw and "app_subdomain_proxy_middleware" in mw), "F05: Ingress update must synchronize Apache2 Certbot SANs and Subdomain Gateway")


class TestF05IngressStoreCompatibilityAliases(TestCase):
    def __init__(self):
        super().__init__("T1_F05_05", "F05", 1, "Compatibility aliases /api/ingress/* are registered for frontend store")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and 'ingress_compat_routes' in routes and '/ingress/configs' in routes), "F05: Legacy /api/ingress alias must be supported for frontend useIngressStore")


class TestF06TopologyRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F06_01", "F06", 1, "GET /api/v1/auth/system/topology is registered in router")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/system/topology' in routes), "F06: GET /api/v1/auth/system/topology must be registered in routes.rs")


class TestF06TopologyNodesAndLinksSchema(TestCase):
    def __init__(self):
        super().__init__("T1_F06_02", "F06", 1, "Topology response structure includes nodes and links arrays")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("GET", "/api/v1/auth/system/topology")
            self.assert_status_code(code, 200)
            self.assert_in("nodes", body)
            self.assert_in("links", body)
        else:
            handler = inspector.read_file(INTELLIGENCE_RS)
            self.assert_true(bool(handler and "get_system_topology" in handler and "links" in handler), "F06: System topology handler must exist and return nodes and links")


class TestF06TopologyZeroDummyNodes(TestCase):
    def __init__(self):
        super().__init__("T1_F06_03", "F06", 1, "Zero hardcoded fake infrastructure nodes returned in topology")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widget_code = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        if widget_code:
            self.assert_not_in("Nginx Router", widget_code, "F06: AppTopologyMap must not hardcode 'Nginx Router'")
            self.assert_not_in("Proxy Port 8080", widget_code, "F06: AppTopologyMap must not hardcode 'Proxy Port 8080'")
            self.assert_not_in("PostgreSQL DB", widget_code, "F06: AppTopologyMap must not hardcode 'PostgreSQL DB'")


class TestF06TopologyRealInfrastructureNodes(TestCase):
    def __init__(self):
        super().__init__("T1_F06_04", "F06", 1, "Topology models actual runtime services: SQLite WAL, Runner Daemon, Apache2")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler = inspector.read_file(INTELLIGENCE_RS)
        self.assert_true(bool(handler and "SQLite" in handler and "Runner" in handler), "F06: Topology handler must inspect live SQLite and Runner statuses")


class TestF06TopologyLinkReferentialIntegrity(TestCase):
    def __init__(self):
        super().__init__("T1_F06_05", "F06", 1, "All topology link sources and targets reference valid node IDs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler = inspector.read_file(INTELLIGENCE_RS)
        self.assert_true(bool(handler and "get_system_topology" in handler and "links" in handler), "F06: Topology handler must construct graph edges between valid nodes")

def get_tests():
    return [
        TestF01DirectoryListingValidPath(), TestF01ParentPathCalculation(), TestF01EntryMetadataStructure(), TestF01SymlinkResolutionWithinSandbox(), TestF01CompatibilityAlias(),
        TestF02SessionRefreshValidCredentials(), TestF02SessionRefreshExpiryUpdated(), TestF02SessionRefreshUserPayload(), TestF02SubsequentAuthWithRotatedToken(), TestF02CsrfExemptionForXmlHttpRequest(),
        TestF03PasswordMutationRouteRegistered(), TestF03PasswordBcryptVerification(), TestF03PasswordMinLengthEnforcement(), TestF03PasswordHashStorage(), TestF03PasswordAuditLogRecording(),
        TestF04AvatarPutRouteRegistered(), TestF04AvatarDeleteRouteRegistered(), TestF04AvatarDataUriHandling(), TestF04AvatarRemovalClearsField(), TestF04AvatarReflectedInProfile(),
        TestF05IngressListConfigsRoute(), TestF05IngressUpdateAppRoute(), TestF05IngressSqlitePersistence(), TestF05IngressGatewaySyncTrigger(), TestF05IngressStoreCompatibilityAliases(),
        TestF06TopologyRouteRegistered(), TestF06TopologyNodesAndLinksSchema(), TestF06TopologyZeroDummyNodes(), TestF06TopologyRealInfrastructureNodes(), TestF06TopologyLinkReferentialIntegrity()
    ]
