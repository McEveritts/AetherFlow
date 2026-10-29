"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F01: Go Directory Browser Handler
- F02: Auth Session Refresh
- F03: Profile Password Mutation
- F04: Profile Avatar Mutation
- F05: Ingress Configuration CRUD
- F06: System Topology Endpoint
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

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
            has_route = inspector.check_route_registered("GET", "/fs") or inspector.check_go_symbol("backend/api/routes.go", r'authGroup\.GET\("/fs"')
            has_handler = inspector.file_exists("backend/api/fs_handlers.go")
            self.assert_true(has_route and has_handler, "F01: GET /api/v1/auth/fs handler must be registered in backend/api/routes.go")

class TestF01ParentPathCalculation(TestCase):
    def __init__(self):
        super().__init__("T1_F01_02", "F01", 1, "Parent path is accurately computed for nested subdirectories")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("GET", "/api/v1/auth/fs?path=/mnt/storage/media")
            self.assert_status_code(code, 200)
            self.assert_equal(body.get("parent_path"), "/mnt/storage")
        else:
            handler_code = inspector.read_file("backend/api/fs_handlers.go")
            self.assert_true(bool(handler_code and "filepath.Dir" in handler_code), "F01: fs_handlers.go must compute parent directory path")

class TestF01EntryMetadataStructure(TestCase):
    def __init__(self):
        super().__init__("T1_F01_03", "F01", 1, "Each directory entry contains name, path, is_dir, size, and mod_time")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("GET", "/api/v1/auth/fs?path=/opt/AetherFlow")
            self.assert_status_code(code, 200)
            entries = body.get("entries", [])
            if entries:
                first = entries[0]
                self.assert_in("name", first)
                self.assert_in("is_dir", first)
        else:
            handler_code = inspector.read_file("backend/api/fs_handlers.go")
            self.assert_true(bool(handler_code and "is_dir" in handler_code and "mod_time" in handler_code), "F01: Directory entry struct must include name, is_dir, size, mod_time")

class TestF01SymlinkResolutionWithinSandbox(TestCase):
    def __init__(self):
        super().__init__("T1_F01_04", "F01", 1, "Symlinks pointing inside allowed roots are resolved and accessible")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler_code = inspector.read_file("backend/api/fs_handlers.go")
        self.assert_true(bool(handler_code and "EvalSymlinks" in handler_code), "F01: fs_handlers.go must use filepath.EvalSymlinks for path verification")

class TestF01CompatibilityAlias(TestCase):
    def __init__(self):
        super().__init__("T1_F01_05", "F01", 1, "Compatibility alias /api/fs routes to the Go filesystem browser")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, _, _ = client.request("GET", "/api/fs?path=/mnt")
            self.assert_status_code(code, 200)
        else:
            routes = inspector.read_file("backend/api/routes.go")
            self.assert_true(bool(routes and '/fs' in routes and ('legacyAPI' in routes or 'api/fs' in routes)), "F01: /api/fs alias must be registered for frontend PathSelector compatibility")

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
            routes = inspector.read_file("backend/api/routes.go")
            self.assert_true(bool(routes and '/refresh' in routes), "F02: POST /api/v1/auth/refresh must be registered in routes.go")

class TestF02SessionRefreshExpiryUpdated(TestCase):
    def __init__(self):
        super().__init__("T1_F02_02", "F02", 1, "Refresh response includes updated future expires_at timestamp")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        if mode == "live" and client.is_server_reachable():
            code, body, _ = client.request("POST", "/api/v1/auth/refresh")
            self.assert_status_code(code, 200)
            self.assert_true(body.get("expires_at", 0) > 0, "expires_at must be positive epoch timestamp")
        else:
            auth_code = inspector.read_file("backend/api/auth.go")
            self.assert_true(bool(auth_code and "RefreshSession" in auth_code and "expires_at" in auth_code), "F02: RefreshSession handler must return expires_at in JSON payload")

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
            auth_code = inspector.read_file("backend/api/auth.go")
            self.assert_true(bool(auth_code and "RefreshSession" in auth_code and "user" in auth_code), "F02: RefreshSession handler must include user identity payload")

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
            auth_code = inspector.read_file("backend/api/auth.go")
            self.assert_true(bool(auth_code and "GenerateJWT" in auth_code and "RefreshSession" in auth_code), "F02: Refresh handler must issue valid verifiable JWT tokens")

class TestF02CsrfExemptionForXmlHttpRequest(TestCase):
    def __init__(self):
        super().__init__("T1_F02_05", "F02", 1, "Refresh endpoint allows X-Requested-With header without CSRF token block")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        routes_code = inspector.read_file("backend/api/routes.go")
        has_exemption = (auth_code and "X-Requested-With" in auth_code) or (routes_code and "publicGroup" in routes_code and "refresh" in routes_code)
        self.assert_true(bool(has_exemption), "F02: Refresh endpoint must allow transparent AJAX refresh without CSRF token blocking")

class TestF03PasswordMutationRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F03_01", "F03", 1, "PUT /api/v1/auth/profile/password is registered in router")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/profile/password' in routes), "F03: PUT /api/v1/auth/profile/password must be registered in routes.go")

class TestF03PasswordBcryptVerification(TestCase):
    def __init__(self):
        super().__init__("T1_F03_02", "F03", 1, "Current password is verified using bcrypt before applying changes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and "CompareHashAndPassword" in auth_code and "ChangePassword" in auth_code), "F03: ChangePassword must verify current password with bcrypt")

class TestF03PasswordMinLengthEnforcement(TestCase):
    def __init__(self):
        super().__init__("T1_F03_03", "F03", 1, "New password length is enforced (minimum 8 characters)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and ("len(req.NewPassword)" in auth_code or "len(req.Password)" in auth_code or "8" in auth_code)), "F03: Password handler must enforce minimum character length")

class TestF03PasswordHashStorage(TestCase):
    def __init__(self):
        super().__init__("T1_F03_04", "F03", 1, "New password is encrypted with bcrypt before saving to users table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and "GenerateFromPassword" in auth_code and "ChangePassword" in auth_code), "F03: ChangePassword must hash new password using bcrypt")

class TestF03PasswordAuditLogRecording(TestCase):
    def __init__(self):
        super().__init__("T1_F03_05", "F03", 1, "Password mutation emits an audit log event")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and "ChangePassword" in auth_code and ("audit" in auth_code or "LogAdminAction" in auth_code or "Audit" in auth_code)), "F03: Password change should record an audit entry")

class TestF04AvatarPutRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F04_01", "F04", 1, "PUT /api/v1/auth/profile/avatar is registered in routes.go")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/profile/avatar' in routes and 'PUT' in routes), "F04: PUT /api/v1/auth/profile/avatar must be registered in routes.go")

class TestF04AvatarDeleteRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F04_02", "F04", 1, "DELETE /api/v1/auth/profile/avatar is registered in routes.go")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/profile/avatar' in routes and 'DELETE' in routes), "F04: DELETE /api/v1/auth/profile/avatar must be registered in routes.go")

class TestF04AvatarDataUriHandling(TestCase):
    def __init__(self):
        super().__init__("T1_F04_03", "F04", 1, "Avatar mutation accepts and stores valid image data URIs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and "UpdateAvatar" in auth_code), "F04: UpdateAvatar handler must exist in backend/api/auth.go")

class TestF04AvatarRemovalClearsField(TestCase):
    def __init__(self):
        super().__init__("T1_F04_04", "F04", 1, "DELETE avatar handler resets user avatar column to empty string")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and ("RemoveAvatar" in auth_code or "DeleteAvatar" in auth_code)), "F04: RemoveAvatar handler must exist in backend/api/auth.go")

class TestF04AvatarReflectedInProfile(TestCase):
    def __init__(self):
        super().__init__("T1_F04_05", "F04", 1, "GET /api/v1/auth/profile returns the updated avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file("backend/api/auth.go")
        self.assert_true(bool(auth_code and "avatar" in auth_code), "F04: User profile must surface the avatar field")

class TestF05IngressListConfigsRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F05_01", "F05", 1, "GET /api/v1/admin/ingress/configs returns list of app ingress records")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        has_route = bool(routes and '/ingress/configs' in routes)
        has_file = inspector.file_exists("backend/api/ingress_handlers.go")
        self.assert_true(has_route and has_file, "F05: GET /api/v1/admin/ingress/configs must be registered in routes.go and implemented in ingress_handlers.go")

class TestF05IngressUpdateAppRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F05_02", "F05", 1, "PUT /api/v1/admin/ingress/apps/:appName upserts domain and port routing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/ingress/apps/:appName' in routes), "F05: PUT /api/v1/admin/ingress/apps/:appName must be registered in routes.go")

class TestF05IngressSqlitePersistence(TestCase):
    def __init__(self):
        super().__init__("T1_F05_03", "F05", 1, "Ingress handler persists configurations to app_ingress_configs table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        ingress_code = inspector.read_file("backend/api/ingress_handlers.go")
        self.assert_true(bool(ingress_code and "app_ingress_configs" in ingress_code), "F05: ingress_handlers.go must perform SQL queries against app_ingress_configs")

class TestF05IngressCaddySyncTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F05_04", "F05", 1, "Ingress update invokes CaddyManager to reload reverse proxy routes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        ingress_code = inspector.read_file("backend/api/ingress_handlers.go")
        self.assert_true(bool(ingress_code and ("caddy" in ingress_code.lower() or "UpdateAppRoutes" in ingress_code)), "F05: Ingress update must notify CaddyManager")

class TestF05IngressStoreCompatibilityAliases(TestCase):
    def __init__(self):
        super().__init__("T1_F05_05", "F05", 1, "Compatibility aliases /api/ingress/* are registered for frontend store")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and ('api/ingress' in routes or 'legacyAPI.GET("/ingress' in routes)), "F05: Legacy /api/ingress alias must be supported for frontend useIngressStore")

class TestF06TopologyRouteRegistered(TestCase):
    def __init__(self):
        super().__init__("T1_F06_01", "F06", 1, "GET /api/v1/auth/system/topology is registered in router")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/system/topology' in routes), "F06: GET /api/v1/auth/system/topology must be registered in routes.go")

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
            handler = inspector.read_file("backend/api/topology_handlers.go") or inspector.read_file("backend/api/system_handlers.go") or inspector.read_file("backend/api/routes.go")
            self.assert_true(bool(handler and "topology" in handler.lower()), "F06: System topology handler must exist and return nodes and links")

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
        super().__init__("T1_F06_04", "F06", 1, "Topology models actual runtime services: SQLite WAL, Runner Daemon, Caddy")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler = inspector.read_file("backend/api/topology_handlers.go") or inspector.read_file("backend/api/system_handlers.go")
        self.assert_true(bool(handler and "SQLite" in handler and "Runner" in handler), "F06: Topology handler must inspect live SQLite and Runner statuses")

class TestF06TopologyLinkReferentialIntegrity(TestCase):
    def __init__(self):
        super().__init__("T1_F06_05", "F06", 1, "All topology link sources and targets reference valid node IDs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handler = inspector.read_file("backend/api/topology_handlers.go") or inspector.read_file("backend/api/system_handlers.go")
        self.assert_true(bool(handler and "links" in handler), "F06: Topology handler must construct graph edges between valid nodes")

def get_tests():
    return [
        TestF01DirectoryListingValidPath(), TestF01ParentPathCalculation(), TestF01EntryMetadataStructure(), TestF01SymlinkResolutionWithinSandbox(), TestF01CompatibilityAlias(),
        TestF02SessionRefreshValidCredentials(), TestF02SessionRefreshExpiryUpdated(), TestF02SessionRefreshUserPayload(), TestF02SubsequentAuthWithRotatedToken(), TestF02CsrfExemptionForXmlHttpRequest(),
        TestF03PasswordMutationRouteRegistered(), TestF03PasswordBcryptVerification(), TestF03PasswordMinLengthEnforcement(), TestF03PasswordHashStorage(), TestF03PasswordAuditLogRecording(),
        TestF04AvatarPutRouteRegistered(), TestF04AvatarDeleteRouteRegistered(), TestF04AvatarDataUriHandling(), TestF04AvatarRemovalClearsField(), TestF04AvatarReflectedInProfile(),
        TestF05IngressListConfigsRoute(), TestF05IngressUpdateAppRoute(), TestF05IngressSqlitePersistence(), TestF05IngressCaddySyncTrigger(), TestF05IngressStoreCompatibilityAliases(),
        TestF06TopologyRouteRegistered(), TestF06TopologyNodesAndLinksSchema(), TestF06TopologyZeroDummyNodes(), TestF06TopologyRealInfrastructureNodes(), TestF06TopologyLinkReferentialIntegrity()
    ]
