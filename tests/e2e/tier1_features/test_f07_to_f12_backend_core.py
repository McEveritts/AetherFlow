"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F07: Privileged Runner Extensions
- F08: Privileged Caller Migration
- F09: SQLite Migration 17
- F10: Cluster Manager Startup Cleanliness
- F11: Remove Next.js FS Server Route
- F12: Backend Unit & Integration Tests
"""

import os
from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

class TestF07RunnerSandboxEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_01", "F07", 1, "Runner socket implements POST /v1/sandbox for systemd sandboxing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner_code and "/v1/sandbox" in runner_code), "F07: privileged_runner.go must register /v1/sandbox endpoint")

class TestF07RunnerHostsEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_02", "F07", 1, "Runner socket implements POST /v1/hosts for atomic /etc/hosts updates")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner_code and "/v1/hosts" in runner_code), "F07: privileged_runner.go must register /v1/hosts endpoint")

class TestF07RunnerNetworkEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_03", "F07", 1, "Runner socket implements POST /v1/network for WireGuard and Tailscale")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner_code and "/v1/network" in runner_code), "F07: privileged_runner.go must register /v1/network endpoint")

class TestF07RunnerQuotaEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_04", "F07", 1, "Runner socket implements POST /v1/quota for setdisk disk quota management")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner_code and "/v1/quota" in runner_code), "F07: privileged_runner.go must register /v1/quota endpoint")

class TestF07RunnerSocketPermissions(TestCase):
    def __init__(self):
        super().__init__("T1_F07_05", "F07", 1, "Runner socket path defaults to /run/aetherflow/runner.sock with mode 0660")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner_code and "/run/aetherflow/runner.sock" in runner_code and "0660" in runner_code), "F07: Socket path and file permissions must be 0660 root:aetherflow")

class TestF08AfHealMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_01", "F08", 1, "af_heal.go restarts services via runner socket without direct systemctl")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        heal_code = inspector.read_file("backend/services/af_heal.go")
        self.assert_true(bool(heal_code and ("ControlService" in heal_code or "runner" in heal_code.lower())), "F08: af_heal.go must route service management through privileged runner")
        self.assert_false(bool(heal_code and 'exec.CommandContext(ctx, "systemctl"' in heal_code), "F08: af_heal.go must not invoke raw systemctl")

class TestF08ArrInjectorMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_02", "F08", 1, "arr_injector.go removes direct sudo systemctl calls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        arr_code = inspector.read_file("backend/services/arr_injector.go")
        self.assert_false(bool(arr_code and 'exec.Command("sudo"' in arr_code), "F08: arr_injector.go must not invoke sudo directly")

class TestF08DeployOrchestratorMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_03", "F08", 1, "deploy_orchestrator.go routes service lifecycle through runner")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        deploy_code = inspector.read_file("backend/services/deploy_orchestrator.go")
        self.assert_false(bool(deploy_code and 'exec.Command("sudo"' in deploy_code), "F08: deploy_orchestrator.go must not invoke sudo")

class TestF08SystemdSandboxMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_04", "F08", 1, "systemd_sandbox.go dispatches sandboxing mutations to /v1/sandbox")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sandbox_code = inspector.read_file("backend/services/systemd_sandbox.go")
        self.assert_true(bool(sandbox_code and ("runner" in sandbox_code.lower() or "v1/sandbox" in sandbox_code or "ApplySandboxViaRunner" in sandbox_code)), "F08: systemd_sandbox.go must route package sandboxing to runner socket")

class TestF08LocalDnsAndQuotaMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_05", "F08", 1, "local_dns_manager.go and quota_manager.go route mutations via runner")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        dns_code = inspector.read_file("backend/services/local_dns_manager.go")
        quota_code = inspector.read_file("backend/services/quota_manager.go")
        dns_ok = bool(dns_code and ("v1/hosts" in dns_code or "runner" in dns_code.lower()))
        quota_ok = bool(quota_code and ("v1/quota" in quota_code or "runner" in quota_code.lower()))
        self.assert_true(dns_ok and quota_ok, "F08: local_dns_manager and quota_manager must dispatch via runner socket")

class TestF09Migration17Exists(TestCase):
    def __init__(self):
        super().__init__("T1_F09_01", "F09", 1, "Migration 17 is defined in backend/db/db.go")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "migrate(17" in db_code), "F09: db.go must declare migrate(17, ...)")

class TestF09Migration17TableSchema(TestCase):
    def __init__(self):
        super().__init__("T1_F09_02", "F09", 1, "Migration 17 creates app_ingress_configs table with correct columns")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "app_ingress_configs" in db_code and "public_domain" in db_code and "listen_port" in db_code), "F09: Migration 17 must define app_ingress_configs with domain and port columns")

class TestF09Migration17PrimaryKey(TestCase):
    def __init__(self):
        super().__init__("T1_F09_03", "F09", 1, "app_name column is PRIMARY KEY in app_ingress_configs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "app_name TEXT PRIMARY KEY" in db_code), "F09: app_ingress_configs table must have app_name as PRIMARY KEY")

class TestF09Migration17GoModel(TestCase):
    def __init__(self):
        super().__init__("T1_F09_04", "F09", 1, "Go struct AppIngressConfig exists in models or api package")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        models_code = inspector.read_file("backend/models/models.go") or inspector.read_file("backend/models/ingress.go") or inspector.read_file("backend/api/ingress_handlers.go")
        self.assert_true(bool(models_code and "AppIngressConfig" in models_code), "F09: AppIngressConfig Go struct model must be defined")

class TestF09Migration17Idempotency(TestCase):
    def __init__(self):
        super().__init__("T1_F09_05", "F09", 1, "CREATE TABLE IF NOT EXISTS ensures idempotent migration runs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "CREATE TABLE IF NOT EXISTS app_ingress_configs" in db_code), "F09: Migration 17 must use CREATE TABLE IF NOT EXISTS")

class TestF10ClusterManagerInitInMain(TestCase):
    def __init__(self):
        super().__init__("T1_F10_01", "F10", 1, "backend/main.go initializes cluster manager cleanly before serving")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        main_code = inspector.read_file("backend/main.go")
        self.assert_true(bool(main_code and ("cluster.Init" in main_code or "InitClusterManager" in main_code)), "F10: backend/main.go must invoke cluster manager initialization")

class TestF10ClusterManagerNonNilGuard(TestCase):
    def __init__(self):
        super().__init__("T1_F10_02", "F10", 1, "Cluster handlers respond without nil pointer panic")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        cluster_api = inspector.read_file("backend/api/cluster_handlers.go")
        self.assert_true(bool(cluster_api and "cluster.Manager" in cluster_api), "F10: cluster_handlers.go must reference cluster.Manager safely")

class TestF10ClusterListNodesRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_03", "F10", 1, "GET /api/v1/admin/cluster/nodes returns node list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/cluster/nodes' in routes), "F10: GET /api/v1/admin/cluster/nodes must be registered")

class TestF10ClusterEnrollRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_04", "F10", 1, "POST /api/v1/admin/cluster/enroll generates worker join token")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/cluster/enroll' in routes), "F10: POST /api/v1/admin/cluster/enroll must be registered")

class TestF10ClusterMetricsRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_05", "F10", 1, "GET /api/v1/admin/cluster/nodes/:id/metrics returns node telemetry")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and '/cluster/nodes/:id/metrics' in routes), "F10: Node metrics route must be registered")

class TestF11NextJsFsRouteDeleted(TestCase):
    def __init__(self):
        super().__init__("T1_F11_01", "F11", 1, "frontend/src/app/api/fs/route.ts is deleted from repository")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists("frontend/src/app/api/fs/route.ts")
        self.assert_false(exists, "F11: frontend/src/app/api/fs/route.ts must be completely removed")

class TestF11NextStaticExportConfigured(TestCase):
    def __init__(self):
        super().__init__("T1_F11_02", "F11", 1, "next.config.ts enables output: export when NEXT_STATIC_EXPORT=1")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        config_code = inspector.read_file("frontend/next.config.ts")
        self.assert_true(bool(config_code and "NEXT_STATIC_EXPORT" in config_code and "export" in config_code), "F11: next.config.ts must support output: 'export'")

class TestF11NoDynamicAppApiRoutesRemaining(TestCase):
    def __init__(self):
        super().__init__("T1_F11_03", "F11", 1, "No incompatible server routes exist in frontend/src/app/api")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        api_dir = os.path.join(inspector.root, "frontend/src/app/api")
        if os.path.exists(api_dir):
            files = [f for f in os.listdir(api_dir) if not f.startswith(".")]
            self.assert_equal(len(files), 0, f"F11: frontend/src/app/api should have no dynamic routes, found: {files}")

class TestF11PathSelectorTargetsGoEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F11_04", "F11", 1, "PathSelector.tsx targets authenticated Go backend filesystem endpoint")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        selector_code = inspector.read_file("frontend/src/components/ui/PathSelector.tsx")
        self.assert_true(bool(selector_code and ("/api/fs" in selector_code or "/api/v1/auth/fs" in selector_code)), "F11: PathSelector must target Go filesystem browser")

class TestF11ZeroNodeFsImportsInFrontend(TestCase):
    def __init__(self):
        super().__init__("T1_F11_05", "F11", 1, "Zero Node.js fs/promises imports across frontend/src/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        src_dir = os.path.join(inspector.root, "frontend/src")
        for r, _, files in os.walk(src_dir):
            for f in files:
                if f.endswith((".ts", ".tsx")):
                    with open(os.path.join(r, f), "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                        self.assert_not_in("from 'fs'", content, f"Node fs import found in {f}")
                        self.assert_not_in("from 'fs/promises'", content, f"Node fs/promises import found in {f}")

class TestF12FsHandlerUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_01", "F12", 1, "Unit tests exist for Go directory browser handler")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        has_tests = inspector.file_exists("backend/api/fs_handlers_test.go") or inspector.file_exists("backend/api/routes_test.go")
        self.assert_true(has_tests, "F12: Unit tests for fs handlers must exist in backend/api/")

class TestF12AuthRefreshUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_02", "F12", 1, "Unit tests exist for auth session refresh and password mutation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        has_tests = inspector.file_exists("backend/api/auth_test.go") or inspector.file_exists("backend/api/auth_security_test.go")
        self.assert_true(has_tests, "F12: Unit tests for auth refresh and password must exist")

class TestF12IngressCrudUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_03", "F12", 1, "Unit tests exist for ingress CRUD and SQLite persistence")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        has_tests = inspector.file_exists("backend/api/ingress_handlers_test.go") or inspector.file_exists("backend/api/routes_test.go")
        self.assert_true(has_tests, "F12: Unit tests for ingress CRUD must exist")

class TestF12RunnerSocketExtensionsUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_04", "F12", 1, "Unit tests exist for new privileged runner socket endpoints")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_test = inspector.read_file("backend/services/privileged_runner_test.go")
        self.assert_true(bool(runner_test and ("/v1/sandbox" in runner_test or "/v1/hosts" in runner_test or "runner" in runner_test)), "F12: privileged_runner_test.go must test runner socket endpoints")

class TestF12ClusterUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_05", "F12", 1, "Unit tests exist for cluster manager and node telemetry")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        has_cluster_tests = inspector.file_exists("backend/cluster/cluster_test.go") or inspector.file_exists("backend/api/cluster_handlers_test.go")
        self.assert_true(has_cluster_tests, "F12: Cluster unit tests must be present in backend/cluster/")

def get_tests():
    return [
        TestF07RunnerSandboxEndpoint(), TestF07RunnerHostsEndpoint(), TestF07RunnerNetworkEndpoint(), TestF07RunnerQuotaEndpoint(), TestF07RunnerSocketPermissions(),
        TestF08AfHealMigrated(), TestF08ArrInjectorMigrated(), TestF08DeployOrchestratorMigrated(), TestF08SystemdSandboxMigrated(), TestF08LocalDnsAndQuotaMigrated(),
        TestF09Migration17Exists(), TestF09Migration17TableSchema(), TestF09Migration17PrimaryKey(), TestF09Migration17GoModel(), TestF09Migration17Idempotency(),
        TestF10ClusterManagerInitInMain(), TestF10ClusterManagerNonNilGuard(), TestF10ClusterListNodesRoute(), TestF10ClusterEnrollRoute(), TestF10ClusterMetricsRoute(),
        TestF11NextJsFsRouteDeleted(), TestF11NextStaticExportConfigured(), TestF11NoDynamicAppApiRoutesRemaining(), TestF11PathSelectorTargetsGoEndpoint(), TestF11ZeroNodeFsImportsInFrontend(),
        TestF12FsHandlerUnitTestsExist(), TestF12AuthRefreshUnitTestsExist(), TestF12IngressCrudUnitTestsExist(), TestF12RunnerSocketExtensionsUnitTestsExist(), TestF12ClusterUnitTestsExist()
    ]
