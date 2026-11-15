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

RUNNER_RS = "backend-rs/crates/af-runner/src/lib.rs"
SERVICES_LIB_RS = "backend-rs/crates/af-services/src/lib.rs"
WORKERS_RS = "backend-rs/crates/af-services/src/workers.rs"
MUTATORS_RS = "backend-rs/crates/af-services/src/mutators.rs"
CLUSTER_DAEMON_RS = "backend-rs/crates/af-services/src/cluster_daemon.rs"
DB_RS = "backend-rs/crates/af-db/src/lib.rs"
MODELS_RS = "backend-rs/crates/af-models/src/lib.rs"
MAIN_RS = "backend-rs/crates/af-api/src/main.rs"
ROUTES_RS = "backend-rs/crates/af-api/src/routes.rs"
AUTH_RS = "backend-rs/crates/af-api/src/auth.rs"
INTELLIGENCE_RS = "backend-rs/crates/af-api/src/intelligence.rs"


class TestF07RunnerSandboxEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_01", "F07", 1, "Runner socket implements POST /v1/sandbox for systemd sandboxing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "/v1/sandbox" in runner_code), "F07: af-runner must register /v1/sandbox endpoint")


class TestF07RunnerHostsEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_02", "F07", 1, "Runner socket implements POST /v1/hosts for atomic /etc/hosts updates")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "/v1/hosts" in runner_code), "F07: af-runner must register /v1/hosts endpoint")


class TestF07RunnerNetworkEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_03", "F07", 1, "Runner socket implements POST /v1/network for WireGuard and Tailscale")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "/v1/network" in runner_code), "F07: af-runner must register /v1/network endpoint")


class TestF07RunnerQuotaEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F07_04", "F07", 1, "Runner socket implements POST /v1/quota for setdisk disk quota management")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "/v1/quota" in runner_code), "F07: af-runner must register /v1/quota endpoint")


class TestF07RunnerSocketPermissions(TestCase):
    def __init__(self):
        super().__init__("T1_F07_05", "F07", 1, "Runner socket path defaults to /run/aetherflow/runner.sock with mode 0660")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "/run/aetherflow/runner.sock" in runner_code and "0o660" in runner_code), "F07: Socket path and file permissions must be 0660 root:aetherflow")


class TestF08AfHealMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_01", "F08", 1, "af-heal restarts services via runner socket without direct systemctl")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        workers_code = inspector.read_file(WORKERS_RS)
        services_code = inspector.read_file(SERVICES_LIB_RS)
        self.assert_true(bool(workers_code and "start_heal_worker" in workers_code and services_code and "dispatch_runner_systemctl_unix" in services_code), "F08: af-heal must route service management through privileged runner")
        self.assert_false(bool(workers_code and 'Command::new("systemctl")' in workers_code), "F08: workers.rs must not invoke raw systemctl directly")


class TestF08ArrInjectorMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_02", "F08", 1, "af-services core removes direct sudo systemctl calls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        services_code = inspector.read_file(SERVICES_LIB_RS)
        self.assert_false(bool(services_code and 'Command::new("sudo")' in services_code), "F08: af-services lib.rs must not invoke sudo directly")


class TestF08DeployOrchestratorMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_03", "F08", 1, "af-services dispatches lifecycle control through runner")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        services_code = inspector.read_file(SERVICES_LIB_RS)
        self.assert_true(bool(services_code and "dispatch_runner_systemctl_unix" in services_code), "F08: af-services must dispatch systemctl lifecycle actions via runner socket")


class TestF08SystemdSandboxMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_04", "F08", 1, "af-runner dispatches sandboxing mutations to /v1/sandbox")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "dispatch_sandbox_apply" in runner_code and "/v1/sandbox" in runner_code), "F08: af-runner must dispatch package sandboxing to runner socket")


class TestF08LocalDnsAndQuotaMigrated(TestCase):
    def __init__(self):
        super().__init__("T1_F08_05", "F08", 1, "Local DNS mutator and quota dispatcher route mutations via runner")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        mutators_code = inspector.read_file(MUTATORS_RS)
        runner_code = inspector.read_file(RUNNER_RS)
        dns_ok = bool(mutators_code and "run_privileged_hosts_command" in mutators_code and runner_code and "/v1/hosts" in runner_code)
        quota_ok = bool(runner_code and "dispatch_quota_set" in runner_code and "/v1/quota" in runner_code)
        self.assert_true(dns_ok and quota_ok, "F08: DNS mutators and quota dispatcher must dispatch via runner socket")


class TestF09Migration17Exists(TestCase):
    def __init__(self):
        super().__init__("T1_F09_01", "F09", 1, "Migration 17 is defined in backend-rs/crates/af-db/src/lib.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "17," in db_code and "app_ingress_configs" in db_code), "F09: af-db lib.rs must declare migration 17 for app_ingress_configs")


class TestF09Migration17TableSchema(TestCase):
    def __init__(self):
        super().__init__("T1_F09_02", "F09", 1, "Migration 17 creates app_ingress_configs table with correct columns")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "app_ingress_configs" in db_code and "public_domain" in db_code and "listen_port" in db_code), "F09: Migration 17 must define app_ingress_configs with domain and port columns")


class TestF09Migration17PrimaryKey(TestCase):
    def __init__(self):
        super().__init__("T1_F09_03", "F09", 1, "app_name column is PRIMARY KEY in app_ingress_configs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "app_name TEXT PRIMARY KEY" in db_code), "F09: app_ingress_configs table must have app_name as PRIMARY KEY")


class TestF09Migration17RustModel(TestCase):
    def __init__(self):
        super().__init__("T1_F09_04", "F09", 1, "Rust struct AppIngressConfig exists in af-models")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        models_code = inspector.read_file(MODELS_RS) or inspector.read_file(DB_RS)
        self.assert_true(bool(models_code and "AppIngressConfig" in models_code), "F09: AppIngressConfig Rust struct model must be defined")


class TestF09Migration17Idempotency(TestCase):
    def __init__(self):
        super().__init__("T1_F09_05", "F09", 1, "CREATE TABLE IF NOT EXISTS ensures idempotent migration runs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "CREATE TABLE IF NOT EXISTS app_ingress_configs" in db_code), "F09: Migration 17 must use CREATE TABLE IF NOT EXISTS")


class TestF10ClusterManagerInitInMain(TestCase):
    def __init__(self):
        super().__init__("T1_F10_01", "F10", 1, "backend-rs/crates/af-api/src/main.rs initializes cluster runtime cleanly before serving")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        main_code = inspector.read_file(MAIN_RS)
        self.assert_true(bool(main_code and "start_cluster_runtime" in main_code), "F10: af-api main.rs must invoke start_cluster_runtime")


class TestF10ClusterManagerNonNilGuard(TestCase):
    def __init__(self):
        super().__init__("T1_F10_02", "F10", 1, "Cluster runtime and handlers respond safely")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        intel_code = inspector.read_file(INTELLIGENCE_RS)
        cluster_code = inspector.read_file(CLUSTER_DAEMON_RS)
        self.assert_true(bool(intel_code and "get_cluster_nodes" in intel_code and cluster_code and "start_cluster_runtime" in cluster_code), "F10: Cluster runtime and node handlers must be present")


class TestF10ClusterListNodesRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_03", "F10", 1, "GET /api/v1/admin/cluster/nodes returns node list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/cluster/nodes' in routes), "F10: GET /api/v1/admin/cluster/nodes must be registered")


class TestF10ClusterEnrollRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_04", "F10", 1, "POST /api/v1/admin/cluster/enroll generates worker join token")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(routes and '/cluster/enroll' in routes), "F10: POST /api/v1/admin/cluster/enroll must be registered")


class TestF10ClusterMetricsRoute(TestCase):
    def __init__(self):
        super().__init__("T1_F10_05", "F10", 1, "GET /api/v1/admin/cluster/nodes/:id/metrics returns node telemetry")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
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


class TestF11PathSelectorTargetsBackendEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F11_04", "F11", 1, "PathSelector.tsx targets authenticated Rust backend filesystem endpoint")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        selector_code = inspector.read_file("frontend/src/components/ui/PathSelector.tsx")
        self.assert_true(bool(selector_code and ("/api/fs" in selector_code or "/api/v1/auth/fs" in selector_code)), "F11: PathSelector must target Rust filesystem browser")


class TestF11ZeroNodeFsImportsInFrontend(TestCase):
    def __init__(self):
        super().__init__("T1_F11_05", "F11", 1, "Zero Node.js fs/promises imports across frontend/src/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        src_dir = os.path.join(inspector.root, "frontend/src")
        for r, _, files in os.walk(src_dir):
            for f in files:
                if f.endswith((".ts", ".tsx")) and not f.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")):
                    with open(os.path.join(r, f), "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                        self.assert_not_in("from 'fs'", content, f"Node fs import found in {f}")
                        self.assert_not_in("from 'fs/promises'", content, f"Node fs/promises import found in {f}")


class TestF12FsHandlerUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_01", "F12", 1, "Unit tests exist for Rust directory/file browser handlers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        has_tests = inspector.file_exists("backend-rs/crates/af-api/src/mcbrowser/actions_tests.rs") and bool(inspector.read_file(ROUTES_RS) and "#[tokio::test]" in inspector.read_file(ROUTES_RS))
        self.assert_true(has_tests, "F12: Unit tests for file/browser handlers must exist in af-api")


class TestF12AuthRefreshUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_02", "F12", 1, "Unit tests exist for auth session refresh and password mutation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        auth_code = inspector.read_file(AUTH_RS)
        routes_code = inspector.read_file(ROUTES_RS)
        has_tests = bool(auth_code and "#[test]" in auth_code and routes_code and "wrong_current_password_is_forbidden_without_expiring_session" in routes_code)
        self.assert_true(has_tests, "F12: Unit tests for auth refresh and password must exist in af-api")


class TestF12IngressCrudUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_03", "F12", 1, "Unit tests exist for ingress CRUD and SQLite persistence")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes_code = inspector.read_file(ROUTES_RS)
        has_tests = bool(routes_code and "test_resolve_patched_ingress_config_preserves_omitted_fields_and_rejects_port_change" in routes_code)
        self.assert_true(has_tests, "F12: Unit tests for ingress CRUD must exist in af-api routes.rs")


class TestF12RunnerSocketExtensionsUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_04", "F12", 1, "Unit tests exist for privileged runner socket endpoints")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_code = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner_code and "test_handle_sandbox_and_quota_graceful_fallback" in runner_code), "F12: af-runner lib.rs must test runner socket endpoints")


class TestF12ClusterUnitTestsExist(TestCase):
    def __init__(self):
        super().__init__("T1_F12_05", "F12", 1, "Unit tests exist for cluster runtime and node telemetry")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        intel_code = inspector.read_file(INTELLIGENCE_RS)
        has_cluster_tests = bool(intel_code and "get_worker_metrics" in intel_code and "#[tokio::test]" in intel_code)
        self.assert_true(has_cluster_tests, "F12: Cluster unit tests must be present in af-api intelligence.rs")


def get_tests():
    return [
        TestF07RunnerSandboxEndpoint(), TestF07RunnerHostsEndpoint(), TestF07RunnerNetworkEndpoint(), TestF07RunnerQuotaEndpoint(), TestF07RunnerSocketPermissions(),
        TestF08AfHealMigrated(), TestF08ArrInjectorMigrated(), TestF08DeployOrchestratorMigrated(), TestF08SystemdSandboxMigrated(), TestF08LocalDnsAndQuotaMigrated(),
        TestF09Migration17Exists(), TestF09Migration17TableSchema(), TestF09Migration17PrimaryKey(), TestF09Migration17RustModel(), TestF09Migration17Idempotency(),
        TestF10ClusterManagerInitInMain(), TestF10ClusterManagerNonNilGuard(), TestF10ClusterListNodesRoute(), TestF10ClusterEnrollRoute(), TestF10ClusterMetricsRoute(),
        TestF11NextJsFsRouteDeleted(), TestF11NextStaticExportConfigured(), TestF11NoDynamicAppApiRoutesRemaining(), TestF11PathSelectorTargetsBackendEndpoint(), TestF11ZeroNodeFsImportsInFrontend(),
        TestF12FsHandlerUnitTestsExist(), TestF12AuthRefreshUnitTestsExist(), TestF12IngressCrudUnitTestsExist(), TestF12RunnerSocketExtensionsUnitTestsExist(), TestF12ClusterUnitTestsExist()
    ]
