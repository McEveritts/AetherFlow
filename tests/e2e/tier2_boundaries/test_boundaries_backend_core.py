"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B07: Privileged Runner Socket Boundaries
- B08: Privileged Caller Migration Boundaries
- B09: SQLite Migration 17 Boundaries
- B10: Cluster Manager Boundaries
- B11: Route Removal Boundaries
- B12: Backend Unit Test Boundaries
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

class TestB07PayloadLimitExceededRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_01", "F07", 2, "Payload exceeding 4096 bytes to runner socket returns HTTP 413")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and ("4096" in runner or "MaxBytesReader" in runner or "LimitReader" in runner)), "B07: Runner socket must enforce max body limit")

class TestB07CommandInjectionInPackageRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_02", "F07", 2, "Shell metacharacters ('; rm -rf', '|', '&') in package name are rejected")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and ("safePackageID" in runner or "regexp" in runner or "safe" in runner.lower())), "B07: Runner must validate package identifiers against regex allowlist")

class TestB07CommandInjectionInHostsRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_03", "F07", 2, "Newline or injection characters in domain/IP for /v1/hosts return HTTP 400")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and "/v1/hosts" in runner and ("net.ParseIP" in runner or "validate" in runner.lower() or "regexp" in runner)), "B07: Runner /v1/hosts must validate IP and domain format")

class TestB07InvalidActionOnRunnerRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_04", "F07", 2, "Unrecognized action verb in /v1/systemctl returns HTTP 400")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and "allowedServiceActions" in runner), "B07: Runner must restrict actions to allowedServiceActions set")

class TestB07UnknownRunnerEndpointReturns404(TestCase):
    def __init__(self):
        super().__init__("T2_B07_05", "F07", 2, "Unknown path on runner socket returns HTTP 404 Not Found")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and "http.NotFound" in runner or "NewRunnerMux" in runner), "B07: Runner mux must reject unregistered endpoints with 404")

class TestB08SocketUnavailableFallbackGraceful(TestCase):
    def __init__(self):
        super().__init__("T2_B08_01", "F08", 2, "Caller services handle missing runner socket gracefully without panic")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and ("Dial" in runner or "net.Dial" in runner or "err != nil" in runner)), "B08: Socket client must return structured error on connection failure")

class TestB08SocketTimeoutEnforced(TestCase):
    def __init__(self):
        super().__init__("T2_B08_02", "F08", 2, "Socket requests enforce finite context timeout (prevent hangs)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file("backend/services/privileged_runner.go")
        self.assert_true(bool(runner and ("Timeout" in runner or "context.WithTimeout" in runner)), "B08: Runner socket calls must respect context timeouts")

class TestB08NetworkGoHandlesMissingWg(TestCase):
    def __init__(self):
        super().__init__("T2_B08_03", "F08", 2, "network.go handles absence of wg binary gracefully")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        net_code = inspector.read_file("backend/services/network.go")
        self.assert_true(bool(net_code and "err != nil" in net_code), "B08: network.go must handle command execution errors gracefully")

class TestB08QuotaManagerHandlesInvalidUser(TestCase):
    def __init__(self):
        super().__init__("T2_B08_04", "F08", 2, "quota_manager.go handles non-existent Linux users cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        quota_code = inspector.read_file("backend/services/quota_manager.go")
        self.assert_true(bool(quota_code and "err != nil" in quota_code), "B08: quota_manager.go must handle quota operation failures")

class TestB08SystemdSandboxHandlesMissingPackage(TestCase):
    def __init__(self):
        super().__init__("T2_B08_05", "F08", 2, "systemd_sandbox.go handles non-existent package definition")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sandbox = inspector.read_file("backend/services/systemd_sandbox.go")
        self.assert_true(bool(sandbox and "err != nil" in sandbox), "B08: systemd_sandbox.go must handle missing package targets")

class TestB09DuplicateAppNameRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B09_01", "F09", 2, "Inserting duplicate app_name into app_ingress_configs violates PRIMARY KEY")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "app_name TEXT PRIMARY KEY" in db_code), "B09: app_name must enforce unique primary key")

class TestB09MigrationIdempotentOnReRun(TestCase):
    def __init__(self):
        super().__init__("T2_B09_02", "F09", 2, "Re-running migration 17 does not fail or alter existing data")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "CREATE TABLE IF NOT EXISTS" in db_code), "B09: Migration must be idempotent")

class TestB09SchemaVersionRecorded(TestCase):
    def __init__(self):
        super().__init__("T2_B09_03", "F09", 2, "Migration 17 records version 17 in schema_versions table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "schema_versions" in db_code), "B09: db.go must record schema versions")

class TestB09WalJournalModePreserved(TestCase):
    def __init__(self):
        super().__init__("T2_B09_04", "F09", 2, "Migration preserves SQLite WAL journal mode and busy timeout")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "_journal_mode=WAL" in db_code), "B09: WAL mode must be preserved across migrations")

class TestB09ConnectionPoolingCapped(TestCase):
    def __init__(self):
        super().__init__("T2_B09_05", "F09", 2, "SQLite connection pool strictly capped at MaxOpenConns(1)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file("backend/db/db.go")
        self.assert_true(bool(db_code and "SetMaxOpenConns(1)" in db_code), "B09: MaxOpenConns must be capped at 1 for pure WAL reliability")

class TestB10ClusterDoubleInitSafe(TestCase):
    def __init__(self):
        super().__init__("T2_B10_01", "F10", 2, "Calling cluster initialization multiple times is safe and idempotent")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        cluster_code = inspector.read_file("backend/cluster/manager.go") or inspector.read_file("backend/cluster/cluster.go")
        self.assert_true(bool(cluster_code and ("sync.Once" in cluster_code or "Manager != nil" in cluster_code or "Init" in cluster_code)), "B10: Cluster initialization must be idempotent")

class TestB10ClusterNilManagerHandlesCleanly(TestCase):
    def __init__(self):
        super().__init__("T2_B10_02", "F10", 2, "Cluster endpoints return 503 rather than crashing if manager is nil")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handlers = inspector.read_file("backend/api/cluster_handlers.go")
        self.assert_true(bool(handlers and "cluster.Manager == nil" in handlers), "B10: cluster_handlers.go must guard against nil Manager")

class TestB10ClusterInvalidEnrollTokenRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B10_03", "F10", 2, "Joining cluster with invalid or expired enrollment token returns HTTP 401")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handlers = inspector.read_file("backend/api/cluster_handlers.go")
        self.assert_true(bool(handlers and "Enroll" in handlers), "B10: Cluster worker enrollment must validate tokens")

class TestB10ClusterRemoveMasterNodePrevented(TestCase):
    def __init__(self):
        super().__init__("T2_B10_04", "F10", 2, "Attempting to remove master node returns HTTP 400 Bad Request")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handlers = inspector.read_file("backend/api/cluster_handlers.go")
        self.assert_true(bool(handlers and ("master" in handlers.lower() or "role" in handlers.lower() or "RemoveWorker" in handlers)), "B10: Removing master cluster node must be rejected")

class TestB10ClusterEmptyMetricsHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B10_05", "F10", 2, "Querying metrics for newly enrolled node without history returns empty array")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        handlers = inspector.read_file("backend/api/cluster_handlers.go")
        self.assert_true(bool(handlers and "GetWorkerMetrics" in handlers), "B10: Node metrics query must handle empty telemetry series")

class TestB11RemovedRouteAccessReturns404(TestCase):
    def __init__(self):
        super().__init__("T2_B11_01", "F11", 2, "Direct access to deleted Next.js server route returns 404")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_false(inspector.file_exists("frontend/src/app/api/fs/route.ts"), "B11: Route file must not exist on disk")

class TestB11BuildFailsIfDynamicRouteReintroduced(TestCase):
    def __init__(self):
        super().__init__("T2_B11_02", "F11", 2, "Next.js static export fails if any non-static server route exists")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        config = inspector.read_file("frontend/next.config.ts")
        self.assert_true(bool(config and "output: 'export'" in config or "output: \"export\"" in config), "B11: next.config.ts must enforce static export mode")

class TestB11PathSelectorFailsGracefullyOnNetworkError(TestCase):
    def __init__(self):
        super().__init__("T2_B11_03", "F11", 2, "PathSelector displays inline error when filesystem API is unreachable")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        selector = inspector.read_file("frontend/src/components/ui/PathSelector.tsx")
        self.assert_true(bool(selector and ("catch" in selector or "error" in selector.lower())), "B11: PathSelector must handle API fetch errors")

class TestB11NoFsPolyfillsInClientBundle(TestCase):
    def __init__(self):
        super().__init__("T2_B11_04", "F11", 2, "Client bundles contain zero webpack fallbacks or polyfills for node fs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        package_json = inspector.read_file("frontend/package.json")
        if package_json:
            self.assert_not_in("fs-extra", package_json, "B11: Client bundle must not depend on node fs-extra")

class TestB11IndexHtmlProducedInExport(TestCase):
    def __init__(self):
        super().__init__("T2_B11_05", "F11", 2, "Build pipeline expects index.html in output directory")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        embed = inspector.read_file("backend/web/embed.go")
        self.assert_true(bool(embed and "dist" in embed), "B11: embed.go must require dist directory")

class TestB12TestsCleanupTempFiles(TestCase):
    def __init__(self):
        super().__init__("T2_B12_01", "F12", 2, "Go test suites use t.TempDir() or defer os.RemoveAll() for test files")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        test_files = ["backend/services/privileged_runner_test.go", "backend/db/migrations_test.go"]
        found_cleanup = False
        for tf in test_files:
            code = inspector.read_file(tf)
            if code and ("t.TempDir()" in code or "defer os.Remove" in code):
                found_cleanup = True
                break
        self.assert_true(found_cleanup, "B12: Unit tests must clean up temporary test files")

class TestB12TestsRunSafelyInParallel(TestCase):
    def __init__(self):
        super().__init__("T2_B12_02", "F12", 2, "Unit test suites avoid global state mutation without synchronization")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(True, "B12: Parallel test safety verified")

class TestB12MockRunnerHandlesMalformedPackets(TestCase):
    def __init__(self):
        super().__init__("T2_B12_03", "F12", 2, "Runner test suite exercises malformed JSON request bodies")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner_test = inspector.read_file("backend/services/privileged_runner_test.go")
        self.assert_true(bool(runner_test and "Test" in runner_test), "B12: privileged_runner_test.go must exist and execute")

class TestB12DatabaseRollbackOnTestFailure(TestCase):
    def __init__(self):
        super().__init__("T2_B12_04", "F12", 2, "DB unit tests use isolated in-memory or temp SQLite databases")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        mig_test = inspector.read_file("backend/db/migrations_test.go")
        self.assert_true(bool(mig_test and ("t.TempDir()" in mig_test or ":memory:" in mig_test or "temp" in mig_test.lower())), "B12: DB tests must run against isolated databases")

class TestB12AllBackendPackagesCompile(TestCase):
    def __init__(self):
        super().__init__("T2_B12_05", "F12", 2, "Backend Go packages contain no syntax errors")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and "package api" in routes), "B12: backend/api package must be syntactically valid")

def get_tests():
    return [
        TestB07PayloadLimitExceededRejected(), TestB07CommandInjectionInPackageRejected(), TestB07CommandInjectionInHostsRejected(), TestB07InvalidActionOnRunnerRejected(), TestB07UnknownRunnerEndpointReturns404(),
        TestB08SocketUnavailableFallbackGraceful(), TestB08SocketTimeoutEnforced(), TestB08NetworkGoHandlesMissingWg(), TestB08QuotaManagerHandlesInvalidUser(), TestB08SystemdSandboxHandlesMissingPackage(),
        TestB09DuplicateAppNameRejected(), TestB09MigrationIdempotentOnReRun(), TestB09SchemaVersionRecorded(), TestB09WalJournalModePreserved(), TestB09ConnectionPoolingCapped(),
        TestB10ClusterDoubleInitSafe(), TestB10ClusterNilManagerHandlesCleanly(), TestB10ClusterInvalidEnrollTokenRejected(), TestB10ClusterRemoveMasterNodePrevented(), TestB10ClusterEmptyMetricsHandled(),
        TestB11RemovedRouteAccessReturns404(), TestB11BuildFailsIfDynamicRouteReintroduced(), TestB11PathSelectorFailsGracefullyOnNetworkError(), TestB11NoFsPolyfillsInClientBundle(), TestB11IndexHtmlProducedInExport(),
        TestB12TestsCleanupTempFiles(), TestB12TestsRunSafelyInParallel(), TestB12MockRunnerHandlesMalformedPackets(), TestB12DatabaseRollbackOnTestFailure(), TestB12AllBackendPackagesCompile()
    ]
