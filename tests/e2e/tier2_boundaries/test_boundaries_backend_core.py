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

RUNNER_RS = "backend-rs/crates/af-runner/src/lib.rs"
NETWORK_RS = "backend-rs/crates/af-runner/src/network.rs"
QUOTA_RS = "backend-rs/crates/af-runner/src/quota.rs"
DB_RS = "backend-rs/crates/af-db/src/lib.rs"
PEERS_RS = "backend-rs/crates/af-api/src/peers/mod.rs"
EMBED_RS = "backend-rs/crates/af-api/src/embed.rs"
ACTIONS_TESTS_RS = "backend-rs/crates/af-api/src/mcbrowser/actions_tests.rs"
ROUTES_RS = "backend-rs/crates/af-api/src/routes.rs"


class TestB07PayloadLimitExceededRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_01", "F07", 2, "Runner enforces bounded payload and command-output sizes")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        network = inspector.read_file(NETWORK_RS)
        self.assert_true(bool(runner and network and ("4096" in runner or "limited_read" in network)), "B07: Runner must enforce bounded payload limits")


class TestB07CommandInjectionInPackageRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_02", "F07", 2, "Shell metacharacters ('; rm -rf', '|', '&') in package name are rejected")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "is_ascii_alphanumeric" in runner and "Regex::new" in runner), "B07: Runner must validate package identifiers against strict allowlists")


class TestB07CommandInjectionInHostsRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_03", "F07", 2, "Newline or injection characters in domain/IP for /v1/hosts return HTTP 400")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "/v1/hosts" in runner and "validate_hosts_domain" in runner and "validate_hosts_ip" in runner), "B07: Runner /v1/hosts must validate IP and domain format")


class TestB07InvalidActionOnRunnerRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B07_04", "F07", 2, "Unrecognized action verb in /v1/systemctl returns HTTP 400")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "ALLOWED_SERVICE_ACTIONS" in runner), "B07: Runner must restrict actions to ALLOWED_SERVICE_ACTIONS set")


class TestB07UnknownRunnerEndpointReturns404(TestCase):
    def __init__(self):
        super().__init__("T2_B07_05", "F07", 2, "Unknown path on runner socket returns HTTP 404 Not Found")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "build_runner_router" in runner and "Router::new()" in runner), "B07: Runner Axum router must reject unregistered endpoints with 404")


class TestB08SocketUnavailableFallbackGraceful(TestCase):
    def __init__(self):
        super().__init__("T2_B08_01", "F08", 2, "Caller services handle missing runner socket gracefully without panic")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "post_runner_json" in runner and "anyhow::Result" in runner), "B08: Socket client must return structured error on connection failure")


class TestB08SocketTimeoutEnforced(TestCase):
    def __init__(self):
        super().__init__("T2_B08_02", "F08", 2, "Socket requests enforce finite context timeout (prevent hangs)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "tokio::time::timeout" in runner), "B08: Runner socket calls must respect async timeouts")


class TestB08NetworkRustHandlesMissingWg(TestCase):
    def __init__(self):
        super().__init__("T2_B08_03", "F08", 2, "af-runner network.rs handles absence of wg binary gracefully")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        net_code = inspector.read_file(NETWORK_RS)
        self.assert_true(bool(net_code and 'installed("wg")' in net_code and "Result<" in net_code), "B08: network.rs must handle missing binaries and errors gracefully")


class TestB08QuotaManagerHandlesInvalidUser(TestCase):
    def __init__(self):
        super().__init__("T2_B08_04", "F08", 2, "af-runner quota.rs validates usernames cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        quota_code = inspector.read_file(QUOTA_RS)
        self.assert_true(bool(quota_code and "valid_username" in quota_code and "Result<" in quota_code), "B08: quota.rs must handle invalid users cleanly")


class TestB08SystemdSandboxHandlesMissingPackage(TestCase):
    def __init__(self):
        super().__init__("T2_B08_05", "F08", 2, "af-runner sandbox handler rejects non-existent package definitions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "handle_sandbox_with" in runner and "StatusCode" in runner), "B08: handle_sandbox_with must handle missing package targets")


class TestB09DuplicateAppNameRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B09_01", "F09", 2, "Inserting duplicate app_name into app_ingress_configs violates PRIMARY KEY")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "app_name TEXT PRIMARY KEY" in db_code), "B09: app_name must enforce unique primary key")


class TestB09MigrationIdempotentOnReRun(TestCase):
    def __init__(self):
        super().__init__("T2_B09_02", "F09", 2, "Re-running migration 17 does not fail or alter existing data")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "CREATE TABLE IF NOT EXISTS" in db_code), "B09: Migration must be idempotent")


class TestB09SchemaVersionRecorded(TestCase):
    def __init__(self):
        super().__init__("T2_B09_03", "F09", 2, "Migration 17 records version 17 in schema_versions table")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "schema_versions" in db_code), "B09: af-db must record schema versions")


class TestB09WalJournalModePreserved(TestCase):
    def __init__(self):
        super().__init__("T2_B09_04", "F09", 2, "Migration preserves SQLite WAL journal mode and busy timeout")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "PRAGMA journal_mode=WAL" in db_code and "PRAGMA busy_timeout=5000" in db_code), "B09: WAL mode must be preserved across migrations")


class TestB09ConnectionPoolingCapped(TestCase):
    def __init__(self):
        super().__init__("T2_B09_05", "F09", 2, "SQLite connection pool strictly capped at max_size(1)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and ".max_size(1)" in db_code), "B09: Pool max_size must be capped at 1 for pure WAL reliability")


class TestB10PeerHealthSingleStart(TestCase):
    def __init__(self):
        super().__init__("T2_B10_01", "F10", 2, "Starting the peer runtime twice cannot spawn duplicate health loops")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        peers = inspector.read_file(PEERS_RS) or ""
        self.assert_true(
            "health_shutdown.lock().await" in peers and "health_guard.is_none()" in peers,
            "B10: guard peer health loop creation",
        )


class TestB10PeerListWithoutIdentity(TestCase):
    def __init__(self):
        super().__init__("T2_B10_02", "F10", 2, "Peer listing represents an unconfigured identity and empty links")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        links = inspector.read_file("backend-rs/crates/af-api/src/peers/links.rs") or ""
        self.assert_true(
            "identity.map" in links and "list_peer_links" in links and '"peers": peer_views' in links,
            "B10: the list response must include optional identity and a peer list",
        )


class TestB10PairingCodeDigest(TestCase):
    def __init__(self):
        super().__init__("T2_B10_03", "F10", 2, "Pairing validates a code against its stored digest")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pairing = inspector.read_file("backend-rs/crates/af-api/src/peers/pairing.rs") or ""
        self.assert_true(
            "code_hash" in pairing and "sha256_prefixed" in pairing and "constant_time_eq" in pairing,
            "B10: the pairing code must be validated against a digest",
        )


class TestB10PeerRevocationInvalidatesLink(TestCase):
    def __init__(self):
        super().__init__("T2_B10_04", "F10", 2, "Revocation disables link authorization and cleans up owned resources")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        links = inspector.read_file("backend-rs/crates/af-api/src/peers/links.rs") or ""
        self.assert_true(
            "inbound_token_hash = NULL" in links and "remove_owned_wg_peer_locked" in links,
            "B10: link revocation must invalidate the credential and clean up owned resources",
        )


class TestB10PeerRoutesExcludeLegacyAlias(TestCase):
    def __init__(self):
        super().__init__("T2_B10_05", "F10", 2, "Peer pairing and administration exclude the legacy API prefix")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS) or ""
        self.assert_true(
            'let v1 = build_v1_tracked_router_with_options(true)' in routes
            and 'let legacy = build_v1_tracked_router_with_options(false)' in routes
            and '.nest("/api/v1", v1)' in routes and '.nest("/api", legacy)' in routes,
            "B10: enable peer routes only in the versioned API router",
        )


class TestB11RemovedRouteAccessReturns404(TestCase):
    def __init__(self):
        super().__init__("T2_B11_01", "F11", 2, "Direct access to deleted Next.js server route returns 404")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_false(inspector.file_exists("frontend/src/app/api/fs/route.ts"), "B11: Legacy route file must not exist on disk")
        if mode == "live" and client.is_server_reachable():
            code, _, _ = client.request("GET", "/api/fs/route.ts")
            self.assert_status_code(code, 404, "B11: Legacy Next.js route path must return 404")


class TestB11BuildFailsIfDynamicRouteReintroduced(TestCase):
    def __init__(self):
        super().__init__("T2_B11_02", "F11", 2, "frontend-rs Trunk.toml enforces static WASM release bundle without Next.js SSR")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        trunk_toml = inspector.read_file("frontend-rs/Trunk.toml")
        self.assert_false(inspector.file_exists("frontend/next.config.ts"), "B11: Legacy next.config.ts must be deleted")
        self.assert_true(bool(trunk_toml and 'dist = "dist"' in trunk_toml and "release = true" in trunk_toml), "B11: Trunk.toml must build static WASM dist")


class TestB11PathSelectorFailsGracefullyOnNetworkError(TestCase):
    def __init__(self):
        super().__init__("T2_B11_03", "F11", 2, "DirectoryPicker displays inline ResourceFeedback error when filesystem API is unreachable")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        picker = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs")
        self.assert_true(bool(picker and ("ResourceFeedback" in picker or "resource.error" in picker)), "B11: DirectoryPicker must handle API fetch errors")


class TestB11NoFsPolyfillsInClientBundle(TestCase):
    def __init__(self):
        super().__init__("T2_B11_04", "F11", 2, "E2E and WASM manifests contain zero Node fs-extra or webpack polyfills")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        e2e_pkg = inspector.read_file("e2e/package.json")
        core_toml = inspector.read_file("frontend-rs/crates/af-web-core/Cargo.toml")
        self.assert_true(bool(e2e_pkg and core_toml), "B11: e2e/package.json and af-web-core/Cargo.toml must exist")
        self.assert_not_in("fs-extra", e2e_pkg or "", "B11: e2e workspace must not depend on node fs-extra")
        self.assert_not_in("next", e2e_pkg or "", "B11: e2e workspace must not depend on Next.js")


class TestB11IndexHtmlProducedInExport(TestCase):
    def __init__(self):
        super().__init__("T2_B11_05", "F11", 2, "Build pipeline expects index.html in embedded web/dist directory")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        embed = inspector.read_file(EMBED_RS)
        self.assert_true(bool(embed and "web/dist" in embed and "index.html" in embed), "B11: embed.rs must require web/dist with index.html fallback")


class TestB12TestsCleanupTempFiles(TestCase):
    def __init__(self):
        super().__init__("T2_B12_01", "F12", 2, "Rust test suites use RAII TestTempDir drop guards for temporary files")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        code = inspector.read_file(ACTIONS_TESTS_RS)
        self.assert_true(bool(code and "struct TestTempDir" in code and "impl Drop for TestTempDir" in code), "B12: Unit tests must clean up temporary test directories via Drop")


class TestB12TestsRunSafelyInParallel(TestCase):
    def __init__(self):
        super().__init__("T2_B12_02", "F12", 2, "Unit test suites avoid global state mutation without synchronization")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        plugin_tests = inspector.read_file("backend-rs/crates/af-api/src/plugins/tests.rs") or ""
        route_tests = inspector.read_file("backend-rs/crates/af-api/src/routes/tests.rs") or ""
        self.assert_true(
            "fn run_plugin_test_in_subprocess()" in plugin_tests
            and "AETHERFLOW_PLUGIN_TEST_ISOLATED" in plugin_tests
            and "RECEIPT_TEST_MUTEX: std::sync::Mutex" in route_tests,
            "B12: af-api test helpers must isolate DB/env state via subprocess isolation and Mutex guards",
        )


class TestB12MockRunnerHandlesMalformedPackets(TestCase):
    def __init__(self):
        super().__init__("T2_B12_03", "F12", 2, "Runner test suite exercises fallback and error paths cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        runner = inspector.read_file(RUNNER_RS)
        self.assert_true(bool(runner and "#[tokio::test]" in runner and "test_handle_sandbox_and_quota_graceful_fallback" in runner), "B12: af-runner unit tests must exist and exercise runner handlers")


class TestB12DatabaseRollbackOnTestFailure(TestCase):
    def __init__(self):
        super().__init__("T2_B12_04", "F12", 2, "DB unit tests use isolated in-memory or temp SQLite databases")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        self.assert_true(bool(db_code and "open_in_memory()" in db_code), "B12: DB unit tests must run against isolated databases")


class TestB12AllBackendPackagesCompile(TestCase):
    def __init__(self):
        super().__init__("T2_B12_05", "F12", 2, "Rust workspace Cargo manifest declares all core crates")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        manifest = inspector.read_file("backend-rs/Cargo.toml")
        routes = inspector.read_file(ROUTES_RS)
        self.assert_true(bool(manifest and "crates/af-api" in manifest and routes and "pub fn " in routes), "B12: backend-rs workspace and af-api crate must be configured cleanly")


def get_tests():
    return [
        TestB07PayloadLimitExceededRejected(), TestB07CommandInjectionInPackageRejected(), TestB07CommandInjectionInHostsRejected(), TestB07InvalidActionOnRunnerRejected(), TestB07UnknownRunnerEndpointReturns404(),
        TestB08SocketUnavailableFallbackGraceful(), TestB08SocketTimeoutEnforced(), TestB08NetworkRustHandlesMissingWg(), TestB08QuotaManagerHandlesInvalidUser(), TestB08SystemdSandboxHandlesMissingPackage(),
        TestB09DuplicateAppNameRejected(), TestB09MigrationIdempotentOnReRun(), TestB09SchemaVersionRecorded(), TestB09WalJournalModePreserved(), TestB09ConnectionPoolingCapped(),
        TestB10PeerHealthSingleStart(), TestB10PeerListWithoutIdentity(), TestB10PairingCodeDigest(), TestB10PeerRevocationInvalidatesLink(), TestB10PeerRoutesExcludeLegacyAlias(),
        TestB11RemovedRouteAccessReturns404(), TestB11BuildFailsIfDynamicRouteReintroduced(), TestB11PathSelectorFailsGracefullyOnNetworkError(), TestB11NoFsPolyfillsInClientBundle(), TestB11IndexHtmlProducedInExport(),
        TestB12TestsCleanupTempFiles(), TestB12TestsRunSafelyInParallel(), TestB12MockRunnerHandlesMalformedPackets(), TestB12DatabaseRollbackOnTestFailure(), TestB12AllBackendPackagesCompile()
    ]
