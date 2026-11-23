"""
Tier 3: Cross-Feature Combinations (Pairwise Interoperability)
12 Comprehensive Pairwise Integration Suites:
1. Ingress + Privileged Hosts + Reverse Proxy Topology + Migration 17
2. Auth Refresh + Profile Password + Session Invalidation + Profile UI
3. DirectoryPicker + Rust FS Browser + MediaFlow Tab + Cookie Auth
4. Quotas Panel + Privileged Runner Quota + Quota Manager Enforcement
5. Network VPN Panel + Privileged Runner Network + WireGuard/Tailscale
6. Peer Runtime + Cluster Tab + Peer Administration
7. External Rust WASM Pipeline + Embedded SPA + Obsidian CSS Tokens
8. Systemd Privilege Units + Sudoers Purge + Caller Migration + Sandbox
9. Debian 13 APT Sources + Core OS Detection + Package Modernization + Keyrings
10. AI Telemetry Predictions + Bandwidth Tuning + OverviewTab Mounting
11. ExternalAccess + DeploymentStatus + Deploy SSE Stream + Apache2 Subdomain Gateway
12. Tri-Mode Mobile Dock + Scroller Containment + Touch Targets + Primitives
"""

import re
from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

ROUTES_RS = "backend-rs/crates/af-api/src/routes.rs"
DB_RS = "backend-rs/crates/af-db/src/lib.rs"
RUNNER_RS = "backend-rs/crates/af-runner/src/lib.rs"
MUTATORS_RS = "backend-rs/crates/af-services/src/mutators.rs"
MAIN_RS = "backend-rs/crates/af-api/src/main.rs"
EMBED_RS = "backend-rs/crates/af-api/src/embed.rs"
STORAGE_RS = "backend-rs/crates/af-api/src/storage.rs"


class TestComboIngressDnsProxyTopology(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_01", "F05+F07+F06+F09", 3, "Ingress CRUD persists to Migration 17, syncs DNS via runner, and reflects in topology")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        db_code = inspector.read_file(DB_RS)
        runner_code = inspector.read_file(RUNNER_RS)
        routes_code = inspector.read_file(ROUTES_RS)
        db_mig = bool(db_code and "app_ingress_configs" in db_code)
        runner_hosts = bool(runner_code and "/v1/hosts" in runner_code)
        ingress_api = bool(routes_code and "/ingress" in routes_code)
        topology_api = bool(routes_code and "/system/topology" in routes_code)
        self.assert_true(db_mig and runner_hosts and ingress_api and topology_api, "Combo 01: Ingress, DNS runner, and topology contracts must be satisfied")


class TestComboAuthSessionPasswordLifecycle(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_02", "F02+F03+F22", 3, "Password mutation, session rotation, and security.rs form interaction")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file(ROUTES_RS)
        profile = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/settings/security.rs")
        has_refresh = bool(routes and "/refresh" in routes)
        has_password = bool(routes and "/profile/password" in routes)
        has_profile_ui = bool(profile and "/api/v1/auth/profile/password" in profile)
        self.assert_true(has_refresh and has_password and has_profile_ui, "Combo 02: Auth refresh, password mutation, and profile security UI wiring must be satisfied")


class TestComboPathSelectorFsMediaflow(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_03", "F01+F20", 3, "DirectoryPicker integration with Rust FS handler and MediaflowTab ApiClient auth")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        picker = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs")
        mediaflow = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs")
        routes = inspector.read_file(ROUTES_RS)
        has_fs = bool(routes and "/fs" in routes)
        has_picker = bool(picker and "/api/v1/auth/fs" in picker)
        has_mediaflow_api = bool(mediaflow and "ApiClient" in mediaflow)
        self.assert_true(has_fs and has_picker and has_mediaflow_api, "Combo 03: DirectoryPicker, FS API, and MediaflowTab wiring must be satisfied")


class TestComboQuotasRunner(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_04", "F26+F07+F08", 3, "Quotas UI, runner /v1/quota dispatch, and quota manager enforcement")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        quotas_ui = inspector.file_exists("frontend-rs/crates/af-web-app/src/tabs/quotas.rs")
        runner_code = inspector.read_file(RUNNER_RS)
        runner_quota = bool(runner_code and "/v1/quota" in runner_code and "dispatch_quota_set" in runner_code)
        quota_impl = bool(inspector.file_exists("backend-rs/crates/af-runner/src/quota.rs"))
        self.assert_true(quotas_ui and runner_quota and quota_impl, "Combo 04: Quotas UI, runner quota socket, and quota handler must be satisfied")


class TestComboNetworkVpnRunner(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_05", "F24+F07+F08", 3, "Network panel UI, runner /v1/network, and WireGuard/Tailscale callers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        net_ui = inspector.file_exists("frontend-rs/crates/af-web-app/src/tabs/network/mod.rs")
        runner_code = inspector.read_file(RUNNER_RS)
        runner_net = bool(runner_code and "/v1/network" in runner_code)
        caller_net = bool(inspector.file_exists("backend-rs/crates/af-runner/src/network.rs"))
        self.assert_true(net_ui and runner_net and caller_net, "Combo 05: Network panel, runner network socket, and network handler must be satisfied")


class TestComboPeerClusterManagement(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_06", "F10+F27", 3, "Peer runtime, Cluster tab, and peer administration")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        main_code = inspector.read_file(MAIN_RS) or ""
        routes_code = inspector.read_file(ROUTES_RS) or ""
        cluster_ui = inspector.file_exists("frontend-rs/crates/af-web-app/src/tabs/cluster/mod.rs")
        self.assert_true(
            "peers::start().await" in main_code and cluster_ui and 'nest("/peers", crate::peers::admin_routes())' in routes_code,
            "Combo 06: the peer runtime, Cluster tab, and admin peer routes must be connected",
        )


class TestComboExternalWasmSpaAtmosphere(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_07", "F32+F11+F13+F14", 3, "External Rust WASM deployment and Obsidian V2 CSS foundation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        stack = inspector.read_file("setup/modules/modern_stack.sh")
        embed = inspector.read_file(EMBED_RS)
        css = inspector.read_file("frontend-rs/styles/input.css")
        stages_wasm = bool(stack and "build_wasm_frontend.sh" in stack and "${release_dir}/web/dist" in stack)
        serves_external = bool(embed and 'join("web/dist")' in embed and "RustEmbed" not in embed)
        has_obsidian = bool(css and "--obs-bg-base:" in css and "var(--obs-bg-base)" in css and "--obs-chromatic-edge-gradient" in css)
        self.assert_true(stages_wasm and serves_external and has_obsidian, "Combo 07: WASM staging, external serving, and Obsidian CSS must be satisfied")


class TestComboPrivilegeBoundarySandbox(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_08", "F33+F34+F07+F08", 3, "Systemd least privilege units, sudoers purge, runner socket, and sandbox caller")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        unit = inspector.read_file("deploy/systemd/aetherflow-api.service")
        stack = inspector.read_file("setup/modules/modern_stack.sh")
        runner = inspector.read_file(RUNNER_RS)
        has_strict = bool(unit and "ProtectSystem=strict" in unit and "NoNewPrivileges=yes" in unit)
        no_sudoers = bool(stack and "aetherflow ALL=(ALL) NOPASSWD: ALL" not in stack)
        has_sandbox_runner = bool(runner and "dispatch_sandbox_apply" in runner and "/v1/sandbox" in runner)
        self.assert_true(has_strict and no_sudoers and has_sandbox_runner, "Combo 08: Privilege boundary, sudoers purge, and sandbox runner must be satisfied")


class TestComboDebian13AptPackaging(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_09", "F28+F29+F30+F31", 3, "Debian 13 APT TLS template, core OS detection, modernized packages, and keyrings")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        core = inspector.read_file("setup/modules/00-core.sh")
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        has_https = bool(template and "https://deb.debian.org/debian" in template and "non-free-firmware" in template)
        has_trixie = bool(core and "trixie" in core)
        has_pcre2 = bool(pkgs and "pcre2" in pkgs)
        self.assert_true(has_https and has_trixie and has_pcre2, "Combo 09: Debian 13 APT, core detection, and modern packages must be satisfied")


class TestComboAiTelemetryPredictions(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_10", "F19+Overview", 3, "Overview tab mounting of CapacityPredictions & Bandwidth tuning with real history")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/overview/mod.rs")
        widgets = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/overview/widgets.rs")
        telemetry = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/overview/telemetry.rs")
        has_cards = bool(overview and "<CapacityPredictions" in overview and widgets and "Overview.networkBandwidth" in widgets)
        has_history = bool(telemetry and "/api/v1/admin/ai/predictions/history" in telemetry)
        self.assert_true(has_cards and has_history, "Combo 10: Overview AI predictions & bandwidth with real history must be satisfied")


class TestComboDeploySseGateway(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_11", "F21+Deploy", 3, "ExternalAccessSettings, DeploymentStatus, EventSource SSE, and Apache2 Subdomain Gateway integration")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        mediaflow = inspector.read_file("frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs")
        deploy_api = inspector.read_file(STORAGE_RS)
        has_stream_ui = bool(mediaflow and "/api/v1/auth/deploy/stream" in mediaflow and "EventSource" in mediaflow)
        has_api = bool(deploy_api and "/api/v1/auth/deploy/stream" in deploy_api)
        self.assert_true(has_stream_ui and has_api, "Combo 11: Deployment SSE stream and Apache2 Subdomain Gateway deploy orchestration must be satisfied")


class TestComboResponsiveDockScrollerContainment(TestCase):
    def __init__(self):
        super().__init__("T3_COMBO_12", "F15+F16+F18", 3, "Tri-mode mobile dock, scroller containment invariant, and Obsidian UI primitives")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        css = inspector.read_file("frontend-rs/styles/input.css")
        shell = inspector.read_file("frontend-rs/crates/af-web-app/src/shell.rs")
        has_dock = bool(shell and "af-mobile-dock" in shell and css and ".af-mobile-dock" in css)
        clean_css = re.sub(r'/\*.*?\*/', '', css or "", flags=re.DOTALL)
        no_overflow = bool(css and not re.search(r'(html|body)\s*\{[^}]*overflow-x:\s*hidden', clean_css, re.IGNORECASE))
        self.assert_true(has_dock and no_overflow, "Combo 12: Mobile dock and scroller containment must be satisfied")


def get_tier3_tests():
    return [
        TestComboIngressDnsProxyTopology(),
        TestComboAuthSessionPasswordLifecycle(),
        TestComboPathSelectorFsMediaflow(),
        TestComboQuotasRunner(),
        TestComboNetworkVpnRunner(),
        TestComboPeerClusterManagement(),
        TestComboExternalWasmSpaAtmosphere(),
        TestComboPrivilegeBoundarySandbox(),
        TestComboDebian13AptPackaging(),
        TestComboAiTelemetryPredictions(),
        TestComboDeploySseGateway(),
        TestComboResponsiveDockScrollerContainment()
    ]
