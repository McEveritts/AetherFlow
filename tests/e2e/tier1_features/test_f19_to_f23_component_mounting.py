"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F19: Mount Bandwidth & Predictions Cards
- F20: Mount Metadata & DirectoryPicker Controls
- F21: Mount ExternalAccess & DeploymentStatus
- F22: Wire Profile Controls
- F23: Real App Topology Map
"""

import re

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

OVERVIEW_MOD = "frontend-rs/crates/af-web-app/src/tabs/overview/mod.rs"
OVERVIEW_WIDGETS = "frontend-rs/crates/af-web-app/src/tabs/overview/widgets.rs"
OVERVIEW_TELEMETRY = "frontend-rs/crates/af-web-app/src/tabs/overview/telemetry.rs"
METADATA_RS = "frontend-rs/crates/af-web-app/src/tabs/settings/metadata.rs"
LOCAL_STORAGE_RS = "frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs"
MEDIAFLOW_RS = "frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs"
SERVICES_MOD = "frontend-rs/crates/af-web-app/src/tabs/services/mod.rs"
MARKETPLACE_MOD = "frontend-rs/crates/af-web-app/src/tabs/marketplace/mod.rs"
MARKETPLACE_CATALOG = "frontend-rs/crates/af-web-app/src/tabs/marketplace/catalog.rs"
TAILSCALE_INGRESS_RS = "frontend-rs/crates/af-web-app/src/tabs/network/tailscale_ingress.rs"
SECURITY_RS = "frontend-rs/crates/af-web-app/src/tabs/settings/security.rs"
TOPOLOGY_UI_RS = "frontend-rs/crates/af-web-ui/src/topology.rs"
TOPOLOGY_CORE_RS = "frontend-rs/crates/af-web-core/src/topology.rs"
STORAGE_RS = "backend-rs/crates/af-api/src/storage.rs"


class TestF19BandwidthCardMountedInOverview(TestCase):
    def __init__(self):
        super().__init__("T1_F19_01", "F19", 1, "Network bandwidth & capacity predictions are mounted in Overview tab")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file(OVERVIEW_MOD)
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        self.assert_true(
            bool(overview and "CapacityPredictions" in overview and widgets and "Overview.networkBandwidth" in widgets),
            "F19: Bandwidth & CapacityPredictions must be mounted in overview/mod.rs",
        )


class TestF19PredictionsCardMountedInOverview(TestCase):
    def __init__(self):
        super().__init__("T1_F19_02", "F19", 1, "CapacityPredictions is imported and rendered in overview/mod.rs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file(OVERVIEW_MOD)
        self.assert_true(bool(overview and "<CapacityPredictions" in overview), "F19: CapacityPredictions must be mounted in overview/mod.rs")


class TestF19PredictionsFetchesRealHistory(TestCase):
    def __init__(self):
        super().__init__("T1_F19_03", "F19", 1, "Capacity telemetry fetches metrics from /api/v1/admin/ai/predictions/history")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        telemetry = inspector.read_file(OVERVIEW_TELEMETRY)
        self.assert_true(bool(telemetry and "/api/v1/admin/ai/predictions/history" in telemetry), "F19: overview/telemetry.rs must query /api/v1/admin/ai/predictions/history")


class TestF19ZeroFakeSineWaveMathematics(TestCase):
    def __init__(self):
        super().__init__("T1_F19_04", "F19", 1, "Overview telemetry contains zero synthetic Math.sin() trend data generation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        telemetry = inspector.read_file(OVERVIEW_TELEMETRY)
        self.assert_true(bool(widgets and telemetry), "F19: overview modules must exist")
        self.assert_not_in("Math.sin", widgets or "", "F19: widgets.rs must not contain synthetic Math.sin() waves")
        self.assert_not_in("sin(", telemetry or "", "F19: telemetry.rs must not synthesize sine wave trends")


class TestF19PredictionsMountLoadsInitialReport(TestCase):
    def __init__(self):
        super().__init__("T1_F19_05", "F19", 1, "CapacityPredictions loads the prediction report on mount when Settings read is granted")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widgets = inspector.read_file(OVERVIEW_WIDGETS) or ""
        component = widgets.partition("fn CapacityPredictions(")[2].split("#[component]", 1)[0]
        permission = r"let\s+can_read_settings\s*=\s*Signal::derive\(move\s*\|\|\s*context\.can_read_area\(PeerArea::Settings\)\)"
        report = r'use_api_when\(\s*can_read_settings\s*,\s*"/api/v1/admin/ai/predictions"'
        self.assert_true(
            bool(re.search(permission, component) and re.search(report, component)),
            "F19: CapacityPredictions must fetch the report on mount when Settings read is granted",
        )


class TestF20MetadataTabMountedInMediaFlow(TestCase):
    def __init__(self):
        super().__init__("T1_F20_01", "F20", 1, "MetadataSettings is wired inside settings module and MediaflowTab is mounted")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        metadata = inspector.read_file(METADATA_RS)
        mediaflow = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(
            bool(metadata and "MetadataSettings" in metadata and mediaflow and "MediaflowTab" in mediaflow),
            "F20: MetadataSettings and MediaflowTab must be present in frontend-rs",
        )


class TestF20PathSelectorIntegrated(TestCase):
    def __init__(self):
        super().__init__("T1_F20_02", "F20", 1, "DirectoryPicker component is integrated for metadata directory inputs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        meta = inspector.read_file(METADATA_RS)
        local_storage = inspector.read_file(LOCAL_STORAGE_RS)
        self.assert_true(
            bool(meta and "DirectoryPicker" in meta and local_storage and "DirectoryPicker" in local_storage),
            "F20: DirectoryPicker must be integrated in metadata.rs and local_storage.rs",
        )


class TestF20PathSelectorCallsGoFsEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F20_03", "F20", 1, "DirectoryPicker queries authenticated Rust /api/v1/auth/fs endpoint")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        local_storage = inspector.read_file(LOCAL_STORAGE_RS)
        self.assert_true(
            bool(local_storage and "/api/v1/auth/fs" in local_storage),
            "F20: DirectoryPicker must target /api/v1/auth/fs",
        )


class TestF20MediaFlowUsesApiFetch(TestCase):
    def __init__(self):
        super().__init__("T1_F20_04", "F20", 1, "MediaflowTab uses ApiClient with cookie/CSRF authentication")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(bool(media and "ApiClient" in media), "F20: mediaflow.rs must use ApiClient")


class TestF20MediaFlowZeroLocalStorageToken(TestCase):
    def __init__(self):
        super().__init__("T1_F20_05", "F20", 1, "MediaflowTab eliminates stale localStorage token usages")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(bool(media), "F20: mediaflow.rs must exist")
        self.assert_not_in("localStorage.getItem('token')", media or "", "F20: mediaflow.rs must not read localStorage token")


class TestF21ExternalAccessCardMounted(TestCase):
    def __init__(self):
        super().__init__("T1_F21_01", "F21", 1, "External access navigation and ingress settings are wired in services/marketplace/network")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        services = inspector.read_file(SERVICES_MOD)
        marketplace = inspector.read_file(MARKETPLACE_CATALOG)
        ingress = inspector.read_file(TAILSCALE_INGRESS_RS)
        mounted = bool(
            (services and "External access" in services)
            and (marketplace and "External access" in marketplace)
            and (ingress and "ExternalAccessSettings" in ingress)
        )
        self.assert_true(mounted, "F21: External access actions and ExternalAccessSettings must be wired")


class TestF21DeploymentStatusMounted(TestCase):
    def __init__(self):
        super().__init__("T1_F21_02", "F21", 1, "DeploymentStatus is mounted inside marketplace Drawer")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        marketplace_mod = inspector.read_file(MARKETPLACE_MOD)
        marketplace_cat = inspector.read_file(MARKETPLACE_CATALOG)
        self.assert_true(
            bool(marketplace_mod and "<DeploymentStatus" in marketplace_mod and marketplace_cat and "pub(super) fn DeploymentStatus" in marketplace_cat),
            "F21: DeploymentStatus must be mounted in marketplace/mod.rs",
        )


class TestF21UseIngressStoreWired(TestCase):
    def __init__(self):
        super().__init__("T1_F21_03", "F21", 1, "ExternalAccessSettings fetches and updates ingress configs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        ingress = inspector.read_file(TAILSCALE_INGRESS_RS)
        self.assert_true(
            bool(ingress and "/api/v1/admin/ingress/configs" in ingress and "/api/v1/admin/ingress/apps/" in ingress),
            "F21: tailscale_ingress.rs must manage ingress configs and app updates",
        )


class TestF21DeploymentStreamUsesAuthPrefix(TestCase):
    def __init__(self):
        super().__init__("T1_F21_04", "F21", 1, "MediaflowTab connects EventSource to /api/v1/auth/deploy/stream")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        mediaflow = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(
            bool(mediaflow and "/api/v1/auth/deploy/stream" in mediaflow and "EventSource" in mediaflow),
            "F21: mediaflow.rs must target /api/v1/auth/deploy/stream",
        )


class TestF21DeployApiStreamTargetIncludesAuth(TestCase):
    def __init__(self):
        super().__init__("T1_F21_05", "F21", 1, "backend-rs/crates/af-api/src/storage.rs returns streamTarget with /api/v1/auth/deploy/stream")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        deploy_api = inspector.read_file(STORAGE_RS)
        self.assert_true(bool(deploy_api and "/api/v1/auth/deploy/stream" in deploy_api), "F21: af-api storage.rs must return /api/v1/auth/deploy/stream in streamTarget")


class TestF22PasswordChangeModalWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_01", "F22", 1, "security.rs wires password mutation form")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(bool(profile and 'mutate("password")' in profile and "current_password" in profile), "F22: security.rs must wire password mutation form")


class TestF22PasswordMutationInvoked(TestCase):
    def __init__(self):
        super().__init__("T1_F22_02", "F22", 1, "Password change form dispatches PUT /api/v1/auth/profile/password")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(bool(profile and "/api/v1/auth/profile/password" in profile), "F22: security.rs must call /api/v1/auth/profile/password")


class TestF22AvatarUploadWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_03", "F22", 1, "security.rs wires avatar upload control to PUT /api/v1/auth/profile/avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(bool(profile and "/api/v1/auth/profile/avatar" in profile and '.put(' in profile), "F22: security.rs must call PUT /api/v1/auth/profile/avatar")


class TestF22AvatarDeleteWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_04", "F22", 1, "security.rs wires Remove avatar button to DELETE /api/v1/auth/profile/avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(bool(profile and "Remove avatar" in profile and '.delete("/api/v1/auth/profile/avatar"' in profile), "F22: security.rs must wire Remove avatar button to DELETE")


class TestF22ProfileZeroSecurityMockupComments(TestCase):
    def __init__(self):
        super().__init__("T1_F22_05", "F22", 1, "security.rs eliminates legacy 'Security Section (Mockup)' markers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(bool(profile), "F22: security.rs must exist")
        self.assert_not_in("Security Section (Mockup)", profile or "", "F22: security.rs must not contain mockup comments")


class TestF23TopologyWidgetFetchesBackend(TestCase):
    def __init__(self):
        super().__init__("T1_F23_01", "F23", 1, "overview/mod.rs queries /api/v1/auth/system/topology for AppTopologyMap")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file(OVERVIEW_MOD)
        self.assert_true(
            bool(overview and "/api/v1/auth/system/topology" in overview and "<AppTopologyMap" in overview),
            "F23: overview/mod.rs must fetch live runtime topology and pass to AppTopologyMap",
        )


class TestF23TopologyWidgetZeroHardcodedNodes(TestCase):
    def __init__(self):
        super().__init__("T1_F23_02", "F23", 1, "AppTopologyMap eliminates hardcoded dummy nodes array")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(bool(topology and topo_core), "F23: topology modules must exist")
        for code in (topology, topo_core):
            self.assert_not_in("Proxy Port 8080", code, "F23: topology must remove dummy node 'Proxy Port 8080'")
            self.assert_not_in("Nginx Router", code, "F23: topology must remove dummy node 'Nginx Router'")


class TestF23TopologyWidgetLiveNodeStatus(TestCase):
    def __init__(self):
        super().__init__("T1_F23_03", "F23", 1, "AppTopologyMap renders live Core/Active/Stopped/Exception service groups")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(
            bool(topology and "ServiceGroup::Active" in topology and topo_core and "service_group" in topo_core),
            "F23: AppTopologyMap must render dynamic node status groups",
        )


class TestF23TopologyWidgetGraphLayoutCoordinates(TestCase):
    def __init__(self):
        super().__init__("T1_F23_04", "F23", 1, "compute_topology_layout calculates node coordinates without canvas collisions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(
            bool(topology and "<svg" in topology and topo_core and "compute_topology_layout" in topo_core),
            "F23: topology modules must compute SVG graph layout coordinates",
        )


class TestF23TopologyWidgetConnectionLinks(TestCase):
    def __init__(self):
        super().__init__("T1_F23_05", "F23", 1, "AppTopologyMap renders SVG links connecting dependent services")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        self.assert_true(bool(topology and "links.get()" in topology and "<line" in topology), "F23: AppTopologyMap must render SVG graph links")


def get_tests():
    return [
        TestF19BandwidthCardMountedInOverview(), TestF19PredictionsCardMountedInOverview(), TestF19PredictionsFetchesRealHistory(), TestF19ZeroFakeSineWaveMathematics(), TestF19PredictionsMountLoadsInitialReport(),
        TestF20MetadataTabMountedInMediaFlow(), TestF20PathSelectorIntegrated(), TestF20PathSelectorCallsGoFsEndpoint(), TestF20MediaFlowUsesApiFetch(), TestF20MediaFlowZeroLocalStorageToken(),
        TestF21ExternalAccessCardMounted(), TestF21DeploymentStatusMounted(), TestF21UseIngressStoreWired(), TestF21DeploymentStreamUsesAuthPrefix(), TestF21DeployApiStreamTargetIncludesAuth(),
        TestF22PasswordChangeModalWired(), TestF22PasswordMutationInvoked(), TestF22AvatarUploadWired(), TestF22AvatarDeleteWired(), TestF22ProfileZeroSecurityMockupComments(),
        TestF23TopologyWidgetFetchesBackend(), TestF23TopologyWidgetZeroHardcodedNodes(), TestF23TopologyWidgetLiveNodeStatus(), TestF23TopologyWidgetGraphLayoutCoordinates(), TestF23TopologyWidgetConnectionLinks()
    ]
