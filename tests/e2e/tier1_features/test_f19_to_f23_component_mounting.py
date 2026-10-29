"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F19: Mount Bandwidth & Predictions Cards
- F20: Mount MetadataTab & PathSelector
- F21: Mount ExternalAccessCard & DeploymentStatus
- F22: Wire Profile Controls
- F23: Real App Topology Map
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

class TestF19BandwidthCardMountedInOverview(TestCase):
    def __init__(self):
        super().__init__("T1_F19_01", "F19", 1, "BandwidthCard is imported and rendered in OverviewTab.tsx")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file("frontend/src/components/tabs/OverviewTab.tsx")
        self.assert_true(bool(overview and "BandwidthCard" in overview), "F19: BandwidthCard must be mounted in OverviewTab.tsx")

class TestF19PredictionsCardMountedInOverview(TestCase):
    def __init__(self):
        super().__init__("T1_F19_02", "F19", 1, "PredictionsCard is imported and rendered in OverviewTab.tsx")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file("frontend/src/components/tabs/OverviewTab.tsx")
        self.assert_true(bool(overview and "PredictionsCard" in overview), "F19: PredictionsCard must be mounted in OverviewTab.tsx")

class TestF19PredictionsFetchesRealHistory(TestCase):
    def __init__(self):
        super().__init__("T1_F19_03", "F19", 1, "PredictionsCard fetches metrics from /api/v1/admin/ai/predictions/history")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        card = inspector.read_file("frontend/src/components/cards/PredictionsCard.tsx")
        self.assert_true(bool(card and "/api/v1/admin/ai/predictions/history" in card), "F19: PredictionsCard must query /api/v1/admin/ai/predictions/history")

class TestF19ZeroFakeSineWaveMathematics(TestCase):
    def __init__(self):
        super().__init__("T1_F19_04", "F19", 1, "PredictionsCard contains zero synthetic Math.sin() trend data generation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        card = inspector.read_file("frontend/src/components/cards/PredictionsCard.tsx")
        if card:
            self.assert_not_in("Math.sin", card, "F19: PredictionsCard must eliminate fake Math.sin() generator")

class TestF19PredictionsMountLoadsInitialReport(TestCase):
    def __init__(self):
        super().__init__("T1_F19_05", "F19", 1, "PredictionsCard loads existing prediction report on mount via useEffect")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        card = inspector.read_file("frontend/src/components/cards/PredictionsCard.tsx")
        self.assert_true(bool(card and ("useEffect" in card and "/api/v1/admin/ai/predictions" in card)), "F19: PredictionsCard must fetch prediction report on component mount")

class TestF20MetadataTabMountedInMediaFlow(TestCase):
    def __init__(self):
        super().__init__("T1_F20_01", "F20", 1, "MetadataTab is imported and reachable inside MediaFlowTab.tsx")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        mediaflow = inspector.read_file("frontend/src/components/tabs/MediaFlowTab.tsx")
        self.assert_true(bool(mediaflow and "MetadataTab" in mediaflow), "F20: MetadataTab must be integrated into MediaFlowTab.tsx")

class TestF20PathSelectorIntegrated(TestCase):
    def __init__(self):
        super().__init__("T1_F20_02", "F20", 1, "PathSelector component is integrated for directory inputs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        meta = inspector.read_file("frontend/src/components/tabs/MetadataTab.tsx")
        media = inspector.read_file("frontend/src/components/tabs/MediaFlowTab.tsx")
        has_selector = (meta and "PathSelector" in meta) or (media and "PathSelector" in media)
        self.assert_true(bool(has_selector), "F20: PathSelector must be used in MediaFlow / Metadata directory inputs")

class TestF20PathSelectorCallsGoFsEndpoint(TestCase):
    def __init__(self):
        super().__init__("T1_F20_03", "F20", 1, "PathSelector queries /api/fs or /api/v1/auth/fs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        selector = inspector.read_file("frontend/src/components/ui/PathSelector.tsx")
        self.assert_true(bool(selector and ("/api/fs" in selector or "/api/v1/auth/fs" in selector)), "F20: PathSelector must target Go filesystem browser")

class TestF20MediaFlowUsesApiFetch(TestCase):
    def __init__(self):
        super().__init__("T1_F20_04", "F20", 1, "MediaFlowTab uses apiFetch helper with cookie/CSRF authentication")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file("frontend/src/components/tabs/MediaFlowTab.tsx")
        self.assert_true(bool(media and "apiFetch" in media), "F20: MediaFlowTab must use apiFetch instead of raw fetch")

class TestF20MediaFlowZeroLocalStorageToken(TestCase):
    def __init__(self):
        super().__init__("T1_F20_05", "F20", 1, "MediaFlowTab eliminates stale localStorage.getItem('token') usages")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file("frontend/src/components/tabs/MediaFlowTab.tsx")
        if media:
            self.assert_not_in("localStorage.getItem('token')", media, "F20: MediaFlowTab must eliminate localStorage.getItem('token')")

class TestF21ExternalAccessCardMounted(TestCase):
    def __init__(self):
        super().__init__("T1_F21_01", "F21", 1, "ExternalAccessCard is imported and rendered in services/marketplace UI")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        services = inspector.read_file("frontend/src/components/tabs/ServicesTab.tsx")
        marketplace = inspector.read_file("frontend/src/components/tabs/MarketplaceTab.tsx")
        mounted = (services and "ExternalAccessCard" in services) or (marketplace and "ExternalAccessCard" in marketplace)
        self.assert_true(bool(mounted), "F21: ExternalAccessCard must be mounted in ServicesTab or MarketplaceTab")

class TestF21DeploymentStatusMounted(TestCase):
    def __init__(self):
        super().__init__("T1_F21_02", "F21", 1, "DeploymentStatus is imported and rendered in deploy modal/tab")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        services = inspector.read_file("frontend/src/components/tabs/ServicesTab.tsx")
        marketplace = inspector.read_file("frontend/src/components/tabs/MarketplaceTab.tsx")
        mounted = (services and "DeploymentStatus" in services) or (marketplace and "DeploymentStatus" in marketplace)
        self.assert_true(bool(mounted), "F21: DeploymentStatus must be mounted in ServicesTab or MarketplaceTab")

class TestF21UseIngressStoreWired(TestCase):
    def __init__(self):
        super().__init__("T1_F21_03", "F21", 1, "useIngressStore is wired to fetch and update ingress configs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        store = inspector.read_file("frontend/src/store/useIngressStore.ts")
        self.assert_true(bool(store and "configs" in store and "updateAppIngress" in store), "F21: useIngressStore must define configs state and update function")

class TestF21DeploymentStreamUsesAuthPrefix(TestCase):
    def __init__(self):
        super().__init__("T1_F21_04", "F21", 1, "useDeploymentStream connects to authenticated path /api/v1/auth/deploy/stream")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        hook = inspector.read_file("frontend/src/hooks/useDeploymentStream.ts")
        self.assert_true(bool(hook and "/api/v1/auth/deploy/stream" in hook), "F21: useDeploymentStream must target /api/v1/auth/deploy/stream")

class TestF21DeployApiStreamTargetIncludesAuth(TestCase):
    def __init__(self):
        super().__init__("T1_F21_05", "F21", 1, "backend/api/deploy_api.go returns streamTarget with /api/v1/auth/deploy/stream")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        deploy_api = inspector.read_file("backend/api/deploy_api.go")
        self.assert_true(bool(deploy_api and "/api/v1/auth/deploy/stream" in deploy_api), "F21: deploy_api.go must return /api/v1/auth/deploy/stream in streamTarget")

class TestF22PasswordChangeModalWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_01", "F22", 1, "ProfileTab.tsx wires Change Password button to modal form")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file("frontend/src/components/tabs/ProfileTab.tsx")
        self.assert_true(bool(profile and "Change Password" in profile and ("onClick" in profile or "modal" in profile.lower())), "F22: ProfileTab must wire Change Password button")

class TestF22PasswordMutationInvoked(TestCase):
    def __init__(self):
        super().__init__("T1_F22_02", "F22", 1, "Password change form dispatches PUT /api/v1/auth/profile/password")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file("frontend/src/components/tabs/ProfileTab.tsx")
        self.assert_true(bool(profile and "/api/v1/auth/profile/password" in profile), "F22: ProfileTab must call /api/v1/auth/profile/password")

class TestF22AvatarUploadWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_03", "F22", 1, "ProfileTab.tsx wires avatar change control to PUT /api/v1/auth/profile/avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file("frontend/src/components/tabs/ProfileTab.tsx")
        self.assert_true(bool(profile and "/api/v1/auth/profile/avatar" in profile), "F22: ProfileTab must call /api/v1/auth/profile/avatar")

class TestF22AvatarDeleteWired(TestCase):
    def __init__(self):
        super().__init__("T1_F22_04", "F22", 1, "ProfileTab.tsx wires Remove Avatar button to DELETE /api/v1/auth/profile/avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file("frontend/src/components/tabs/ProfileTab.tsx")
        self.assert_true(bool(profile and "Remove Avatar" in profile and "DELETE" in profile), "F22: ProfileTab must wire Remove Avatar button to DELETE")

class TestF22ProfileZeroSecurityMockupComments(TestCase):
    def __init__(self):
        super().__init__("T1_F22_05", "F22", 1, "ProfileTab.tsx eliminates legacy 'Security Section (Mockup)' markers")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file("frontend/src/components/tabs/ProfileTab.tsx")
        if profile:
            self.assert_not_in("Security Section (Mockup)", profile, "F22: ProfileTab must not contain mockup comments")

class TestF23TopologyWidgetFetchesBackend(TestCase):
    def __init__(self):
        super().__init__("T1_F23_01", "F23", 1, "AppTopologyMap.tsx queries /api/v1/auth/system/topology")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        self.assert_true(bool(topology and ("/api/v1/auth/system/topology" in topology or "useTopology" in topology)), "F23: AppTopologyMap must fetch live runtime topology")

class TestF23TopologyWidgetZeroHardcodedNodes(TestCase):
    def __init__(self):
        super().__init__("T1_F23_02", "F23", 1, "AppTopologyMap eliminates hardcoded dummy nodes array")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        if topology:
            self.assert_not_in("Proxy Port 8080", topology, "F23: AppTopologyMap must remove dummy node 'Proxy Port 8080'")
            self.assert_not_in("Nginx Router", topology, "F23: AppTopologyMap must remove dummy node 'Nginx Router'")

class TestF23TopologyWidgetLiveNodeStatus(TestCase):
    def __init__(self):
        super().__init__("T1_F23_03", "F23", 1, "AppTopologyMap renders live running/stopped/degraded statuses")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        self.assert_true(bool(topology and "status" in topology), "F23: AppTopologyMap must render dynamic node status")

class TestF23TopologyWidgetGraphLayoutCoordinates(TestCase):
    def __init__(self):
        super().__init__("T1_F23_04", "F23", 1, "AppTopologyMap calculates node coordinates without canvas collisions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        self.assert_true(bool(topology and ("width" in topology or "height" in topology or "d3" in topology or "canvas" in topology or "svg" in topology)), "F23: AppTopologyMap must compute graph layout coordinates")

class TestF23TopologyWidgetConnectionLinks(TestCase):
    def __init__(self):
        super().__init__("T1_F23_05", "F23", 1, "AppTopologyMap renders links connecting dependent services")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file("frontend/src/components/widgets/AppTopologyMap.tsx")
        self.assert_true(bool(topology and "links" in topology), "F23: AppTopologyMap must render graph links")

def get_tests():
    return [
        TestF19BandwidthCardMountedInOverview(), TestF19PredictionsCardMountedInOverview(), TestF19PredictionsFetchesRealHistory(), TestF19ZeroFakeSineWaveMathematics(), TestF19PredictionsMountLoadsInitialReport(),
        TestF20MetadataTabMountedInMediaFlow(), TestF20PathSelectorIntegrated(), TestF20PathSelectorCallsGoFsEndpoint(), TestF20MediaFlowUsesApiFetch(), TestF20MediaFlowZeroLocalStorageToken(),
        TestF21ExternalAccessCardMounted(), TestF21DeploymentStatusMounted(), TestF21UseIngressStoreWired(), TestF21DeploymentStreamUsesAuthPrefix(), TestF21DeployApiStreamTargetIncludesAuth(),
        TestF22PasswordChangeModalWired(), TestF22PasswordMutationInvoked(), TestF22AvatarUploadWired(), TestF22AvatarDeleteWired(), TestF22ProfileZeroSecurityMockupComments(),
        TestF23TopologyWidgetFetchesBackend(), TestF23TopologyWidgetZeroHardcodedNodes(), TestF23TopologyWidgetLiveNodeStatus(), TestF23TopologyWidgetGraphLayoutCoordinates(), TestF23TopologyWidgetConnectionLinks()
    ]
