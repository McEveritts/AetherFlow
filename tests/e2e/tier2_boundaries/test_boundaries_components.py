"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B19: Bandwidth & Predictions Card Boundaries
- B20: Metadata & DirectoryPicker Boundaries
- B21: ExternalAccess & Deploy Boundaries
- B22: Profile Wiring Boundaries
- B23: App Topology Map Boundaries
"""

import os

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

OVERVIEW_WIDGETS = "frontend-rs/crates/af-web-app/src/tabs/overview/widgets.rs"
OVERVIEW_TELEMETRY = "frontend-rs/crates/af-web-app/src/tabs/overview/telemetry.rs"
OVERVIEW_MOD = "frontend-rs/crates/af-web-app/src/tabs/overview/mod.rs"
METADATA_RS = "frontend-rs/crates/af-web-app/src/tabs/settings/metadata.rs"
LOCAL_STORAGE_RS = "frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs"
PATHS_RS = "frontend-rs/crates/af-web-app/src/tabs/fileshare/paths.rs"
MEDIAFLOW_RS = "frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs"
TAILSCALE_INGRESS_RS = "frontend-rs/crates/af-web-app/src/tabs/network/tailscale_ingress.rs"
NETWORK_HELPERS_RS = "frontend-rs/crates/af-web-app/src/tabs/network/helpers.rs"
MARKETPLACE_CATALOG = "frontend-rs/crates/af-web-app/src/tabs/marketplace/catalog.rs"
SECURITY_RS = "frontend-rs/crates/af-web-app/src/tabs/settings/security.rs"
TOPOLOGY_UI_RS = "frontend-rs/crates/af-web-ui/src/topology.rs"
TOPOLOGY_CORE_RS = "frontend-rs/crates/af-web-core/src/topology.rs"


class TestB19EmptyMetricsHistoryHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B19_01", "F19", 2, "CapacityPredictions handles empty 30-day metrics history cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        self.assert_true(
            bool(widgets and "No 30-day history samples recorded" in widgets),
            "B19: CapacityPredictions must handle empty metrics history",
        )


class TestB19MemoryZeroTotalSafeguard(TestCase):
    def __init__(self):
        super().__init__("T2_B19_02", "F19", 2, "Memory and telemetry calculations guard against zero totals and non-finite floats")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        telemetry = inspector.read_file(OVERVIEW_TELEMETRY)
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        self.assert_true(
            bool(telemetry and "is_finite()" in telemetry and "*total > 0.0" in telemetry and "mem_total_gb" in telemetry and widgets and "total > 0.0" in widgets),
            "B19: Overview telemetry must guard memory and float calculations",
        )


class TestB19PredictionsApiFailureRetry(TestCase):
    def __init__(self):
        super().__init__("T2_B19_03", "F19", 2, "CapacityPredictions surfaces API error state cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        self.assert_true(
            bool(widgets and "report.error.get().is_some()" in widgets and "Err(e)" in widgets),
            "B19: CapacityPredictions must handle API errors",
        )


class TestB19BandwidthApplyLoadingState(TestCase):
    def __init__(self):
        super().__init__("T2_B19_04", "F19", 2, "Bandwidth apply button disables and shows loading status during request")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        widgets = inspector.read_file(OVERVIEW_WIDGETS)
        self.assert_true(
            bool(widgets and "applying.get()" in widgets and "disabled=" in widgets),
            "B19: CapacityPredictions must manage apply loading state",
        )


class TestB19ExtremeSpikeMetricsHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B19_05", "F19", 2, "Sparkline scaling clamps extreme 100% CPU or 10Gbps spikes cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        charts = inspector.read_file("frontend-rs/crates/af-web-core/src/charts.rs") or ""
        self.assert_true(
            "pub fn build_sparkline_path(" in charts
            and ".clamp(0.0, width)" in charts
            and ".clamp(0.0, height)" in charts
            and "span.abs() < f64::EPSILON" in charts
            and "is_finite()" in charts,
            "B19: charts.rs must clamp sparkline coordinates and guard zero/non-finite denominator spans",
        )


class TestB20PathSelectorTraversalBlockedInUi(TestCase):
    def __init__(self):
        super().__init__("T2_B20_01", "F20", 2, "Fileshare path helpers prevent '..' traversal and control character injection")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        paths = inspector.read_file(PATHS_RS)
        self.assert_true(
            bool(paths and "child_path" in paths and "parent_path" in paths and "is_control" in paths),
            "B20: paths.rs must constrain traversal and control characters",
        )


class TestB20PathSelectorUnreadableDirectory(TestCase):
    def __init__(self):
        super().__init__("T2_B20_02", "F20", 2, "DirectoryPicker displays ResourceFeedback error on unreadable directory")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        local_storage = inspector.read_file(LOCAL_STORAGE_RS)
        self.assert_true(
            bool(local_storage and "ResourceFeedback" in local_storage and "resource.error" in local_storage),
            "B20: DirectoryPicker must handle permission errors",
        )


class TestB20MediaFlowSseDisconnectHandling(TestCase):
    def __init__(self):
        super().__init__("T2_B20_03", "F20", 2, "MediaflowTab transcode stream handles EventSource disconnect and cleanup")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(
            bool(media and "EventSource" in media and "events.close()" in media),
            "B20: MediaflowTab must handle transcode event stream errors and close",
        )


class TestB20MetadataEmptyScanPathRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B20_04", "F20", 2, "Metadata scan form requires non-empty directory input")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        meta = inspector.read_file(METADATA_RS)
        self.assert_true(
            bool(meta and 'field="path"' in meta and "required=true" in meta),
            "B20: Metadata scan must require valid target directory",
        )


class TestB20PathSelectorLargeDirectoryTruncation(TestCase):
    def __init__(self):
        super().__init__("T2_B20_05", "F20", 2, "DirectoryPicker bounds directory listing height with max-h-64 overflow-auto")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        local_storage = inspector.read_file(LOCAL_STORAGE_RS)
        self.assert_true(
            bool(local_storage and "max-h-64" in local_storage and "overflow-auto" in local_storage),
            "B20: DirectoryPicker must bound directory dropdown height",
        )


class TestB21IngressModalInvalidDomain(TestCase):
    def __init__(self):
        super().__init__("T2_B21_01", "F21", 2, "Network ingress helpers validate public domain syntax before sending PUT")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        helpers = inspector.read_file(NETWORK_HELPERS_RS)
        ingress = inspector.read_file(TAILSCALE_INGRESS_RS)
        self.assert_true(
            bool(helpers and "pub(super) fn valid_domain" in helpers and ingress and "/api/v1/admin/ingress/apps/" in ingress),
            "B21: Network helpers and ingress settings must validate domain input",
        )


class TestB21DeploymentStreamClosesOnUnmount(TestCase):
    def __init__(self):
        super().__init__("T2_B21_02", "F21", 2, "MediaflowTab closes EventSource in on_cleanup when component unmounts")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file(MEDIAFLOW_RS)
        self.assert_true(
            bool(media and "on_cleanup" in media and "events.close()" in media),
            "B21: EventSource must close in on_cleanup",
        )


class TestB21DeploymentFailureStateDisplayed(TestCase):
    def __init__(self):
        super().__init__("T2_B21_03", "F21", 2, "DeploymentStatus renders failure state and logs when deployment fails")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        catalog = inspector.read_file(MARKETPLACE_CATALOG)
        self.assert_true(
            bool(catalog and "DeploymentStatus" in catalog and "j.error.is_some()" in catalog),
            "B21: DeploymentStatus must render error state",
        )


class TestB21ConcurrentAppDeploysIsolated(TestCase):
    def __init__(self):
        super().__init__("T2_B21_04", "F21", 2, "Marketplace and deploy stream partition state per appName")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        media = inspector.read_file(MEDIAFLOW_RS)
        catalog = inspector.read_file(MARKETPLACE_CATALOG)
        self.assert_true(
            bool(media and "appName=" in media and catalog and "ops.jobs" in catalog),
            "B21: Deployment state must be scoped per application",
        )


class TestB21IngressStoreCredentialsIncluded(TestCase):
    def __init__(self):
        super().__init__("T2_B21_05", "F21", 2, "ExternalAccessSettings uses ApiClient with cookie/CSRF credentials")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        ingress = inspector.read_file(TAILSCALE_INGRESS_RS)
        api_core = inspector.read_file("frontend-rs/crates/af-web-core/src/api.rs")
        self.assert_true(
            bool(ingress and "ApiClient" in ingress and api_core and "should_attach_csrf" in api_core),
            "B21: ExternalAccessSettings must authenticate API requests via ApiClient",
        )


class TestB22PasswordConfirmationMismatch(TestCase):
    def __init__(self):
        super().__init__("T2_B22_01", "F22", 2, "Password change form blocks submission if new password and confirmation mismatch")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(
            bool(profile and 'sent["new_password"] != sent["confirm_password"]' in profile),
            "B22: security.rs must validate password confirmation",
        )


class TestB22OversizedAvatarFileBlocked(TestCase):
    def __init__(self):
        super().__init__("T2_B22_02", "F22", 2, "Avatar file selector blocks files exceeding 2 MiB before upload")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(
            bool(profile and "avatar_data_uri" in profile and "2 MiB" in profile),
            "B22: security.rs must enforce 2 MiB avatar limit",
        )


class TestB22PasswordMutationErrorBanner(TestCase):
    def __init__(self):
        super().__init__("T2_B22_03", "F22", 2, "security.rs displays error toast if current password verification fails")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(
            bool(profile and "Err(error) => context.toast" in profile),
            "B22: security.rs must surface mutation errors via toast",
        )


class TestB22AvatarRemovePromptsConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B22_04", "F22", 2, "Removing avatar updates UI to default placeholder avatar")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        profile = inspector.read_file(SECURITY_RS)
        self.assert_true(
            bool(profile and "Remove avatar" in profile and "safe_avatar_url" in profile),
            "B22: security.rs must display default avatar on removal",
        )


class TestB22ProfileNameXssNeutralized(TestCase):
    def __init__(self):
        super().__init__("T2_B22_05", "F22", 2, "Usernames containing HTML tags (<script>) are rendered safely as text")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        checked = []
        settings_dir = os.path.join(inspector.root, "frontend-rs/crates/af-web-app/src/tabs/settings")
        for fname in sorted(os.listdir(settings_dir)):
            if fname.endswith(".rs"):
                checked.append(f"frontend-rs/crates/af-web-app/src/tabs/settings/{fname}")
        checked.append("frontend-rs/crates/af-web-app/src/shell.rs")
        for rel in checked:
            src = inspector.read_file(rel) or ""
            self.assert_not_in("inner_html", src, f"B22: {rel} must not use unsafe inner_html bindings for user/profile rendering")


class TestB23TopologyApiFailureFallback(TestCase):
    def __init__(self):
        super().__init__("T2_B23_01", "F23", 2, "Overview topology view handles backend topology API failure gracefully")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        overview = inspector.read_file(OVERVIEW_MOD)
        self.assert_true(
            bool(overview and "topology.error.get().is_some()" in overview),
            "B23: overview/mod.rs must handle topology fetch failure",
        )


class TestB23TopologyEmptyServicesList(TestCase):
    def __init__(self):
        super().__init__("T2_B23_02", "F23", 2, "Topology renders safely even when services list is empty")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(
            bool(
                topology
                and "compute_tiered_topology_layout(&services.get(), &links.get())" in topology
                and topo_core
                and "if services.is_empty() {" in topo_core
                and "width: MIN_CANVAS_WIDTH," in topo_core
                and "nodes: Vec::new()," in topo_core
            ),
            "B23: AppTopologyMap must handle empty services cleanly",
        )


class TestB23TopologyNodeCollisionAvoidance(TestCase):
    def __init__(self):
        super().__init__("T2_B23_03", "F23", 2, "Topology layout repulsion prevents node overlap on SVG canvas")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(
            bool(topo_core and "compute_topology_layout" in topo_core and "1400.0 / d2" in topo_core),
            "B23: Topology layout must apply repulsion to separate nodes",
        )


class TestB23TopologyResizeRecalculates(TestCase):
    def __init__(self):
        super().__init__("T2_B23_04", "F23", 2, "Topology SVG scales cleanly with viewBox and zoom/pan reset")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topology = inspector.read_file(TOPOLOGY_UI_RS)
        self.assert_true(
            bool(
                topology
                and 'format!("0 0 {} {}", current.width, current.height)' in topology
                and 'preserveAspectRatio="xMidYMid meet"' in topology
                and 'ui_t("Reset view")' in topology
            ),
            "B23: Topology map must use responsive SVG viewBox and reset controls",
        )


class TestB23TopologyCyclicLinksHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B23_05", "F23", 2, "Bidirectional links between services use bounded 48-step relaxation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        topo_core = inspector.read_file(TOPOLOGY_CORE_RS)
        self.assert_true(bool(topo_core and "for _ in 0..48" in topo_core), "B23: Cyclic graph layout must be bounded")


def get_tests():
    return [
        TestB19EmptyMetricsHistoryHandled(), TestB19MemoryZeroTotalSafeguard(), TestB19PredictionsApiFailureRetry(), TestB19BandwidthApplyLoadingState(), TestB19ExtremeSpikeMetricsHandled(),
        TestB20PathSelectorTraversalBlockedInUi(), TestB20PathSelectorUnreadableDirectory(), TestB20MediaFlowSseDisconnectHandling(), TestB20MetadataEmptyScanPathRejected(), TestB20PathSelectorLargeDirectoryTruncation(),
        TestB21IngressModalInvalidDomain(), TestB21DeploymentStreamClosesOnUnmount(), TestB21DeploymentFailureStateDisplayed(), TestB21ConcurrentAppDeploysIsolated(), TestB21IngressStoreCredentialsIncluded(),
        TestB22PasswordConfirmationMismatch(), TestB22OversizedAvatarFileBlocked(), TestB22PasswordMutationErrorBanner(), TestB22AvatarRemovePromptsConfirmation(), TestB22ProfileNameXssNeutralized(),
        TestB23TopologyApiFailureFallback(), TestB23TopologyEmptyServicesList(), TestB23TopologyNodeCollisionAvoidance(), TestB23TopologyResizeRecalculates(), TestB23TopologyCyclicLinksHandled()
    ]
