"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F24: Network & VPN Operator Panel
- F25: Notifications & Alerting Panel
- F26: Storage Quotas Panel
- F27: Cluster Nodes Panel
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

TABS_MOD = "frontend-rs/crates/af-web-app/src/tabs/mod.rs"
STATE_RS = "frontend-rs/crates/af-web-app/src/state.rs"
NETWORK_MOD = "frontend-rs/crates/af-web-app/src/tabs/network/mod.rs"
WIREGUARD_RS = "frontend-rs/crates/af-web-app/src/tabs/network/wireguard.rs"
TAILSCALE_RS = "frontend-rs/crates/af-web-app/src/tabs/network/tailscale.rs"
NOTIFICATIONS_RS = "frontend-rs/crates/af-web-app/src/tabs/notifications.rs"
QUOTAS_RS = "frontend-rs/crates/af-web-app/src/tabs/quotas.rs"
CLUSTER_RS = "frontend-rs/crates/af-web-app/src/tabs/cluster.rs"


class TestF24NetworkTabComponentExists(TestCase):
    def __init__(self):
        super().__init__("T1_F24_01", "F24", 1, "NetworkTab exists in frontend-rs/crates/af-web-app/src/tabs/network/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists(NETWORK_MOD) and inspector.file_exists(WIREGUARD_RS) and inspector.file_exists(TAILSCALE_RS)
        self.assert_true(exists, "F24: frontend-rs network tab modules must exist")


class TestF24NetworkTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F24_02", "F24", 1, "NetworkTab is registered in TabId navigation and TabRouter")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        tabs = inspector.read_file(TABS_MOD)
        mounted = bool(state and "TabId::Network" in state and tabs and "network::NetworkTab" in tabs)
        self.assert_true(mounted, "F24: NetworkTab must be navigable via TabId::Network and mounted in TabRouter")


class TestF24WireGuardPeersDisplay(TestCase):
    def __init__(self):
        super().__init__("T1_F24_03", "F24", 1, "Network wireguard.rs displays WireGuard peers and key generation controls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(WIREGUARD_RS)
        self.assert_true(
            bool(tab and "/api/v1/admin/network/wireguard/keygen" in tab and "/api/v1/admin/network/wireguard/peers" in tab),
            "F24: wireguard.rs must implement WireGuard keygen and peer management",
        )


class TestF24TailscaleRoutesControls(TestCase):
    def __init__(self):
        super().__init__("T1_F24_04", "F24", 1, "Network tailscale.rs displays Tailscale status and route advertisement")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(TAILSCALE_RS)
        self.assert_true(
            bool(tab and "/api/v1/admin/network/tailscale/routes" in tab and "/api/v1/admin/network/tailscale/connect" in tab),
            "F24: tailscale.rs must implement Tailscale status and route controls",
        )


class TestF24NetworkBackendEndpointsWired(TestCase):
    def __init__(self):
        super().__init__("T1_F24_05", "F24", 1, "NetworkTab queries /api/v1/admin/network/status")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NETWORK_MOD)
        self.assert_true(bool(tab and "/api/v1/admin/network/status" in tab), "F24: network/mod.rs must query backend network status API")


class TestF25NotificationsTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F25_01", "F25", 1, "NotificationsTab exists in frontend-rs/crates/af-web-app/src/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(inspector.file_exists(NOTIFICATIONS_RS), "F25: notifications.rs must exist")


class TestF25NotificationsTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F25_02", "F25", 1, "NotificationsTab is registered in TabId navigation and TabRouter")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        tabs = inspector.read_file(TABS_MOD)
        mounted = bool(state and "TabId::Notifications" in state and tabs and "notifications::NotificationsTab" in tabs)
        self.assert_true(mounted, "F25: NotificationsTab must be navigable via TabId::Notifications and mounted in TabRouter")


class TestF25NotificationRulesList(TestCase):
    def __init__(self):
        super().__init__("T1_F25_03", "F25", 1, "NotificationsTab lists alert rules with enabled toggles")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/notifications/rules" in tab), "F25: notifications.rs must manage notification rules")


class TestF25NotificationChannelsManagement(TestCase):
    def __init__(self):
        super().__init__("T1_F25_04", "F25", 1, "NotificationsTab supports channel management (discord, slack, email, webhook)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/notifications/channels" in tab), "F25: notifications.rs must manage delivery channels")


class TestF25TestNotificationChannelTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F25_05", "F25", 1, "NotificationsTab provides channel test trigger")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/notifications/channels/{}/test" in tab), "F25: notifications.rs must support testing channels")


class TestF26QuotasTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F26_01", "F26", 1, "QuotasTab exists in frontend-rs/crates/af-web-app/src/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(inspector.file_exists(QUOTAS_RS), "F26: quotas.rs must exist")


class TestF26QuotasMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F26_02", "F26", 1, "QuotasTab is registered in TabId navigation and TabRouter")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        tabs = inspector.read_file(TABS_MOD)
        mounted = bool(state and "TabId::Quotas" in state and tabs and "quotas::QuotasTab" in tabs)
        self.assert_true(mounted, "F26: QuotasTab must be navigable via TabId::Quotas and mounted in TabRouter")


class TestF26UserQuotasTable(TestCase):
    def __init__(self):
        super().__init__("T1_F26_03", "F26", 1, "QuotasTab lists user storage usage and quota thresholds")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/quotas" in tab), "F26: quotas.rs must display user quotas")


class TestF26QuotaEditModal(TestCase):
    def __init__(self):
        super().__init__("T1_F26_04", "F26", 1, "QuotasTab provides per-user quota editor wired to PUT /api/v1/admin/quotas/{id}")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/quotas/{id}" in tab and ".put(" in tab), "F26: quotas.rs must allow updating user storage quota")


class TestF26QuotaRefreshTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F26_05", "F26", 1, "QuotasTab provides manual disk usage refresh trigger")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "/api/v1/admin/quotas/{id}/refresh" in tab), "F26: quotas.rs must allow refreshing quota stats")


class TestF27ClusterTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F27_01", "F27", 1, "ClusterTab exists in frontend-rs/crates/af-web-app/src/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(inspector.file_exists(CLUSTER_RS), "F27: cluster.rs must exist")


class TestF27ClusterTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F27_02", "F27", 1, "ClusterTab is registered in TabId navigation and TabRouter")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        state = inspector.read_file(STATE_RS)
        tabs = inspector.read_file(TABS_MOD)
        mounted = bool(state and "TabId::Cluster" in state and tabs and "cluster::ClusterTab" in tabs)
        self.assert_true(mounted, "F27: ClusterTab must be navigable via TabId::Cluster and mounted in TabRouter")


class TestF27ClusterNodesList(TestCase):
    def __init__(self):
        super().__init__("T1_F27_03", "F27", 1, "ClusterTab lists worker nodes with status, CPU, and memory")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(CLUSTER_RS)
        self.assert_true(bool(tab and "/api/v1/admin/cluster/nodes" in tab), "F27: cluster.rs must display cluster nodes")


class TestF27ClusterEnrollWorkerModal(TestCase):
    def __init__(self):
        super().__init__("T1_F27_04", "F27", 1, "ClusterTab provides Enroll Worker modal with join token")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(CLUSTER_RS)
        self.assert_true(bool(tab and "/api/v1/admin/cluster/enroll" in tab and "enrollment_token" in tab), "F27: cluster.rs must provide worker enrollment modal")


class TestF27ClusterNodeRemovalAction(TestCase):
    def __init__(self):
        super().__init__("T1_F27_05", "F27", 1, "ClusterTab wires node removal to DELETE /api/v1/admin/cluster/nodes/:id")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(CLUSTER_RS)
        self.assert_true(bool(tab and "/api/v1/admin/cluster/nodes/{}" in tab and ".delete(" in tab), "F27: cluster.rs must support removing worker nodes")


def get_tests():
    return [
        TestF24NetworkTabComponentExists(), TestF24NetworkTabMountedInSidebar(), TestF24WireGuardPeersDisplay(), TestF24TailscaleRoutesControls(), TestF24NetworkBackendEndpointsWired(),
        TestF25NotificationsTabExists(), TestF25NotificationsTabMountedInSidebar(), TestF25NotificationRulesList(), TestF25NotificationChannelsManagement(), TestF25TestNotificationChannelTrigger(),
        TestF26QuotasTabExists(), TestF26QuotasMountedInSidebar(), TestF26UserQuotasTable(), TestF26QuotaEditModal(), TestF26QuotaRefreshTrigger(),
        TestF27ClusterTabExists(), TestF27ClusterTabMountedInSidebar(), TestF27ClusterNodesList(), TestF27ClusterEnrollWorkerModal(), TestF27ClusterNodeRemovalAction()
    ]
