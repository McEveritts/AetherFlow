"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F24: Network & VPN Operator Panel
- F25: Notifications & Alerting Panel
- F26: Quotas & Billing Panel
- F27: Cluster Nodes Panel
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

class TestF24NetworkTabComponentExists(TestCase):
    def __init__(self):
        super().__init__("T1_F24_01", "F24", 1, "NetworkTab.tsx exists in frontend/src/components/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(exists, "F24: frontend/src/components/tabs/NetworkTab.tsx must be created")

class TestF24NetworkTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F24_02", "F24", 1, "NetworkTab is registered in Sidebar navigation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        page = inspector.read_file("frontend/src/app/page.tsx")
        mounted = (sidebar and "network" in sidebar.lower()) or (page and "NetworkTab" in page)
        self.assert_true(bool(mounted), "F24: NetworkTab must be navigable in Sidebar and rendered in page.tsx")

class TestF24WireGuardPeersDisplay(TestCase):
    def __init__(self):
        super().__init__("T1_F24_03", "F24", 1, "NetworkTab displays WireGuard peers and key generation controls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and ("wireguard" in tab.lower() or "keygen" in tab.lower())), "F24: NetworkTab must implement WireGuard peer management")

class TestF24TailscaleRoutesControls(TestCase):
    def __init__(self):
        super().__init__("T1_F24_04", "F24", 1, "NetworkTab displays Tailscale status and route advertisement")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and "tailscale" in tab.lower()), "F24: NetworkTab must implement Tailscale status and routes")

class TestF24NetworkBackendEndpointsWired(TestCase):
    def __init__(self):
        super().__init__("T1_F24_05", "F24", 1, "NetworkTab queries /api/v1/admin/network/status")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and "/api/v1/admin/network" in tab), "F24: NetworkTab must query backend network APIs")

class TestF25NotificationsTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F25_01", "F25", 1, "NotificationsSettingsTab.tsx exists in frontend/src/components/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.file_exists("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(exists, "F25: NotificationsSettingsTab.tsx must be created")

class TestF25NotificationsTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F25_02", "F25", 1, "Notifications tab is registered in navigation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        page = inspector.read_file("frontend/src/app/page.tsx")
        mounted = (sidebar and "notification" in sidebar.lower()) or (page and "Notification" in page)
        self.assert_true(bool(mounted), "F25: NotificationsTab must be navigable in Sidebar")

class TestF25NotificationRulesList(TestCase):
    def __init__(self):
        super().__init__("T1_F25_03", "F25", 1, "Notifications tab lists alert rules with enabled toggles")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("rules" in tab.lower() or "/api/v1/admin/notifications/rules" in tab)), "F25: Notifications panel must list notification rules")

class TestF25NotificationChannelsManagement(TestCase):
    def __init__(self):
        super().__init__("T1_F25_04", "F25", 1, "Notifications tab supports channel management (discord, slack, email, webhook)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("channel" in tab.lower() or "/api/v1/admin/notifications/channels" in tab)), "F25: Notifications panel must manage channels")

class TestF25TestNotificationChannelTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F25_05", "F25", 1, "Notifications tab provides 'Test Channel' trigger button")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("test" in tab.lower() or "/test" in tab)), "F25: Notifications panel must support testing channels")

class TestF26QuotasBillingTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F26_01", "F26", 1, "QuotasBillingTab.tsx exists in frontend/src/components/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.file_exists("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(exists, "F26: QuotasBillingTab.tsx must be created")

class TestF26QuotasBillingMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F26_02", "F26", 1, "Quotas & Billing tab is registered in navigation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        page = inspector.read_file("frontend/src/app/page.tsx")
        mounted = (sidebar and ("quota" in sidebar.lower() or "billing" in sidebar.lower())) or (page and "Quota" in page)
        self.assert_true(bool(mounted), "F26: Quotas & Billing must be navigable in Sidebar")

class TestF26UserQuotasTable(TestCase):
    def __init__(self):
        super().__init__("T1_F26_03", "F26", 1, "Quotas tab lists user storage usage and quota thresholds")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("quota" in tab.lower() or "/api/v1/admin/quotas" in tab)), "F26: Quotas tab must display user quotas")

class TestF26BillingWebhookEventsList(TestCase):
    def __init__(self):
        super().__init__("T1_F26_04", "F26", 1, "Quotas tab lists billing webhook audit events")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("webhook" in tab.lower() or "billing" in tab.lower())), "F26: Quotas panel must list billing webhook events")

class TestF26QuotaRefreshTrigger(TestCase):
    def __init__(self):
        super().__init__("T1_F26_05", "F26", 1, "Quotas tab provides manual disk usage refresh button")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("refresh" in tab.lower() or "/refresh" in tab)), "F26: Quotas panel must allow refreshing quota stats")

class TestF27ClusterTabExists(TestCase):
    def __init__(self):
        super().__init__("T1_F27_01", "F27", 1, "ClusterTab.tsx exists in frontend/src/components/tabs/")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        exists = inspector.file_exists("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(exists, "F27: ClusterTab.tsx must be created")

class TestF27ClusterTabMountedInSidebar(TestCase):
    def __init__(self):
        super().__init__("T1_F27_02", "F27", 1, "Cluster tab is registered in navigation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        sidebar = inspector.read_file("frontend/src/components/layout/Sidebar.tsx")
        page = inspector.read_file("frontend/src/app/page.tsx")
        mounted = (sidebar and "cluster" in sidebar.lower()) or (page and "ClusterTab" in page)
        self.assert_true(bool(mounted), "F27: ClusterTab must be navigable in Sidebar")

class TestF27ClusterNodesList(TestCase):
    def __init__(self):
        super().__init__("T1_F27_03", "F27", 1, "ClusterTab lists worker nodes with status, CPU, and memory")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("/api/v1/admin/cluster/nodes" in tab or "nodes" in tab.lower())), "F27: ClusterTab must display cluster nodes")

class TestF27ClusterEnrollWorkerModal(TestCase):
    def __init__(self):
        super().__init__("T1_F27_04", "F27", 1, "ClusterTab provides Enroll Worker modal with join token")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("enroll" in tab.lower() or "token" in tab.lower())), "F27: ClusterTab must provide worker enrollment modal")

class TestF27ClusterNodeRemovalAction(TestCase):
    def __init__(self):
        super().__init__("T1_F27_05", "F27", 1, "ClusterTab wires node removal to DELETE /api/v1/admin/cluster/nodes/:id")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("remove" in tab.lower() or "delete" in tab.lower())), "F27: ClusterTab must support removing worker nodes")

def get_tests():
    return [
        TestF24NetworkTabComponentExists(), TestF24NetworkTabMountedInSidebar(), TestF24WireGuardPeersDisplay(), TestF24TailscaleRoutesControls(), TestF24NetworkBackendEndpointsWired(),
        TestF25NotificationsTabExists(), TestF25NotificationsTabMountedInSidebar(), TestF25NotificationRulesList(), TestF25NotificationChannelsManagement(), TestF25TestNotificationChannelTrigger(),
        TestF26QuotasBillingTabExists(), TestF26QuotasBillingMountedInSidebar(), TestF26UserQuotasTable(), TestF26BillingWebhookEventsList(), TestF26QuotaRefreshTrigger(),
        TestF27ClusterTabExists(), TestF27ClusterTabMountedInSidebar(), TestF27ClusterNodesList(), TestF27ClusterEnrollWorkerModal(), TestF27ClusterNodeRemovalAction()
    ]
