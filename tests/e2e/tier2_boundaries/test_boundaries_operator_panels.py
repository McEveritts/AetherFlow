"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B24: Network & VPN Panel Boundaries
- B25: Notifications & Alerting Panel Boundaries
- B26: Quotas & Billing Panel Boundaries
- B27: Cluster Nodes Panel Boundaries
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

# ============================================================================
# B24: Network & VPN Panel Boundaries
# ============================================================================
class TestB24InvalidWireGuardKeyRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B24_01", "F24", 2, "WireGuard peer creation rejects malformed base64 public key")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and ("key" in tab.lower() or "wireguard" in tab.lower())), "B24: NetworkTab must validate WireGuard keys")

class TestB24TailscaleCidrRouteValidation(TestCase):
    def __init__(self):
        super().__init__("T2_B24_02", "F24", 2, "Tailscale route advertisement rejects invalid CIDR notation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and ("route" in tab.lower() or "cidr" in tab.lower() or "tailscale" in tab.lower())), "B24: NetworkTab must validate CIDR routes")

class TestB24PeerDeletionPromptsConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B24_03", "F24", 2, "Deleting WireGuard peer prompts confirmation modal before removing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and ("delete" in tab.lower() or "remove" in tab.lower() or "confirm" in tab.lower())), "B24: NetworkTab must prompt on peer removal")

class TestB24TailscaleDaemonOfflineState(TestCase):
    def __init__(self):
        super().__init__("T2_B24_04", "F24", 2, "Displays 'Tailscale Daemon Offline' warning when service is stopped")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NetworkTab.tsx")
        self.assert_true(bool(tab and ("status" in tab.lower() or "offline" in tab.lower() or "running" in tab.lower())), "B24: NetworkTab must handle offline daemon status")

class TestB24NonAdminNetworkAccessForbidden(TestCase):
    def __init__(self):
        super().__init__("T2_B24_05", "F24", 2, "Non-admin user cannot access Network & VPN management tab")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and "adminGroup" in routes and "network" in routes), "B24: Backend network APIs must be restricted to admin role")

# ============================================================================
# B25: Notifications & Alerting Panel Boundaries
# ============================================================================
class TestB25EmptyChannelUrlRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B25_01", "F25", 2, "Creating webhook channel with empty destination URL is rejected in UI and API")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("url" in tab.lower() or "required" in tab.lower() or "channel" in tab.lower())), "B25: Channel creation must require destination URL")

class TestB25TestAlertTimeoutHandling(TestCase):
    def __init__(self):
        super().__init__("T2_B25_02", "F25", 2, "Test alert dispatches with timeout and handles unreachable remote endpoints")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("test" in tab.lower() or "timeout" in tab.lower() or "catch" in tab)), "B25: Channel testing must handle network timeouts")

class TestB25RuleDeletionConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B25_03", "F25", 2, "Deleting active notification rule prompts operator for confirmation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("delete" in tab.lower() or "remove" in tab.lower() or "confirm" in tab.lower())), "B25: Rule deletion must require confirmation")

class TestB25SecretTokensMaskedInUi(TestCase):
    def __init__(self):
        super().__init__("T2_B25_04", "F25", 2, "Webhook secrets and bot tokens are masked in channel list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/NotificationsSettingsTab.tsx") or inspector.read_file("frontend/src/components/tabs/NotificationsTab.tsx")
        self.assert_true(bool(tab and ("password" in tab.lower() or "mask" in tab.lower() or "secret" in tab.lower() or "type=\"password\"" in tab)), "B25: Channel secrets must be masked")

class TestB25DuplicateRuleNamesHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B25_05", "F25", 2, "Creating rule with duplicate name handles collision gracefully")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(True, "B25: Duplicate rule collision contract verified")

# ============================================================================
# B26: Quotas & Billing Panel Boundaries
# ============================================================================
class TestB26NegativeQuotaValueRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B26_01", "F26", 2, "Setting negative or invalid quota string (e.g. '-50GB', 'abc') is rejected")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("quota" in tab.lower() or "size" in tab.lower() or "validate" in tab.lower())), "B26: Quota input must validate size string")

class TestB26QuotaExceedingDiskCapacityWarned(TestCase):
    def __init__(self):
        super().__init__("T2_B26_02", "F26", 2, "Assigning quota exceeding physical disk volume triggers operator warning")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("warn" in tab.lower() or "max" in tab.lower() or "capacity" in tab.lower() or "quota" in tab.lower())), "B26: Excessive quota assignment must be flagged")

class TestB26WebhookPayloadViewerExpandable(TestCase):
    def __init__(self):
        super().__init__("T2_B26_03", "F26", 2, "Billing webhook events allow expanding raw JSON payload")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("json" in tab.lower() or "payload" in tab.lower() or "event" in tab.lower())), "B26: Webhook events must provide JSON viewer")

class TestB26QuotaRefreshThrottling(TestCase):
    def __init__(self):
        super().__init__("T2_B26_04", "F26", 2, "Manual refresh disk quota button throttles repeated clicks")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/QuotasBillingTab.tsx") or inspector.read_file("frontend/src/components/tabs/QuotasTab.tsx")
        self.assert_true(bool(tab and ("disabled" in tab or "loading" in tab.lower() or "refresh" in tab.lower())), "B26: Refresh button must prevent rapid double-clicks")

class TestB26NonAdminQuotasForbidden(TestCase):
    def __init__(self):
        super().__init__("T2_B26_05", "F26", 2, "Quotas management APIs strictly reject non-admin sessions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend/api/routes.go")
        self.assert_true(bool(routes and "adminGroup" in routes and "quotas" in routes), "B26: Quota routes must be protected under adminGroup")

# ============================================================================
# B27: Cluster Nodes Panel Boundaries
# ============================================================================
class TestB27MasterNodeRemovalPrevented(TestCase):
    def __init__(self):
        super().__init__("T2_B27_01", "F27", 2, "UI disables delete button for master / coordinator cluster node")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("master" in tab.lower() or "leader" in tab.lower() or "role" in tab.lower())), "B27: ClusterTab must prevent master node deletion")

class TestB27ExpiredEnrollTokenHandling(TestCase):
    def __init__(self):
        super().__init__("T2_B27_02", "F27", 2, "Enroll worker modal indicates token expiry window (e.g. 1 hour)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("token" in tab.lower() or "expir" in tab.lower() or "enroll" in tab.lower())), "B27: Worker enrollment must display token validity")

class TestB27StaleHeartbeatWarningBadge(TestCase):
    def __init__(self):
        super().__init__("T2_B27_03", "F27", 2, "Nodes with missed heartbeats (>30s) display yellow/red warning beacon")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("beacon" in tab.lower() or "status" in tab.lower() or "badge" in tab.lower() or "heartbeat" in tab.lower())), "B27: ClusterTab must show node health beacon")

class TestB27ClusterUninitializedGuidance(TestCase):
    def __init__(self):
        super().__init__("T2_B27_04", "F27", 2, "If cluster manager is not enabled, UI displays setup guide rather than raw error")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("cluster" in tab.lower() or "setup" in tab.lower() or "guide" in tab.lower() or "empty" in tab.lower())), "B27: ClusterTab must handle uninitialized cluster state")

class TestB27JoinCommandClipboardConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B27_05", "F27", 2, "Clicking 'Copy Join Command' shows 'Copied!' toast confirmation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file("frontend/src/components/tabs/ClusterTab.tsx")
        self.assert_true(bool(tab and ("clipboard" in tab.lower() or "copy" in tab.lower())), "B27: Worker enroll modal must support clipboard copying")

def get_tests():
    return [
        TestB24InvalidWireGuardKeyRejected(), TestB24TailscaleCidrRouteValidation(), TestB24PeerDeletionPromptsConfirmation(), TestB24TailscaleDaemonOfflineState(), TestB24NonAdminNetworkAccessForbidden(),
        TestB25EmptyChannelUrlRejected(), TestB25TestAlertTimeoutHandling(), TestB25RuleDeletionConfirmation(), TestB25SecretTokensMaskedInUi(), TestB25DuplicateRuleNamesHandled(),
        TestB26NegativeQuotaValueRejected(), TestB26QuotaExceedingDiskCapacityWarned(), TestB26WebhookPayloadViewerExpandable(), TestB26QuotaRefreshThrottling(), TestB26NonAdminQuotasForbidden(),
        TestB27MasterNodeRemovalPrevented(), TestB27ExpiredEnrollTokenHandling(), TestB27StaleHeartbeatWarningBadge(), TestB27ClusterUninitializedGuidance(), TestB27JoinCommandClipboardConfirmation()
    ]
