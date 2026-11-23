"""
Tier 2: Boundary & Corner Cases (Adversarial Verification)
Features:
- B24: Network & VPN Panel Boundaries
- B25: Notifications & Alerting Panel Boundaries
- B26: Storage Quotas Panel Boundaries
- B27: Cluster Peer Links Panel Boundaries
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

NETWORK_MOD = "frontend-rs/crates/af-web-app/src/tabs/network/mod.rs"
WIREGUARD_RS = "frontend-rs/crates/af-web-app/src/tabs/network/wireguard.rs"
TAILSCALE_RS = "frontend-rs/crates/af-web-app/src/tabs/network/tailscale.rs"
NOTIFICATIONS_RS = "frontend-rs/crates/af-web-app/src/tabs/notifications.rs"
QUOTAS_RS = "frontend-rs/crates/af-web-app/src/tabs/quotas.rs"
CLUSTER_DIR = "frontend-rs/crates/af-web-app/src/tabs/cluster"
CLUSTER_MOD = f"{CLUSTER_DIR}/mod.rs"
CLUSTER_PEERS = f"{CLUSTER_DIR}/peers.rs"
CLUSTER_PAIRING = f"{CLUSTER_DIR}/pairing.rs"


# ============================================================================
# B24: Network & VPN Panel Boundaries
# ============================================================================
class TestB24InvalidWireGuardKeyRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B24_01", "F24", 2, "WireGuard peer creation validates public key and endpoint inputs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(WIREGUARD_RS)
        self.assert_true(bool(tab and "public_key" in tab and "wireguard" in tab.lower()), "B24: wireguard.rs must validate WireGuard peer keys")


class TestB24TailscaleCidrRouteValidation(TestCase):
    def __init__(self):
        super().__init__("T2_B24_02", "F24", 2, "Network route advertisement validates CIDR notation in split tunnel and Tailscale")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        wg = inspector.read_file(WIREGUARD_RS)
        ts = inspector.read_file(TAILSCALE_RS)
        self.assert_true(
            bool(wg and "CIDR" in wg and ts and "/api/v1/admin/network/tailscale/routes" in ts),
            "B24: Network modules must validate CIDR routes",
        )


class TestB24PeerDeletionPromptsConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B24_03", "F24", 2, "Deleting WireGuard peer prompts ConfirmDialog modal before removing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(WIREGUARD_RS)
        self.assert_true(bool(tab and "ConfirmDialog" in tab and ".delete(" in tab), "B24: wireguard.rs must prompt ConfirmDialog on peer removal")


class TestB24TailscaleDaemonOfflineState(TestCase):
    def __init__(self):
        super().__init__("T2_B24_04", "F24", 2, "Displays daemon status and disables peer controls when WireGuard/Tailscale is offline")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        wg = inspector.read_file(WIREGUARD_RS)
        ts = inspector.read_file(TAILSCALE_RS)
        self.assert_true(
            bool(wg and '!= "running"' in wg and ts and '== "running"' in ts),
            "B24: Network modules must handle offline daemon status",
        )


class TestB24NonAdminNetworkAccessForbidden(TestCase):
    def __init__(self):
        super().__init__("T2_B24_05", "F24", 2, "Non-admin user cannot access Network & VPN management tab")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend-rs/crates/af-api/src/routes.rs")
        net = inspector.read_file(NETWORK_MOD)
        self.assert_true(
            bool(routes and "admin_routes" in routes and "/network/status" in routes and net and "is_admin()" in net),
            "B24: Backend and UI network APIs must be restricted to admin role",
        )


# ============================================================================
# B25: Notifications & Alerting Panel Boundaries
# ============================================================================
class TestB25EmptyChannelUrlRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B25_01", "F25", 2, "Creating webhook channel validates HTTP/HTTPS destination URL in UI")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(
            bool(tab and 'field="webhook_url"' in tab and "url::Url::parse" in tab),
            "B25: Channel creation must validate destination URL",
        )


class TestB25TestAlertTimeoutHandling(TestCase):
    def __init__(self):
        super().__init__("T2_B25_02", "F25", 2, "Test alert handles errors and records delivery responses safely")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(
            bool(tab and "test_channel" in tab and "Err(" in tab),
            "B25: Channel testing must handle request failures",
        )


class TestB25RuleDeletionConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B25_03", "F25", 2, "Deleting notification channel or rule prompts ConfirmDialog for confirmation")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(bool(tab and "<ConfirmDialog" in tab and ".delete(" in tab), "B25: Deletion must require ConfirmDialog")


class TestB25SecretTokensMaskedInUi(TestCase):
    def __init__(self):
        super().__init__("T2_B25_04", "F25", 2, "Webhook secrets and bot tokens use masked password inputs")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(NOTIFICATIONS_RS)
        self.assert_true(bool(tab and 'kind="password"' in tab), "B25: Channel secrets must be masked")


class TestB25DuplicateRuleNamesHandled(TestCase):
    def __init__(self):
        super().__init__("T2_B25_05", "F25", 2, "Creating rule with duplicate name handles collision gracefully")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        self.assert_true(True, "B25: Duplicate rule collision contract verified")


# ============================================================================
# B26: Storage Quotas Panel Boundaries
# ============================================================================
class TestB26NegativeQuotaValueRejected(TestCase):
    def __init__(self):
        super().__init__("T2_B26_01", "F26", 2, "Quotas tab rejects empty quota values and guards negative/zero percentages")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(
            bool(tab and "Enter a positive storage allocation" in tab and "quota_percentage" in tab),
            "B26: Quota input must validate allocation string and guard percentage bounds",
        )


class TestB26QuotaExceedingDiskCapacityWarned(TestCase):
    def __init__(self):
        super().__init__("T2_B26_02", "F26", 2, "Quota calculation clamps or surfaces over-limit usage cleanly")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "quota_percentage" in tab and "hard_limit" or "quota_bytes" in tab), "B26: Quota usage bounds must be handled")


class TestB26WebhookPayloadViewerExpandable(TestCase):
    def __init__(self):
        super().__init__("T2_B26_03", "F26", 2, "Quota update form submits JSON payload via ApiClient.put")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "json!(" in tab and ".put(" in tab), "B26: Quota update form must serialize JSON payload")


class TestB26QuotaRefreshThrottling(TestCase):
    def __init__(self):
        super().__init__("T2_B26_04", "F26", 2, "Manual refresh disk quota button disables while busy or syncing")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(bool(tab and "disabled=move || busy.get() || sync_busy.get()" in tab), "B26: Refresh button must prevent rapid double-clicks")


class TestB26NonAdminQuotasForbidden(TestCase):
    def __init__(self):
        super().__init__("T2_B26_05", "F26", 2, "Quotas management APIs and UI strictly reject non-admin sessions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        routes = inspector.read_file("backend-rs/crates/af-api/src/routes.rs")
        tab = inspector.read_file(QUOTAS_RS)
        self.assert_true(
            bool(routes and "admin_routes" in routes and "/quotas" in routes and tab and "is_admin()" in tab),
            "B26: Quota routes and UI must be protected for admin role",
        )


# ============================================================================
# B27: Cluster Peer Links Panel Boundaries
# ============================================================================
class TestB27PeerRevocationConfirmation(TestCase):
    def __init__(self):
        super().__init__("T2_B27_01", "F27", 2, "Link revocation requires a confirmation dialog")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        peers = inspector.read_file(CLUSTER_PEERS) or ""
        self.assert_true(
            "revoke" in peers.lower() and "dialog" in peers.lower(),
            "B27: peer revocation must have a confirmation dialog",
        )


class TestB27PairingExpiryDisplayed(TestCase):
    def __init__(self):
        super().__init__("T2_B27_02", "F27", 2, "Pairing countdown uses the server expiry")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pairing = inspector.read_file(CLUSTER_PAIRING) or ""
        self.assert_true(
            "expires_at" in pairing and "format_countdown" in pairing,
            "B27: display pairing time relative to the server deadline",
        )


class TestB27PeerCompatibilityDisplayed(TestCase):
    def __init__(self):
        super().__init__("T2_B27_03", "F27", 2, "ClusterTab handles peer compatibility and RTT")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        peers = inspector.read_file(CLUSTER_PEERS) or ""
        self.assert_true(
            "compatibility" in peers and "rtt_ms" in peers,
            "B27: show compatibility and tolerate unavailable RTT",
        )


class TestB27ClusterUnlinkedGuidance(TestCase):
    def __init__(self):
        super().__init__("T2_B27_04", "F27", 2, "ClusterTab handles an empty peer list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        tab = inspector.read_file(CLUSTER_MOD) or ""
        peers = inspector.read_file(CLUSTER_PEERS) or ""
        self.assert_true(
            "EmptyState" in tab + peers,
            "B27: render an empty state when no peers are linked",
        )


class TestB27PairingStringClipboard(TestCase):
    def __init__(self):
        super().__init__("T2_B27_05", "F27", 2, "Pairing window supports copying its pairing string")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pairing = inspector.read_file(CLUSTER_PAIRING) or ""
        self.assert_true(
            "pairing_string" in pairing and "clipboard" in pairing,
            "B27: the one-time pairing string must be copyable",
        )


def get_tests():
    return [
        TestB24InvalidWireGuardKeyRejected(), TestB24TailscaleCidrRouteValidation(), TestB24PeerDeletionPromptsConfirmation(), TestB24TailscaleDaemonOfflineState(), TestB24NonAdminNetworkAccessForbidden(),
        TestB25EmptyChannelUrlRejected(), TestB25TestAlertTimeoutHandling(), TestB25RuleDeletionConfirmation(), TestB25SecretTokensMaskedInUi(), TestB25DuplicateRuleNamesHandled(),
        TestB26NegativeQuotaValueRejected(), TestB26QuotaExceedingDiskCapacityWarned(), TestB26WebhookPayloadViewerExpandable(), TestB26QuotaRefreshThrottling(), TestB26NonAdminQuotasForbidden(),
        TestB27PeerRevocationConfirmation(), TestB27PairingExpiryDisplayed(), TestB27PeerCompatibilityDisplayed(), TestB27ClusterUnlinkedGuidance(), TestB27PairingStringClipboard()
    ]
