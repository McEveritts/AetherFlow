import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CiAndSecurityWorkflowGateTests(unittest.TestCase):
    def test_ci_enforces_rustfmt_and_go_64hex_aes_gate(self) -> None:
        ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("cargo fmt --all -- --check", ci_text)
        fmt_block = ci_text.split("Enforce Rust Formatting Gate", 1)[1].split("- name:", 1)[0]
        self.assertNotIn("continue-on-error: true", fmt_block)
        self.assertIn("go vet ./...", ci_text)
        self.assertIn("bytes(range(32)).hex()", ci_text)
        self.assertIn("python3-yaml apache2-bin jq sqlite3 bc", ci_text)

    def test_release_workflow_runs_legacy_go_gate_and_optional_sigstore_bundle(self) -> None:
        rel_text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("Legacy Go Backend Build & Security Regression Gate", rel_text)
        self.assertIn("cargo fmt --all -- --check", rel_text)
        self.assertIn("ATTEST_BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}", rel_text)
        self.assertIn("aetherflow-linux-amd64.tar.gz.sigstore.json", rel_text)
        self.assertIn("python3-yaml apache2-bin jq sqlite3 bc", rel_text)

    def test_security_workflow_retains_gitleaks_rust_go_and_npm_gates(self) -> None:
        sec_text = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertTrue(re.search(r'GITLEAKS_VERSION="8\.30\.1"', sec_text))
        self.assertIn("cargo deny --locked check advisories bans licenses sources", sec_text)
        self.assertIn("go test -v -count=1 -race ./...", sec_text)
        self.assertIn("npm audit --workspaces --include-workspace-root --omit=dev --audit-level=high", sec_text)


if __name__ == "__main__":
    unittest.main()
