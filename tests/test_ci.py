import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CiAndSecurityWorkflowGateTests(unittest.TestCase):
    def test_ci_enforces_rust_zero_go_and_speedtest_backend_gates(self) -> None:
        ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("cargo fmt --all -- --check", ci_text)
        fmt_block = ci_text.split("Enforce Rust Formatting Gate", 1)[1].split("- name:", 1)[0]
        self.assertNotIn("continue-on-error: true", fmt_block)
        self.assertIn("Verify Zero-Go Repository Hygiene", ci_text)
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", ci_text)
        self.assertIn("-p af-librespeed", ci_text)
        self.assertIn("cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend", ci_text)
        self.assertIn("backend-rs/target/release/speedtest-backend", ci_text)
        self.assertIn("python3-yaml apache2-bin jq sqlite3 bc", ci_text)
        for forbidden in ("actions/setup-go", "go vet ./...", "backend/go.mod", "backend/web/dist"):
            self.assertNotIn(forbidden, ci_text)

    def test_release_workflow_enforces_rust_zero_go_and_optional_sigstore_bundle(self) -> None:
        rel_text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("Verify Zero-Go Repository Hygiene", rel_text)
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", rel_text)
        self.assertIn("-p af-librespeed", rel_text)
        self.assertIn("cargo fmt --all -- --check", rel_text)
        self.assertIn("cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend", rel_text)
        self.assertIn("${STAGE_DIR}/bin/speedtest-backend", rel_text)
        self.assertIn("ATTEST_BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}", rel_text)
        self.assertIn("aetherflow-linux-amd64.tar.gz.sigstore.json", rel_text)
        self.assertIn("python3-yaml apache2-bin jq sqlite3 bc", rel_text)
        for forbidden in (
            "Legacy Go Backend",
            "actions/setup-go",
            "govulncheck",
            "gosec",
            "staticcheck",
            "backend/web/dist",
            "backend/config",
        ):
            self.assertNotIn(forbidden, rel_text)

    def test_security_workflow_retains_gitleaks_rust_zero_go_and_npm_gates(self) -> None:
        sec_text = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertTrue(re.search(r'GITLEAKS_VERSION="8\.30\.1"', sec_text))
        self.assertIn("Verify Zero-Go Repository Hygiene", sec_text)
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", sec_text)
        self.assertIn("cargo deny --locked check advisories bans licenses sources", sec_text)
        self.assertIn("cargo audit --file Cargo.lock", sec_text)
        self.assertIn("-p af-librespeed", sec_text)
        self.assertIn("npm audit --workspaces --include-workspace-root --omit=dev --audit-level=high", sec_text)
        for forbidden in (
            "security-checks:",
            "actions/setup-go",
            "govulncheck",
            "gosec",
            "staticcheck",
            "backend/web/dist",
        ):
            self.assertNotIn(forbidden, sec_text)


if __name__ == "__main__":
    unittest.main()
