import re
import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CiAndSecurityWorkflowGateTests(unittest.TestCase):
    def test_browser_harness_uses_wasm_and_preserves_real_service_worker_coverage(self) -> None:
        config = (ROOT / "e2e/playwright.config.ts").read_text(encoding="utf-8")
        self.assertNotIn("npm run dev", config)
        self.assertIn("PLAYWRIGHT_BASE_URL", config)
        self.assertIn("serviceWorkers: 'block'", config)
        for browser in ("chromium", "firefox", "webkit"):
            self.assertIn(f"name: '{browser}'", config)
        for filename in ("ci.yml", "release.yml"):
            workflow = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            self.assertIn("playwright install --with-deps chromium firefox webkit", workflow)
        live = (ROOT / "e2e/tests/e2e/embedded.live.spec.ts").read_text(encoding="utf-8")
        self.assertIn("test.use({ serviceWorkers: 'allow' })", live)
        self.assertIn("Real service-worker cache boundaries", live)

    def test_workflows_select_the_repository_rust_compiler_pin(self) -> None:
        manifest = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        compiler = re.search(r'^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$', manifest, re.MULTILINE)
        self.assertIsNotNone(compiler, "The Rust toolchain must use an exact release")
        for filename in ("ci.yml", "release.yml", "security.yml"):
            workflow = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            setups = re.findall(r'uses: dtolnay/rust-toolchain@[^\n]+\n(.*?)(?=\n      - |\Z)', workflow, re.DOTALL)
            self.assertTrue(setups, filename)
            for setup in setups:
                self.assertIn(f'toolchain: "{compiler.group(1)}"', setup, filename)

    def test_embedded_contracts_typecheck_and_cover_wasm_parity(self) -> None:
        ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        embedded = ci_text.split("  embedded-e2e:\n", 1)[1].split("\n  backend:\n", 1)[0]
        typecheck = embedded.index("- name: Typecheck Playwright E2E Suite")
        self.assertIn("../node_modules/.bin/tsc --noEmit --incremental false", embedded)
        self.assertLess(embedded.index("npm ci"), typecheck)
        self.assertLess(typecheck, embedded.index("bash scripts/run_embedded_e2e.sh"))
        self.assertIn('export AF_ALLOWED_FS_ROOTS="${AETHERFLOW_FS_ROOT},${MCBROWSER_ROOT}"', embedded)
        self.assertIn('"${MCBROWSER_ROOT}/user-1/README.md"', embedded)
        self.assertIn("needs: [backend-rs, frontend-rs]", embedded)
        self.assertIn("path: backend-rs/target/release/web/dist", embedded)
        self.assertIn("name: aetherflow-rs-binaries", embedded)
        self.assertIn("name: frontend-wasm-dist", embedded)
        self.assertIn('--static-dir "${PWD}/backend-rs/target/release/web/dist"', embedded)
        contract_gate = embedded.split("- name: Execute All Playwright Contract Specs Against Isolated API", 1)[1]
        command = next(line.strip() for line in contract_gate.splitlines()
                       if line.strip().startswith("npx playwright test "))
        selector = shlex.split(command)[3]
        specs = {p.name for p in (ROOT / "e2e/tests/e2e").glob("*.spec.ts")}
        selected = {name for name in specs if re.search(selector, f"tests/e2e/{name}")}
        self.assertEqual(selected, {name for name in specs
                                    if not name.endswith(".live.spec.ts") and name != "visual.spec.ts"})
        for name in ("wasm.cluster.spec.ts", "wasm.history.spec.ts", "wasm.navigation.spec.ts"):
            self.assertIn(name, selected)
        self.assertRegex("tests/e2e/wasm.future.spec.ts", selector)
        self.assertNotRegex("tests/e2e/wasm.future.live.spec.ts", selector)

    def test_ci_builds_wasm_and_rust_binaries_independently(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("\n  frontend:\n", ci)
        self.assertNotIn("working-directory: frontend", ci)
        wasm = ci.split("  frontend-rs:\n", 1)[1].split("\n  backend-rs:\n", 1)[0]
        backend = ci.split("  backend-rs:\n", 1)[1].split("\n  embedded-e2e:\n", 1)[0]
        self.assertIn("scripts/install_wasm_build_tools.sh", wasm)
        self.assertIn("scripts/build_wasm_frontend.sh --stage", wasm)
        self.assertIn("name: frontend-wasm-dist", wasm)
        self.assertIn("path: web/dist", wasm)
        self.assertNotIn("needs:", backend)
        self.assertNotIn("download-artifact", backend)
        self.assertIn("name: aetherflow-rs-binaries", backend)


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
        for forbidden in ("actions/setup-go", "go vet ./...", "backend/go.mod", "backend/web/dist"):
            self.assertNotIn(forbidden, ci_text)

    def test_release_workflow_enforces_rust_zero_go_and_requires_sigstore_bundle(self) -> None:
        rel_text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("Verify Zero-Go Repository Hygiene", rel_text)
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", rel_text)
        self.assertIn("-p af-librespeed", rel_text)
        self.assertIn("cargo fmt --all -- --check", rel_text)
        self.assertIn("BUILD_FRONTEND=0 RUN_TESTS=0 PACKAGE_RELEASE=1 BUILD_CLI=1 BUILD_SPEEDTEST=1", rel_text)
        self.assertIn("bash scripts/build_gold.sh", rel_text)
        self.assertIn("aetherflow-api bin/af bin/speedtest-backend", rel_text)
        self.assertIn("ATTEST_BUNDLE_PATH: ${{ steps.attest.outputs.bundle-path }}", rel_text)
        self.assertIn("aetherflow-linux-amd64.tar.gz.sigstore.json", rel_text)
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

    def test_python_verification_workflows_install_marketplace_dependencies(self) -> None:
        required = {"python3-yaml", "python3-tomlkit", "apache2-bin", "jq", "sqlite3", "bc"}
        for filename in ("ci.yml", "release.yml"):
            with self.subTest(workflow=filename):
                workflow = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
                workflow = re.sub(r"\\\n[ \t]*", " ", workflow)
                install_commands = [
                    shlex.split(line)
                    for line in workflow.splitlines()
                    if line.lstrip().startswith("sudo apt-get install ")
                ]
                self.assertTrue(
                    any(required.issubset(command) for command in install_commands),
                    f"Expected an install command with {sorted(required)}",
                )

    def test_security_workflow_retains_gitleaks_rust_zero_go_and_npm_gates(self) -> None:
        sec_text = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertTrue(re.search(r'GITLEAKS_VERSION="8\.30\.1"', sec_text))
        self.assertIn("Verify Zero-Go Repository Hygiene", sec_text)
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", sec_text)
        self.assertIn("cargo deny --locked check advisories bans licenses sources", sec_text)
        self.assertIn("cargo audit --file Cargo.lock", sec_text)
        self.assertIn("cargo fmt --manifest-path ../frontend-rs/Cargo.toml --all -- --check", sec_text)
        self.assertIn("cargo clippy --manifest-path ../frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings", sec_text)
        self.assertIn("cargo clippy --manifest-path ../frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings", sec_text)
        self.assertIn("python3 ../scripts/finalize_wasm_assets.py --self-test", sec_text)
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
