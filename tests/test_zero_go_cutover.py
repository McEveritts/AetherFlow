import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestZeroGoCutoverInvariants(unittest.TestCase):
    """Verify AetherFlow Zero-Go cutover invariants across repo, CI workflows, and scripts."""

    def test_git_has_no_tracked_go_files(self) -> None:
        proc = subprocess.run(
            ["git", "ls-files", "*.go", "*go.mod", "*go.sum"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        tracked = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(
            tracked,
            [],
            f"Zero-Go invariant violated: tracked Go files still present: {tracked}",
        )

    def test_legacy_go_directories_are_removed(self) -> None:
        for rel in (
            "backend",
            "plugins/sdk-template",
            "packages/package/assets/librespeed/backend-patches",
        ):
            self.assertFalse(
                (ROOT / rel).exists(),
                f"Legacy Go directory still exists after cutover: {rel}",
            )

    def test_canonical_root_config_and_openapi_assets_exist(self) -> None:
        for rel in (
            "config/packages.json",
            "config/package_automation.json",
            "config/openapi-v1.yaml",
        ):
            path = ROOT / rel
            self.assertTrue(path.is_file(), f"Missing canonical root config asset: {rel}")
            if path.suffix == ".json":
                parsed = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(parsed, f"Expected non-empty JSON asset: {rel}")

    def test_rust_librespeed_and_neutral_spa_embed_present(self) -> None:
        librespeed_toml = ROOT / "backend-rs/crates/af-librespeed/Cargo.toml"
        self.assertTrue(
            librespeed_toml.is_file(),
            "Missing native Rust LibreSpeed crate: backend-rs/crates/af-librespeed/Cargo.toml",
        )
        toml_text = librespeed_toml.read_text(encoding="utf-8")
        self.assertIn("speedtest-backend", toml_text)

        embed_rs = (ROOT / "backend-rs/crates/af-api/src/embed.rs").read_text(encoding="utf-8")
        self.assertIn("web/dist", embed_rs)
        self.assertNotIn("backend/web/dist", embed_rs)

    def test_workflows_are_pure_rust_and_enforce_zero_go_hygiene(self) -> None:
        banned = (
            "actions/setup-go",
            "govulncheck",
            "staticcheck",
            "gosec",
            "backend/web/dist",
            "backend/config",
        )
        for name in ("ci.yml", "release.yml", "security.yml"):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(token, text, f"{name} must not reference legacy token {token!r}")
            self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", text)
            self.assertIn("-p af-librespeed", text)
            if name in ("ci.yml", "release.yml"):
                self.assertIn("speedtest-backend", text)

    def test_scripts_and_sdk_scaffolder_are_zero_go(self) -> None:
        sdk_script = (ROOT / "scripts/create-plugin-sdk.sh").read_text(encoding="utf-8")
        self.assertIn("rust", sdk_script)
        self.assertNotIn("plugins/sdk-template/", sdk_script)

        modern_stack = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        build_gold = (ROOT / "scripts/build_gold.sh").read_text(encoding="utf-8")
        for label, content in (("modern_stack.sh", modern_stack), ("build_gold.sh", build_gold)):
            for token in ("_install_go", "AF_GO_VERSION", "go build", "backend/web/dist", "backend/config"):
                self.assertNotIn(token, content, f"{label} must not reference legacy token {token!r}")


if __name__ == "__main__":
    unittest.main()
