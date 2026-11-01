import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires Linux shell tools")
class RustBuildToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="af-rust-build-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "backend-rs").mkdir()
        (self.root / "backend-rs/Cargo.toml").write_text("[workspace]\n")
        (self.root / "backend/config").mkdir(parents=True)
        (self.root / "backend/config/packages.json").write_text("[]")
        (self.root / "packages").mkdir()
        (self.root / "deploy").mkdir()
        (self.root / "deploy/release-manager.sh").write_text("#!/bin/bash\n")
        (self.root / ".version").write_text("4.0.0\n")
        for name in ("build_gold.sh", "create-plugin-sdk.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        tools = self.root / "tools"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text(r"""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
arguments = sys.argv[1:]
with Path(os.environ["TEST_CARGO_LOG"]).open("a") as log:
    log.write(" ".join(arguments) + "\n")
if arguments[0] == "test":
    sys.exit(int(os.environ.get("TEST_CARGO_FAILURE", "0")))
target = arguments[arguments.index("--target") + 1]
binary = arguments[arguments.index("--bin") + 1]
directory = Path(os.environ.get("CARGO_TARGET_DIR", "target")) / target / "release"
directory.mkdir(parents=True, exist_ok=True)
(directory / binary).write_text(target)
""")
        cargo.chmod(0o755)
        self.environment = os.environ.copy()
        for name in ("CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "BACKEND_DIR", "BACKEND_RS_DIR"):
            self.environment.pop(name, None)
        self.environment.update({
            "PATH": str(tools) + os.pathsep + self.environment["PATH"],
            "BUILD_FRONTEND": "0", "RUN_TESTS": "1", "PACKAGE_RELEASE": "1",
            "TARGETS": "amd64 arm64", "OUTPUT_DIR": str(self.root / "output"),
            "TEST_CARGO_LOG": str(self.root / "cargo.log"),
        })

    def run_build(self):
        return subprocess.run(["bash", str(self.root / "scripts/build_gold.sh")],
                              env=self.environment, capture_output=True, text=True)

    def test_packages_only_requested_architecture(self):
        self.environment["CARGO_TARGET_DIR"] = "custom-target"
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        for label, triple in (("amd64", "x86_64-unknown-linux-gnu"),
                              ("arm64", "aarch64-unknown-linux-gnu")):
            artifact = self.root / "output" / ("linux-" + label) / "aetherflow-api"
            self.assertEqual(artifact.read_text(), triple)
            self.assertTrue((self.root / "output" / ("aetherflow-linux-" + label + ".tar.gz")).exists())
        self.assertEqual(len((self.root / "output/SHA256SUMS").read_text().splitlines()), 2)

    def test_test_failure_is_not_retried_or_packaged(self):
        self.environment["TEST_CARGO_FAILURE"] = "17"
        result = self.run_build()
        self.assertEqual(result.returncode, 17)
        self.assertEqual((self.root / "cargo.log").read_text().splitlines(), ["test --workspace"])
        self.assertFalse(list((self.root / "output").glob("*.tar.gz")))

    def test_rejects_conflicting_target_override(self):
        self.environment["CARGO_BUILD_TARGET"] = "aarch64-unknown-linux-gnu"
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicts with requested target", result.stderr)
        self.assertFalse(list((self.root / "output").glob("*.tar.gz")))

    def test_rust_scaffold_selector_replaces_placeholders(self):
        shutil.copytree(ROOT / "plugins/sdk-template-rust", self.root / "plugins/sdk-template-rust")
        target = self.root / "generated"
        result = subprocess.run(["bash", str(self.root / "scripts/create-plugin-sdk.sh"),
                                 "example-plugin", "Example Plugin", str(target), "rust"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = (target / "plugin.manifest.json").read_text()
        self.assertIn("example-plugin", manifest)
        self.assertNotIn("{{PLUGIN_ID}}", manifest)
        self.assertTrue((target / "backend/Cargo.toml").exists())


if __name__ == "__main__":
    unittest.main()
