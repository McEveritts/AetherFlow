import os
from pathlib import Path
import shutil
import subprocess
import tarfile
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
        (self.root / "backend-rs/Cargo.lock").write_text("# lockfile\n")
        (self.root / "backend-rs/crates/af-cli").mkdir(parents=True)
        (self.root / "backend-rs/crates/af-cli/Cargo.toml").write_text('[package]\nname = "af-cli"\n')
        (self.root / "backend-rs/crates/af-librespeed").mkdir(parents=True)
        (self.root / "backend-rs/crates/af-librespeed/Cargo.toml").write_text('[package]\nname = "af-librespeed"\n')
        (self.root / "config").mkdir(parents=True)
        (self.root / "config/packages.json").write_text("[]")
        (self.root / "packages").mkdir()
        (self.root / "deploy").mkdir()
        (self.root / "deploy/release-manager.sh").write_text("#!/bin/bash\n")
        for name in ("verify-provenance.py", "log-retention.py"):
            (self.root / "deploy" / name).write_text("#!/usr/bin/env python3\n")
            (self.root / "deploy" / name).chmod(0o644)
        for name in ("packages/package/example/install", "packages/system/af-tune"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\n")
            path.chmod(0o755)
        (self.root / "packages/system/af-tune").chmod(0o775)
        for name in ("packages/ui/src/App.tsx", "packages/ui/tsconfig.tsbuildinfo",
                     "packages/README.md",
                     "packages/node_modules/unused/index.js", "deploy/__pycache__/unused.pyc",
                     "packages/system/target/cache", "deploy/.pytest_cache/unused",
                     "deploy/unused.pyo", "backend/config/__pycache__/unused.pyc"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"host-generated")
        assets = self.root / "web/dist"
        assets.mkdir(parents=True)
        (assets / "index.html").write_text('<!doctype html><script src="app-01234567.js"></script>')
        (assets / "app-01234567.js").write_text('export const frontend = "wasm";\n')
        (assets / "app-01234567.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
        (assets / "node_modules").mkdir()
        (assets / "node_modules/unused.js").write_text("host-generated")
        (assets / "__pycache__").mkdir()
        (assets / "__pycache__/unused.pyc").write_bytes(b"host-generated")
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
Path(os.environ["TEST_BUILD_DATE_LOG"]).write_text(os.environ["AETHERFLOW_BUILD_DATE"])
target = arguments[arguments.index("--target") + 1]
bins = [
    arguments[i + 1]
    for i, arg in enumerate(arguments)
    if arg == "--bin" and i + 1 < len(arguments)
]
directory = Path(os.environ.get("CARGO_TARGET_DIR", "target")) / target / "release"
directory.mkdir(parents=True, exist_ok=True)
for binary in bins:
    (directory / binary).write_text(target)
""")
        cargo.chmod(0o755)
        self.environment = os.environ.copy()
        for name in ("CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "BACKEND_DIR", "BACKEND_RS_DIR", "CARGO_LOCKED", "CARGO_ALLOW_UNLOCKED_DEV", "FRONTEND_DIST_DIR", "EMBED_DIST_DIR", "LEGACY_EMBED_DIST_DIR"):
            self.environment.pop(name, None)
        self.environment.update({
            "PATH": str(tools) + os.pathsep + self.environment["PATH"],
            "BUILD_FRONTEND": "0", "RUN_TESTS": "1", "PACKAGE_RELEASE": "1",
            "TARGETS": "amd64 arm64", "OUTPUT_DIR": str(self.root / "output"),
            "TEST_CARGO_LOG": str(self.root / "cargo.log"),
            "TEST_BUILD_DATE_LOG": str(self.root / "build-date.log"),
            "SOURCE_DATE_EPOCH": "1234567890",
        })
        self.environment.pop("BUILD_DATE", None)

    def run_build(self, **kwargs):
        return subprocess.run(["bash", str(self.root / "scripts/build_gold.sh")],
                              env=self.environment, capture_output=True, text=True, **kwargs)

    def test_packages_only_requested_architecture(self):
        self.environment["CARGO_TARGET_DIR"] = "custom-target"
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        cargo_lines = (self.root / "cargo.log").read_text().splitlines()
        self.assertTrue(all("--locked" in line for line in cargo_lines), cargo_lines)
        for label, triple in (("amd64", "x86_64-unknown-linux-gnu"),
                              ("arm64", "aarch64-unknown-linux-gnu")):
            artifact = self.root / "output" / ("linux-" + label) / "aetherflow-api"
            cli_artifact = self.root / "output" / ("linux-" + label) / "af"
            speedtest_artifact = self.root / "output" / ("linux-" + label) / "speedtest-backend"
            self.assertEqual(artifact.read_text(), triple)
            self.assertEqual(cli_artifact.read_text(), triple)
            self.assertEqual(speedtest_artifact.read_text(), triple)
            archive = self.root / "output" / ("aetherflow-linux-" + label + ".tar.gz")
            with tarfile.open(archive) as bundle:
                self.assertEqual(bundle.extractfile("./web/dist/index.html").read(),
                                 (self.root / "web/dist/index.html").read_bytes())
                self.assertEqual(bundle.extractfile("./web/dist/app-01234567.wasm").read(),
                                 b"\x00asm\x01\x00\x00\x00")
        self.assertEqual(len((self.root / "output/SHA256SUMS").read_text().splitlines()), 2)
        self.assertEqual((self.root / "build-date.log").read_text(), "2009-02-13T23:31:30Z")
        archives = {label: (self.root / "output" / ("aetherflow-linux-" + label + ".tar.gz")).read_bytes()
                    for label in ("amd64", "arm64")}
        # Rebuilding the same version must replace each staging tree rather than
        # recursively nesting its previous config, package and deployment copies.
        rebuilt = self.run_build(umask=0o077)
        self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
        for label in ("amd64", "arm64"):
            archive = self.root / "output" / ("aetherflow-linux-" + label + ".tar.gz")
            self.assertEqual(archive.read_bytes(), archives[label])
            self.assertEqual(archive.read_bytes()[4:8], b"\0\0\0\0")
            with tarfile.open(archive) as bundle:
                members = bundle.getnames()
                self.assertIn("./config/packages.json", members)
                for name in ("./packages/package/example/install", "./packages/system/af-tune",
                             "./deploy/verify-provenance.py", "./deploy/log-retention.py",
                             "./aetherflow-api", "./af", "./bin/af", "./speedtest-backend",
                             "./bin/speedtest-backend", "./web/dist/index.html"):
                    self.assertIn(name, members)
                    self.assertEqual(bundle.getmember(name).mode & 0o111, 0o111 if "web/dist" not in name else 0)
                for member in bundle.getmembers():
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1234567890))
                self.assertEqual(bundle.getmember("./packages/system/af-tune").mode, 0o755)
                self.assertEqual(members, sorted(members))
                self.assertFalse(any(part in name for name in members for part in
                                     ("/ui/", "node_modules", "__pycache__", ".pytest_cache", ".pyc", ".pyo", "tsbuildinfo", "/target/")))
                self.assertNotIn("./packages/README.md", members)
                for nested in ("./config/config", "./packages/packages", "./deploy/deploy"):
                    self.assertFalse(any(name == nested or name.startswith(nested + "/") for name in members))
        self.assertEqual(len((self.root / "output/SHA256SUMS").read_text().splitlines()), 2)

    def test_invalid_source_date_epoch_is_rejected(self):
        self.environment["SOURCE_DATE_EPOCH"] = "not-a-timestamp"
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SOURCE_DATE_EPOCH must be a non-negative integer", result.stderr)

    def test_standalone_speedtest_archive_and_armv7_target_support(self):
        self.environment["TARGETS"] = "armv7"
        self.environment["PACKAGE_SPEEDTEST_STANDALONE"] = "1"
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "output/aetherflow-linux-armv7.tar.gz").exists())
        standalone = self.root / "output/speedtest-backend_4.0.0_linux_armv7.tar.gz"
        original = standalone.read_bytes()
        self.assertEqual(self.run_build(umask=0o077).returncode, 0)
        self.assertEqual(standalone.read_bytes(), original)
        with tarfile.open(standalone) as archive:
            [member] = archive.getmembers()
            self.assertEqual((member.name, member.mode, member.mtime),
                             ("speedtest-backend", 0o755, 1234567890))
        sums = (self.root / "output/SHA256SUMS").read_text()
        self.assertIn("aetherflow-linux-armv7.tar.gz", sums)
        self.assertIn("speedtest-backend_4.0.0_linux_armv7.tar.gz", sums)

    def test_test_failure_is_not_retried_or_packaged(self):
        self.environment["TEST_CARGO_FAILURE"] = "17"
        result = self.run_build()
        self.assertEqual(result.returncode, 17)
        self.assertEqual((self.root / "cargo.log").read_text().splitlines(), ["test --locked --workspace"])
        self.assertFalse(list((self.root / "output").glob("*.tar.gz")))

    def test_missing_cargo_lock_fails_closed_by_default(self):
        (self.root / "backend-rs/Cargo.lock").unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cargo.lock is required for reproducible locked builds", result.stderr)
        self.assertFalse((self.root / "cargo.log").exists())
        self.assertFalse(list((self.root / "output").glob("*.tar.gz")))

    def test_full_release_rejects_missing_external_frontend(self):
        shutil.rmtree(self.root / "web/dist")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full release requires", result.stderr)
        self.assertFalse((self.root / "cargo.log").exists())
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

    def test_plugin_sdk_defaults_to_rust_and_rejects_go(self):
        shutil.copytree(ROOT / "plugins/sdk-template-rust", self.root / "plugins/sdk-template-rust")
        default_target = self.root / "generated-default"
        result_default = subprocess.run(
            [
                "bash",
                str(self.root / "scripts/create-plugin-sdk.sh"),
                "example-default",
                "Example Default",
                str(default_target),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result_default.returncode, 0, result_default.stderr)
        self.assertTrue((default_target / "backend/Cargo.toml").exists())

        go_target = self.root / "generated-go"
        result_go = subprocess.run(
            [
                "bash",
                str(self.root / "scripts/create-plugin-sdk.sh"),
                "example-go",
                "Example Go",
                str(go_target),
                "go",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result_go.returncode, 0)


if __name__ == "__main__":
    unittest.main()
