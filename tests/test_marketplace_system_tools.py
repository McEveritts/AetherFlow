import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class MarketplaceSystemToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_bash(self, script, **environment):
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], capture_output=True, text=True,
                                env={**os.environ, "TEST_ROOT": str(self.root), **environment}, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_sandbox_sources_local_current_then_legacy_helpers(self):
        source = (ROOT / "packages/system/af-systemd-sandbox").read_text()
        for prefix in ("/opt/", "/usr/local/"):
            source = source.replace(prefix, str(self.root) + prefix)
        script = self.file("local/system/af-systemd-sandbox", source)
        helpers = [
            self.file("local/common.sh", "echo local\n"),
            self.file("opt/AetherFlow/current/packages/common.sh", "echo current\n"),
            self.file("opt/AetherFlow/packages/common.sh", "echo opt-legacy\n"),
            self.file("usr/local/bin/AetherFlow/common.sh", "echo bin-legacy\n"),
        ]
        for helper, expected in zip(helpers, ("local", "current", "opt-legacy", "bin-legacy")):
            result = subprocess.run(["bash", str(script), "--help"], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[0], expected)
            helper.unlink()

    def test_sandbox_apply_and_remove_clean_legacy_dropins_only(self):
        source = (ROOT / "packages/system/af-systemd-sandbox").read_text()
        functions = source[source.index("usage() {"):source.index('command_name="${1:-}"')]
        functions = functions.replace("/etc/systemd/system", str(self.root / "units"))
        overrides = '''
log_info() { :; }
service_user_for_unit() { echo dispatcharr; }
service_home_for_user() { echo /var/lib/dispatcharr; }
resolve_master_user() { echo admin; }
'''
        dropin = self.root / "units/dispatcharr.service.d"
        unrelated = self.file("units/dispatcharr.service.d/local-policy.conf", "keep-policy")
        legacy = self.file("units/dispatcharr.service.d/aetherflow-sandbox.conf", "stale")
        self.run_bash(functions + overrides + "apply_sandbox_dropin python dispatcharr.service /data/logos")
        self.assertFalse(legacy.exists())
        self.assertIn("ProtectSystem=strict", (dropin / "10-aetherflow-sandbox.conf").read_text())
        legacy.write_text("stale-again")
        self.run_bash(functions + overrides + "remove_sandbox_dropin dispatcharr.service")
        self.assertFalse(legacy.exists())
        self.assertFalse((dropin / "10-aetherflow-sandbox.conf").exists())
        self.assertEqual(unrelated.read_text(), "keep-policy")
        legacy.write_text("stale-exempt")
        self.run_bash(functions + overrides + "apply_sandbox_dropin none dispatcharr.service")
        self.assertFalse(legacy.exists())

    def test_cli_package_scripts_prefer_current_release_with_legacy_fallbacks(self):
        source = (ROOT / "packages/system/af").read_text()
        functions = source[source.index("package_roots=("):source.index("\n#\n# [AetherFlow")]
        for prefix in ("/opt/", "/usr/local/"):
            functions = functions.replace(prefix, str(self.root) + prefix)
        for action in ("install", "remove"):
            scripts = [self.file(f"{prefix}/{action}/{action}package-dispatcharr", prefix) for prefix in (
                "opt/AetherFlow/current/packages/package", "opt/AetherFlow/packages/package", "usr/local/bin/AetherFlow/package",
            )]
            for script in scripts:
                result = self.run_bash(functions + f"\npackage_script {action} dispatcharr")
                self.assertEqual(result, [str(script)])
                script.unlink()

    @unittest.skipUnless(shutil.which("rsync"), "requires rsync")
    def test_release_swap_syncs_existing_legacy_packages_and_shared_helpers(self):
        source = (ROOT / "deploy/release-manager.sh").read_text()
        functions = source[source.index("sync_legacy_package_paths() {"):source.index("\n###############################################################################\n# STAGE 3")]
        validator_start = source.index("validate_path_within_isolated_root() {")
        validator_end = source.index("\n}\n", validator_start) + 3
        functions = source[validator_start:validator_end] + "\n" + functions
        self.file("releases/new/packages/package/install/installpackage-dispatcharr", "new-installer")
        self.file("releases/new/packages/common.sh", "new-common")
        self.file("releases/old/packages/package/install/installpackage-dispatcharr", "old-installer")
        self.file("releases/old/packages/common.sh", "old-common")
        self.file("legacy-opt/packages/package/install/installpackage-dispatcharr", "stale-opt")
        stale = self.file("legacy-opt/packages/package/install/stale-script", "stale")
        self.file("legacy-bin/package/install/installpackage-dispatcharr", "stale-bin")
        self.file("legacy-bin/common.sh", "stale-common")
        for path in self.root.rglob("*"):
            if path.is_file():
                os.utime(path, (1700000000, 1700000000))
        current = self.root / "current"
        current.symlink_to(self.root / "releases/old")
        environment = {
            "DRY_RUN": "false", "CURRENT_LINK": str(current), "RELEASE_DIR": str(self.root / "releases/new"),
            "RELEASES_DIR": str(self.root / "releases"), "EPOCH": "1",
            "EFFECTIVE_RELEASE_ROOT": str(self.root), "DRY_RUN_ROOT": str(self.root / "dry-run"),
            "LEGACY_OPT_ROOT": str(self.root / "legacy-opt"), "LEGACY_BIN_ROOT": str(self.root / "legacy-bin"),
        }
        for release, expected in (("new", "new"), ("old", "old")):
            environment["RELEASE_DIR"] = str(self.root / "releases" / release)
            self.run_bash(functions + "\nlog_info() { :; }; symlink_swap", **environment)
            self.assertEqual((self.root / "legacy-opt/packages/package/install/installpackage-dispatcharr").read_text(), expected + "-installer")
            self.assertEqual((self.root / "legacy-bin/package/install/installpackage-dispatcharr").read_text(), expected + "-installer")
            self.assertEqual((self.root / "legacy-bin/common.sh").read_text(), expected + "-common")
            self.assertFalse(stale.exists())
        environment.update(DRY_RUN="true", RELEASE_DIR=str(self.root / "releases/new"))
        self.run_bash(functions + "\nlog_info() { :; }; symlink_swap", **environment)
        self.assertEqual((self.root / "legacy-bin/common.sh").read_text(), "old-common")


if __name__ == "__main__":
    unittest.main()
