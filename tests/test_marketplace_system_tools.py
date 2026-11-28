import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import COMMON_LIB_MODULES, common_functions, replace_paths_once


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

    def test_setdisk_uses_decimal_quantities_and_rejects_overflow(self):
        setquota = self.file("bin/setquota", '#!/bin/sh\nprintf "%s\\n" "$@" > "$QUOTA_CALL"\n')
        setquota.chmod(0o755)
        call_path = self.root / "quota-call"
        environment = {
            **os.environ,
            "PATH": f"{setquota.parent}:/usr/bin:/bin",
            "QUOTA_CALL": str(call_path),
        }
        for size, expected in (("08GB", 8 << 30), ("0009mb", 9 << 20), ("000TB", 0),
                               ("8796093022208MB", None), ("999999999999999999999999TB", None)):
            with self.subTest(size=size):
                call_path.unlink(missing_ok=True)
                result = subprocess.run(
                    ["bash", str(ROOT / "packages/system/setdisk"), "--username", "testuser", "--size", size, "--json"],
                    env=environment, capture_output=True, text=True, timeout=5,
                )
                response = json.loads(result.stdout)
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(response["status"], "failed")
                    self.assertFalse(call_path.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(response["quota_bytes"], expected)
                    blocks = str(expected // 1024)
                    self.assertEqual(call_path.read_text().splitlines(), ["-u", "testuser", blocks, blocks, "0", "0", "-a"])

    def test_sandbox_sources_local_current_then_legacy_helpers(self):
        source = replace_paths_once(
            (ROOT / "packages/system/af-systemd-sandbox").read_text(),
            [(prefix, str(self.root) + prefix) for prefix in ("/opt/", "/usr/local/")],
        )
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
        functions = replace_paths_once(
            source[source.index("package_roots=("):source.index("\n#\n# [AetherFlow")],
            [(prefix, str(self.root) + prefix) for prefix in ("/opt/", "/usr/local/")],
        )
        for action in ("install", "remove"):
            scripts = [self.file(f"{prefix}/{action}/{action}package-dispatcharr", prefix) for prefix in (
                "opt/AetherFlow/current/packages/package", "opt/AetherFlow/packages/package", "usr/local/bin/AetherFlow/package",
            )]
            for script in scripts:
                result = self.run_bash(functions + f"\npackage_script {action} dispatcharr")
                self.assertEqual(result, [str(script)])
                script.unlink()

    def cli_script(self):
        source = replace_paths_once(
            (ROOT / "packages/system/af").read_text(),
            [(prefix, str(self.root) + prefix) for prefix in ("/opt/", "/usr/local/", "/install/")],
        )
        return self.file("af", source)

    def test_cli_executes_authoritative_binary_before_loading_legacy_helpers(self):
        script = self.cli_script()
        for relative in (
            "custom/af-cli",
            "opt/AetherFlow/current/bin/af",
            "opt/AetherFlow/current/af",
            "usr/local/bin/af-cli",
            "opt/AetherFlow/bin/af-cli",
        ):
            with self.subTest(binary=relative):
                binary = self.file(relative, '#!/bin/bash\nprintf "%s\\n" "$@"\nexit 23\n')
                binary.chmod(0o755)
                environment = {**os.environ, "AETHERFLOW_USE_RUNNER": "1"}
                if relative.startswith("custom/"):
                    environment["AETHERFLOW_CLI_BIN"] = str(binary)
                result = subprocess.run(["bash", str(script), "install", "rclone", "--port", "23456"],
                                        env=environment, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["install", "rclone", "--port", "23456"])
                binary.unlink()

    def test_cli_runner_required_without_binary_fails_closed(self):
        result = subprocess.run(["bash", str(self.cli_script()), "remove", "rclone"],
                                env={**os.environ, "AETHERFLOW_USE_RUNNER": "1", "AETHERFLOW_CLI_BIN": ""},
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authoritative af-cli is required", result.stderr)

    def test_cli_bash_fallback_honors_shared_maintenance_lock(self):
        script = self.cli_script()
        self.file("opt/AetherFlow/packages/common.sh", common_functions("safe_config_python", "validate_config_paths"))
        self.file("opt/AetherFlow/packages/package/install/installpackage-fixture", '#!/bin/sh\necho fixture-install\n')
        lock = self.file("opt/AetherFlow/logs/maintenance.lock", "")
        environment = {**os.environ, "TERM": "xterm", "AETHERFLOW_USE_RUNNER": "0", "AETHERFLOW_CLI_BIN": ""}
        with lock.open("a") as descriptor:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(["bash", str(script), "install", "fixture"], env=environment,
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("maintenance operation is running", result.stderr)
            self.assertNotIn("fixture-install", result.stdout)
        result = subprocess.run(["bash", str(script), "install", "fixture"], env=environment,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-install", result.stdout)

    @unittest.skipUnless(shutil.which("rsync"), "requires rsync")
    @unittest.skipUnless((ROOT / "deploy/release-manager.sh").is_file(), "requires deploy/release-manager.sh")
    def test_release_swap_syncs_existing_legacy_packages_and_shared_helpers(self):
        source = (ROOT / "deploy/release-manager.sh").read_text()
        functions = source[source.index("sync_legacy_package_paths() {"):source.index("\n###############################################################################\n# STAGE 3")]
        validator_start = source.index("validate_path_within_isolated_root() {")
        validator_end = source.index("\n}\n", validator_start) + 3
        writer_start = source.index("write_atomic_private_file() {")
        writer_end = source.index("\n}\n", writer_start) + 3
        functions = source[validator_start:validator_end] + "\n" + source[writer_start:writer_end] + "\n" + functions
        self.file("releases/new/packages/package/install/installpackage-dispatcharr", "new-installer")
        self.file("releases/new/packages/common.sh", "new-common")
        self.file("releases/new/packages/lib/logging_archives.sh", "new-lib")
        self.file("releases/old/packages/package/install/installpackage-dispatcharr", "old-installer")
        self.file("releases/old/packages/common.sh", "old-common")
        self.file("releases/old/packages/lib/logging_archives.sh", "old-lib")
        self.file("legacy-opt/packages/package/install/installpackage-dispatcharr", "stale-opt")
        stale = self.file("legacy-opt/packages/package/install/stale-script", "stale")
        self.file("legacy-bin/package/install/installpackage-dispatcharr", "stale-bin")
        self.file("legacy-bin/common.sh", "stale-common")
        stale_lib = self.file("legacy-bin/lib/stale-module.sh", "stale-lib")
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
            self.assertEqual((self.root / "legacy-bin/lib/logging_archives.sh").read_text(), expected + "-lib")
            self.assertFalse(stale.exists())
            self.assertFalse(stale_lib.exists())
        environment.update(DRY_RUN="true", RELEASE_DIR=str(self.root / "releases/new"))
        self.run_bash(functions + "\nlog_info() { :; }; symlink_swap", **environment)
        self.assertEqual((self.root / "legacy-bin/common.sh").read_text(), "old-common")
        self.assertEqual((self.root / "legacy-bin/lib/logging_archives.sh").read_text(), "old-lib")

    def test_legacy_system_shims_delegate_via_shared_helper_without_recursion(self):
        native_cli = self.file("bin/native-af", '#!/usr/bin/env bash\nprintf "%s\\n" "$@"\n')
        native_cli.chmod(0o755)

        for shim_name, expected_subcommand in (
            ("af-tune", "tune"),
            ("clean_log", "clean-logs"),
            ("showspace", "showspace"),
            ("af-backup", "backup"),
        ):
            with self.subTest(shim=shim_name):
                shim_path = ROOT / "packages/system" / shim_name
                self.assertTrue(os.access(shim_path, os.X_OK))
                shim_text = shim_path.read_text(encoding="utf-8")
                self.assertIn("cli_shim.sh", shim_text)
                self.assertIn(f"af_exec_native_cli {expected_subcommand}", shim_text)
                self.assertNotIn("is_legacy_af_wrapper()", shim_text)

                result = subprocess.run(
                    ["bash", str(shim_path), "--dry-run", "--json"],
                    env={**os.environ, "AETHERFLOW_CLI_BIN": str(native_cli)},
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [expected_subcommand, "--dry-run", "--json"])

                # Invoking via a symlink in another directory must still locate ../lib/cli_shim.sh
                symlink = self.root / f"links/{shim_name}"
                symlink.parent.mkdir(parents=True, exist_ok=True)
                symlink.symlink_to(shim_path)
                linked_res = subprocess.run(
                    [str(symlink), "--flag"],
                    env={**os.environ, "AETHERFLOW_CLI_BIN": str(native_cli)},
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(linked_res.returncode, 0, linked_res.stderr)
                self.assertEqual(linked_res.stdout.splitlines(), [expected_subcommand, "--flag"])

        # Verify recursion guard rejects pointing AETHERFLOW_CLI_BIN at legacy packages/system/af
        staged_pkg = self.root / "isolated/packages"
        (staged_pkg / "lib").mkdir(parents=True, exist_ok=True)
        (staged_pkg / "system").mkdir(parents=True, exist_ok=True)
        shim_helper = replace_paths_once(
            (ROOT / "packages/lib/cli_shim.sh").read_text(encoding="utf-8"),
            [(prefix, str(self.root) + prefix) for prefix in ("/opt/", "/usr/local/")],
        )
        (staged_pkg / "lib/cli_shim.sh").write_text(shim_helper, encoding="utf-8")
        legacy_af = staged_pkg / "system/af"
        legacy_af.write_text('#!/usr/bin/env bash\necho RECURSED >&2\nexit 99\n', encoding="utf-8")
        legacy_af.chmod(0o755)
        staged_tune = staged_pkg / "system/af-tune"
        staged_tune.write_text((ROOT / "packages/system/af-tune").read_text(encoding="utf-8"), encoding="utf-8")
        staged_tune.chmod(0o755)
        blocked = subprocess.run(
            ["bash", str(staged_tune), "--dry-run"],
            env={**os.environ, "AETHERFLOW_CLI_BIN": str(legacy_af)},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assertNotIn("RECURSED", blocked.stderr)
        self.assertIn("Native AetherFlow CLI binary", blocked.stderr)

    def test_common_sh_modular_loader_is_idempotent_and_bounded(self):
        common_lines = (ROOT / "packages/common.sh").read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(common_lines), 100)
        for mod in COMMON_LIB_MODULES:
            mod_path = ROOT / "packages/lib" / mod
            self.assertTrue(mod_path.is_file(), f"missing common.sh module {mod}")
            # Cap raised from 1800 to 2200 after Wave 1B hardening grew apache_dns_locks.sh
            # (1944 lines) and systemd_credentials.sh (1966 lines) with dirfd/atomic guards.
            self.assertLess(len(mod_path.read_text(encoding="utf-8").splitlines()), 2200, mod)

        probe = f"""
export LOGFILE="{self.root / 'loader.log'}"
export LOCK_DIR="{self.root / 'install'}"
export AETHERFLOW_SKIP_ENV_FILES=1
source "{ROOT / 'packages/common.sh'}"
AF_PENDING_VERSION_PATHS+=("/tmp/sentinel")
source "{ROOT / 'packages/common.sh'}"
printf 'count=%s\\n' "${{#AF_PENDING_VERSION_PATHS[@]}}"
declare -F af_logged prepare_apt_package_transaction begin_state_transaction safe_config_python configure_apache_app_listener af_write_failure_receipt af_syncthing_listener_owned_by_unit wait_for_service_ready >/dev/null
printf 'ok\\n'
"""
        lines = self.run_bash(probe)
        self.assertEqual(lines, ["count=1", "ok"])


if __name__ == "__main__":
    unittest.main()
