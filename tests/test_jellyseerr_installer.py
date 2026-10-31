#!/usr/bin/env python3
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packages/package/install/installpackage-jellyseerr"
MOCK_COMMAND = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["TEST_ROOT"])
command = Path(sys.argv[0]).name
arguments = sys.argv[1:]
failure = os.environ.get("TEST_FAILURE", "")
running = root / "running"
app = root / "opt/jellyseerr"
state = root / "var/lib/jellyseerr/settings.json"
with (root / "commands").open("a") as output:
    output.write(command + " " + " ".join(arguments) + "\n")
if command in ("apt-get", "chown", "id", "sleep"):
    pass
elif command == "git":
    target = Path(arguments[-1])
    (target / "package.json").write_text(json.dumps({"version": "3.5.1", "packageManager": "pnpm@10.24.0"}))
elif command == "node":
    if arguments[0] == "-p":
        print(json.loads(Path("package.json").read_text())["packageManager"])
elif command == "npm":
    target = Path(arguments[arguments.index("--prefix") + 1]) / "node_modules/.bin"
    target.mkdir(parents=True)
    shutil.copy2(root / "mock-bin/pnpm", target / "pnpm")
elif command == "pnpm":
    if failure == arguments[0]:
        sys.exit(1)
    if arguments[0] == "build":
        assert running.exists() or os.environ.get("TEST_FRESH") == "1", "service stopped before build"
        Path("dist").mkdir()
        Path("dist/index.js").write_text("built")
elif command == "curl":
    if "-o" in arguments:
        target = Path(arguments[arguments.index("-o") + 1])
        if target.name == "node-shasums.txt":
            shutil.copyfile(root / "SHASUMS256.txt", target)
        else:
            shutil.copyfile(root / "node.tar.xz", target)
    else:
        print(json.dumps({"version": os.environ.get("TEST_HEALTH", "3.5.1")}))
elif command == "systemctl":
    action = arguments[0]
    if action == "is-active":
        sys.exit(0 if running.exists() else 3)
    elif action == "stop":
        running.unlink(missing_ok=True)
    elif action == "restart":
        state.write_text("migrated")
        if failure == "restart":
            sys.exit(1)
        running.touch()
    elif action == "start":
        running.touch()
else:
    raise RuntimeError(command)
'''


class JellyseerrInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ("mock-bin", "opt/AetherFlow/packages", "var/lib/jellyseerr", "var/backups", "etc/systemd/system"):
            (self.root / directory).mkdir(parents=True)
        self.app = self.root / "opt/jellyseerr"
        self.app.mkdir()
        (self.app / ".af-version").write_text("2.7.3\n")
        self.state = self.root / "var/lib/jellyseerr/settings.json"
        self.state.write_text("original-state")
        self.unit = self.root / "etc/systemd/system/jellyseerr.service"
        self.unit.write_text("original-unit")
        (self.root / "running").touch()
        common = self.root / "opt/AetherFlow/packages/common.sh"
        common.write_text('''require_root() { :; }
log_info() { printf '%s\\n' "$*"; }
log_error() { printf '%s\\n' "$*" >&2; }
report_progress() { :; }
github_latest_tag() { printf '%s\\n' "${TEST_TAG-v3.5.1}"; }
write_lock() { touch "$TEST_ROOT/completed"; }
''')
        for command in ("apt-get", "chown", "id", "sleep", "git", "node", "npm", "pnpm", "curl", "systemctl"):
            executable = self.root / "mock-bin" / command
            executable.write_text(MOCK_COMMAND)
            executable.chmod(0o755)
        archive = self.root / "node.tar.xz"
        with tarfile.open(archive, "w:xz") as output:
            for command in ("node", "npm"):
                payload = MOCK_COMMAND.encode()
                info = tarfile.TarInfo(f"node-v22.23.4-linux-{self.architecture()}/bin/{command}")
                info.size = len(payload)
                info.mode = 0o755
                output.addfile(info, io.BytesIO(payload))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "SHASUMS256.txt").write_text(f"{checksum}  node-v22.23.4-linux-{self.architecture()}.tar.xz\n")
        source = INSTALLER.read_text()
        for prefix in ("/opt/", "/var/", "/etc/", "/run/", "/install"):
            source = source.replace(prefix, str(self.root) + prefix)
        self.script = self.root / "installer"
        self.script.write_text(source)

    @staticmethod
    def architecture():
        return "arm64" if os.uname().machine in ("aarch64", "arm64") else "x64"

    def run_installer(self, **environment):
        return subprocess.run(
            ["bash", str(self.script)],
            env={**os.environ, "PATH": f"{self.root}/mock-bin:{os.environ['PATH']}", "TEST_ROOT": str(self.root), **environment},
            text=True, capture_output=True, timeout=30,
        )

    def assert_original_restored(self):
        self.assertEqual((self.app / ".af-version").read_text(), "2.7.3\n")
        self.assertEqual(self.state.read_text(), "original-state")
        self.assertEqual(self.unit.read_text(), "original-unit")
        self.assertTrue((self.root / "running").exists())
        self.assertFalse((self.root / "completed").exists())

    def test_upgrade_verifies_version_and_retains_backup(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.app / ".af-version").read_text(), "3.5.1\n")
        self.assertIn(".runtime/bin/node dist/index.js", self.unit.read_text())
        backups = list((self.root / "var/backups").glob("aetherflow-jellyseerr.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "app/.af-version").read_text(), "2.7.3\n")
        self.assertTrue((backups[0] / "data.tar.gz").exists())
        self.assertTrue((self.root / "completed").exists())
        self.assertEqual(list((self.root / "opt").glob(".jellyseerr-build.*")), [])

    def test_build_failure_keeps_running_installation_untouched(self):
        result = self.run_installer(TEST_FAILURE="build")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_restored()
        self.assertNotIn("systemctl stop", (self.root / "commands").read_text())

    def test_dependency_failure_keeps_running_installation_untouched(self):
        result = self.run_installer(TEST_FAILURE="install")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_restored()

    def test_wrong_running_version_restores_app_state_and_unit(self):
        result = self.run_installer(TEST_HEALTH="2.7.3")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_restored()

    def test_restart_failure_restores_app_state_and_unit(self):
        result = self.run_installer(TEST_FAILURE="restart")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_restored()

    def test_missing_or_prerelease_tag_is_rejected(self):
        for tag in ("", "v3.6.0-beta.1"):
            with self.subTest(tag=tag):
                result = self.run_installer(TEST_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_restored()

    def test_corrupt_runtime_is_rejected_before_cutover(self):
        (self.root / "node.tar.xz").write_bytes(b"corrupt")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_restored()

    def test_first_install_failure_removes_new_app_and_unit(self):
        (self.app / ".af-version").unlink()
        self.app.rmdir()
        self.unit.unlink()
        (self.root / "running").unlink()
        result = self.run_installer(TEST_FRESH="1", TEST_HEALTH="wrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.root / "running").exists())
        self.assertEqual(self.state.read_text(), "original-state")


if __name__ == "__main__":
    unittest.main()
