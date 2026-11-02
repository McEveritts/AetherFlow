import fcntl
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packages/package/install/installpackage-maintainerr"
REMOVER = ROOT / "packages/package/remove/removepackage-maintainerr"
SANDBOX = ROOT / "packages/system/af-systemd-sandbox"
MOCK_COMMAND = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

root = Path(os.environ["TEST_ROOT"])
command = Path(sys.argv[0]).name
arguments = sys.argv[1:]
failure = os.environ.get("TEST_FAILURE", "")
running = root / "running"
database = root / "var/lib/maintainerr/maintainerr.sqlite"
unit = root / "etc/systemd/system/af-maintainerr.service"
users_file = root / "users"
groups_file = root / "groups"
procs_file = root / "builder-procs.json"


def load_procs():
    if not procs_file.exists():
        return []
    return json.loads(procs_file.read_text(encoding="utf-8"))


def save_procs(procs):
    procs_file.write_text(json.dumps(procs), encoding="utf-8")


with (root / "commands").open("a") as output:
    output.write(command + " " + " ".join(arguments) + "\n")
if command in ("apt-get", "chown"):
    pass
elif command == "sleep":
    procs = load_procs()
    if procs:
        updated = []
        for proc in procs:
            if proc.get("state") == "dying":
                rem = int(proc.get("remaining_sleeps", 1)) - 1
                if rem > 0:
                    proc["remaining_sleeps"] = rem
                    updated.append(proc)
            else:
                updated.append(proc)
        save_procs(updated)
elif command == "pgrep":
    if failure == "pgrep-error":
        sys.exit(2)
    flag = arguments[0] if arguments else ""
    target = arguments[1] if len(arguments) > 1 else ""
    if flag not in ("-U", "-u") or target != "998":
        sys.exit(2)
    procs = load_procs()
    matching = [str(p["pid"]) for p in procs if str(p.get("uid", "998")) == target]
    if matching:
        print("\n".join(matching))
        sys.exit(0)
    sys.exit(1)
elif command == "pkill":
    if failure == "pkill-error":
        sys.exit(2)
    if len(arguments) >= 3 and arguments[0] == "-KILL" and arguments[1] in ("-U", "-u"):
        target = arguments[2]
        procs = load_procs()
        matched = False
        updated = []
        for proc in procs:
            proc_id = str(proc.get("uid", "998")) if target.isdigit() else str(proc.get("user", "af-maintainerr-build"))
            if proc_id == target:
                matched = True
                if proc.get("unkillable"):
                    updated.append(proc)
                elif int(proc.get("delay_sleeps", 0)) > 0:
                    if proc.get("state") != "dying":
                        proc["state"] = "dying"
                        proc["remaining_sleeps"] = int(proc["delay_sleeps"])
                    updated.append(proc)
            else:
                updated.append(proc)
        save_procs(updated)
        sys.exit(0 if matched else 1)
    sys.exit(2)
elif command == "useradd":
    users = set(users_file.read_text().splitlines()) if users_file.exists() else set()
    users.add(arguments[-1])
    users_file.write_text("\n".join(sorted(users)) + "\n")
    if "--user-group" in arguments:
        groups = set(groups_file.read_text().splitlines()) if groups_file.exists() else set()
        groups.add(arguments[-1])
        groups_file.write_text("\n".join(sorted(groups)) + "\n")
elif command == "userdel":
    if failure == "userdel":
        sys.exit(1)
    force = "-f" in arguments or "--force" in arguments
    if arguments and arguments[-1] == "af-maintainerr-build" and not force:
        if any(str(p.get("uid", "998")) == "998" for p in load_procs()):
            sys.exit(8)
    users = set(users_file.read_text().splitlines()) if users_file.exists() else set()
    users.discard(arguments[-1])
    users_file.write_text("\n".join(sorted(users)) + "\n")
    if failure != "linger-group":
        groups = set(groups_file.read_text().splitlines()) if groups_file.exists() else set()
        groups.discard(arguments[-1])
        groups_file.write_text("\n".join(sorted(groups)) + "\n")
elif command == "groupdel":
    if failure == "groupdel":
        sys.exit(1)
    groups = set(groups_file.read_text().splitlines()) if groups_file.exists() else set()
    groups.discard(arguments[-1])
    groups_file.write_text("\n".join(sorted(groups)) + "\n")
elif command == "getent":
    database_name = arguments[0] if arguments else ""
    key = arguments[1] if len(arguments) > 1 else ""
    if database_name == "group":
        groups = set(groups_file.read_text().splitlines()) if groups_file.exists() else set()
        if key in groups:
            print(f"{key}:x:998:")
            sys.exit(0)
        sys.exit(2)
    elif database_name == "passwd":
        if key == "maintainerr":
            print(f"maintainerr:x:997:997::{(root / 'var/lib/maintainerr')}:/usr/sbin/nologin")
            sys.exit(0)
        sys.exit(2)
    sys.exit(2)
elif command == "id":
    user = arguments[-1]
    users = set(users_file.read_text().splitlines()) if users_file.exists() else set()
    if user == "af-maintainerr-build":
        if user in users:
            print("998")
            sys.exit(0)
        sys.exit(1)
    if os.environ.get("TEST_FRESH") == "1" and user not in users:
        sys.exit(1)
    print("997")
    sys.exit(0)
elif command == "runuser":
    assert arguments[:3] == ["-u", "af-maintainerr-build", "--"], f"unexpected runuser args: {arguments}"
    assert arguments[3:5] == ["env", "-i"], f"expected clean env -i in runuser: {arguments}"
    env_vars = {}
    idx = 5
    while idx < len(arguments) and "=" in arguments[idx] and not arguments[idx].startswith("-"):
        k, v = arguments[idx].split("=", 1)
        env_vars[k] = v
        idx += 1
    cmd = arguments[idx:]
    with (root / "builder-runs").open("a") as output:
        output.write(json.dumps({"user": arguments[1], "env": env_vars, "cmd": cmd}) + "\n")
    child_env = dict(env_vars)
    child_env["PATH"] = f"{root}/mock-bin:{env_vars.get('PATH', '')}"
    for passthrough in (
        "TEST_ROOT", "TEST_FAILURE", "TEST_FRESH", "TEST_VERSION",
        "TEST_MANAGER", "TEST_ARCHITECTURE", "TEST_SENTINEL", "TEST_EXTERNAL_SYMLINK",
    ):
        if passthrough in os.environ:
            child_env[passthrough] = os.environ[passthrough]
    child_env["MOCK_BUILDER_USER"] = arguments[1]
    res = subprocess.run(cmd, env=child_env)
    sys.exit(res.returncode)
elif command == "uname":
    print(os.environ.get("TEST_ARCHITECTURE", os.uname().machine))
elif command == "git":
    assert os.environ.get("MOCK_BUILDER_USER") == "af-maintainerr-build", "git must run as af-maintainerr-build"
    target = Path(arguments[-1])
    for directory in (".yarn/releases", "apps/ui", "apps/server/assets", "packages/contracts"):
        (target / directory).mkdir(parents=True, exist_ok=True)
    (target / "package.json").write_text(json.dumps({
        "version": os.environ.get("TEST_VERSION", "3.31.0"),
        "packageManager": os.environ.get("TEST_MANAGER", "yarn@4.17.1"),
    }))
    if failure != "missing-yarn":
        (target / ".yarn/releases/yarn-4.17.1.cjs").write_text("bundled yarn")
    (target / "apps/server/assets/font.ttf").write_text("font")
elif command == "node":
    assert os.environ.get("MOCK_BUILDER_USER") == "af-maintainerr-build", "all node executions must run as af-maintainerr-build"
    assert "SECRET_LEAK_TEST" not in os.environ, "builder node environment must not leak root variables"
    for key in (
        "HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
        "TMPDIR", "YARN_CACHE_FOLDER", "npm_config_cache",
    ):
        assert ".maintainerr-build." in os.environ.get(key, ""), f"unisolated builder env {key}"
        assert "var/lib/maintainerr" not in os.environ.get(key, ""), f"builder env {key} references runtime state"
    if arguments[0] == "-p":
        raise RuntimeError("node -p must not be executed as root on upstream metadata")
    elif arguments[0] == "-e":
        with (root / "node-probes").open("a") as output:
            output.write(json.dumps({
                "user": os.environ.get("MOCK_BUILDER_USER"),
                "executable": sys.argv[0],
                "args": arguments,
                "secret_leaked": "SECRET_LEAK_TEST" in os.environ,
            }) + "\n")
        if failure in ("node-version", "node-probe-compromised"):
            if failure == "node-probe-compromised":
                assert os.environ.get("MOCK_BUILDER_USER") == "af-maintainerr-build"
                assert "SECRET_LEAK_TEST" not in os.environ
            sys.exit(1)
    else:
        action = arguments[1]
        if failure == action:
            sys.exit(1)
        if action == "install":
            assert "--immutable" in arguments
        elif action == "turbo":
            assert running.exists() or os.environ.get("TEST_FRESH") == "1", "service stopped before build"
            for directory in ("apps/server/dist", "apps/ui/dist", "packages/contracts/dist", "node_modules/.bin"):
                Path(directory).mkdir(parents=True, exist_ok=True)
            if failure == "symlink-required":
                Path("apps/server/dist/main.js").symlink_to("../assets/font.ttf")
            else:
                Path("apps/server/dist/main.js").write_text("built server")
            if failure != "missing-ui":
                Path("apps/ui/dist/index.html").write_text("built UI")
            Path("packages/contracts/dist/index.js").write_text("built contracts")
            internal_link = Path("node_modules/.bin/maintainerr-helper")
            if not internal_link.exists() and not internal_link.is_symlink():
                internal_link.symlink_to("../../packages/contracts/dist/index.js")
            if failure == "symlink-escape":
                Path("apps/server/dist/escape").symlink_to("/etc/passwd")
            elif failure == "relative-symlink-escape":
                Path("apps/server/dist/escape-rel").symlink_to("../../../../etc/passwd")
        elif action == "workspaces":
            assert arguments[2:] == ["focus", "--all", "--production"]
            sentinel = Path(os.environ.get("TEST_SENTINEL", str(root / "sentinel-secret")))
            if failure == "detached-delayed":
                save_procs([{"pid": 4242, "uid": "998", "user": "af-maintainerr-build", "delay_sleeps": 2, "attack": "app_swap"}])
            elif failure == "detached-final-interval":
                save_procs([{"pid": 4244, "uid": "998", "user": "af-maintainerr-build", "delay_sleeps": 50}])
            elif failure in ("detached-timeout", "pkill-error"):
                save_procs([{"pid": 4243, "uid": "998", "user": "af-maintainerr-build", "unkillable": True}])
            elif failure == "signal-with-survivor":
                import signal
                save_procs([{"pid": 4245, "uid": "998", "user": "af-maintainerr-build", "unkillable": True}])
                os.kill(os.getppid(), signal.SIGTERM)
                sys.exit(143)
            elif failure == "build-error-with-survivor":
                save_procs([{"pid": 4246, "uid": "998", "user": "af-maintainerr-build", "unkillable": True}])
                sys.exit(1)
            elif failure == "hardlink-sentinel":
                os.link(sentinel, Path("apps/server/dist/hardlinked-secret"))
            elif failure == "hardlink-file-symlink":
                external_symlink = Path(os.environ["TEST_EXTERNAL_SYMLINK"])
                os.link(external_symlink, Path("apps/server/dist/aliased-file-link"), follow_symlinks=False)
            elif failure == "hardlink-dir-symlink":
                external_symlink = Path(os.environ["TEST_EXTERNAL_SYMLINK"])
                os.link(external_symlink, Path("apps/server/dist/aliased-dir-link"), follow_symlinks=False)
            elif failure == "fifo-artifact":
                os.mkfifo("apps/server/dist/unexpected.fifo")
            elif failure == "privileged-modes":
                Path(".").chmod(0o3777)
                Path("apps/server/dist").chmod(0o2777)
                Path(".runtime/bin/node").chmod(0o6777)
                Path("apps/server/dist/main.js").chmod(0o6666)
            elif failure == "parent-app-swap":
                parent_dir = Path.cwd().parent
                parent_mode = stat.S_IMODE(parent_dir.lstat().st_mode)
                if parent_mode & 0o022:
                    shutil.rmtree(Path.cwd())
                    Path.cwd().symlink_to(sentinel)
        else:
            raise RuntimeError(arguments)
elif command == "curl":
    if "-o" in arguments:
        target = Path(arguments[arguments.index("-o") + 1])
        if target.name == "node-shasums.txt":
            shutil.copyfile(root / "SHASUMS256.txt", target)
        else:
            shutil.copyfile(root / "node.tar.xz", target)
    else:
        if failure == "health":
            print('{"status":"degraded","database":"unreachable"}')
        else:
            print('{"status":"ok","database":"ok"}')
elif command == "systemctl":
    action = arguments[0]
    if action == "show":
        print("maintainerr")
        sys.exit(0)
    elif action == "is-active":
        sys.exit(0 if running.exists() else 3)
    elif action == "stop":
        if not unit.exists() and not running.exists():
            sys.exit(5)
        if failure == "stop":
            sys.exit(1)
        running.unlink(missing_ok=True)
    elif action == "restart":
        if not unit.exists():
            sys.exit(5)
        database.write_text("migrated database")
        if failure == "restart":
            sys.exit(1)
        running.touch()
    elif action == "start":
        if not unit.exists():
            sys.exit(5)
        running.touch()
    elif action == "enable":
        if not unit.exists():
            sys.exit(5)
else:
    raise RuntimeError(command)
'''


class MaintainerrInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in (
            "mock-bin", "opt/AetherFlow/packages/system", "var/lib/maintainerr",
            "var/backups", "etc/systemd/system", "install",
        ):
            (self.root / directory).mkdir(parents=True)
        self.app = self.root / "opt/maintainerr"
        self.app.mkdir()
        (self.app / ".af-version").write_text("3.30.0\n")
        self.database = self.root / "var/lib/maintainerr/maintainerr.sqlite"
        self.database.write_text("original database")
        self.settings = self.root / "var/lib/maintainerr/settings.json"
        self.settings.write_text("integration credentials")
        self.unit = self.root / "etc/systemd/system/af-maintainerr.service"
        self.unit.write_text("original unit")
        self.dropin_dir = self.root / "etc/systemd/system/af-maintainerr.service.d"
        self.dropin = self.dropin_dir / "10-aetherflow-sandbox.conf"
        self.lock = self.root / "install/.maintainerr.lock"
        self.lock.touch()
        (self.root / "running").touch()
        common = self.root / "opt/AetherFlow/packages/common.sh"
        common.write_text('''require_root() { :; }
log_info() { printf '%s\\n' "$*"; }
log_error() { printf '%s\\n' "$*" >&2; }
report_progress() { :; }
github_latest_tag() { printf '%s\\n' "${TEST_TAG-v3.31.0}"; }
write_lock() { touch "$TEST_ROOT/install/.maintainerr.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.maintainerr.lock"; }
purge_systemd_unit() {
    systemctl stop "$1"
    systemctl disable "$1"
    rm -f "$TEST_ROOT/etc/systemd/system/$1.service"
    rm -rf "$TEST_ROOT/etc/systemd/system/$1.service.d"
}
purge_system_user() { touch "$TEST_ROOT/user-removed"; }
''')
        for command in (
            "apt-get", "chown", "id", "getent", "uname", "sleep", "useradd", "userdel",
            "groupdel", "pgrep", "pkill", "runuser", "git", "node", "curl", "systemctl",
        ):
            executable = self.root / "mock-bin" / command
            executable.write_text(MOCK_COMMAND)
            executable.chmod(0o755)
        archive = self.root / "node.tar.xz"
        architecture = "arm64" if os.uname().machine in ("aarch64", "arm64") else "x64"
        with tarfile.open(archive, "w:xz") as output:
            payload = MOCK_COMMAND.encode()
            entry = tarfile.TarInfo(f"node-v26.12.1-linux-{architecture}/bin/node")
            entry.size = len(payload)
            entry.mode = 0o755
            output.addfile(entry, io.BytesIO(payload))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "SHASUMS256.txt").write_text(f"{checksum}  node-v26.12.1-linux-{architecture}.tar.xz\n")
        self.sandbox = self.rewrite_script(SANDBOX, "opt/AetherFlow/packages/system/af-systemd-sandbox")
        self.sandbox.chmod(0o644)
        self.installer = self.rewrite_script(INSTALLER, "installer")
        self.remover = self.rewrite_script(REMOVER, "remover")

    def rewrite_script(self, path, filename):
        source = path.read_text()
        for prefix in ("/opt/", "/var/", "/etc/", "/run/", "/install"):
            source = source.replace(prefix, str(self.root) + prefix)
        target = self.root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        return target

    def run_script(self, script=None, **environment):
        return subprocess.run(
            ["bash", str(script or self.installer)],
            env={
                **os.environ, "PATH": f"{self.root}/mock-bin:{os.environ['PATH']}", "TEST_ROOT": str(self.root),
                "AF_APP_PORT": "", "AETHERFLOW_APP_PORT": "", "DELETE_DATA": "false", **environment,
            },
            text=True, capture_output=True, timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_original_installation(self, running=True, expect_clean_workspaces=True):
        self.assertEqual((self.app / ".af-version").read_text(), "3.30.0\n")
        self.assertEqual(self.database.read_text(), "original database")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertEqual(self.unit.read_text(), "original unit")
        self.assertEqual((self.root / "running").exists(), running)
        self.assertTrue(self.lock.exists())
        if expect_clean_workspaces:
            self.assertEqual(list((self.root / "opt").glob(".maintainerr-build.*")), [])

    def clear_builder_state(self):
        (self.root / "commands").unlink(missing_ok=True)
        (self.root / "builder-procs.json").unlink(missing_ok=True)
        (self.root / "users").unlink(missing_ok=True)
        (self.root / "groups").unlink(missing_ok=True)
        for workspace in (self.root / "opt").glob(".maintainerr-build.*"):
            shutil.rmtree(workspace, ignore_errors=True)

    def test_upgrade_preserves_state_and_backs_up_before_migrations(self):
        self.assert_success(self.run_script(AF_APP_PORT="17846"))
        self.assertEqual((self.app / ".af-version").read_text(), "3.31.0\n")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertEqual(self.database.read_text(), "migrated database")
        self.assertEqual((self.app / "apps/server/dist/ui/index.html").read_text(), "built UI")
        self.assertEqual((self.app / "apps/server/dist/assets/font.ttf").read_text(), "font")
        internal_link = self.app / "node_modules/.bin/maintainerr-helper"
        self.assertTrue(internal_link.is_symlink())
        self.assertEqual(os.readlink(internal_link), "../../packages/contracts/dist/index.js")
        backups = list((self.root / "var/backups").glob("aetherflow-maintainerr.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "app/.af-version").read_text(), "3.30.0\n")
        self.assertEqual((backups[0] / "af-maintainerr.service").read_text(), "original unit")
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
        with tarfile.open(backups[0] / "data.tar.gz") as archive:
            self.assertEqual(archive.extractfile("./maintainerr.sqlite").read(), b"original database")
        unit = self.unit.read_text()
        for setting in (
            "User=maintainerr", "Environment=UI_PORT=17846", "Environment=UI_HOSTNAME=127.0.0.1",
            "Environment=NODE_ENV=production", "Environment=BASE_PATH=", "Environment=npm_package_version=3.31.0",
            "NoNewPrivileges=true", "ProtectSystem=strict",
        ):
            self.assertIn(setting, unit)
        self.assertIn(str(self.root / "var/lib/maintainerr"), unit)
        self.assertTrue(self.dropin.exists())
        dropin_content = self.dropin.read_text()
        self.assertIn("ProtectSystem=strict", dropin_content)
        self.assertNotIn("MemoryDenyWriteExecute=yes", dropin_content)
        self.assertIn(str(self.root / "var/lib/maintainerr"), dropin_content)
        commands = (self.root / "commands").read_text().splitlines()
        restart_commands = [line for line in commands if line.startswith("systemctl restart")]
        self.assertEqual(len(restart_commands), 1)
        self.assertIn("http://127.0.0.1:17846/api/health/ready", "\n".join(commands))
        self.assertTrue(self.lock.exists())

    def test_fresh_install_creates_service_with_default_port(self):
        shutil.rmtree(self.app)
        shutil.rmtree(self.database.parent)
        self.unit.unlink()
        self.lock.unlink()
        (self.root / "running").unlink()
        self.assert_success(self.run_script(TEST_FRESH="1"))
        self.assertIn("Environment=UI_PORT=6246", self.unit.read_text())
        self.assertTrue(self.dropin.exists())
        commands = (self.root / "commands").read_text()
        self.assertIn("useradd --system", commands)
        self.assertNotIn("systemctl stop", commands)
        self.assertTrue(self.database.exists())
        self.assertTrue(self.lock.exists())
        self.assertTrue((self.root / "running").exists())

    def test_fallback_port_environment_is_honored(self):
        self.assert_success(self.run_script(AETHERFLOW_APP_PORT="17847"))
        self.assertIn("Environment=UI_PORT=17847", self.unit.read_text())

    def test_reinstall_is_idempotent_and_retains_integration_settings(self):
        self.assert_success(self.run_script())
        self.assert_success(self.run_script())
        self.assertEqual((self.app / ".af-version").read_text(), "3.31.0\n")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertEqual(len(list((self.root / "var/backups").glob("aetherflow-maintainerr.*"))), 2)
        self.assertTrue(self.lock.exists())

    def test_install_and_remove_share_an_exclusive_lifecycle_lock(self):
        lock_path = self.root / "run/lock/aetherflow-maintainerr.lock"
        lock_path.parent.mkdir(parents=True)
        with lock_path.open("w") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for script in (self.installer, self.remover):
                with self.subTest(script=script.name):
                    result = self.run_script(script)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Another Maintainerr lifecycle operation", result.stderr)
                    self.assert_original_installation()
        self.assertFalse((self.root / "commands").exists())

    def test_dependency_build_and_production_failures_leave_service_untouched(self):
        for failure in ("install", "turbo", "workspaces", "missing-ui", "missing-yarn"):
            with self.subTest(failure=failure):
                result = self.run_script(TEST_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation()
        self.assertNotIn("systemctl stop", (self.root / "commands").read_text())

    def test_upgrade_stop_failure_is_not_suppressed_and_leaves_installation_untouched(self):
        for initially_running in (True, False):
            with self.subTest(initially_running=initially_running):
                if not initially_running:
                    (self.root / "running").unlink(missing_ok=True)
                else:
                    (self.root / "running").touch()
                result = self.run_script(TEST_FRESH="1" if not initially_running else "0", TEST_FAILURE="stop")
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation(running=initially_running)
                self.assertEqual(list((self.root / "var/backups").glob("aetherflow-maintainerr.*")), [])

    def test_existing_inactive_service_upgrades_and_rolls_back_without_restarting(self):
        (self.root / "running").unlink()
        for failure in ("restart", "health"):
            with self.subTest(failure=failure):
                result = self.run_script(TEST_FRESH="1", TEST_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation(running=False)
        self.assert_success(self.run_script(TEST_FRESH="1"))
        self.assertEqual((self.app / ".af-version").read_text(), "3.31.0\n")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertEqual(self.database.read_text(), "migrated database")
        self.assertTrue((self.root / "running").exists())
        self.assertTrue(self.lock.exists())

    def test_failed_restart_restores_database_bundle_unit_and_service(self):
        result = self.run_script(TEST_FAILURE="restart")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_installation()
        self.assertFalse(self.dropin_dir.exists())

    def test_failed_readiness_restores_database_bundle_unit_and_service(self):
        self.dropin_dir.mkdir(parents=True, exist_ok=True)
        self.dropin.write_text("original sandbox dropin\n")
        result = self.run_script(TEST_FAILURE="health")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_installation()
        self.assertEqual(self.dropin.read_text(), "original sandbox dropin\n")

    def test_sandbox_helper_failure_aborts_activation_and_restores_previous_dropin(self):
        self.dropin_dir.mkdir(parents=True, exist_ok=True)
        self.dropin.write_text("original sandbox dropin\n")
        self.sandbox.write_text(":\nrm -rf \"" + str(self.dropin_dir) + "\"\nexit 1\n")
        self.sandbox.chmod(0o755)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_installation(running=True)
        self.assertEqual(self.dropin.read_text(), "original sandbox dropin\n")

    def test_failed_first_activation_removes_incomplete_installation(self):
        for failure in ("restart", "health"):
            with self.subTest(failure=failure):
                shutil.rmtree(self.app, ignore_errors=True)
                shutil.rmtree(self.database.parent, ignore_errors=True)
                self.unit.unlink(missing_ok=True)
                shutil.rmtree(self.dropin_dir, ignore_errors=True)
                self.lock.unlink(missing_ok=True)
                (self.root / "running").unlink(missing_ok=True)
                result = self.run_script(TEST_FRESH="1", TEST_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.app.exists())
                self.assertFalse(self.unit.exists())
                self.assertFalse(self.dropin_dir.exists())
                self.assertFalse(self.database.exists())
                self.assertFalse(self.lock.exists())
                self.assertFalse((self.root / "running").exists())

    def test_reinstall_after_default_removal_preserves_and_restores_retained_data(self):
        self.assert_success(self.run_script(self.remover))
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.root / "running").exists())
        result = self.run_script(TEST_FRESH="1", TEST_FAILURE="health")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.lock.exists())
        self.assertFalse((self.root / "running").exists())
        self.assertEqual(self.database.read_text(), "original database")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assert_success(self.run_script(TEST_FRESH="1"))
        self.assertEqual((self.app / ".af-version").read_text(), "3.31.0\n")
        self.assertEqual(self.database.read_text(), "migrated database")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertTrue(self.unit.exists())
        self.assertTrue(self.lock.exists())
        self.assertTrue((self.root / "running").exists())

    def test_node_checksum_failure_leaves_service_untouched(self):
        (self.root / "SHASUMS256.txt").write_text((self.root / "SHASUMS256.txt").read_text().replace(
            hashlib.sha256((self.root / "node.tar.xz").read_bytes()).hexdigest(), "0" * 64,
        ))
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_installation()

    def test_invalid_release_and_build_metadata_leave_service_untouched(self):
        for environment in (
            {"TEST_TAG": ""}, {"TEST_TAG": "v3.31.0-rc.1"}, {"TEST_MANAGER": "yarn@1.22.0"},
            {"TEST_VERSION": "3.30.0"}, {"TEST_ARCHITECTURE": "riscv64"},
        ):
            with self.subTest(environment=environment):
                result = self.run_script(**environment)
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation()

    def test_invalid_ports_fail_before_dependency_installation(self):
        for port in ("80", "0", "65536", "-1", "6246\nmalicious", "not-a-port"):
            with self.subTest(port=port):
                result = self.run_script(AF_APP_PORT=port)
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation()
        self.assertFalse((self.root / "commands").exists())

    def test_remove_preserves_database_settings_and_account_by_default(self):
        self.assert_success(self.run_script(self.remover))
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.lock.exists())
        self.assertEqual(self.database.read_text(), "original database")
        self.assertEqual(self.settings.read_text(), "integration credentials")
        self.assertFalse((self.root / "user-removed").exists())

    def test_explicit_data_removal_deletes_database_and_account(self):
        self.assert_success(self.run_script(self.remover, DELETE_DATA="true"))
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse(self.database.parent.exists())
        self.assertFalse(self.lock.exists())
        self.assertTrue((self.root / "user-removed").exists())

    def test_unprivileged_builder_isolation_and_account_cleanup(self):
        import json
        import stat

        (self.root / "commands").unlink(missing_ok=True)
        (self.root / "users").write_text("af-maintainerr-build\n")
        (self.root / "groups").unlink(missing_ok=True)
        preexisting_user_result = self.run_script()
        self.assertNotEqual(preexisting_user_result.returncode, 0)
        self.assertIn("Refusing to reuse pre-existing af-maintainerr-build", preexisting_user_result.stderr)
        preexisting_user_commands = (self.root / "commands").read_text()
        self.assertNotIn("pkill", preexisting_user_commands)
        self.assertNotIn("userdel", preexisting_user_commands)
        self.assertNotIn("groupdel", preexisting_user_commands)
        self.assertIn("af-maintainerr-build", (self.root / "users").read_text().splitlines())
        self.assert_original_installation(running=True)

        (self.root / "commands").unlink(missing_ok=True)
        (self.root / "users").unlink(missing_ok=True)
        (self.root / "groups").write_text("af-maintainerr-build\n")
        preexisting_group_result = self.run_script()
        self.assertNotEqual(preexisting_group_result.returncode, 0)
        self.assertIn("Refusing to reuse pre-existing af-maintainerr-build", preexisting_group_result.stderr)
        preexisting_group_commands = (self.root / "commands").read_text()
        self.assertNotIn("pkill", preexisting_group_commands)
        self.assertNotIn("userdel", preexisting_group_commands)
        self.assertNotIn("groupdel", preexisting_group_commands)
        self.assertIn("af-maintainerr-build", (self.root / "groups").read_text().splitlines())
        self.assert_original_installation(running=True)

        for removal_failure in ("userdel", "groupdel"):
            with self.subTest(removal_failure=removal_failure):
                self.clear_builder_state()
                extra_failure = "groupdel" if removal_failure == "groupdel" else "userdel"
                if removal_failure == "groupdel":
                    (self.root / "mock-bin/userdel").write_text(
                        MOCK_COMMAND.replace('if failure != "linger-group":', "if False:")
                    )
                removal_result = self.run_script(TEST_FAILURE=extra_failure)
                (self.root / "mock-bin/userdel").write_text(MOCK_COMMAND)
                self.assertNotEqual(removal_result.returncode, 0)
                self.assertNotIn("systemctl stop", (self.root / "commands").read_text())
                self.assert_original_installation(running=True, expect_clean_workspaces=False)
                retained_workspaces = list((self.root / "opt").glob(".maintainerr-build.*"))
                self.assertEqual(len(retained_workspaces), 1)
                self.assertEqual(stat.S_IMODE(retained_workspaces[0].lstat().st_mode), 0o700)
                if removal_failure == "userdel":
                    self.assertIn("af-maintainerr-build", (self.root / "users").read_text().splitlines())
                else:
                    self.assertIn("af-maintainerr-build", (self.root / "groups").read_text().splitlines())
                collision_result = self.run_script()
                self.assertNotEqual(collision_result.returncode, 0)
                self.assertIn("Refusing to reuse pre-existing af-maintainerr-build", collision_result.stderr)

        self.clear_builder_state()
        (self.root / "builder-runs").unlink(missing_ok=True)
        (self.root / "node-probes").unlink(missing_ok=True)
        self.assert_success(self.run_script(SECRET_LEAK_TEST="must-not-pass-to-builder"))
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o750)
        builder_runs = [
            json.loads(line)
            for line in (self.root / "builder-runs").read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(len(builder_runs), 5)
        for run in builder_runs:
            self.assertEqual(run["user"], "af-maintainerr-build")
            env = run["env"]
            self.assertNotIn("SECRET_LEAK_TEST", env)
            for key in (
                "HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                "TMPDIR", "YARN_CACHE_FOLDER", "npm_config_cache",
            ):
                self.assertIn(".maintainerr-build.", env[key])
                self.assertNotIn("var/lib/maintainerr", env[key])
        self.assertEqual(builder_runs[0]["cmd"][:4], ["git", "-c", "core.hooksPath=/dev/null", "clone"])
        self.assertEqual(builder_runs[1]["cmd"][0], "mkdir")
        self.assertTrue(builder_runs[1]["cmd"][1].endswith("/app/.runtime"))
        self.assertEqual(builder_runs[2]["cmd"][:2], ["tar", "-xJf"])
        self.assertIn("--no-same-owner", builder_runs[2]["cmd"])
        self.assertIn("--no-same-permissions", builder_runs[2]["cmd"])
        self.assertTrue(builder_runs[3]["cmd"][0].endswith("/app/.runtime/bin/node"))
        self.assertEqual(builder_runs[3]["cmd"][1], "-e")
        self.assertEqual(builder_runs[4]["cmd"][:3], ["/bin/bash", "-e", "-c"])
        node_probes = [
            json.loads(line)
            for line in (self.root / "node-probes").read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(len(node_probes), 1)
        self.assertEqual(node_probes[0]["user"], "af-maintainerr-build")
        self.assertFalse(node_probes[0]["secret_leaked"])
        self.assertTrue(node_probes[0]["executable"].endswith("/app/.runtime/bin/node"))
        commands = (self.root / "commands").read_text()
        self.assertIn(
            "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin af-maintainerr-build",
            commands,
        )
        self.assertIn("pgrep -U 998", commands)
        self.assertIn("pgrep -u 998", commands)
        self.assertIn("userdel af-maintainerr-build", commands)
        users = (self.root / "users").read_text().splitlines() if (self.root / "users").exists() else []
        groups = (self.root / "groups").read_text().splitlines() if (self.root / "groups").exists() else []
        self.assertNotIn("af-maintainerr-build", users)
        self.assertNotIn("af-maintainerr-build", groups)
        for path in (
            self.app / ".af-version",
            self.app / "apps/server/dist/main.js",
            self.app / "apps/server/dist/ui/index.html",
            self.app / "packages/contracts/dist/index.js",
        ):
            self.assertEqual(path.stat().st_mode & 0o022, 0)

    def test_runtime_version_probe_isolation_and_failure_leaves_service_untouched(self):
        import json

        for failure in ("node-version", "node-probe-compromised"):
            with self.subTest(failure=failure):
                (self.root / "commands").unlink(missing_ok=True)
                (self.root / "builder-runs").unlink(missing_ok=True)
                (self.root / "node-probes").unlink(missing_ok=True)
                result = self.run_script(TEST_FAILURE=failure, SECRET_LEAK_TEST="must-not-pass-to-builder")
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation(running=True)
                commands = (self.root / "commands").read_text()
                self.assertNotIn("systemctl stop", commands)
                self.assertNotIn("systemctl restart", commands)
                self.assertIn("userdel af-maintainerr-build", commands)
                probes = [
                    json.loads(line)
                    for line in (self.root / "node-probes").read_text().splitlines()
                    if line.strip()
                ]
                self.assertEqual(len(probes), 1)
                self.assertEqual(probes[0]["user"], "af-maintainerr-build")
                self.assertFalse(probes[0]["secret_leaked"])
                users = (self.root / "users").read_text().splitlines() if (self.root / "users").exists() else []
                groups = (self.root / "groups").read_text().splitlines() if (self.root / "groups").exists() else []
                self.assertNotIn("af-maintainerr-build", users)
                self.assertNotIn("af-maintainerr-build", groups)

        direct_root_installer = self.root / "installer-direct-root-probe"
        direct_root_installer.write_text(
            self.installer.read_text().replace(
                'run_as_builder "$BUILD_DIR/.runtime/bin/node" -e',
                '"$BUILD_DIR/.runtime/bin/node" -e',
            )
        )
        (self.root / "commands").unlink(missing_ok=True)
        mutation_result = self.run_script(direct_root_installer, SECRET_LEAK_TEST="must-not-pass-to-builder")
        self.assertNotEqual(mutation_result.returncode, 0)
        self.assertIn("all node executions must run as af-maintainerr-build", mutation_result.stderr)
        self.assert_original_installation(running=True)

    def test_symlink_escape_and_symlinked_required_artifacts_rejected_before_cutover(self):
        import stat

        for failure in ("symlink-escape", "relative-symlink-escape", "symlink-required", "hardlink-sentinel", "fifo-artifact"):
            with self.subTest(failure=failure):
                sentinel = self.root / "sentinel-secret"
                sentinel.write_text("top-secret-key")
                sentinel.chmod(0o600)
                self.clear_builder_state()
                result = self.run_script(TEST_FAILURE=failure, TEST_SENTINEL=str(sentinel))
                self.assertNotEqual(result.returncode, 0)
                self.assert_original_installation(running=True)
                self.assertEqual(sentinel.read_text(), "top-secret-key")
                self.assertEqual(sentinel.stat().st_mode & 0o777, 0o600)
                commands = (self.root / "commands").read_text()
                self.assertNotIn("systemctl stop", commands)
                self.assertIn("userdel af-maintainerr-build", commands)
                users = (self.root / "users").read_text().splitlines() if (self.root / "users").exists() else []
                groups = (self.root / "groups").read_text().splitlines() if (self.root / "groups").exists() else []
                self.assertNotIn("af-maintainerr-build", users)
                self.assertNotIn("af-maintainerr-build", groups)

        for symlink_branch in ("hardlink-file-symlink", "hardlink-dir-symlink"):
            with self.subTest(symlink_branch=symlink_branch):
                sentinel = self.root / "sentinel-secret"
                sentinel.write_text("top-secret-key")
                sentinel.chmod(0o600)
                external_dir = self.root / "external-shared"
                shutil.rmtree(external_dir, ignore_errors=True)
                external_dir.mkdir(parents=True)
                if symlink_branch == "hardlink-dir-symlink":
                    external_target = external_dir / "target-dir"
                    external_target.mkdir()
                    external_symlink = external_dir / "external-dir-symlink"
                    external_symlink.symlink_to("target-dir")
                else:
                    external_symlink = external_dir / "external-file-symlink"
                    external_symlink.symlink_to("../../packages/contracts/dist/index.js")
                before_stat = os.lstat(external_symlink)
                self.clear_builder_state()
                result = self.run_script(
                    TEST_FAILURE=symlink_branch,
                    TEST_SENTINEL=str(sentinel),
                    TEST_EXTERNAL_SYMLINK=str(external_symlink),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Refusing multi-linked symlink in build tree", result.stderr)
                self.assert_original_installation(running=True)
                after_stat = os.lstat(external_symlink)
                self.assertEqual(after_stat.st_ino, before_stat.st_ino)
                self.assertEqual(after_stat.st_uid, before_stat.st_uid)
                self.assertEqual(after_stat.st_gid, before_stat.st_gid)
                self.assertEqual(after_stat.st_nlink, 1)
                self.assertEqual(sentinel.read_text(), "top-secret-key")
                self.assertEqual(stat.S_IMODE(sentinel.lstat().st_mode), 0o600)

    def test_promoted_artifacts_strip_special_and_unsafe_write_permissions(self):
        import stat

        result = self.run_script(TEST_FAILURE="privileged-modes")
        self.assert_success(result)
        for artifact in [self.app, *self.app.rglob("*")]:
            if artifact.is_symlink():
                continue
            mode = stat.S_IMODE(artifact.stat().st_mode)
            if artifact.is_dir():
                self.assertEqual(mode, 0o755, str(artifact))
            else:
                self.assertIn(mode, (0o644, 0o755), str(artifact))
        self.assertEqual(stat.S_IMODE((self.app / ".runtime/bin/node").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.app / "apps/server/dist/main.js").stat().st_mode), 0o644)

    def test_builder_quiescence_containment_and_path_swap_regressions(self):
        import json
        import stat

        sentinel = self.root / "sentinel-secret"
        sentinel.write_text("top-secret-key")
        sentinel.chmod(0o600)

        self.clear_builder_state()
        delayed_res = self.run_script(TEST_FAILURE="detached-delayed", TEST_SENTINEL=str(sentinel))
        self.assert_success(delayed_res)
        self.assertEqual(json.loads((self.root / "builder-procs.json").read_text()), [])
        delayed_cmds = (self.root / "commands").read_text()
        self.assertIn("pkill -KILL -U 998", delayed_cmds)
        self.assertIn("pkill -KILL -u 998", delayed_cmds)

        (self.app / ".af-version").write_text("3.30.0\n")
        self.database.write_text("original database")
        self.settings.write_text("integration credentials")
        self.unit.write_text("original unit")
        (self.root / "running").touch()
        for backup_item in (self.root / "var/backups").glob("aetherflow-maintainerr.*"):
            shutil.rmtree(backup_item)

        self.clear_builder_state()
        final_interval_res = self.run_script(TEST_FAILURE="detached-final-interval", TEST_SENTINEL=str(sentinel))
        self.assert_success(final_interval_res)
        self.assertEqual(json.loads((self.root / "builder-procs.json").read_text()), [])
        users_after_final = (self.root / "users").read_text().splitlines() if (self.root / "users").exists() else []
        groups_after_final = (self.root / "groups").read_text().splitlines() if (self.root / "groups").exists() else []
        self.assertNotIn("af-maintainerr-build", users_after_final)
        self.assertNotIn("af-maintainerr-build", groups_after_final)
        self.assertEqual(list((self.root / "opt").glob(".maintainerr-build.*")), [])

        (self.app / ".af-version").write_text("3.30.0\n")
        self.database.write_text("original database")
        self.settings.write_text("integration credentials")
        self.unit.write_text("original unit")
        (self.root / "running").touch()
        for backup_item in (self.root / "var/backups").glob("aetherflow-maintainerr.*"):
            shutil.rmtree(backup_item)

        for failure in ("pgrep-error", "pkill-error", "detached-timeout", "signal-with-survivor", "build-error-with-survivor"):
            with self.subTest(failure=failure):
                self.clear_builder_state()
                res = self.run_script(TEST_FAILURE=failure, TEST_SENTINEL=str(sentinel))
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("Retaining builder identity af-maintainerr-build", res.stderr)
                self.assert_original_installation(running=True, expect_clean_workspaces=False)
                cmds = (self.root / "commands").read_text()
                self.assertNotIn("systemctl stop", cmds)
                self.assertNotIn("systemctl restart", cmds)
                self.assertNotIn("userdel", cmds)
                self.assertNotIn("groupdel", cmds)
                retained_users = (self.root / "users").read_text().splitlines() if (self.root / "users").exists() else []
                retained_groups = (self.root / "groups").read_text().splitlines() if (self.root / "groups").exists() else []
                self.assertIn("af-maintainerr-build", retained_users)
                self.assertIn("af-maintainerr-build", retained_groups)
                retained_workspaces = list((self.root / "opt").glob(".maintainerr-build.*"))
                self.assertEqual(len(retained_workspaces), 1)
                self.assertEqual(stat.S_IMODE(retained_workspaces[0].lstat().st_mode), 0o700)
                self.assertTrue((retained_workspaces[0] / "app").exists())
                collision_res = self.run_script()
                self.assertNotEqual(collision_res.returncode, 0)
                self.assertIn("Refusing to reuse pre-existing af-maintainerr-build", collision_res.stderr)

        self.clear_builder_state()
        swap_res = self.run_script(TEST_FAILURE="parent-app-swap", TEST_SENTINEL=str(sentinel))
        self.assert_success(swap_res)
        self.assertEqual(sentinel.read_text(), "top-secret-key")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o600)

        (self.app / ".af-version").write_text("3.30.0\n")
        self.database.write_text("original database")
        self.settings.write_text("integration credentials")
        self.unit.write_text("original unit")
        (self.root / "running").touch()
        for backup_item in (self.root / "var/backups").glob("aetherflow-maintainerr.*"):
            shutil.rmtree(backup_item)

        boundary_swap_installer = self.root / "installer-boundary-swap"
        boundary_swap_installer.write_text(
            self.installer.read_text().replace(
                'python3 - "$BUILD_ROOT" "${LATEST_TAG#v}" <<\'PY\'\nimport os, pathlib, stat, sys',
                'rm -rf "$BUILD_DIR"\nln -s "' + str(sentinel) + '" "$BUILD_DIR"\n'
                'python3 - "$BUILD_ROOT" "${LATEST_TAG#v}" <<\'PY\'\nimport os, pathlib, stat, sys',
            )
        )
        self.clear_builder_state()
        boundary_res = self.run_script(boundary_swap_installer, TEST_SENTINEL=str(sentinel))
        self.assertNotEqual(boundary_res.returncode, 0)
        self.assertEqual(sentinel.read_text(), "top-secret-key")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o600)
        self.assert_original_installation(running=True)

        best_effort_kill_installer = self.root / "installer-best-effort-kill"
        best_effort_kill_installer.write_text(
            self.installer.read_text().replace(
                "if [[ \"$BUILD_USER_CREATED\" -eq 1 ]]; then\n    quiesce_builder_processes\nfi",
                "if [[ \"$BUILD_USER_CREATED\" -eq 1 ]]; then\n    pkill -KILL -u \"$BUILD_USER\" >/dev/null 2>&1 || true\nfi",
            ).replace(
                "if [[ \"$BUILD_USER_CREATED\" -eq 1 ]]; then\n    quiesce_builder_processes\n    if ! userdel",
                "if [[ \"$BUILD_USER_CREATED\" -eq 1 ]]; then\n    if ! userdel",
            )
        )
        self.clear_builder_state()
        mut_kill_res = self.run_script(best_effort_kill_installer, TEST_FAILURE="detached-delayed", TEST_SENTINEL=str(sentinel))
        self.assertNotEqual(mut_kill_res.returncode, 0)
        self.assert_original_installation(running=True)

        vulnerable_chmod_probe = self.root / "vulnerable-chmod-probe.py"
        vulnerable_chmod_probe.write_text(
            "import os, pathlib, stat, sys\n"
            "build_dir = pathlib.Path(sys.argv[1])\n"
            "sentinel = pathlib.Path(sys.argv[2])\n"
            "for root, dirs, files in os.walk(build_dir, topdown=True, followlinks=False):\n"
            "    root_path = pathlib.Path(root)\n"
            "    st = root_path.lstat()\n"
            "    if root_path == build_dir:\n"
            "        import shutil\n"
            "        shutil.rmtree(root_path)\n"
            "        root_path.symlink_to(sentinel)\n"
            "    os.chmod(root_path, (stat.S_IMODE(st.st_mode) & ~0o022) | 0o755)\n"
        )
        probe_dir = self.root / "probe-build-app"
        probe_dir.mkdir(mode=0o700)
        probe_sentinel = self.root / "probe-sentinel"
        probe_sentinel.write_text("secret")
        probe_sentinel.chmod(0o600)
        subprocess.run(["python3", str(vulnerable_chmod_probe), str(probe_dir), str(probe_sentinel)], check=True)
        self.assertEqual(stat.S_IMODE(probe_sentinel.lstat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(sentinel.lstat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
