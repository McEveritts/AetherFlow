#!/usr/bin/env python3
"""Exercise The Lounge runtime, provisioning and readiness without changing the host."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packages/package/install/installpackage-thelounge"
REAL_NODE = shutil.which("node")
MOCK_COMMAND = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["TEST_ROOT"])
command = Path(sys.argv[0]).name
arguments = sys.argv[1:]
failure = os.environ.get("TEST_FAILURE", "")
with (root / "commands").open("a") as output:
    output.write(json.dumps([command, *arguments]) + "\n")
if command in ("apt-get", "chown", "id"):
    pass
elif command == "node":
    mode = os.environ.get("TEST_NODE_MODE", "flagged")
    flagged = "--experimental-sqlite" in arguments
    if "-e" in arguments and "DatabaseSync" in arguments[arguments.index("-e") + 1] and mode != "real":
        sys.exit(0 if mode == "native" or (mode == "flagged" and flagged) else 1)
    if mode == "flagged" and not flagged:
        sys.exit("SQLite flag was not passed to the CLI")
    forwarded = arguments if mode == "real" else [argument for argument in arguments if argument != "--experimental-sqlite"]
    os.execv(os.environ["TEST_REAL_NODE"], [os.environ["TEST_REAL_NODE"], *forwarded])
elif command == "sudo":
    assert arguments[:2] == ["-u", "thelounge"]
    arguments = arguments[2:]
    environment = dict(os.environ)
    while "=" in arguments[0]:
        name, value = arguments.pop(0).split("=", 1)
        environment[name] = value
    os.execvpe(arguments[0], arguments, environment)
elif command == "systemctl":
    if arguments[0] == "restart":
        if failure == "restart":
            sys.exit(1)
        (root / "running").touch()
    elif arguments[0] == "is-active":
        sys.exit(3 if failure == "inactive" or not (root / "running").exists() else 0)
elif command == "curl":
    if failure == "http":
        sys.exit(22)
else:
    raise RuntimeError(command)
'''
LOUNGE_FIXTURE = r'''
const fs = require("fs");
const path = require("path");
const arguments = process.argv.slice(2);
const failure = process.env.TEST_FAILURE;
if (arguments[0] === "-v") {
    if (failure === "version") process.exit(1);
    if (failure !== "version-empty") {
        console.log(failure === "version-invalid" ? "invalid-version" : "v4.5.2");
    }
} else if (arguments[0] === "add") {
    if (failure === "user") process.exit(1);
    if (failure === "user-silent") process.exit(0);
    const password = arguments[arguments.indexOf("--password") + 1];
    if (password !== process.env.TEST_PASSWORD) throw new Error("Password input did not match");
    if (!arguments.includes("--save-logs")) throw new Error("Log preference missing");
    const file = path.join(process.env.THELOUNGE_HOME, "users", arguments[1] + ".json");
    fs.writeFileSync(file, failure === "user-empty" ? "" : JSON.stringify({password: "fixture-hash"}), {mode: 0o600});
} else {
    throw new Error("Unexpected CLI arguments");
}
'''


@unittest.skipUnless(REAL_NODE and shutil.which("bash"), "Requires Bash and Node.js")
class TheLoungeInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="af-thelounge-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ("mock-bin", "opt/AetherFlow/packages", "var/lib/thelounge", "etc/systemd/system"):
            (self.root / directory).mkdir(parents=True)
        self.state = self.root / "var/lib/thelounge"
        self.version = self.state / ".af-version"
        self.version.write_text("4.4.3\n")
        self.unit = self.root / "etc/systemd/system/thelounge.service"
        (self.root / "lounge.js").write_text(LOUNGE_FIXTURE)
        common = self.root / "opt/AetherFlow/packages/common.sh"
        common.write_text(r'''MASTER_USER=fixture-user
MASTER_PASS="$TEST_PASSWORD"
require_root() { :; }
log_info() { printf '%s\n' "$*" >> "$LOGFILE"; }
log_error() { printf '%s\n' "$*" >&2; }
report_progress() { :; }
ensure_node() { printf '%s\n' "$1" > "$TEST_ROOT/requested-node"; }
install_npm_app() {
    touch "$TEST_ROOT/npm-install"
    [[ "${TEST_FAILURE:-}" != install ]] || return 1
    mkdir -p "$2" "$(dirname "$3")"
    cp "$TEST_ROOT/lounge.js" "$3"
}
write_lock() { touch "$TEST_ROOT/completed"; }
''')
        for command in ("apt-get", "chown", "id", "node", "sudo", "systemctl", "curl"):
            executable = self.root / "mock-bin" / command
            executable.write_text(MOCK_COMMAND)
            executable.chmod(0o755)
        source = re.sub(r"/(?:opt|var|etc|usr/local|install)(?=/|\s|$)",
                        lambda match: str(self.root) + match.group(), INSTALLER.read_text())
        self.script = self.root / "installer.sh"
        self.script.write_text(source)

    def run_installer(self, **environment):
        return subprocess.run(
            ["bash", str(self.script)],
            env={**os.environ, "PATH": f"{self.root}/mock-bin:{os.environ['PATH']}",
                 "TEST_ROOT": str(self.root), "TEST_REAL_NODE": REAL_NODE,
                 "TEST_PASSWORD": "fixture-password-'$ with spaces\nand a newline", **environment},
            text=True, capture_output=True, timeout=20,
        )

    def commands(self):
        return [json.loads(line) for line in (self.root / "commands").read_text().splitlines()]

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "completed").exists())
        self.assertEqual(self.version.read_text(), "4.4.3\n")

    def test_node_22_12_flag_reaches_version_provisioning_and_service(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "requested-node").read_text(), "22\n")
        self.assertIn("--experimental-sqlite", self.unit.read_text())
        self.assertTrue((self.state / "users/fixture-user.json").exists())
        self.assertEqual(self.version.read_text(), "4.5.2\n")
        self.assertTrue((self.root / "completed").exists())
        commands = self.commands()
        restart = commands.index(["systemctl", "restart", "thelounge"])
        health = next(index for index, command in enumerate(commands) if command[0] == "curl")
        self.assertLess(restart, health)
        self.assertIn(["systemctl", "is-active", "--quiet", "thelounge"], commands)
        self.assertNotIn("fixture-password", (self.root / "commands").read_text())
        self.assertNotIn("fixture-password", (self.root / "var/log/aetherflow/install-thelounge.log").read_text())

    def test_native_sqlite_does_not_add_experimental_flag(self):
        result = self.run_installer(TEST_NODE_MODE="native")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("--experimental-sqlite", self.unit.read_text())
        self.assertFalse(any("--experimental-sqlite" in command for command in self.commands()))

    def test_real_node_runtime_capability_probe(self):
        version = subprocess.check_output([REAL_NODE, "--version"], text=True)
        if int(version.lstrip("v").split(".")[0]) < 22:
            self.skipTest("The real runtime probe requires Node.js 22+")
        result = self.run_installer(TEST_NODE_MODE="real")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_sqlite_is_rejected_before_package_installation(self):
        result = self.run_installer(TEST_NODE_MODE="missing")
        self.assert_failed(result)
        self.assertFalse((self.root / "npm-install").exists())
        self.assertIn("node:sqlite", result.stderr)

    def test_dependency_install_failure_is_not_success(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="install"))

    def test_version_command_failure_is_not_ignored(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="version"))

    def test_empty_version_is_rejected(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="version-empty"))

    def test_invalid_version_is_rejected(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="version-invalid"))

    def test_account_creation_failure_is_not_ignored(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="user"))

    def test_account_command_success_without_account_is_rejected(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="user-silent"))

    def test_empty_account_file_is_rejected(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="user-empty"))

    def test_existing_account_and_configuration_are_preserved(self):
        user = self.state / "users/fixture-user.json"
        user.parent.mkdir()
        user.write_text('{"password":"existing-hash","networks":[]}')
        config = self.state / "config.js"
        config.write_text('module.exports = {port: 9000, reverseProxy: true};\n')
        result = self.run_installer(TEST_FAILURE="user")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(user.read_text(), '{"password":"existing-hash","networks":[]}')
        self.assertEqual(config.read_text(), 'module.exports = {port: 9000, reverseProxy: true};\n')
        self.assertFalse(any(command[0] == "sudo" for command in self.commands()))

    def test_restart_failure_is_not_success(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="restart"))

    def test_http_failure_is_not_success(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="http"))

    def test_http_success_with_crashed_service_is_not_success(self):
        self.assert_failed(self.run_installer(TEST_FAILURE="inactive"))

    def test_custom_port_is_used_for_configuration_and_bounded_readiness(self):
        result = self.run_installer(AF_APP_PORT="19000")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("port: 19000", (self.state / "config.js").read_text())
        health = next(command for command in self.commands() if command[0] == "curl")
        self.assertEqual(health[-1], "http://127.0.0.1:19000/")
        self.assertIn("--retry-connrefused", health)
        self.assertEqual(health[health.index("--retry-max-time") + 1], "60")
        self.assertEqual(health[health.index("--max-time") + 1], "5")


if __name__ == "__main__":
    unittest.main()
