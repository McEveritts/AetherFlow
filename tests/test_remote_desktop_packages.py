import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO / "packages" / "package"

MOCK_COMMON = r'''
source "$REAL_COMMON"
record() { printf '%s\n' "$*" >> "$TEST_ROOT/commands"; }
apt-get() {
    record "apt-get $*"
    if [[ "$1" == remove && "$MOCK_FAIL_REMOVE" == 1 ]]; then return 42; fi
}
systemctl() {
    record "systemctl $*"
    if [[ "$1" == restart && "$MOCK_FAIL_START" == 1 ]]; then return 42; fi
}
id() { return 0; }
useradd() { record "useradd $*"; }
usermod() { record "usermod $*"; }
chown() { :; }
sleep() { :; }
install() {
    local last
    for last; do :; done
    command install -d -m 700 "$last"
}
curl() { python3 "$TEST_ROOT/mock.py" curl "$@"; }
jq() { python3 "$TEST_ROOT/mock.py" jq "$@"; }
kasmvncpasswd() {
    local first second last
    read -r first
    read -r second
    [[ "$first" == "$second" ]]
    for last; do :; done
    printf 'hashed-test-password\n' > "$last"
}
'''

MOCK_COMMANDS = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[2:]
root = Path(os.environ["TEST_ROOT"])
if sys.argv[1] == "curl":
    if "-w" in args:
        print(os.environ.get("MOCK_HTTP_STATUS", "401"), end="")
    else:
        output = Path(args[args.index("-o") + 1])
        if "https://api.github.com/repos/kasmtech/KasmVNC/releases/latest" in args:
            output.write_bytes((root / "release.json").read_bytes())
        else:
            output.write_bytes(b"bad package" if os.environ.get("MOCK_CORRUPT") == "1" else b"fake upstream package")
else:
    data = json.loads(Path(args[-1]).read_text())
    if "--arg" not in args:
        value = data["tag_name"].removeprefix("v")
    else:
        name = args[args.index("--arg") + 2]
        assets = [asset for asset in data["assets"] if asset["name"] == name]
        if not assets:
            sys.exit(4)
        value = assets[0].get("digest" if ".digest" in args[-2] else "browser_download_url")
    if value is None:
        sys.exit(1)
    print(value)
'''


@unittest.skipUnless(shutil.which("bash") and os.name == "posix", "Requires Linux Bash")
class RemoteDesktopPackagesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="af-desktop-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("etc/systemd/system", "etc/xrdp", "var/lib", "var/log/aetherflow", "tmp", "install"):
            (self.root / directory).mkdir(parents=True)
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_CODENAME=bookworm\n')
        (self.root / "etc/xrdp/startwm.sh").write_text("original session script\n")
        (self.root / "common.sh").write_text(MOCK_COMMON)
        common = (REPO / "packages/common.sh").read_text()
        common = re.sub(r"/(?:etc|var/lib|var/log|tmp)/", lambda match: str(self.root) + match.group(), common)
        (self.root / "real-common.sh").write_text(common)
        (self.root / "mock.py").write_text(MOCK_COMMANDS)
        self.release = {
            "tag_name": "v1.5.2",
            "assets": [{
                "name": "kasmvncserver_debian_bookworm_1.5.2_amd64.deb",
                "browser_download_url": "https://github.com/kasmtech/KasmVNC/releases/download/v1.5.2/desktop.deb",
                "digest": "sha256:" + hashlib.sha256(b"fake upstream package").hexdigest(),
            }],
        }
        self.env = dict(os.environ, TEST_ROOT=str(self.root), REAL_COMMON=str(self.root / "real-common.sh"),
                        LOCK_DIR=str(self.root / "install"), LOGFILE=str(self.root / "var/log/aetherflow/test.log"),
                        MOCK_FAIL_START="0", MOCK_FAIL_REMOVE="0", MOCK_CORRUPT="0")

    def run_script(self, action, package, **environment):
        (self.root / "release.json").write_text(json.dumps(self.release))
        script = (PACKAGE_DIR / action / (action + "package-" + package)).read_text()
        script = 'set -euo pipefail\nsource "$TEST_ROOT/common.sh"\n' + script.split("require_root\n", 1)[1]
        script = re.sub(r"/(?:etc|var/lib|var/log|tmp)/", lambda match: str(self.root) + match.group(), script)
        script = script.replace("/usr/bin/kasmvncpasswd", "kasmvncpasswd")
        script = script.replace('ARCH="$(dpkg --print-architecture)"', 'ARCH="amd64"')
        script_path = self.root / "run.sh"
        script_path.write_text(script)
        return subprocess.run(["bash", str(script_path)], env=dict(self.env, **environment), capture_output=True, text=True, timeout=15)

    def commands(self):
        path = self.root / "commands"
        return path.read_text() if path.exists() else ""

    def test_original_script_syntax(self):
        for package in ("kasmvnc", "xrdp"):
            for action in ("install", "remove"):
                with self.subTest(package=package, action=action):
                    subprocess.run(["bash", "-n", str(PACKAGE_DIR / action / (action + "package-" + package))], check=True)

    def test_kasm_install_port_credentials_and_reinstall(self):
        result = self.run_script("install", "kasmvnc", AF_APP_PORT="17003")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = (self.root / "var/lib/kasmvnc/.vnc/kasmvnc.yaml").read_text()
        self.assertIn("websocket_port: 17003", config)
        self.assertIn("interface: 127.0.0.1", config)
        self.assertIn("prompt: false", config)
        password_file = self.root / "etc/kasmvnc/aetherflow-password"
        password = password_file.read_text()
        self.assertEqual(password_file.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(len(password.strip()), 32)
        self.assertTrue((self.root / "install/.kasmvnc.lock").exists())
        self.assertNotIn(password.strip(), result.stdout + result.stderr)
        self.assertIn("--no-remove", self.commands())
        result = self.run_script("install", "kasmvnc", AF_APP_PORT="17003")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(password_file.read_text(), password)
        self.assertFalse(list((self.root / "tmp").glob("af-kasmvnc-*")))

    def test_kasm_rejects_invalid_ports(self):
        for port in ("0", "80", "65536", "abc", "6081;touch bad"):
            with self.subTest(port=port):
                result = self.run_script("install", "kasmvnc", AF_APP_PORT=port)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("apt-get", self.commands())

    def test_kasm_unsupported_os(self):
        (self.root / "etc/os-release").write_text("ID=fedora\nVERSION_CODENAME=test\n")
        result = self.run_script("install", "kasmvnc")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("apt-get", self.commands())

    def test_kasm_missing_asset(self):
        self.release["assets"] = []
        result = self.run_script("install", "kasmvnc")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No upstream KasmVNC package", result.stdout + result.stderr)
        self.assertFalse((self.root / "install/.kasmvnc.lock").exists())

    def test_kasm_missing_digest(self):
        del self.release["assets"][0]["digest"]
        result = self.run_script("install", "kasmvnc")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("kasmvnc.deb", self.commands())

    def test_kasm_bad_checksum(self):
        result = self.run_script("install", "kasmvnc", MOCK_CORRUPT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("kasmvnc.deb", self.commands())
        self.assertFalse((self.root / "install/.kasmvnc.lock").exists())

    def test_failed_start_never_marks_installed(self):
        for package in ("kasmvnc", "xrdp"):
            with self.subTest(package=package):
                result = self.run_script("install", package, MOCK_FAIL_START="1")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "install" / ("." + package + ".lock")).exists())

    def test_kasm_failed_readiness_never_marks_installed(self):
        result = self.run_script("install", "kasmvnc", MOCK_HTTP_STATUS="503")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become ready", result.stdout + result.stderr)
        self.assertFalse((self.root / "install/.kasmvnc.lock").exists())

    def test_xrdp_preserves_port_and_restores_session_script(self):
        ini = self.root / "etc/xrdp/xrdp.ini"
        ini.write_text("[Globals]\nport=3391\n")
        result = self.run_script("install", "xrdp")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(ini.read_text(), "[Globals]\nport=3391\n")
        self.assertIn("xrdp-sesman.service xrdp.service", self.commands())
        result = self.run_script("install", "xrdp")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_script("remove", "xrdp")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "etc/xrdp/startwm.sh").read_text(), "original session script\n")
        self.assertTrue(ini.exists())
        self.assertFalse((self.root / "install/.xrdp.lock").exists())

    def test_removal_preserves_data_until_explicit_delete(self):
        for package in ("kasmvnc", "xrdp"):
            with self.subTest(package=package):
                data_dir = self.root / "var/lib" / package
                data_dir.mkdir(exist_ok=True)
                (data_dir / "keep.txt").write_text("desktop data")
                lock = self.root / "install" / ("." + package + ".lock")
                lock.touch()
                result = self.run_script("remove", package, MOCK_FAIL_REMOVE="1")
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(lock.exists())
                result = self.run_script("remove", package)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((data_dir / "keep.txt").exists())
                result = self.run_script("remove", package, DELETE_DATA="true")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(data_dir.exists())
                self.assertNotRegex(self.commands(), r"apt-get (remove|purge).*xfce|userdel")


if __name__ == "__main__":
    unittest.main()
