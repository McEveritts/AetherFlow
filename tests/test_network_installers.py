"""Exercise VPN installers with isolated files and fake host commands."""
import base64
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/python3
import base64,hashlib,json,os
from pathlib import Path
import sys
root=Path(os.environ['TEST_ROOT'])
name=Path(sys.argv[0]).name
args=sys.argv[1:]
failure=os.environ.get('TEST_FAILURE','')
with (root/'commands').open('a') as log:
    log.write(json.dumps([name]+args)+'\n')
if name in ('apt-get','flock'):
    pass
elif name=='wg':
    if args==['genkey']:
        counter=root/'key-count'
        value=int(counter.read_text())+1 if counter.exists() else 1
        counter.write_text(str(value))
        print(base64.b64encode(bytes([value])*32).decode())
    elif args==['pubkey']:
        private=sys.stdin.read()
        print(base64.b64encode(hashlib.sha256(private.encode()).digest()).decode())
    elif args==['show','wg0','public-key']:
        if failure=='wgshow':sys.exit(1)
        print('synthetic-public-key')
    else:raise RuntimeError(args)
elif name=='ip':
    if args[:3]==['route','show','default']:
        print('default via 192.0.2.1 dev eth0')
    elif args==['-o','link','show','dev','wg0']:
        print('4: wg0: <POINTOPOINT,NOARP'+('' if failure=='linkdown' else ',UP,LOWER_UP')+'> mtu 1420')
    else:raise RuntimeError(args)
elif name=='curl':
    if '-o' in args:
        Path(args[args.index('-o')+1]).write_text('synthetic-repository-key')
    else:print('192.0.2.25')
elif name=='hostname':print('192.0.2.25')
elif name=='sysctl':
    if failure=='forwarding':sys.exit(1)
elif name=='systemctl':
    if args[0] in ('start','enable') and failure==args[0]:sys.exit(1)
    if args[0]=='restart':raise RuntimeError('Installer must preserve live sessions with start')
    if args[0]=='is-active' and failure=='inactive':sys.exit(3)
elif name=='tailscale':
    if args[0]!='login':raise RuntimeError(args)
    arg=next(arg for arg in args if arg.startswith('--auth-key='))
    assert arg.startswith('--auth-key=file:'), 'key leaked in process arguments'
    path=Path(arg.removeprefix('--auth-key=file:'))
    key=path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    assert 'AF_TAILSCALE_AUTHKEY' not in os.environ
    assert 'TAILSCALE_AUTHKEY' not in os.environ
    if failure=='enrollment':
        print('upstream error with sensitive key '+key,file=sys.stderr)
        sys.exit(1)
else:raise RuntimeError(name)
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux Bash is required")
class NetworkInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="af-vpn-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("bin", "opt/AetherFlow/packages", "etc/apt/sources.list.d", "run", "var/log/aetherflow", "install"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/os-release").write_text("ID=debian\nVERSION_CODENAME=bookworm\n")
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(r'''
require_root() { :; }
log_info() { printf '%s\n' "$*"; }
log_error() { printf '%s\n' "$*" >&2; }
log_warn() { printf '%s\n' "$*" >&2; }
report_progress() { printf '[PROGRESS:%s] %s\n' "$1" "$2"; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
''')
        for command in ("apt-get", "flock", "wg", "ip", "curl", "hostname", "sysctl", "systemctl", "tailscale"):
            path = self.root / "bin" / command
            path.write_text(MOCK)
            path.chmod(0o700)
        self.env = {**os.environ, "PATH": f"{self.root}/bin:{os.environ['PATH']}", "TEST_ROOT": str(self.root)}

    def run_installer(self, provider="wireguard", **environment):
        source = (ROOT / f"packages/package/install/installpackage-{provider}").read_text()
        for prefix in ("/opt/", "/var/", "/etc/", "/run/"):
            source = source.replace(prefix, str(self.root) + prefix)
        source = source.replace(" /install", " " + str(self.root) + "/install")
        path = self.root / f"install-{provider}.sh"
        path.write_text(source)
        return subprocess.run(["bash", str(path)], env={**self.env, **environment},
                              capture_output=True, text=True, timeout=20)

    def install(self, provider="wireguard", **environment):
        result = self.run_installer(provider, **environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def marker(self, provider):
        return self.root / f"install/.{provider}.lock"

    def test_fresh_wireguard_installs_ipv4_client_and_private_files(self):
        self.install()
        directory = self.root / "etc/wireguard"
        self.assertTrue(self.marker("wireguard").exists())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        client = (directory / "client.conf").read_text()
        self.assertIn("Address = 10.66.66.2/32", client)
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", client)
        self.assertNotIn("::/0", client)
        server = (directory / "wg0.conf").read_text()
        self.assertIn("-o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", server)
        for name in ("wg0.conf", "client.conf", "server_private.key", "client_private.key"):
            self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
        self.assertFalse(list(directory.glob(".aetherflow-install.*")))

    def test_reinstall_keeps_all_keys_configs_and_customizations(self):
        self.install()
        directory = self.root / "etc/wireguard"
        with (directory / "wg0.conf").open("a") as output:
            output.write("# administrator customization\n")
        before = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
        self.install()
        for name, contents in before.items():
            self.assertEqual((directory / name).read_bytes(), contents, name)
        self.assertEqual((self.root / "key-count").read_text(), "2")
        self.assertNotIn('"restart"', (self.root / "commands").read_text())

    def test_partial_identity_does_not_get_rotated(self):
        directory = self.root / "etc/wireguard"
        directory.mkdir()
        existing = directory / "server_private.key"
        existing.write_text("important-existing-identity")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Incomplete WireGuard", result.stderr)
        self.assertEqual(existing.read_text(), "important-existing-identity")
        self.assertFalse((self.root / "key-count").exists())
        self.assertFalse(self.marker("wireguard").exists())

    def test_forwarding_and_service_failures_cannot_report_installation_success(self):
        for failure in ("forwarding", "start", "enable", "inactive", "wgshow", "linkdown"):
            with self.subTest(failure=failure):
                result = self.run_installer(TEST_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker("wireguard").exists())
                self.assertNotIn("[PROGRESS:100]", result.stdout)
        saved = (self.root / "etc/wireguard/server_private.key").read_bytes()
        self.install()
        self.assertEqual((self.root / "etc/wireguard/server_private.key").read_bytes(), saved)
        self.assertEqual((self.root / "key-count").read_text(), "2")

    def test_symlinked_identity_and_lock_do_not_touch_their_targets(self):
        directory = self.root / "etc/wireguard"
        directory.mkdir()
        outside = self.root / "outside"
        outside.write_text("protected")
        for name in ("server_private.key", ".aetherflow-network.lock"):
            with self.subTest(name=name):
                link = directory / name
                link.unlink(missing_ok=True)
                link.symlink_to(outside)
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outside.read_text(), "protected")
                link.unlink()
        self.assertFalse(self.marker("wireguard").exists())

    def test_tailscale_preserves_state_and_start_does_not_restart_daemon(self):
        state = self.root / "var/lib/tailscale/tailscaled.state"
        state.parent.mkdir(parents=True)
        state.write_text("existing-authenticated-identity")
        self.install("tailscale")
        self.install("tailscale")
        self.assertTrue(self.marker("tailscale").exists())
        self.assertEqual(state.read_text(), "existing-authenticated-identity")
        self.assertNotIn('"restart"', (self.root / "commands").read_text())

    def test_tailscale_failure_propagation_and_private_auth_key_cleanup(self):
        for failure in ("forwarding", "start", "inactive", "enrollment"):
            with self.subTest(failure=failure):
                result = self.run_installer("tailscale", TEST_FAILURE=failure,
                                            AF_TAILSCALE_AUTHKEY="tskey-auth-isolated-test-value")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker("tailscale").exists())
                self.assertFalse(list((self.root / "run").glob("aetherflow-tailscale-auth.*")))
                self.assertNotIn("tskey-auth-isolated-test-value", result.stdout + result.stderr)
                log = self.root / "var/log/aetherflow/install-tailscale.log"
                self.assertNotIn("tskey-auth-isolated-test-value", log.read_text())
        self.install("tailscale", AF_TAILSCALE_AUTHKEY="tskey-auth-isolated-test-value")
        self.assertFalse(list((self.root / "run").glob("aetherflow-tailscale-auth.*")))
        self.assertNotIn("tskey-auth-isolated-test-value", (self.root / "commands").read_text())


if __name__ == "__main__":
    unittest.main()
