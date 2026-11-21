"""Targeted regression tests for Pi-hole v6 native install readiness, webroot permissions, and rollback."""
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import unittest
from pathlib import Path

from tests.installer_test_helpers import common_functions
from tests.test_marketplace_catalog_lifecycle_matrix import InstallerFixture

ROOT = Path(__file__).resolve().parents[1]


def _build_dns_localhost_response(query: bytes) -> bytes:
    """Build a minimal valid RFC 1035 A response (127.0.0.1) echoing the query."""
    txid = query[:2]
    question = query[12:]
    header = txid + struct.pack(">HHHHH", 0x8580, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
    return header + question + answer


class _DelayedLocalDnsServer:
    """Loopback UDP responder that drops the first `drop_count` packets before answering."""

    def __init__(self, drop_count: int = 0, never_answer: bool = False):
        self.drop_count = drop_count
        self.never_answer = never_answer
        self.received = 0
        self._stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            self.received += 1
            if self.never_answer or self.received <= self.drop_count:
                continue
            self.sock.sendto(_build_dns_localhost_response(data), addr)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class PiHoleLocalDnsHelperTests(unittest.TestCase):
    def _run_dns_helper(self, invocation: str) -> subprocess.CompletedProcess:
        script = "set -euo pipefail\n" + common_functions("af_verify_local_dns_lookup") + "\n" + invocation + "\n"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)

    def test_af_verify_local_dns_lookup_delayed_startup_succeeds(self):
        with _DelayedLocalDnsServer(drop_count=2) as server:
            res = self._run_dns_helper(f"af_verify_local_dns_lookup {server.port} 5 0.05 0.15")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(server.received, 3)

    def test_af_verify_local_dns_lookup_rejects_persistent_timeout(self):
        with _DelayedLocalDnsServer(never_answer=True) as server:
            res = self._run_dns_helper(f"af_verify_local_dns_lookup {server.port} 2 0.05 0.15")
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual(server.received, 2)
            self.assertIn(f"Local DNS lookup probe failed against 127.0.0.1:{server.port}:", res.stderr)
            self.assertIn("timed out", res.stderr)

    def test_af_verify_local_dns_lookup_rejects_unbound_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        unused_port = probe.getsockname()[1]
        probe.close()
        res = self._run_dns_helper(f"af_verify_local_dns_lookup {unused_port} 2 0.05 0.15")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(f"Local DNS lookup probe failed against 127.0.0.1:{unused_port}:", res.stderr)

    def test_af_verify_local_dns_lookup_single_arg_compatibility(self):
        with _DelayedLocalDnsServer(drop_count=0) as server:
            res = self._run_dns_helper(f"af_verify_local_dns_lookup {server.port}")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(server.received, 1)


class PiHoleInstallReadinessTests(unittest.TestCase):
    def _patch_host_command(self, fixture: InstallerFixture, command: str, old: str, new: str):
        for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
            path = directory / command
            source = path.read_text()
            self.assertIn(old, source)
            path.write_text(source.replace(old, new, 1))

    def _commands(self, fixture: InstallerFixture) -> list[list[str]]:
        return [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines() if line]

    def _set_bootstrap(self, fixture: InstallerFixture, script: str) -> str:
        fixture.file("pihole-bootstrap.sh", script)
        return hashlib.sha256(script.encode()).hexdigest()

    def _setup_resolved_stub(self, fixture: InstallerFixture) -> str:
        stub = fixture.file("run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
        fixture.file("run/systemd/resolve/resolv.conf", "nameserver 192.0.2.53\n")
        resolver = fixture.root / "etc/resolv.conf"
        resolver.unlink()
        resolver.symlink_to(stub)
        fixture.file("active-systemd-resolved.service", "active\n")
        return os.readlink(resolver)

    def _v6_bootstrap_script(self, create_toml: bool = True, create_resolved_dropin: bool = True) -> str:
        toml_block = """
if [[ ! -s "$AF_FIXTURE_ROOT/etc/pihole/pihole.toml" ]]; then
    mkdir -p "$AF_FIXTURE_ROOT/etc/pihole"
    cat > "$AF_FIXTURE_ROOT/etc/pihole/pihole.toml" <<'TOML'
[dns]
upstreams = ["1.1.1.1", "8.8.8.8"]
[webserver]
port = "80o,443os"
[webserver.api]
pwhash = "migrated-hash"
TOML
    rm -f "$AF_FIXTURE_ROOT/etc/pihole/setupVars.conf"
fi
""" if create_toml else ""
        dropin_block = """
if [[ -e "$AF_FIXTURE_ROOT/active-systemd-resolved.service" ]]; then
    mkdir -p "$AF_FIXTURE_ROOT/etc/systemd/resolved.conf.d"
    printf '[Resolve]\\nDNSStubListener=no\\n' > "$AF_FIXTURE_ROOT/etc/systemd/resolved.conf.d/90-pi-hole-disable-stub-listener.conf"
fi
""" if create_resolved_dropin else ""
        return f"""#!/bin/bash
set -euo pipefail
printf 'umask=%s\\n' "$(umask)" >> "$AF_FIXTURE_ROOT/bootstrap.log"
mkdir -p "$AF_FIXTURE_ROOT/var/www/html/admin" "$AF_FIXTURE_ROOT/etc/dnsmasq.d"
printf '<? -- admin -- ?>\\n' > "$AF_FIXTURE_ROOT/var/www/html/admin/index.lp"
chmod -R a+rX "$AF_FIXTURE_ROOT/var/www/html/admin"
{toml_block}
{dropin_block}
touch "$AF_FIXTURE_ROOT/active-pihole-FTL.service"
"""

    def test_pihole_v6_fresh_install_bootstrap_umask_and_delayed_http_and_dns_readiness(self):
        with InstallerFixture("pihole") as fixture:
            shutil.rmtree(fixture.root / "etc/lighttpd")
            shutil.rmtree(fixture.root / "var/www")
            self._setup_resolved_stub(fixture)
            digest = self._set_bootstrap(fixture, self._v6_bootstrap_script())

            # Delay HTTP readiness on 18089/admin/ for first 2 attempts, then succeed on attempt 3
            self._patch_host_command(
                fixture,
                "curl",
                "elif command in ('curl', 'wget'):\n",
                """elif command in ('curl', 'wget'):
    if any(url == 'http://127.0.0.1:18089/admin/' for url in arguments):
        counter_path = root / 'http-probe-count'
        count = int(counter_path.read_text()) + 1 if counter_path.exists() else 1
        counter_path.write_text(str(count))
        with (root / 'probe-order.log').open('a') as fh:
            fh.write(f'http:{count}\\n')
        if count <= 2:
            sys.exit(7)
        if '-w' in arguments:
            print('302', end='')
        sys.exit(0)
""",
            )
            # Record DNS probe arguments and verify it runs AFTER HTTP readiness
            self._patch_host_command(
                fixture,
                "python3",
                "        if 'Local DNS lookup probe failed' in program:\n            sys.exit(0)\n",
                """        if 'Local DNS lookup probe failed' in program:
            with (root / 'probe-order.log').open('a') as fh:
                fh.write('dns:' + ','.join(arguments[1:]) + '\\n')
            sys.exit(0)
""",
            )

            res = fixture.run(
                "install",
                port=18089,
                AF_PIHOLE_BOOTSTRAP_SHA256=digest,
                AF_FIXTURE_PIHOLE_FTL_VERSION="v6.9",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            # Bootstrap ran under umask 022 so webroot parents & resolved drop-in dir are traversable
            self.assertIn("umask=0022", (fixture.root / "bootstrap.log").read_text())
            for rel in ("var/www", "var/www/html", "var/www/html/admin", "etc/systemd/resolved.conf.d"):
                mode = (fixture.root / rel).stat().st_mode & 0o777
                self.assertEqual(mode & 0o005, 0o005, f"{rel} expected world r+x, got {oct(mode)}")

            # FTL was stopped before mutating pihole.toml to prevent inotify restart race
            commands = self._commands(fixture)
            stop_indices = [i for i, cmd in enumerate(commands) if cmd == ["systemctl", "stop", "--", "pihole-FTL"]]
            config_indices = [i for i, cmd in enumerate(commands) if cmd[:3] == ["pihole-FTL", "--config", "webserver.port"]]
            self.assertTrue(config_indices, commands)
            self.assertTrue(any(s < config_indices[0] for s in stop_indices[1:]), (stop_indices, config_indices))

            # Optional web listener configured to 18089o
            toml_text = (fixture.root / "etc/pihole/pihole.toml").read_text()
            self.assertIn('port = "18089o"', toml_text)

            # HTTP readiness ran BEFORE DNS probe, and DNS probe received bounded 30-attempt budget
            probe_order = (fixture.root / "probe-order.log").read_text().splitlines()
            self.assertEqual(probe_order[:3], ["http:1", "http:2", "http:3"], probe_order)
            dns_entries = [entry for entry in probe_order if entry.startswith("dns:")]
            self.assertEqual(dns_entries, ["dns:53,30,1,2.0"], probe_order)
            self.assertGreater(probe_order.index(dns_entries[0]), probe_order.index("http:3"))

            self.assertEqual((fixture.root / "etc/pihole/.af-version").read_text().strip(), "6.9")
            self.assertTrue(fixture.lock.exists())

    def test_pihole_v6_preexisting_restricted_webroot_becomes_traversable(self):
        with InstallerFixture("pihole") as fixture:
            shutil.rmtree(fixture.root / "etc/lighttpd")
            (fixture.root / "var/www/html").mkdir(parents=True, exist_ok=True)
            (fixture.root / "var/www/html").chmod(0o700)
            (fixture.root / "var/www").chmod(0o700)
            bootstrap = self._v6_bootstrap_script() + """
python3 - "$AF_FIXTURE_ROOT/var/www" "$AF_FIXTURE_ROOT/var/www/html" <<'PY'
import os, sys
for p in sys.argv[1:]:
    mode = os.stat(p).st_mode & 0o777
    assert (mode & 0o005) == 0o005, f"{p} mode {oct(mode)} not traversable"
PY
"""
            digest = self._set_bootstrap(fixture, bootstrap)
            res = fixture.run(
                "install",
                port=18089,
                AF_PIHOLE_BOOTSTRAP_SHA256=digest,
                AF_FIXTURE_PIHOLE_FTL_VERSION="v6.9",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual((fixture.root / "var/www").stat().st_mode & 0o005, 0o005)
            self.assertEqual((fixture.root / "var/www/html").stat().st_mode & 0o005, 0o005)

    def test_pihole_missing_admin_web_provider_fails_closed_and_rolls_back(self):
        with InstallerFixture("pihole") as fixture:
            shutil.rmtree(fixture.root / "etc/lighttpd")
            original_link = self._setup_resolved_stub(fixture)
            digest = self._set_bootstrap(fixture, self._v6_bootstrap_script(create_toml=False))

            res = fixture.run("install", port=18089, AF_PIHOLE_BOOTSTRAP_SHA256=digest)
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("Pi-hole web admin provider not found", res.stdout + res.stderr)
            self.assertEqual(os.readlink(fixture.root / "etc/resolv.conf"), original_link)
            self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/pihole.conf").exists())
            self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/90-pi-hole-disable-stub-listener.conf").exists())
            self.assertFalse((fixture.root / "etc/pihole/setupVars.conf").exists())
            self.assertFalse((fixture.root / "etc/pihole/.af-version").exists())
            self.assertFalse(fixture.lock.exists())

    def _assert_v6_readiness_failure_rolls_back(self, failure_mode: str):
        with InstallerFixture("pihole") as fixture:
            shutil.rmtree(fixture.root / "etc/lighttpd")
            original_link = self._setup_resolved_stub(fixture)
            digest = self._set_bootstrap(fixture, self._v6_bootstrap_script())

            if failure_mode == "http_unavailable":
                self._patch_host_command(
                    fixture,
                    "curl",
                    "elif command in ('curl', 'wget'):\n",
                    """elif command in ('curl', 'wget'):
    if any(url == 'http://127.0.0.1:18089/admin/' for url in arguments):
        if '-w' in arguments:
            print('000', end='')
        sys.exit(7)
""",
                )
            else:
                self._patch_host_command(
                    fixture,
                    "python3",
                    "        if 'Local DNS lookup probe failed' in program:\n            sys.exit(0)\n",
                    """        if 'Local DNS lookup probe failed' in program:
            print('Local DNS lookup probe failed against 127.0.0.1:53: timed out', file=sys.stderr)
            sys.exit(1)
""",
                )

            res = fixture.run("install", port=18089, AF_PIHOLE_BOOTSTRAP_SHA256=digest)
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(os.readlink(fixture.root / "etc/resolv.conf"), original_link)
            self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/pihole.conf").exists())
            self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/90-pi-hole-disable-stub-listener.conf").exists())
            self.assertFalse((fixture.root / "etc/pihole/pihole.toml").exists())
            self.assertFalse((fixture.root / "etc/pihole/setupVars.conf").exists())
            self.assertFalse((fixture.root / "etc/pihole/.af-version").exists())
            self.assertFalse(fixture.lock.exists())
            commands = self._commands(fixture)
            self.assertGreaterEqual(commands.count(["systemctl", "restart", "systemd-resolved"]), 2)

    def test_pihole_v6_persistent_http_failure_rolls_back_resolved_and_receipts(self):
        self._assert_v6_readiness_failure_rolls_back("http_unavailable")

    def test_pihole_v6_persistent_dns_failure_rolls_back_resolved_and_receipts(self):
        self._assert_v6_readiness_failure_rolls_back("dns_unavailable")

    def test_pihole_v6_retained_update_preserves_operator_credentials_and_settings(self):
        with InstallerFixture("pihole") as fixture:
            shutil.rmtree(fixture.root / "etc/lighttpd")
            original_toml = (
                '[dns]\n'
                'upstreams = ["9.9.9.9"]\n'
                '[webserver]\n'
                'port = "8089o"\n'
                '[webserver.paths]\n'
                'webroot = "/var/www/html"\n'
                '[webserver.api]\n'
                'pwhash = "operator-retained-hash"\n'
            )
            toml_path = fixture.file("etc/pihole/pihole.toml", original_toml)
            digest = self._set_bootstrap(fixture, self._v6_bootstrap_script())

            res = fixture.run(
                "update",
                port=18089,
                AF_PIHOLE_BOOTSTRAP_SHA256=digest,
                AF_KEEP_EXISTING_SECRETS="1",
                AF_FIXTURE_PIHOLE_FTL_VERSION="v6.9",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            updated = toml_path.read_text()
            self.assertIn('pwhash = "operator-retained-hash"', updated)
            self.assertIn('upstreams = ["9.9.9.9"]', updated)
            self.assertIn('port = "18089o"', updated)
            self.assertNotIn('"setpassword"', (fixture.root / "commands.jsonl").read_text())
            self.assertEqual((fixture.root / "etc/pihole/.af-version").read_text().strip(), "6.9")
            self.assertTrue(fixture.lock.exists())


if __name__ == "__main__":
    unittest.main()
