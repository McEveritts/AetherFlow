"""Isolated regression tests for multi-port installer guards, safe removers, and release build cleanup."""

import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest

from tests.installer_test_helpers import ROOT, read_common_sh_source, replace_paths_once


INSTALL_DIR = ROOT / "packages/package/install"
REMOVE_DIR = ROOT / "packages/package/remove"


def make_tar_gz(path: Path, members: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(payload))


def rebase_root(source: str, root: Path) -> str:
    root_str = str(root)
    prefixes = (
        "/etc/",
        "/var/",
        "/opt/",
        "/home/",
        "/install/",
        "/usr/local/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/share/",
        "/usr/lib/",
        "/usr/libexec/",
        "/run/",
        "/srv/",
        "/mnt/",
    )
    return replace_paths_once(source, [(prefix, root_str + prefix) for prefix in prefixes])


def reserve_loopback_port(port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        return sock
    except OSError:
        sock.close()
        return None


class BaseSandboxTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-hardening-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.root / "commands.jsonl"

        for rel in (
            "install",
            "etc/apt/keyrings",
            "etc/apt/sources.list.d",
            "etc/deluge",
            "etc/duplicati",
            "etc/kasmvnc",
            "etc/netdata",
            "etc/novnc",
            "etc/prometheus",
            "etc/systemd/system",
            "etc/x2go",
            "opt/flood",
            "opt/n8n",
            "opt/thelounge",
            "opt/audiobookshelf",
            "opt/netdata",
            "usr/bin",
            "usr/local/bin",
            "usr/local/nodejs/bin",
            "usr/share/keyrings",
            "var/lib/aetherflow/apt-reinstall-required",
            "var/lib/audiobookshelf",
            "var/lib/deluge",
            "var/lib/duplicati",
            "var/lib/flood",
            "var/lib/kasmvnc",
            "var/lib/n8n",
            "var/lib/netdata",
            "var/lib/novnc",
            "var/lib/prometheus",
            "var/lib/quassel",
            "var/lib/thelounge",
            "var/lib/x2go",
            "var/cache/audiobookshelf",
            "var/cache/netdata",
            "var/log/aetherflow",
            "var/log/deluge",
            "var/log/netdata",
            "var/log/quassel",
            "tmp/tx-root",
            "tmp/scratch",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        (self.root / "tmp/tx-root").chmod(0o700)

        self.common_sh = self.root / "packages/common.sh"
        self.common_sh.parent.mkdir(parents=True, exist_ok=True)
        raw_common = read_common_sh_source()
        common_text = rebase_root(raw_common, self.root)
        common_text = common_text.replace(
            f'export PATH="{self.root}/usr/local/nodejs/bin:',
            f'export PATH="{self.bin_dir}:{self.root}/usr/sbin:{self.root}/usr/bin:{self.root}/usr/local/nodejs/bin:',
            1,
        )
        self.common_sh.write_text(common_text, encoding="utf-8")
        self._install_common_shims()

    def write_file(self, relative: str, content: str = "synthetic") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_executable(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def _install_common_shims(self):
        self.write_executable(
            self.bin_dir / "apt-get",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with Path(os.environ["AF_TEST_LOG"]).open("a") as fh:
    fh.write(json.dumps(["apt-get", *sys.argv[1:]]) + "\n")
sys.exit(0)
""",
        )
        self.write_executable(
            self.bin_dir / "dpkg",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["AF_TEST_LOG"]).open("a") as fh:
    fh.write(json.dumps(["dpkg", *args]) + "\n")
if args == ["--print-architecture"]:
    print("amd64")
sys.exit(0)
""",
        )
        self.write_executable(
            self.bin_dir / "dpkg-query",
            r"""#!/usr/bin/env python3
import sys
args = sys.argv[1:]
joined = " ".join(args)
if "db:Status-Status" in joined:
    print("installed 1.4.0-1")
else:
    print("1.4.0-1")
sys.exit(0)
""",
        )
        self.write_executable(
            self.bin_dir / "systemctl",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["AF_TEST_LOG"]).open("a") as fh:
    fh.write(json.dumps(["systemctl", *args]) + "\n")
cmd = args[0] if args else ""
state_file = Path(os.environ["AF_TEST_ROOT"]) / "svc-state.json"
state = json.loads(state_file.read_text()) if state_file.exists() else {}
units = [a for a in args[1:] if not a.startswith("-") and a != "--"]
if cmd in ("start", "restart") or (cmd == "enable" and "--now" in args):
    for u in units:
        state[u] = True
    state_file.write_text(json.dumps(state))
    sys.exit(0)
if cmd == "stop":
    for u in units:
        state[u] = False
    state_file.write_text(json.dumps(state))
    sys.exit(0)
if cmd == "is-active":
    active = bool(units) and all(state.get(u, False) for u in units)
    if "--quiet" not in args:
        print("active" if active else "inactive")
    sys.exit(0 if active else 3)
if cmd == "show":
    u = units[-1] if units else ""
    active = state.get(u, False)
    print(f"LoadState=loaded\nActiveState={'active' if active else 'inactive'}\nMainPID={'1234' if active else '0'}\nUnitFileState=disabled")
    sys.exit(0)
sys.exit(0)
""",
        )
        self.write_executable(
            self.bin_dir / "id",
            "#!/bin/bash\nif [[ \"${1:-}\" == \"-u\" ]]; then echo 0; fi\nexit 0\n",
        )
        for tool in ("chown", "chmod", "useradd", "userdel", "groupdel", "npm", "sleep"):
            self.write_executable(
                self.bin_dir / tool,
                "#!/bin/bash\nexit 0\n",
            )
        self.write_executable(
            self.bin_dir / "getent",
            "#!/bin/bash\nexit 2\n",
        )
        self.write_executable(
            self.bin_dir / "pm2",
            "#!/bin/bash\nif [[ \"${1:-}\" == \"jlist\" ]]; then printf '[]\\n'; fi\nexit 0\n",
        )
        self.write_executable(
            self.bin_dir / "dpkg-query",
            "#!/bin/bash\nif [[ \"$*\" == *'db:Status-Status'* ]]; then printf 'installed 1.4.0-1\\n'; else printf '1.4.0-1\\n'; fi\n",
        )
        self.write_executable(
            self.bin_dir / "vncpasswd",
            "#!/bin/bash\ncat >/dev/null\nprintf 'synthetic-vnc-hash\\n'\n",
        )

    def commands(self) -> list[list[str]]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def base_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}:{self.root / 'usr/sbin'}:{self.root / 'usr/bin'}:/usr/bin:/bin",
            "AF_TEST_ROOT": str(self.root),
            "AF_TEST_LOG": str(self.log_path),
            "LOCK_DIR": str(self.root / "install"),
            "AF_TRANSACTION_ROOT": str(self.root / "tmp/tx-root"),
            "AF_JOB_SCRATCH_ROOT": str(self.root / "tmp/scratch"),
            "MASTER_USER": "admin",
            "MASTER_PASS": "test-pass-1234",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        for key in (
            "AF_APP_PORT",
            "AETHERFLOW_APP_PORT",
            "AF_BIND_ADDRESS",
            "AF_NODE_EXPORTER_PORT",
            "AF_NOVNC_VNC_PORT",
            "AF_TARGET_VERSION",
            "DELETE_DATA",
        ):
            env.pop(key, None)
        if extra:
            env.update(extra)
        return env

    def run_installer(self, app: str, extra_env: dict[str, str] | None = None, prelude: str = "") -> subprocess.CompletedProcess:
        raw = (INSTALL_DIR / f"installpackage-{app}").read_text(encoding="utf-8")
        rebased = rebase_root(raw, self.root)
        inject = f"""
export PATH="{self.bin_dir}:{self.root}/usr/sbin:{self.root}/usr/bin:$PATH"
require_root() {{ :; }}
af_logged() {{ "$@" >>"${{LOGFILE:-/dev/null}}" 2>&1; }}
af_logged_stderr() {{ "$@" 2>>"${{LOGFILE:-/dev/null}}"; }}
load_master_credentials() {{ MASTER_USER="admin"; MASTER_PASS="test-pass-1234"; }}
{prelude}
"""
        if "\nrequire_root\n" in rebased:
            rebased = rebased.replace("\nrequire_root\n", "\n" + inject + "\nrequire_root\n", 1)
        else:
            rebased = inject + "\n" + rebased
        script_path = self.root / "packages/package/install" / f"installpackage-{app}"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(rebased, encoding="utf-8")
        script_path.chmod(0o755)
        return subprocess.run(
            ["bash", str(script_path)],
            env=self.base_env(extra_env),
            text=True,
            capture_output=True,
            timeout=30,
        )

    def run_remover(self, app: str, delete_data: str = "false", extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        raw = (REMOVE_DIR / f"removepackage-{app}").read_text(encoding="utf-8")
        rebased = rebase_root(raw, self.root)
        inject = (
            f'export PATH="{self.bin_dir}:{self.root}/usr/sbin:{self.root}/usr/bin:$PATH"\n'
            'require_root() { :; }\n'
            'af_logged() { "$@" >>"${LOGFILE:-/dev/null}" 2>&1; }\n'
            'af_logged_stderr() { "$@" 2>>"${LOGFILE:-/dev/null}"; }\n'
        )
        if "\nrequire_root\n" in rebased:
            rebased = rebased.replace("\nrequire_root\n", "\n" + inject + "\nrequire_root\n", 1)
        else:
            rebased = inject + "\n" + rebased
        script_path = self.root / "packages/package/remove" / f"removepackage-{app}"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(rebased, encoding="utf-8")
        script_path.chmod(0o755)
        merged = {"DELETE_DATA": delete_data, **(extra_env or {})}
        return subprocess.run(
            ["bash", str(script_path)],
            env=self.base_env(merged),
            text=True,
            capture_output=True,
            timeout=30,
        )


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires POSIX bash")
class MultiPortInstallerHardeningTests(BaseSandboxTest):
    def _setup_prometheus_fixtures(self) -> None:
        make_tar_gz(
            self.root / "prometheus.tar.gz",
            {
                "prometheus-2.53.1.linux-amd64/prometheus": b"#!/bin/sh\nexit 0\n",
                "prometheus-2.53.1.linux-amd64/promtool": b"#!/bin/sh\nexit 0\n",
            },
        )
        make_tar_gz(
            self.root / "node_exporter.tar.gz",
            {
                "node_exporter-1.8.2.linux-amd64/node_exporter": b"#!/bin/sh\nexit 0\n",
            },
        )
        self.write_executable(
            self.bin_dir / "curl",
            r"""#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ["AF_TEST_ROOT"])
with Path(os.environ["AF_TEST_LOG"]).open("a") as fh:
    fh.write(json.dumps(["curl", *args]) + "\n")
url = next((a for a in reversed(args) if a.startswith("http")), "")
if "-o" in args:
    out = Path(args[args.index("-o") + 1])
    if "node_exporter" in url:
        shutil.copyfile(root / "node_exporter.tar.gz", out)
    else:
        shutil.copyfile(root / "prometheus.tar.gz", out)
    sys.exit(0)
if "-w" in args:
    sys.stdout.write("200")
    sys.exit(0)
if "/api/v1/status/buildinfo" in url:
    print(json.dumps({"status": "success", "data": {"version": "2.53.1"}}))
    sys.exit(0)
if url.endswith("/metrics"):
    print('node_exporter_build_info{version="1.8.2"} 1')
    sys.exit(0)
sys.exit(0)
""",
        )

    def test_prometheus_binds_node_exporter_to_loopback_and_honors_bind_address(self):
        self._setup_prometheus_fixtures()
        prelude = """
verify_download_sha256() { return 0; }
github_latest_tag() {
    if [[ "$1" == "prometheus/node_exporter" ]]; then printf '1.8.2\\n'; else printf '2.53.1\\n'; fi
}
"""
        res = self.run_installer("prometheus", extra_env={"AF_APP_PORT": "19090"}, prelude=prelude)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        ne_unit = (self.root / "etc/systemd/system/node_exporter.service").read_text(encoding="utf-8")
        prom_unit = (self.root / "etc/systemd/system/prometheus.service").read_text(encoding="utf-8")
        prom_yml = (self.root / "etc/prometheus/prometheus.yml").read_text(encoding="utf-8")
        self.assertIn("--web.listen-address=127.0.0.1:9100", ne_unit)
        self.assertIn("--web.listen-address=127.0.0.1:19090", prom_unit)
        self.assertIn("targets: ['localhost:19090']", prom_yml)
        self.assertIn("targets: ['localhost:9100']", prom_yml)
        self.assertTrue((self.root / "install/.prometheus.lock").exists())

        res_custom = self.run_installer(
            "prometheus",
            extra_env={"AF_APP_PORT": "19091", "AF_BIND_ADDRESS": "127.0.0.2"},
            prelude=prelude,
        )
        self.assertEqual(res_custom.returncode, 0, res_custom.stdout + res_custom.stderr)
        ne_unit_custom = (self.root / "etc/systemd/system/node_exporter.service").read_text(encoding="utf-8")
        self.assertIn("--web.listen-address=127.0.0.2:9100", ne_unit_custom)

    def test_prometheus_shifts_node_exporter_when_app_port_is_9100_and_updates_scrape_target(self):
        self._setup_prometheus_fixtures()
        prelude = """
verify_download_sha256() { return 0; }
github_latest_tag() {
    if [[ "$1" == "prometheus/node_exporter" ]]; then printf '1.8.2\\n'; else printf '2.53.1\\n'; fi
}
"""
        # Occupy 9101 if available to verify busy-port skipping
        blocker = reserve_loopback_port(9101)
        if blocker is not None:
            self.addCleanup(blocker.close)

        res = self.run_installer("prometheus", extra_env={"AF_APP_PORT": "9100"}, prelude=prelude)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        prom_unit = (self.root / "etc/systemd/system/prometheus.service").read_text(encoding="utf-8")
        ne_unit = (self.root / "etc/systemd/system/node_exporter.service").read_text(encoding="utf-8")
        prom_yml = (self.root / "etc/prometheus/prometheus.yml").read_text(encoding="utf-8")

        self.assertIn("--web.listen-address=127.0.0.1:9100", prom_unit)
        self.assertNotIn("--web.listen-address=127.0.0.1:9100", ne_unit)
        match = [line for line in ne_unit.splitlines() if "--web.listen-address=" in line]
        self.assertEqual(len(match), 1, ne_unit)
        ne_port = int(match[0].rsplit(":", 1)[1].strip())
        self.assertNotEqual(ne_port, 9100)
        if blocker is not None:
            self.assertNotEqual(ne_port, 9101)
        self.assertGreaterEqual(ne_port, 9101)
        self.assertLess(ne_port, 9200)
        self.assertIn(f"targets: ['localhost:{ne_port}']", prom_yml)

        curl_urls = [arg for cmd in self.commands() if cmd[0] == "curl" for arg in cmd[1:] if arg.startswith("http")]
        self.assertIn(f"http://127.0.0.1:{ne_port}/metrics", curl_urls)
        self.assertNotIn("http://127.0.0.1:9100/metrics", curl_urls)

        # Updating an existing prometheus.yml preserves unrelated jobs while keeping node_exporter synced
        existing_yml = (
            "global:\n  scrape_interval: 15s\nscrape_configs:\n"
            "  - job_name: 'prometheus'\n    static_configs:\n      - targets: ['localhost:9090']\n"
            "  - job_name: 'node_exporter'\n    static_configs:\n      - targets: ['localhost:9100']\n"
            "  - job_name: 'remote_host'\n    static_configs:\n      - targets: ['10.0.0.5:9100']\n"
        )
        self.write_file("etc/prometheus/prometheus.yml", existing_yml)
        res_upgrade = self.run_installer("prometheus", extra_env={"AF_APP_PORT": "9100"}, prelude=prelude)
        self.assertEqual(res_upgrade.returncode, 0, res_upgrade.stdout + res_upgrade.stderr)
        updated_yml = (self.root / "etc/prometheus/prometheus.yml").read_text(encoding="utf-8")
        self.assertIn(f"targets: ['localhost:{ne_port}']", updated_yml)
        self.assertIn("targets: ['10.0.0.5:9100']", updated_yml)

    def test_prometheus_rejects_explicit_colliding_node_exporter_port_before_mutation(self):
        self._setup_prometheus_fixtures()
        res = self.run_installer(
            "prometheus",
            extra_env={"AF_APP_PORT": "9100", "AF_NODE_EXPORTER_PORT": "9100"},
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("collides", res.stdout + res.stderr)
        self.assertEqual([c for c in self.commands() if c[0] in ("apt-get", "systemctl")], [])
        self.assertFalse((self.root / "install/.prometheus.lock").exists())

    def test_novnc_shifts_rfbport_on_5901_collision_and_keeps_websockify_in_sync(self):
        # Default non-colliding port keeps 5901
        res_default = self.run_installer("novnc", extra_env={"AF_APP_PORT": "6080"}, prelude="wait_for_service_ready() { :; }")
        self.assertEqual(res_default.returncode, 0, res_default.stdout + res_default.stderr)
        xvnc_default = (self.root / "etc/systemd/system/novnc-xvnc.service").read_text(encoding="utf-8")
        proxy_default = (self.root / "etc/systemd/system/novnc.service").read_text(encoding="utf-8")
        self.assertIn("-rfbport 5901", xvnc_default)
        self.assertIn("127.0.0.1:6080 127.0.0.1:5901", proxy_default)

        # Remove unit so fresh collision test probes free loopback port
        (self.root / "etc/systemd/system/novnc-xvnc.service").unlink()
        blocker = reserve_loopback_port(5902)
        if blocker is not None:
            self.addCleanup(blocker.close)

        res_collide = self.run_installer("novnc", extra_env={"AF_APP_PORT": "5901"}, prelude="wait_for_service_ready() { :; }")
        self.assertEqual(res_collide.returncode, 0, res_collide.stdout + res_collide.stderr)
        xvnc_unit = (self.root / "etc/systemd/system/novnc-xvnc.service").read_text(encoding="utf-8")
        proxy_unit = (self.root / "etc/systemd/system/novnc.service").read_text(encoding="utf-8")
        self.assertNotIn("-rfbport 5901", xvnc_unit)
        rfb_tokens = [tok for line in xvnc_unit.splitlines() if "-rfbport" in line for tok in line.split()]
        vnc_port = int(rfb_tokens[rfb_tokens.index("-rfbport") + 1])
        self.assertNotEqual(vnc_port, 5901)
        if blocker is not None:
            self.assertNotEqual(vnc_port, 5902)
        self.assertGreaterEqual(vnc_port, 5902)
        self.assertLess(vnc_port, 6000)
        self.assertIn(f"127.0.0.1:5901 127.0.0.1:{vnc_port}", proxy_unit)

    def test_novnc_rejects_explicit_colliding_vnc_port_and_has_aligned_apt_and_snapshot_lists(self):
        script_text = (INSTALL_DIR / "installpackage-novnc").read_text(encoding="utf-8")
        self.assertIn(
            "prepare_apt_package_transaction /etc/novnc/.af-version novnc python3-websockify tigervnc-standalone-server tigervnc-common",
            script_text,
        )
        self.assertNotIn("/usr/local/bin/af-novnc-start", script_text)
        self.assertNotIn("/usr/local/bin/af-novnc-xvnc-start", script_text)
        self.assertNotIn("/usr/bin/x11vnc", script_text)

        res = self.run_installer(
            "novnc",
            extra_env={"AF_APP_PORT": "5901", "AF_NOVNC_VNC_PORT": "5901"},
            prelude="wait_for_service_ready() { :; }",
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("collides", res.stdout + res.stderr)
        self.assertEqual([c for c in self.commands() if c[0] in ("apt-get", "systemctl")], [])

    def test_deluge_rejects_colliding_daemon_port_58846_and_custom_core_conf_port(self):
        # Default daemon port 58846 collides with AF_APP_PORT=58846
        res_default = self.run_installer(
            "deluge",
            extra_env={"AF_APP_PORT": "58846"},
            prelude="wait_for_service_ready() { :; }",
        )
        self.assertNotEqual(res_default.returncode, 0)
        self.assertIn("58846", res_default.stdout + res_default.stderr)
        self.assertEqual([c for c in self.commands() if c[0] in ("apt-get", "systemctl")], [])
        self.assertFalse((self.root / "install/.deluge.lock").exists())

        # Custom daemon_port in core.conf collides with matching AF_APP_PORT
        self.write_file(
            "var/lib/deluge/.config/deluge/core.conf",
            json.dumps({"file": 1, "format": 1}) + json.dumps({"daemon_port": 58900}),
        )
        res_custom = self.run_installer(
            "deluge",
            extra_env={"AF_APP_PORT": "58900"},
            prelude="wait_for_service_ready() { :; }",
        )
        self.assertNotEqual(res_custom.returncode, 0)
        self.assertIn("58900", res_custom.stdout + res_custom.stderr)
        self.assertEqual([c for c in self.commands() if c[0] in ("apt-get", "systemctl")], [])

        # Non-colliding port succeeds cleanly
        res_ok = self.run_installer(
            "deluge",
            extra_env={"AF_APP_PORT": "8112"},
            prelude="wait_for_service_ready() { :; }",
        )
        self.assertEqual(res_ok.returncode, 0, res_ok.stdout + res_ok.stderr)
        self.assertIn("-p 8112", (self.root / "etc/systemd/system/deluge-web.service").read_text(encoding="utf-8"))
        self.assertTrue((self.root / "install/.deluge.lock").exists())


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires POSIX bash")
class RemoverHardeningTests(BaseSandboxTest):
    def test_npm_removers_guard_usr_bin_preserving_distro_files_and_unlinking_managed_symlinks(self):
        for app in ("flood", "n8n", "thelounge"):
            # 1. Distro-owned regular binary at /usr/bin/<app> MUST be preserved
            with self.subTest(app=app, case="distro-regular-file"):
                (self.root / "usr/bin" / app).unlink(missing_ok=True)
                usr_bin = self.write_file(f"usr/bin/{app}", "distro-binary")
                local_bin = self.write_file(f"usr/local/bin/{app}", "managed-binary")
                opt_code = self.write_file(f"opt/{app}/index.js", "managed-code")
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertTrue(usr_bin.exists(), f"/usr/bin/{app} regular file was unexpectedly deleted")
                self.assertEqual(usr_bin.read_text(encoding="utf-8"), "distro-binary")
                self.assertFalse(local_bin.exists())
                self.assertFalse(opt_code.exists())
                usr_bin.unlink(missing_ok=True)

            # 2. Distro-owned symlink pointing outside /opt/<app> and /usr/local/bin/<app> MUST be preserved
            with self.subTest(app=app, case="distro-external-symlink"):
                distro_target = self.write_file(f"usr/lib/distro-{app}/{app}", "distro-target")
                usr_bin = self.root / "usr/bin" / app
                usr_bin.unlink(missing_ok=True)
                usr_bin.symlink_to(distro_target)
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertTrue(usr_bin.is_symlink(), f"external symlink /usr/bin/{app} was unexpectedly deleted")
                self.assertEqual(usr_bin.resolve(), distro_target.resolve())
                usr_bin.unlink(missing_ok=True)

            # 3. Symlink to unrelated /opt/<app>-other/ MUST be preserved
            with self.subTest(app=app, case="sibling-opt-prefix-symlink"):
                other_target = self.write_file(f"opt/{app}-other/bin/{app}", "other-app")
                usr_bin = self.root / "usr/bin" / app
                usr_bin.unlink(missing_ok=True)
                usr_bin.symlink_to(other_target)
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertTrue(usr_bin.is_symlink())
                usr_bin.unlink(missing_ok=True)

            # 4. AetherFlow-managed symlink /usr/bin/<app> -> /usr/local/bin/<app> MUST be unlinked
            with self.subTest(app=app, case="managed-usr-local-bin-symlink"):
                local_bin = self.write_file(f"usr/local/bin/{app}", "managed-binary")
                usr_bin = self.root / "usr/bin" / app
                usr_bin.unlink(missing_ok=True)
                usr_bin.symlink_to(local_bin)
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(usr_bin.exists() or usr_bin.is_symlink())
                self.assertFalse(local_bin.exists())

            # 5. AetherFlow-managed symlink /usr/bin/<app> -> /opt/<app>/node_modules/.bin/<app> MUST be unlinked
            with self.subTest(app=app, case="managed-opt-symlink"):
                opt_bin = self.write_file(f"opt/{app}/node_modules/.bin/{app}", "managed-opt-bin")
                usr_bin = self.root / "usr/bin" / app
                usr_bin.unlink(missing_ok=True)
                usr_bin.symlink_to(opt_bin)
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(usr_bin.exists() or usr_bin.is_symlink())
                self.assertFalse(opt_bin.exists())

            # 6. Relative symlink /usr/bin/<app> -> ../local/bin/<app> MUST be unlinked
            with self.subTest(app=app, case="managed-relative-symlink"):
                local_bin = self.write_file(f"usr/local/bin/{app}", "managed-binary")
                usr_bin = self.root / "usr/bin" / app
                usr_bin.unlink(missing_ok=True)
                usr_bin.symlink_to(f"../local/bin/{app}")
                res = self.run_remover(app, "false")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(usr_bin.exists() or usr_bin.is_symlink())
                self.assertFalse(local_bin.exists())

    def test_audiobookshelf_and_netdata_purge_active_and_legacy_apt_keyrings(self):
        unrelated = self.write_file("etc/apt/keyrings/unrelated.gpg", "keep-me")
        for app, files in (
            (
                "audiobookshelf",
                (
                    "etc/apt/keyrings/audiobookshelf-archive-keyring.gpg",
                    "usr/share/keyrings/audiobookshelf-keyring.gpg",
                    "etc/apt/sources.list.d/audiobookshelf.list",
                ),
            ),
            (
                "netdata",
                (
                    "etc/apt/keyrings/netdata.gpg",
                    "usr/share/keyrings/netdata-archive-keyring.gpg",
                    "etc/apt/sources.list.d/netdata.list",
                ),
            ),
        ):
            for delete_data in ("false", "true"):
                with self.subTest(app=app, DELETE_DATA=delete_data):
                    created = [self.write_file(rel, "keyring-or-list") for rel in files]
                    res = self.run_remover(app, delete_data)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    for path in created:
                        self.assertFalse(path.exists(), f"{path} should be removed by removepackage-{app}")
                    self.assertTrue(unrelated.exists())

    def test_five_apt_removers_use_remove_by_default_and_purge_on_delete_data(self):
        cases = (
            ("duplicati", ("duplicati",), ("var/lib/duplicati/db.sqlite", "etc/duplicati/duplicati.env")),
            ("kasmvnc", ("kasmvncserver",), ("var/lib/kasmvnc/.vnc/kasmvnc.yaml", "etc/kasmvnc/aetherflow-password")),
            ("novnc", ("novnc", "python3-websockify"), ("var/lib/novnc/.vnc/passwd", "etc/novnc/config")),
            ("quassel", ("quassel-core",), ("var/lib/quassel/quassel-storage.sqlite",)),
            ("x2go", ("x2goserver", "x2goserver-xsession"), ("var/lib/x2go/state", "etc/x2go/x2goserver.conf")),
        )
        for app, pkgs, data_files in cases:
            for delete_data, expected_action, forbidden_action in (
                ("false", "remove", "purge"),
                ("true", "purge", "remove"),
            ):
                with self.subTest(app=app, DELETE_DATA=delete_data):
                    for rel in data_files:
                        self.write_file(rel, "operator-state")
                    lock = self.write_file(f"install/.{app}.lock", "installed")
                    before = len(self.commands())
                    res = self.run_remover(app, delete_data)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    apt_cmds = [c for c in self.commands()[before:] if c[0] == "apt-get"]
                    self.assertTrue(
                        any(
                            c[:2] == ["apt-get", expected_action] and all(pkg in c for pkg in pkgs)
                            for c in apt_cmds
                        ),
                        f"{app} (DELETE_DATA={delete_data}) expected apt-get {expected_action} for {pkgs}, got {apt_cmds}",
                    )
                    self.assertFalse(
                        any(c[:2] == ["apt-get", forbidden_action] for c in apt_cmds),
                        f"{app} (DELETE_DATA={delete_data}) must not run apt-get {forbidden_action}: {apt_cmds}",
                    )
                    for rel in data_files:
                        self.assertEqual((self.root / rel).exists(), delete_data == "false", rel)
                    self.assertFalse(lock.exists())


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires POSIX bash")
class CiAndReleaseBuildCleanupTests(unittest.TestCase):
    def test_ci_and_release_workflows_drop_redundant_subset_clippy_and_check_web_dist_keep(self):
        subset_clippy = "cargo clippy --no-deps -p af-models -p af-host -p af-release -p af-cli -p af-librespeed"
        workspace_clippy = "cargo clippy --workspace --all-targets --locked -- -D warnings"
        for filename in ("ci.yml", "release.yml"):
            text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            with self.subTest(workflow=filename):
                self.assertIn(workspace_clippy, text)
                self.assertNotIn(subset_clippy, text)

        release_text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('test ! -e "${RELEASE_E2E_DIR}/web/dist/.keep"', release_text)

    def test_build_gold_and_release_manager_drop_stale_packages_ui_and_plugin_excludes(self):
        for rel in ("scripts/build_gold.sh", "deploy/release-manager.sh"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(file=rel):
                self.assertNotIn("packages/ui", text)
                self.assertNotIn("packages/plugin", text)

    def test_build_gold_combines_cargo_build_into_single_call_preserving_companion_flags(self):
        cases = (
            ("all-binaries", {"PACKAGE_RELEASE": "1", "BUILD_CLI": "1", "BUILD_SPEEDTEST": "1"}, ["aetherflow-api", "af", "speedtest-backend"]),
            ("no-speedtest", {"PACKAGE_RELEASE": "1", "BUILD_CLI": "1", "BUILD_SPEEDTEST": "0"}, ["aetherflow-api", "af"]),
            ("api-only", {"PACKAGE_RELEASE": "0", "BUILD_CLI": "0", "BUILD_SPEEDTEST": "0"}, ["aetherflow-api"]),
            ("api-and-speedtest", {"PACKAGE_RELEASE": "0", "BUILD_CLI": "0", "BUILD_SPEEDTEST": "1"}, ["aetherflow-api", "speedtest-backend"]),
        )
        for label, flags, expected_bins in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="af-gold-bin-") as tmp:
                root = Path(tmp)
                for rel in (
                    "scripts",
                    "backend-rs/crates/af-cli",
                    "backend-rs/crates/af-librespeed",
                    "config",
                    "packages/package/install",
                    "deploy",
                    "web/dist",
                    "plugins/telemetry-inspector/backend/hooks",
                    "plugins/telemetry-inspector/frontend/dist",
                ):
                    (root / rel).mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / "scripts/build_gold.sh", root / "scripts/build_gold.sh")
                (root / ".version").write_text("v4.0.0\n", encoding="utf-8")
                (root / "backend-rs/Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
                (root / "backend-rs/Cargo.lock").write_text("# lock\n", encoding="utf-8")
                (root / "backend-rs/crates/af-cli/Cargo.toml").write_text('[package]\nname = "af-cli"\n', encoding="utf-8")
                (root / "backend-rs/crates/af-librespeed/Cargo.toml").write_text('[package]\nname = "af-librespeed"\n', encoding="utf-8")
                (root / "config/packages.json").write_text("[]\n", encoding="utf-8")
                (root / "deploy/release-manager.sh").write_text("#!/bin/sh\n", encoding="utf-8")
                (root / "web/dist/index.html").write_text("<html>ok</html>\n", encoding="utf-8")
                (root / "web/dist/app.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
                (root / "web/dist/.keep").write_text("", encoding="utf-8")
                (root / "plugins/telemetry-inspector/plugin.manifest.json").write_text('{"id":"telemetry-inspector"}\n', encoding="utf-8")
                (root / "plugins/telemetry-inspector/backend/hooks/start.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                (root / "plugins/telemetry-inspector/backend/runtime.py").write_text("print('ok')\n", encoding="utf-8")
                (root / "plugins/telemetry-inspector/frontend/dist/index.html").write_text("<html>p</html>\n", encoding="utf-8")

                tools = root / "tools"
                tools.mkdir()
                cargo_log = root / "cargo.jsonl"
                cargo = tools / "cargo"
                cargo.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json, os, pathlib, sys\n"
                    "args = sys.argv[1:]\n"
                    "with pathlib.Path(os.environ['TEST_CARGO_LOG']).open('a') as fh:\n"
                    "    fh.write(json.dumps(args) + '\\n')\n"
                    "target = args[args.index('--target') + 1]\n"
                    "bins = [args[i + 1] for i, a in enumerate(args) if a == '--bin' and i + 1 < len(args)]\n"
                    "out = pathlib.Path(os.environ['CARGO_TARGET_DIR']) / target / 'release'\n"
                    "out.mkdir(parents=True, exist_ok=True)\n"
                    "for b in bins:\n"
                    "    (out / b).write_text(f'bin:{b}')\n",
                    encoding="utf-8",
                )
                cargo.chmod(0o755)

                env = os.environ.copy()
                for key in (
                    "CARGO_BUILD_TARGET",
                    "CARGO_TARGET_DIR",
                    "BACKEND_RS_DIR",
                    "CONFIG_DIR",
                    "PLUGINS_DIR",
                    "FRONTEND_DIST_DIR",
                    "EMBED_DIST_DIR",
                    "BUILD_DATE",
                ):
                    env.pop(key, None)
                env.update(
                    {
                        "PATH": f"{tools}{os.pathsep}{env['PATH']}",
                        "BUILD_FRONTEND": "0",
                        "RUN_TESTS": "0",
                        "TARGETS": "amd64",
                        "SOURCE_DATE_EPOCH": "1700000000",
                        "CARGO_TARGET_DIR": str(root / "target"),
                        "OUTPUT_DIR": str(root / "out"),
                        "TEST_CARGO_LOG": str(cargo_log),
                        **flags,
                    }
                )
                res = subprocess.run(
                    ["bash", str(root / "scripts/build_gold.sh")],
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                invocations = [json.loads(line) for line in cargo_log.read_text(encoding="utf-8").splitlines()]
                build_calls = [args for args in invocations if args and args[0] == "build"]
                self.assertEqual(len(build_calls), 1, f"Expected a single combined cargo build call, got: {build_calls}")
                actual_bins = [
                    build_calls[0][i + 1]
                    for i, arg in enumerate(build_calls[0])
                    if arg == "--bin" and i + 1 < len(build_calls[0])
                ]
                self.assertEqual(actual_bins, expected_bins)
                if flags["PACKAGE_RELEASE"] == "1":
                    with tarfile.open(root / "out/aetherflow-linux-amd64.tar.gz") as bundle:
                        self.assertNotIn("./web/dist/.keep", bundle.getnames())


if __name__ == "__main__":
    unittest.main()
