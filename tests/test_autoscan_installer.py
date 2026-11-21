#!/usr/bin/env python3
"""Focused offline regressions for Cloudbox Autoscan installer, checksums, and readiness."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, common_functions

COMMON_SH = ROOT / "packages/common.sh"
INSTALLER_SH = ROOT / "packages/package/install/installpackage-autoscan"
AUTOMATION_JSON = ROOT / "config/package_automation.json"

REBASE_RE = re.compile(
    r"(?<![\w/.-])(/usr/local|/opt|/var|/etc|/install)(?=/|[^\w.-]|$)"
)


def rebase_text(text: str, root: Path) -> str:
    return REBASE_RE.sub(lambda m: str(root) + m.group(0), text)


class _AutoscanRouterServer:
    """Minimal loopback HTTP server matching Cloudbox Autoscan v1.4.0 routes."""

    def __init__(self, *, health_status: int = 200, require_trigger_auth: bool = False):
        self.health_status = health_status
        self.require_trigger_auth = require_trigger_auth
        self.requests: list[tuple[str, str]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> tuple[int, "_AutoscanRouterServer"]:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _handle(self):
                path = self.path.split("?", 1)[0]
                outer.requests.append((self.command, path))
                if path == "/health" and self.command == "GET":
                    self.send_response(outer.health_status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path == "/health":
                    self.send_response(405)
                    self.end_headers()
                    return
                if path.startswith("/triggers/"):
                    if outer.require_trigger_auth:
                        self.send_response(401)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.end_headers()
                    return
                self.send_response(404)
                body = b"404 page not found\n"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                self._handle()

            def do_HEAD(self):
                self._handle()

            def do_POST(self):
                self._handle()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server.server_port, self

    def __exit__(self, exc_type, exc, tb):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class _DisposableAutoscanFixture:
    """Unprivileged disposable root for running installpackage-autoscan end-to-end."""

    def __init__(
        self,
        *,
        version: str = "1.4.0",
        arch: str = "amd64",
        corrupt_checksum: bool = False,
        readiness_attempts: int = 2,
    ):
        self.version = version
        self.arch = arch
        self.corrupt_checksum = corrupt_checksum
        self.readiness_attempts = readiness_attempts
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self.root: Path | None = None

    def __enter__(self) -> "_DisposableAutoscanFixture":
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for rel in (
            "etc/autoscan",
            "etc/systemd/system",
            "var/lib/autoscan",
            "var/log/aetherflow",
            "var/tmp",
            "opt/autoscan",
            "usr/local/bin",
            "install",
            "shim-bin",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)

        fake_bin = (
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then\n'
            '  cfg_root="${XDG_CONFIG_HOME:-$HOME/.config}"\n'
            '  mkdir -p "$cfg_root/autoscan" || exit 2\n'
            f'  printf "{self.version} (fixture@1694864132)\\n"\n'
            "  exit 0\n"
            "fi\n"
            "exit 0\n"
        ).encode("utf-8")
        self.payload = fake_bin
        self.sha512 = hashlib.sha512(fake_bin).hexdigest()
        (self.root / "fixture-autoscan-bin").write_bytes(fake_bin)
        (self.root / "fixture-autoscan-bin").chmod(0o755)

        common_src = rebase_text(COMMON_SH.read_text(encoding="utf-8"), self.root)
        # Bound readiness wait attempts in tests so negative rollback cases finish quickly.
        common_src = common_src.replace(
            'attempts="${4:-30}"',
            f'attempts="${{4:-{self.readiness_attempts}}}"',
            1,
        )
        common_src += (
            f'\nexport PATH="{self.root}/shim-bin:$PATH"\n'
            f'LOCK_DIR="{self.root}/install"\n'
            "require_root() { :; }\n"
            "apt-get() { :; }\n"
        )
        (self.root / "common.sh").write_text(common_src, encoding="utf-8")

        inst_src = INSTALLER_SH.read_text(encoding="utf-8")
        inst_src = inst_src.replace(
            'if [[ -f "${SELF_DIR}/../../common.sh" ]]; then',
            f'if [[ -f "{self.root}/common.sh" ]]; then',
        )
        inst_src = inst_src.replace(
            'source "${SELF_DIR}/../../common.sh"',
            f'source "{self.root}/common.sh"',
        )
        (self.root / "installpackage-autoscan").write_text(
            rebase_text(inst_src, self.root), encoding="utf-8"
        )
        (self.root / "installpackage-autoscan").chmod(0o755)

        as_arch = {"amd64": "amd64", "arm64": "arm64", "armhf": "armv7"}[self.arch]
        asset_name = f"autoscan_v{self.version}_linux_{as_arch}"
        digest = ("0" * 128) if self.corrupt_checksum else self.sha512

        shims = {
            "id": "#!/bin/sh\nexit 0\n",
            "useradd": "#!/bin/sh\nexit 0\n",
            "chown": "#!/bin/sh\nexit 0\n",
            "dpkg": f"#!/bin/sh\necho {self.arch}\n",
            "systemctl": f"""#!/usr/bin/env python3
import pathlib, sys
root = pathlib.Path({str(self.root)!r})
args = sys.argv[1:]
cmd = args[0] if args else ''
active = root / 'service.active'
if cmd in ('enable', 'start', 'restart'):
    active.touch()
    sys.exit(0)
if cmd == 'stop':
    active.unlink(missing_ok=True)
    sys.exit(0)
if cmd == 'is-active':
    sys.exit(0 if active.exists() else 3)
if cmd == 'show':
    state = 'active' if active.exists() else 'inactive'
    pid = 1234 if active.exists() else 0
    print(f'LoadState=loaded\\nActiveState={{state}}\\nMainPID={{pid}}\\nUnitFileState=enabled')
    sys.exit(0)
sys.exit(0)
""",
            "curl": f"""#!/usr/bin/env python3
import json, pathlib, shutil, subprocess, sys
root = pathlib.Path({str(self.root)!r})
args = sys.argv[1:]
url = next((a for a in args if a.startswith('http')), '')
with (root / 'curl-calls.jsonl').open('a', encoding='utf-8') as fh:
    fh.write(json.dumps({{'url': url, 'args': args}}) + '\\n')
if 'github.com/Cloudbox/autoscan/releases/latest' in url:
    print('https://github.com/Cloudbox/autoscan/releases/tag/v{self.version}')
    sys.exit(0)
if 'api.github.com/repos/Cloudbox/autoscan/releases/tags/v{self.version}' in url:
    print(json.dumps({{
        'tag_name': 'v{self.version}',
        'assets': [
            {{'name': {asset_name!r}, 'browser_download_url': 'https://github.com/Cloudbox/autoscan/releases/download/v{self.version}/{asset_name}'}},
            {{'name': 'checksums.txt', 'browser_download_url': 'https://github.com/Cloudbox/autoscan/releases/download/v{self.version}/checksums.txt'}},
        ],
    }}))
    sys.exit(0)
out = args[args.index('-o') + 1] if '-o' in args else None
if url == 'https://github.com/Cloudbox/autoscan/releases/download/v{self.version}/{asset_name}':
    shutil.copyfile(root / 'fixture-autoscan-bin', out)
    sys.exit(0)
if url == 'https://github.com/Cloudbox/autoscan/releases/download/v{self.version}/checksums.txt':
    pathlib.Path(out).write_text('{digest}  {asset_name}\\n', encoding='utf-8')
    sys.exit(0)
if url.endswith(('.sha256', '.sha256sum')):
    sys.exit(22)
sys.exit(subprocess.run(['/usr/bin/curl', *args]).returncode)
""",
        }
        for name, body in shims.items():
            p = self.root / "shim-bin" / name
            p.write_text(body, encoding="utf-8")
            p.chmod(0o755)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._tmp is not None:
            self._tmp.cleanup()

    def run(self, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        assert self.root is not None
        env = {
            "PATH": f"{self.root / 'shim-bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/nonexistent",
            "AF_JOB_SCRATCH_ROOT": str(self.root / "var/tmp"),
            "AF_BIND_ADDRESS": "127.0.0.1",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/bash", str(self.root / "installpackage-autoscan")],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def curl_calls(self) -> list[dict]:
        assert self.root is not None
        log = self.root / "curl-calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


class AutoscanInstallerRegressionTests(unittest.TestCase):
    def test_fresh_install_without_arr_uses_strict_yaml_and_health_probe_only(self):
        with _AutoscanRouterServer() as (port, srv), _DisposableAutoscanFixture() as fx:
            res = fx.run({"AF_APP_PORT": str(port)})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            cfg = (fx.root / "etc/autoscan/config.yml").read_text(encoding="utf-8")
            self.assertIn("host:\n  - 127.0.0.1\n", cfg)
            self.assertIn(f"port: {port}\n", cfg)
            self.assertIn("triggers:\n  manual:\n    priority: 0\n", cfg)
            self.assertNotIn("scan-priority", cfg)
            self.assertNotIn("api-key", cfg)
            self.assertNotRegex(cfg, r"(?m)^anchors:")
            self.assertNotIn("sonarr:", cfg)
            self.assertNotIn("radarr:", cfg)
            self.assertNotIn("Zero-Touch Arr", res.stdout + res.stderr)
            self.assertNotIn("Arr webhooks ready", res.stdout + res.stderr)

            unit = (fx.root / "etc/systemd/system/autoscan.service").read_text(encoding="utf-8")
            self.assertIn("Environment=XDG_CONFIG_HOME=", unit)
            self.assertIn("autoscan --config ", unit)

            # Confirm readiness used read-only GET /health and never hit / or any webhook trigger.
            self.assertEqual(srv.requests, [("GET", "/health")])
            self.assertTrue((fx.root / "install/.autoscan.lock").is_file())
            self.assertEqual((fx.root / "opt/autoscan/.af-version").read_text().strip(), "1.4.0")

    def test_fresh_install_with_arr_config_does_not_copy_api_keys_or_write_invalid_fields(self):
        with _AutoscanRouterServer() as (port, srv), _DisposableAutoscanFixture() as fx:
            for app in ("sonarr", "radarr"):
                d = fx.root / "var/lib" / app
                d.mkdir(parents=True, exist_ok=True)
                (d / "config.xml").write_text(
                    f"<Config><ApiKey>secret-{app}-token-12345</ApiKey></Config>\n",
                    encoding="utf-8",
                )
            res = fx.run({"AF_APP_PORT": str(port)})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            cfg = (fx.root / "etc/autoscan/config.yml").read_text(encoding="utf-8")
            self.assertIn("manual:\n    priority: 0\n", cfg)
            self.assertIn("sonarr:\n    - name: sonarr\n      priority: 1\n", cfg)
            self.assertIn("radarr:\n    - name: radarr\n      priority: 1\n", cfg)
            self.assertNotIn("api-key", cfg)
            self.assertNotIn("secret-sonarr-token-12345", cfg)
            self.assertNotIn("secret-radarr-token-12345", cfg)
            self.assertEqual(srv.requests, [("GET", "/health")])

    def test_armhf_selects_armv7_raw_binary_asset_and_verifies_sha512(self):
        with _AutoscanRouterServer() as (port, _), _DisposableAutoscanFixture(arch="armhf") as fx:
            res = fx.run({"AF_APP_PORT": str(port)})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            urls = [entry["url"] for entry in fx.curl_calls()]
            self.assertIn(
                "https://github.com/Cloudbox/autoscan/releases/download/v1.4.0/autoscan_v1.4.0_linux_armv7",
                urls,
            )
            self.assertIn(
                "https://github.com/Cloudbox/autoscan/releases/download/v1.4.0/checksums.txt",
                urls,
            )

    def test_corrupt_sha512_checksums_manifest_fails_closed(self):
        with _AutoscanRouterServer() as (port, _), _DisposableAutoscanFixture(corrupt_checksum=True) as fx:
            res = fx.run({"AF_APP_PORT": str(port)})
            self.assertNotEqual(res.returncode, 0)
            log = (fx.root / "var/log/aetherflow/install-autoscan.log").read_text(encoding="utf-8")
            self.assertIn("SHA-512 digest mismatch", log + res.stderr)
            self.assertFalse((fx.root / "usr/local/bin/autoscan").exists())
            self.assertFalse((fx.root / "install/.autoscan.lock").exists())

    def test_retained_nonstandard_port_and_auth_are_preserved_and_probed_without_auth(self):
        with _AutoscanRouterServer(require_trigger_auth=True) as (port, srv), _DisposableAutoscanFixture() as fx:
            retained_cfg = (
                "# operator custom config\n"
                "host:\n"
                "  - 127.0.0.1\n"
                f"port: {port}\n"
                "minimum-age: 5m\n"
                "anchors:\n"
                "  - /mnt/custom/mount.anchor\n"
                "authentication:\n"
                "  username: admin\n"
                "  password: operator-secret\n"
                "triggers:\n"
                "  manual:\n"
                "    priority: 4\n"
            )
            cfg_path = fx.root / "etc/autoscan/config.yml"
            cfg_path.write_text(retained_cfg, encoding="utf-8")

            # Omit AF_APP_PORT so the installer must preserve the retained nonstandard port.
            res = fx.run()
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(cfg_path.read_text(encoding="utf-8"), retained_cfg)
            self.assertIn(f"port {port}", res.stdout)
            self.assertEqual(srv.requests, [("GET", "/health")])

    def test_retained_explicit_host_port_takes_precedence_over_top_level_port(self):
        with _AutoscanRouterServer() as (port, srv), _DisposableAutoscanFixture() as fx:
            retained_cfg = (
                "host:\n"
                f"  - 127.0.0.1:{port}\n"
                "port: 3030\n"
                "minimum-age: 2m\n"
            )
            cfg_path = fx.root / "etc/autoscan/config.yml"
            cfg_path.write_text(retained_cfg, encoding="utf-8")

            res = fx.run()
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn(f"127.0.0.1:{port}", cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(srv.requests, [("GET", "/health")])

            conflict = fx.run({"AF_APP_PORT": str(port + 1 if port < 65535 else port - 1)})
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("retained host port overrides requested port", conflict.stderr)
            self.assertEqual(cfg_path.read_text(encoding="utf-8"), retained_cfg)

    def test_wildcard_host_at_eof_without_newline_hardens_without_duplicate_key(self):
        with _AutoscanRouterServer() as (port, _), _DisposableAutoscanFixture() as fx:
            cfg_path = fx.root / "etc/autoscan/config.yml"
            cfg_path.write_text(f"port: {port}\nhost: []", encoding="utf-8")

            res = fx.run()
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            updated = cfg_path.read_text(encoding="utf-8")
            self.assertEqual(len(re.findall(r"(?m)^host:", updated)), 1, updated)
            self.assertIn("host:\n  - 127.0.0.1\n", updated)

    def test_failed_health_probe_rolls_back_previous_runtime_and_config(self):
        with _AutoscanRouterServer(health_status=503) as (port, srv), _DisposableAutoscanFixture(
            readiness_attempts=1
        ) as fx:
            prev_bin = fx.root / "usr/local/bin/autoscan"
            prev_bin.write_text("#!/bin/sh\necho previous-autoscan\n", encoding="utf-8")
            prev_bin.chmod(0o755)
            prev_ver = fx.root / "opt/autoscan/.af-version"
            prev_ver.write_text("1.3.0\n", encoding="utf-8")
            prev_cfg = fx.root / "etc/autoscan/config.yml"
            prev_cfg_text = f"host:\n  - 127.0.0.1\nport: {port}\n"
            prev_cfg.write_text(prev_cfg_text, encoding="utf-8")
            prev_unit = fx.root / "etc/systemd/system/autoscan.service"
            prev_unit.write_text("[Unit]\nDescription=Previous Autoscan\n", encoding="utf-8")
            (fx.root / "service.active").touch()
            (fx.root / "install/.autoscan.lock").write_text("previous-lock\n", encoding="utf-8")

            res = fx.run({"AF_APP_PORT": str(port)})
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(("GET", "/health"), srv.requests)
            self.assertIn("previous-autoscan", prev_bin.read_text(encoding="utf-8"))
            self.assertEqual(prev_ver.read_text(encoding="utf-8"), "1.3.0\n")
            self.assertEqual(prev_cfg.read_text(encoding="utf-8"), prev_cfg_text)
            self.assertIn("Previous Autoscan", prev_unit.read_text(encoding="utf-8"))
            self.assertEqual((fx.root / "install/.autoscan.lock").read_text(encoding="utf-8"), "previous-lock\n")

    def test_package_automation_version_command_succeeds_with_unwritable_home(self):
        automation = json.loads(AUTOMATION_JSON.read_text(encoding="utf-8"))["autoscan"]
        with _DisposableAutoscanFixture() as fx:
            script = automation["version_command"][-1].replace(
                "/usr/local/bin/autoscan",
                str(fx.root / "fixture-autoscan-bin"),
            )
            res = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", script],
                env={
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "HOME": "/nonexistent",
                    "LANG": "C.UTF-8",
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue(res.stdout.strip().startswith("1.4.0"), res.stdout)

    def test_application_readiness_url_parses_autoscan_with_and_without_pyyaml(self):
        helpers = common_functions(
            "resolve_app_readiness_path",
            "application_readiness_url",
            "wait_for_service_ready",
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / "etc/autoscan/config.yml"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            rebased_helpers = helpers.replace("/etc/autoscan/config.yml", str(cfg))

            # Shadow PyYAML in a separate directory to exercise the stdlib fallback path too.
            no_yaml_dir = root / "no-yaml"
            no_yaml_dir.mkdir()
            (no_yaml_dir / "yaml.py").write_text("raise ImportError('no pyyaml')\n", encoding="utf-8")

            cases = [
                ("host:\n  - 127.0.0.1\nport: 4141\n", "3030", "http://127.0.0.1:4141/health"),
                ("host:\n  - 192.0.2.45\n  - 127.0.0.1:4242\nport: 3030\n", "3030", "http://127.0.0.1:4242/health"),
                ("host:\n  - 192.0.2.45:5959\nport: 3030\n", "3030", "http://192.0.2.45:5959/health"),
                ('host: ["0.0.0.0:4343"]\n', "3030", "http://127.0.0.1:4343/health"),
                ("host:\n  - '[::1]:4444'\n", "3030", "http://[::1]:4444/health"),
            ]
            for yaml_text, fallback_port, expected_url in cases:
                cfg.write_text(yaml_text, encoding="utf-8")
                for mode, extra_env in (("default", {}), ("stdlib-fallback", {"PYTHONPATH": str(no_yaml_dir)})):
                    with self.subTest(mode=mode, expected=expected_url):
                        res = subprocess.run(
                            [
                                "bash",
                                "-c",
                                f"{rebased_helpers}\napplication_readiness_url autoscan {fallback_port}",
                            ],
                            env={**os.environ, **extra_env},
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                        self.assertEqual(res.stdout.strip(), expected_url)

    def test_verify_download_sha256_supports_sha512_in_checksums_and_rejects_sha256_manifest_mismatch(self):
        helpers = common_functions("verify_sha256", "verify_download_sha256")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = root / "autoscan_v1.4.0_linux_amd64"
            payload.write_bytes(b"autoscan-binary-payload")
            sha512 = hashlib.sha512(payload.read_bytes()).hexdigest()

            # Valid local checksums.txt with SHA-512 succeeds
            manifest = root / "checksums.txt"
            manifest.write_text(f"{sha512}  autoscan_v1.4.0_linux_amd64\n", encoding="utf-8")
            script = (
                helpers
                + '\nprint_error() { printf "%s\\n" "$*" >&2; }; log_info() { :; }; af_logged_stderr() { "$@"; }; curl() { return 22; }\n'
                + 'verify_download_sha256 "$1" autoscan "https://github.com/Cloudbox/autoscan/releases/download/v1.4.0/autoscan_v1.4.0_linux_amd64"\n'
            )
            ok = subprocess.run(["bash", "-c", script, "_", str(payload)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

            # Corrupt SHA-512 fails closed
            manifest.write_text(f"{'f' * 128}  autoscan_v1.4.0_linux_amd64\n", encoding="utf-8")
            bad = subprocess.run(["bash", "-c", script, "_", str(payload)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("SHA-512 digest mismatch", bad.stderr)

            # SHA-256-only manifest (.sha256) still rejects 128-hex digest
            manifest.unlink()
            (root / "autoscan_v1.4.0_linux_amd64.sha256").write_text(f"{sha512}\n", encoding="utf-8")
            reject = subprocess.run(["bash", "-c", script, "_", str(payload)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(reject.returncode, 0)
            self.assertIn("SHA-256 verification failed", reject.stderr)


if __name__ == "__main__":
    unittest.main()
