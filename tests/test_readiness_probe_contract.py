import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tests.installer_test_helpers import common_functions
from tests.test_marketplace_catalog_lifecycle_matrix import InstallerFixture


ROOT = Path(__file__).resolve().parents[1]
AUTOMATION_CONFIG = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))


def _parse_probe_records(text: str):
    return [
        json.loads(line.split("=", 1)[1])
        for line in text.splitlines()
        if line.strip().startswith("__AF_READINESS_PROBE__=")
    ]


class _StatusHandler(http.server.BaseHTTPRequestHandler):
    status_code = 200
    headers_extra = {}

    def do_GET(self):
        self.send_response(self.status_code)
        for key, value in self.headers_extra.items():
            self.send_header(key, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


def _start_server(status_code=200, headers_extra=None):
    headers = dict(headers_extra or {})

    class Handler(_StatusHandler):
        pass

    Handler.status_code = status_code
    Handler.headers_extra = headers
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("curl"),
    "requires POSIX bash and curl",
)
class ReadinessProbeContractTests(unittest.TestCase):
    def _make_fake_systemctl(self, tmp_path: Path, exit_code: int = 0) -> Path:
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        sc = fake_bin / "systemctl"
        sc.write_text(f"#!/bin/bash\nexit {exit_code}\n", encoding="utf-8")
        sc.chmod(0o755)
        return fake_bin

    def _run_wait(self, tmp_path: Path, command: str, env_overrides=None):
        fake_bin = self._make_fake_systemctl(tmp_path)
        helpers = common_functions(
            "resolve_app_readiness_path",
            "application_readiness_url",
            "wait_for_service_ready",
        )
        script = (
            "set -euo pipefail\n"
            "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            f"{helpers}\n"
            f"{command}\n"
        )
        env = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
            "LOGFILE": "/dev/null",
        }
        env.pop("AF_EMIT_READINESS_RECORD", None)
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_record_is_opt_in_and_silent_by_default(self):
        server, port = _start_server(401)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                res = self._run_wait(
                    Path(tmp),
                    f"wait_for_service_ready filebot.service {port} / 2",
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertNotIn("__AF_READINESS_PROBE__=", res.stdout + res.stderr)
        finally:
            server.shutdown()
            server.server_close()

    def test_opt_in_emits_filebot_auth_record_and_redirect_and_custom_path(self):
        s_401, p_401 = _start_server(401)
        s_302, p_302 = _start_server(302, {"Location": "/login"})
        s_200, p_200 = _start_server(200)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                # 1. FileBot 401 -> accept_auth=true
                res = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready filebot.service {p_401} / 2",
                    {"AF_EMIT_READINESS_RECORD": "1"},
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                lines = [
                    l for l in res.stderr.splitlines() if l.startswith("__AF_READINESS_PROBE__=")
                ]
                self.assertEqual(len(lines), 1, res.stderr)
                rec = json.loads(lines[0].split("=", 1)[1])
                self.assertEqual(
                    rec,
                    {
                        "unit": "filebot.service",
                        "url": f"http://127.0.0.1:{p_401}/",
                        "accept_auth": True,
                        "accept_409": False,
                    },
                )

                # 2. Redirected resource (302) -> succeeds and emits exact URL
                res_redir = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready duplicati {p_302} / 2",
                    {"AF_EMIT_READINESS_RECORD": "1"},
                )
                self.assertEqual(res_redir.returncode, 0, res_redir.stderr)
                lines_redir = [
                    l
                    for l in res_redir.stderr.splitlines()
                    if l.startswith("__AF_READINESS_PROBE__=")
                ]
                self.assertEqual(len(lines_redir), 1, res_redir.stderr)
                rec_redir = json.loads(lines_redir[0].split("=", 1)[1])
                self.assertEqual(
                    rec_redir,
                    {
                        "unit": "duplicati.service",
                        "url": f"http://127.0.0.1:{p_302}/",
                        "accept_auth": False,
                        "accept_409": False,
                    },
                )

                # 3. Custom retained address & alternate path & safe query
                custom_url = f"http://127.0.0.1:{p_200}/custom/sab/api?mode=version"
                res_custom = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready sabnzbd.service {p_200} '{custom_url}' 2",
                    {"AF_EMIT_READINESS_RECORD": "1"},
                )
                self.assertEqual(res_custom.returncode, 0, res_custom.stderr)
                lines_custom = [
                    l
                    for l in res_custom.stderr.splitlines()
                    if l.startswith("__AF_READINESS_PROBE__=")
                ]
                self.assertEqual(len(lines_custom), 1, res_custom.stderr)
                rec_custom = json.loads(lines_custom[0].split("=", 1)[1])
                self.assertEqual(rec_custom["unit"], "sabnzbd.service")
                self.assertEqual(rec_custom["url"], custom_url)
                self.assertTrue(rec_custom["accept_auth"])
                self.assertFalse(rec_custom["accept_409"])
        finally:
            for s in (s_401, s_302, s_200):
                s.shutdown()
                s.server_close()

    def test_authenticated_transmission_and_nzbget_never_emit_credentials(self):
        s_409, p_409 = _start_server(409)
        s_200, p_200 = _start_server(200)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                secret = "super-secret-pass-9876"
                res_tr = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready transmission-daemon {p_409} /transmission/rpc 2",
                    {
                        "AF_EMIT_READINESS_RECORD": "1",
                        "TRANSMISSION_USER": "tradmin",
                        "TRANSMISSION_PASS": secret,
                    },
                )
                self.assertEqual(res_tr.returncode, 0, res_tr.stderr)
                self.assertNotIn(secret, res_tr.stdout + res_tr.stderr)
                self.assertNotIn("tradmin", res_tr.stdout + res_tr.stderr)
                lines_tr = [
                    l for l in res_tr.stderr.splitlines() if l.startswith("__AF_READINESS_PROBE__=")
                ]
                self.assertEqual(len(lines_tr), 1, res_tr.stderr)
                rec_tr = json.loads(lines_tr[0].split("=", 1)[1])
                self.assertEqual(
                    rec_tr,
                    {
                        "unit": "transmission-daemon.service",
                        "url": f"http://127.0.0.1:{p_409}/transmission/rpc",
                        "accept_auth": True,
                        "accept_409": True,
                    },
                )

                res_nzb = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready nzbget {p_200} /jsonrpc/version 2",
                    {
                        "AF_EMIT_READINESS_RECORD": "1",
                        "NZBGET_USER": "nzbadmin",
                        "NZBGET_PASS": secret,
                    },
                )
                self.assertEqual(res_nzb.returncode, 0, res_nzb.stderr)
                self.assertNotIn(secret, res_nzb.stdout + res_nzb.stderr)
                self.assertNotIn("nzbadmin", res_nzb.stdout + res_nzb.stderr)
                lines_nzb = [
                    l for l in res_nzb.stderr.splitlines() if l.startswith("__AF_READINESS_PROBE__=")
                ]
                self.assertEqual(len(lines_nzb), 1, res_nzb.stderr)
                rec_nzb = json.loads(lines_nzb[0].split("=", 1)[1])
                self.assertEqual(
                    rec_nzb,
                    {
                        "unit": "nzbget.service",
                        "url": f"http://127.0.0.1:{p_200}/jsonrpc/version",
                        "accept_auth": True,
                        "accept_409": False,
                    },
                )
        finally:
            for s in (s_409, s_200):
                s.shutdown()
                s.server_close()

    def test_refuses_credentialed_urls_and_never_emits_on_failure(self):
        s_503, p_503 = _start_server(503)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                # Failed readiness check emits nothing
                res_fail = self._run_wait(
                    tmp_path,
                    f"wait_for_service_ready filebot.service {p_503} / 1",
                    {"AF_EMIT_READINESS_RECORD": "1"},
                )
                self.assertNotEqual(res_fail.returncode, 0)
                self.assertNotIn("__AF_READINESS_PROBE__=", res_fail.stdout + res_fail.stderr)

                # Direct emit helper refuses userinfo credentials and secret query parameters
                res_cred = self._run_wait(
                    tmp_path,
                    "af_emit_readiness_record filebot.service 'http://user:pass@127.0.0.1:5452/' true false\n"
                    "af_emit_readiness_record sonarr.service 'http://127.0.0.1:8989/ping?apikey=secret123' false false",
                    {"AF_EMIT_READINESS_RECORD": "1"},
                )
                self.assertEqual(res_cred.returncode, 0, res_cred.stderr)
                self.assertNotIn("__AF_READINESS_PROBE__=", res_cred.stdout + res_cred.stderr)
        finally:
            s_503.shutdown()
            s_503.server_close()


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("curl"),
    "requires POSIX bash and curl",
)
class LocalInstallerReadinessRecordTests(unittest.TestCase):
    EXPECTED_LOCAL_HTTP_PROBES = {
        "audiobookshelf": (
            18378,
            [
                {
                    "unit": "audiobookshelf.service",
                    "url": "http://127.0.0.1:18378/status",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
        "invidious": (
            18281,
            [
                {
                    "unit": "af-invidious.service",
                    "url": "http://127.0.0.1:18281/",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
        "jellyseerr": (
            15055,
            [
                {
                    "unit": "jellyseerr.service",
                    "url": "http://127.0.0.1:15055/api/v1/status",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
        "kasmvnc": (
            16081,
            [
                {
                    "unit": "af-kasmvnc.service",
                    "url": "https://127.0.0.1:16081/",
                    "accept_auth": True,
                    "accept_409": False,
                }
            ],
        ),
        "maintainerr": (
            16246,
            [
                {
                    "unit": "af-maintainerr.service",
                    "url": "http://127.0.0.1:16246/api/health/ready",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
        "mcvnc": (
            16900,
            [
                {
                    "unit": "af-mcvnc.service",
                    "url": "http://127.0.0.1:16900/",
                    "accept_auth": True,
                    "accept_409": False,
                }
            ],
        ),
        "palate": (
            28114,
            [
                {
                    "unit": "af-palate.service",
                    "url": "http://127.0.0.1:28114/login",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
        "piped": (
            18280,
            [
                {
                    "unit": "af-piped.service",
                    "url": "http://127.0.0.1:18280/",
                    "accept_auth": False,
                    "accept_409": False,
                },
                {
                    "unit": "af-piped.service",
                    "url": "http://127.0.0.1:18280/api/healthcheck",
                    "accept_auth": False,
                    "accept_409": False,
                },
            ],
        ),
        "thelounge": (
            19000,
            [
                {
                    "unit": "thelounge.service",
                    "url": "http://127.0.0.1:19000/",
                    "accept_auth": False,
                    "accept_409": False,
                }
            ],
        ),
    }

    SYSTEMD_ONLY_INSTALLERS = (
        "calibreweb",
        "dispatcharr",
        "homeassistant",
        "paperless-ngx",
        "pyload",
        "znc",
    )

    def test_local_http_installers_emit_verified_records_opt_in_and_silent_by_default(self):
        for app, (port, expected_records) in self.EXPECTED_LOCAL_HTTP_PROBES.items():
            managed_units = set(AUTOMATION_CONFIG[app]["sandbox_service_units"])
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                silent = fixture.run("install", port=port, AF_EMIT_READINESS_RECORD="0")
                self.assertEqual(silent.returncode, 0, silent.stdout + silent.stderr)
                self.assertEqual(_parse_probe_records(silent.stdout + silent.stderr), [])

                emitted = fixture.run("reinstall", port=port, AF_EMIT_READINESS_RECORD="1")
                self.assertEqual(emitted.returncode, 0, emitted.stdout + emitted.stderr)
                self.assertEqual(_parse_probe_records(emitted.stdout), [])
                records = _parse_probe_records(emitted.stderr)
                self.assertEqual(records, expected_records)
                for rec in records:
                    self.assertIn(rec["unit"], managed_units)
                self.assertNotIn("bootstrap-password", emitted.stderr)

    def test_audiobookshelf_preserves_retained_bind_host_in_probe_and_record(self):
        cases = (
            ("192.0.2.45", "192.0.2.45"),
            ("0.0.0.0", "127.0.0.1"),
            ("::", "[::1]"),
            ("::1", "[::1]"),
            ("[::1]", "[::1]"),
        )
        source = (ROOT / "packages/package/install/installpackage-audiobookshelf").read_text(encoding="utf-8")
        bootstrap_program = next(
            block for block in re.findall(r"<<'PYEOF'\n(.*?)\nPYEOF", source, re.DOTALL)
            if "urllib.request" in block
        )
        for configured_host, expected_probe_host in cases:
            with self.subTest(host=configured_host), InstallerFixture("audiobookshelf") as fixture:
                fixture.file(
                    "etc/systemd/system/audiobookshelf.service",
                    f"[Service]\nEnvironment=HOST={configured_host}\nEnvironment=PORT=13378\n",
                )
                res = fixture.run("reinstall", port=18379, AF_EMIT_READINESS_RECORD="1")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                expected_url = f"http://{expected_probe_host}:18379/status"
                self.assertEqual(
                    _parse_probe_records(res.stderr),
                    [
                        {
                            "unit": "audiobookshelf.service",
                            "url": expected_url,
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
                self.assertIn(
                    f"Environment=HOST={configured_host}",
                    (fixture.root / "etc/systemd/system/audiobookshelf.service").read_text(encoding="utf-8"),
                )

                response = mock.MagicMock(status=200)
                response.__enter__.return_value = response
                response.read.return_value = b'{"isInit": true}'
                urlopen_mock = mock.Mock(return_value=response)
                with mock.patch.dict(
                    os.environ,
                    {
                        "AF_APP_PORT": "18379",
                        "AF_PROBE_HOST": expected_probe_host,
                        "AF_SEED_USER": "admin",
                        "AF_SEED_PASS": "secret-pass",
                    },
                ), mock.patch("urllib.request.urlopen", side_effect=urlopen_mock), mock.patch("time.sleep"):
                    with self.assertRaises(SystemExit) as exited:
                        exec(compile(bootstrap_program, "installpackage-audiobookshelf", "exec"), {})
                self.assertEqual(exited.exception.code, 0)
                self.assertEqual(urlopen_mock.call_args.args[0], expected_url)

    def test_kasmvnc_records_actual_http_fallback_scheme_and_omits_on_failure(self):
        source = (ROOT / "packages/package/install/installpackage-kasmvnc").read_text(encoding="utf-8")
        probe_start = source.index("READY=false\nREADY_URL=")
        probe_end = source.index("VERSION_FILE=/var/lib/kasmvnc/.af-version", probe_start)
        probe_block = source[probe_start:probe_end]
        emit_start = source.index("if declare -F af_emit_readiness_record", probe_end)
        emit_end = source.index("fi\n", emit_start) + 3
        emit_block = source[emit_start:emit_end]
        emit_helper = common_functions("af_emit_readiness_record")

        s_401, p_401 = _start_server(401)
        s_503, p_503 = _start_server(503)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                fake_bin = tmp_path / "bin"
                fake_bin.mkdir()
                sc = fake_bin / "systemctl"
                sc.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
                sc.chmod(0o755)
                sleep_shim = fake_bin / "sleep"
                sleep_shim.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
                sleep_shim.chmod(0o755)
                env = {
                    **os.environ,
                    "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                    "AF_EMIT_READINESS_RECORD": "1",
                }
                base_script = (
                    "set -euo pipefail\n"
                    "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
                    f"{emit_helper}\n"
                    f"{probe_block}\n"
                    f"{emit_block}\n"
                )

                res_ok = subprocess.run(
                    ["bash", "-c", f"APP_PORT={p_401}\n{base_script}"],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=15,
                )
                self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
                self.assertEqual(
                    _parse_probe_records(res_ok.stderr),
                    [
                        {
                            "unit": "af-kasmvnc.service",
                            "url": f"http://127.0.0.1:{p_401}/",
                            "accept_auth": True,
                            "accept_409": False,
                        }
                    ],
                )

                res_fail = subprocess.run(
                    ["bash", "-c", f"APP_PORT={p_503}\n{base_script}"],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=15,
                )
                self.assertNotEqual(res_fail.returncode, 0)
                self.assertEqual(_parse_probe_records(res_fail.stdout + res_fail.stderr), [])
        finally:
            for s in (s_401, s_503):
                s.shutdown()
                s.server_close()

    def test_local_http_installers_never_emit_records_on_failure(self):
        failure_modes = (
            ("audiobookshelf", "bootstrap-python"),
            ("invidious", "readiness"),
            ("jellyseerr", "readiness"),
            ("kasmvnc", "service"),
            ("maintainerr", "readiness"),
            ("mcvnc", "service"),
            ("palate", "readiness"),
            ("piped", "readiness"),
            ("thelounge", "readiness"),
        )
        for app, failure in failure_modes:
            with self.subTest(app=app, failure=failure), InstallerFixture(app) as fixture:
                res = fixture.run(
                    "install",
                    AF_FIXTURE_FAILURE=failure,
                    AF_EMIT_READINESS_RECORD="1",
                )
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])

    def test_systemd_only_installers_emit_no_http_probe_records(self):
        for app in self.SYSTEMD_ONLY_INSTALLERS:
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                res = fixture.run("install", AF_EMIT_READINESS_RECORD="1")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])


if __name__ == "__main__":
    unittest.main()
