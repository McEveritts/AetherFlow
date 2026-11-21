import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

from tests.installer_test_helpers import common_functions


ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
