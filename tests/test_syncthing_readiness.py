#!/usr/bin/env python3
"""Focused regressions for Syncthing modern and legacy (< v1.22.0) HTTP readiness checks."""

import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from installer_test_helpers import common_functions


class _LocalSyncthingStub:
    def __init__(self, handler_fn):
        self.requests: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.requests.append(self.path)
                status, headers, body = handler_fn(self.path)
                self.send_response(status)
                for key, val in headers.items():
                    self.send_header(key, val)
                payload = body.encode("utf-8") if isinstance(body, str) else body
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._server.server_port)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class SyncthingReadinessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-syncthing-ready-")
        self.root = Path(self._tmp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.helpers_path = self.root / "helpers.sh"
        extracted = common_functions(
            "resolve_app_readiness_path",
            "af_emit_readiness_record",
            "af_syncthing_listener_owned_by_unit",
            "wait_for_service_ready",
        )
        self.helpers_path.write_text(
            "set -euo pipefail\n"
            'print_error() { printf "ERROR: %s\\n" "$*" >&2; }\n'
            + extracted
            + "\n",
            encoding="utf-8",
        )
        systemctl_shim = self.bin_dir / "systemctl"
        systemctl_shim.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "op = args[0] if args else ''\n"
            "active = os.environ.get('AF_ST_ACTIVE', '1') == '1'\n"
            "main_pid = os.environ.get('AF_ST_MAIN_PID', '0')\n"
            "if op == 'is-active':\n"
            "    if '--quiet' not in args:\n"
            "        print('active' if active else 'inactive')\n"
            "    sys.exit(0 if active else 3)\n"
            "if op == 'show':\n"
            "    print(f'MainPID={main_pid}')\n"
            "    print('ControlGroup=')\n"
            "    sys.exit(0)\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        systemctl_shim.chmod(0o755)

    def tearDown(self):
        self._tmp.cleanup()

    def _run_wait(
        self,
        port: int,
        *,
        active: bool = True,
        main_pid: int | None = None,
        attempts: int = 1,
        emit_record: bool = True,
    ) -> subprocess.CompletedProcess:
        pid_val = os.getpid() if main_pid is None else main_pid
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}:/usr/bin:/bin",
            "AF_ST_ACTIVE": "1" if active else "0",
            "AF_ST_MAIN_PID": str(pid_val),
            "AF_EMIT_READINESS_RECORD": "1" if emit_record else "0",
        }
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'source "{self.helpers_path}" && wait_for_service_ready syncthing.service {port} / {attempts}',
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def _parse_probe_record(self, stderr: str) -> dict | None:
        prefix = "__AF_READINESS_PROBE__="
        for line in stderr.splitlines():
            if line.startswith(prefix):
                return json.loads(line[len(prefix) :])
        return None

    def test_modern_syncthing_health_endpoint_200_succeeds_without_fallback(self):
        def handler(path: str):
            if path == "/rest/noauth/health":
                return 200, {"Content-Type": "application/json"}, '{"status":"OK"}'
            return 500, {}, "unexpected fallback"

        with _LocalSyncthingStub(handler) as srv:
            res = self._run_wait(srv.port)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(srv.requests, ["/rest/noauth/health"])
            record = self._parse_probe_record(res.stderr)
            self.assertEqual(
                record,
                {
                    "unit": "syncthing.service",
                    "url": f"http://127.0.0.1:{srv.port}/rest/noauth/health",
                    "accept_auth": False,
                    "accept_409": False,
                },
            )

    def test_legacy_syncthing_404_on_health_falls_back_to_root_for_200_401_302(self):
        for status, expect_auth in ((200, False), (401, True), (302, False)):
            with self.subTest(root_status=status):
                def handler(path: str, code: int = status):
                    if path == "/rest/noauth/health":
                        return 404, {"Content-Type": "text/plain"}, "404 page not found"
                    if path == "/":
                        headers = {"Location": "/login"} if code == 302 else {}
                        return code, headers, "Syncthing"
                    return 404, {}, "not found"

                with _LocalSyncthingStub(handler) as srv:
                    res = self._run_wait(srv.port, active=True, main_pid=os.getpid())
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertIn("/rest/noauth/health", srv.requests)
                    self.assertIn("/", srv.requests)
                    record = self._parse_probe_record(res.stderr)
                    self.assertEqual(
                        record,
                        {
                            "unit": "syncthing.service",
                            "url": f"http://127.0.0.1:{srv.port}/",
                            "accept_auth": expect_auth,
                            "accept_409": False,
                        },
                    )

    def test_rejects_500_inactive_unit_unbound_port_and_unowned_listener(self):
        # 1. Primary 500 must NOT fall back to /
        with self.subTest(case="primary-500"):
            def handler(path: str):
                if path == "/rest/noauth/health":
                    return 500, {}, "Internal Server Error"
                return 200, {}, "should not be probed"

            with _LocalSyncthingStub(handler) as srv:
                res = self._run_wait(srv.port)
                self.assertNotEqual(res.returncode, 0)
                self.assertNotIn("/", srv.requests)

        # 2. Primary 404 + fallback / returning 500 must fail
        with self.subTest(case="fallback-500"):
            def handler(path: str):
                if path == "/rest/noauth/health":
                    return 404, {}, "Not Found"
                return 500, {}, "Broken"

            with _LocalSyncthingStub(handler) as srv:
                res = self._run_wait(srv.port)
                self.assertNotEqual(res.returncode, 0)

        # 3. Inactive systemd unit must fail even when listener answers 200/401
        with self.subTest(case="inactive-unit"):
            def handler(path: str):
                return (404, {}, "404") if path == "/rest/noauth/health" else (200, {}, "ok")

            with _LocalSyncthingStub(handler) as srv:
                res = self._run_wait(srv.port, active=False)
                self.assertNotEqual(res.returncode, 0)
                self.assertEqual(srv.requests, [])

        # 4. Connection refused (unbound port) must fail
        with self.subTest(case="connection-refused"):
            res = self._run_wait(_free_port())
            self.assertNotEqual(res.returncode, 0)

        # 5. Listener owned by a DIFFERENT process (not syncthing.service MainPID) must fail closed
        with self.subTest(case="foreign-listener-owner"):
            sleep_bin = shutil.which("sleep") or "/bin/sleep"
            decoy = subprocess.Popen([sleep_bin, "30"])
            try:
                def handler(path: str):
                    return (404, {}, "404") if path == "/rest/noauth/health" else (200, {}, "foreign")

                with _LocalSyncthingStub(handler) as srv:
                    res = self._run_wait(srv.port, active=True, main_pid=decoy.pid)
                    self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertNotIn("/", srv.requests)
            finally:
                decoy.terminate()
                decoy.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
