"""Focused regressions for Dispatcharr, Paperless-ngx, and Calibre-Web HTTP readiness."""

import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest

from tests.installer_test_helpers import common_functions, replace_paths_once
from tests.test_marketplace_catalog_lifecycle_matrix import InstallerFixture


ROOT = Path(__file__).resolve().parents[1]
AUTOMATION_CONFIG = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
INSTALL_DIR = ROOT / "packages/package/install"


def _parse_probe_records(text: str):
    return [
        json.loads(line.split("=", 1)[1])
        for line in text.splitlines()
        if line.strip().startswith("__AF_READINESS_PROBE__=")
    ]


def _extract_block(path: Path, start_marker: str, end_marker: str | None = None) -> str:
    source = path.read_text(encoding="utf-8")
    start = source.index(start_marker)
    if end_marker is None:
        return source[start:]
    end = source.index(end_marker, start)
    return source[start:end]


def _generate_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    cert = directory / "test.crt"
    key = directory / "test.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return cert, key


class _RecordingHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_cls, family=socket.AF_INET):
        self.address_family = family
        super().__init__(server_address, handler_cls)


def _start_local_server(
    *,
    bind_addr: str = "127.0.0.1",
    family: int = socket.AF_INET,
    status_fn=None,
    headers_fn=None,
    tls_pair: tuple[Path, Path] | None = None,
):
    recorded = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            recorded.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "host": self.headers.get("Host", ""),
                    "authorization": self.headers.get("Authorization"),
                }
            )
            code = status_fn(self) if status_fn else 200
            extra = headers_fn(self) if headers_fn else {}
            self.send_response(code)
            for k, v in extra.items():
                self.send_header(k, v)
            body = b'{"version":"0.34.1"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = _RecordingHTTPServer((bind_addr, 0), Handler, family=family)
    if tls_pair is not None:
        cert, key = tls_pair
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1], recorded


def _ipv6_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
            return True
    except OSError:
        return False


def _make_systemctl_and_sleep(bin_dir: Path, inactive_units: set[str] | None = None) -> None:
    inactive = sorted(inactive_units or set())
    bin_dir.mkdir(parents=True, exist_ok=True)
    inactive_list = " ".join(f'"{u}"' for u in inactive)
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        f"""#!/bin/bash
if [[ "${{1:-}}" == "is-active" ]]; then
    unit="${{@: -1}}"
    unit="${{unit%.service}}"
    for dead in {inactive_list}; do
        if [[ "$unit" == "${{dead%.service}}" ]]; then
            exit 3
        fi
    done
    exit 0
fi
exit 0
""",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    sleep_bin = bin_dir / "sleep"
    sleep_bin.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    sleep_bin.chmod(0o755)


def _make_curl_sentinel(bin_dir: Path, log_file: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    curl_bin = bin_dir / "curl"
    curl_bin.write_text(
        f"""#!/bin/bash
printf '%s\\n' "$*" >> "{log_file}"
exit 99
""",
        encoding="utf-8",
    )
    curl_bin.chmod(0o755)


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("curl"),
    "requires POSIX bash and curl",
)
class DispatcharrManagedReadinessTests(unittest.TestCase):
    def _run_readiness_block(
        self,
        tmp_path: Path,
        *,
        bind_host: str,
        port: int,
        emit_record: str = "1",
        inactive_units: set[str] | None = None,
        extra_env: dict[str, str] | None = None,
        block_curl_with_log: Path | None = None,
    ):
        bin_dir = tmp_path / "bin"
        _make_systemctl_and_sleep(bin_dir, inactive_units=inactive_units)
        if block_curl_with_log is not None:
            _make_curl_sentinel(bin_dir, block_curl_with_log)
        block = _extract_block(
            INSTALL_DIR / "installpackage-dispatcharr",
            'DISPATCHARR_READY_META="$(python3 -',
        )
        helpers = common_functions("af_emit_readiness_record")
        script = (
            "set -Eeuo pipefail\n"
            f'APP_NAME="dispatcharr"\n'
            f'PACKAGE_NAME="dispatcharr"\n'
            f'INSTALL_DIR="{tmp_path / "opt/dispatcharr"}"\n'
            f'LATEST_TAG="v0.34.1"\n'
            f'DISPATCHARR_BIND_HOST="{bind_host}"\n'
            f'APP_PORT="{port}"\n'
            "SUCCESS=0\n"
            "af_logged() { \"$@\" >/dev/null 2>&1; }\n"
            "log_info() { :; }\n"
            "log_warn() { printf '[LOG_WARN] %s\\n' \"$*\" >&2; }\n"
            "print_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "log_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            "report_progress() { :; }\n"
            f'queue_app_version() {{ printf "%s\\n" "$2" > "{tmp_path / "queued_version"}"; }}\n'
            f'commit_app_versions() {{ touch "{tmp_path / "committed"}"; }}\n'
            f'write_lock() {{ touch "{tmp_path / "locked"}"; }}\n'
            f"{helpers}\n"
            f"{block}\n"
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "AF_EMIT_READINESS_RECORD": emit_record,
            "AF_READINESS_ATTEMPTS": "2",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_default_path_direct_http_bypasses_proxy_does_not_follow_redirects_and_records_opt_in(self):
        trap_server, trap_port, trap_hits = _start_local_server()
        app_server, app_port, app_hits = _start_local_server(
            status_fn=lambda req: 200 if req.path == "/api/core/version/" else 404,
        )
        redir_server, redir_port, redir_hits = _start_local_server(
            status_fn=lambda req: 302 if req.path == "/api/core/version/" else 404,
            headers_fn=lambda _req: {"Location": f"http://127.0.0.1:{trap_port}/should-not-follow"},
        )
        try:
            proxy_env = {
                "HTTP_PROXY": f"http://127.0.0.1:{trap_port}",
                "http_proxy": f"http://127.0.0.1:{trap_port}",
                "ALL_PROXY": f"http://127.0.0.1:{trap_port}",
            }
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                # Silent by default
                silent = self._run_readiness_block(
                    tmp_path,
                    bind_host="127.0.0.1",
                    port=app_port,
                    emit_record="0",
                    extra_env=proxy_env,
                )
                self.assertEqual(silent.returncode, 0, silent.stderr)
                self.assertEqual(_parse_probe_records(silent.stdout + silent.stderr), [])
                self.assertTrue((tmp_path / "committed").exists())

                # Opt-in emits exact checked endpoint on stderr only
                emitted = self._run_readiness_block(
                    tmp_path,
                    bind_host="0.0.0.0",
                    port=app_port,
                    emit_record="1",
                    extra_env=proxy_env,
                )
                self.assertEqual(emitted.returncode, 0, emitted.stderr)
                self.assertEqual(_parse_probe_records(emitted.stdout), [])
                self.assertEqual(
                    _parse_probe_records(emitted.stderr),
                    [
                        {
                            "unit": "dispatcharr.service",
                            "url": f"http://127.0.0.1:{app_port}/api/core/version/",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
                self.assertGreaterEqual(len(app_hits), 2)
                self.assertTrue(all(h["path"] == "/api/core/version/" for h in app_hits))
                self.assertTrue(all(h["authorization"] is None for h in app_hits))

                # 302 redirect is accepted without following Location
                redir_res = self._run_readiness_block(
                    tmp_path,
                    bind_host="127.0.0.1",
                    port=redir_port,
                    emit_record="1",
                    extra_env=proxy_env,
                )
                self.assertEqual(redir_res.returncode, 0, redir_res.stderr)
                self.assertEqual(len(redir_hits), 1)
                self.assertEqual(trap_hits, [], "Probe must never use proxy or follow redirects")
        finally:
            for srv in (trap_server, app_server, redir_server):
                srv.shutdown()
                srv.server_close()

    def test_hard_http_failure_and_inactive_companion_abort_commit_and_emit_nothing(self):
        fail_server, fail_port, _ = _start_local_server(status_fn=lambda _req: 503)
        ok_server, ok_port, _ = _start_local_server(status_fn=lambda _req: 200)
        try:
            for label, port, inactive in (
                ("http-503-with-active-units", fail_port, set()),
                ("inactive-celery-companion", ok_port, {"dispatcharr-celery"}),
                ("inactive-celerybeat-companion", ok_port, {"dispatcharr-celerybeat"}),
            ):
                with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    res = self._run_readiness_block(
                        tmp_path,
                        bind_host="127.0.0.1",
                        port=port,
                        emit_record="1",
                        inactive_units=inactive,
                    )
                    self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertFalse((tmp_path / "committed").exists())
                    self.assertFalse((tmp_path / "locked").exists())
                    self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
        finally:
            for srv in (fail_server, ok_server):
                srv.shutdown()
                srv.server_close()

    def test_retained_ipv6_and_secondary_loopback_addresses_probe_and_emit_exact_urls(self):
        v4_alt, p_v4_alt, hits_v4 = _start_local_server(bind_addr="127.0.0.2")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                res = self._run_readiness_block(Path(tmp), bind_host="127.0.0.2", port=p_v4_alt)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(len(hits_v4), 1)
                self.assertEqual(
                    _parse_probe_records(res.stderr),
                    [
                        {
                            "unit": "dispatcharr.service",
                            "url": f"http://127.0.0.2:{p_v4_alt}/api/core/version/",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
        finally:
            v4_alt.shutdown()
            v4_alt.server_close()

        if _ipv6_loopback_available():
            v6_srv, p_v6, hits_v6 = _start_local_server(bind_addr="::1", family=socket.AF_INET6)
            try:
                for bind_host in ("::", "::1", "[::1]"):
                    with self.subTest(bind_host=bind_host), tempfile.TemporaryDirectory() as tmp:
                        res = self._run_readiness_block(Path(tmp), bind_host=bind_host, port=p_v6)
                        self.assertEqual(res.returncode, 0, res.stderr)
                        self.assertEqual(
                            _parse_probe_records(res.stderr),
                            [
                                {
                                    "unit": "dispatcharr.service",
                                    "url": f"http://[::1]:{p_v6}/api/core/version/",
                                    "accept_auth": False,
                                    "accept_409": False,
                                }
                            ],
                        )
                self.assertEqual(len(hits_v6), 3)
            finally:
                v6_srv.shutdown()
                v6_srv.server_close()

    def test_unproven_external_bind_address_surfaces_boundary_without_probing_or_emitting(self):
        for bind_host, expected_msg in (
            ("192.0.2.45", "not assigned to a local interface"),
            ("remote.example.com", "non-loopback hostname"),
        ):
            with self.subTest(bind_host=bind_host), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                curl_log = tmp_path / "curl.log"
                res = self._run_readiness_block(
                    tmp_path,
                    bind_host=bind_host,
                    port=9191,
                    emit_record="1",
                    block_curl_with_log=curl_log,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertFalse(curl_log.exists(), "Must not invoke curl for unproven external address")
                self.assertIn(expected_msg, res.stderr)
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
                self.assertTrue((tmp_path / "committed").exists())

    def test_fixture_preserves_retained_bind_and_port_and_rolls_back_on_readiness_failure(self):
        with InstallerFixture("dispatcharr") as fixture:
            fixture.file("etc/dispatcharr/dispatcharr.env", "DISPATCHARR_PORT=19222\nCUSTOM_FLAG=keep\n")
            res_retained_port = fixture.run(
                "reinstall",
                port=0,
                AF_EMIT_READINESS_RECORD="1",
            )
            self.assertEqual(res_retained_port.returncode, 0, res_retained_port.stdout + res_retained_port.stderr)
            self.assertIn("DISPATCHARR_PORT=19222", (fixture.root / "etc/dispatcharr/dispatcharr.env").read_text())
            self.assertEqual(
                _parse_probe_records(res_retained_port.stderr),
                [
                    {
                        "unit": "dispatcharr.service",
                        "url": "http://127.0.0.1:19222/api/core/version/",
                        "accept_auth": False,
                        "accept_409": False,
                    }
                ],
            )

            # Retained off-host bind address is preserved, surfaces boundary, emits no record
            fixture.file(
                "etc/systemd/system/dispatcharr.service",
                "[Service]\nExecStart=/bin/sh -ec 'exec /opt/dispatcharr/env/bin/daphne -b 192.0.2.45 -p 19222 aetherflow_asgi:application'\n",
            )
            res = fixture.run(
                "reinstall",
                port=0,
                AF_EMIT_READINESS_RECORD="1",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("daphne -b 192.0.2.45", (fixture.root / "etc/systemd/system/dispatcharr.service").read_text())
            self.assertIn("DISPATCHARR_PORT=19222", (fixture.root / "etc/dispatcharr/dispatcharr.env").read_text())
            self.assertIn("not assigned to a local interface", res.stderr)
            self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])

            # Reset to loopback and verify readiness failure rolls back cleanly without emitting
            fixture.file(
                "etc/systemd/system/dispatcharr.service",
                "[Service]\nExecStart=/bin/sh -ec 'exec /opt/dispatcharr/env/bin/daphne -b 127.0.0.1 -p 19222 aetherflow_asgi:application'\n",
            )
            sentinel = fixture.file("opt/dispatcharr/prior-code", "keep-prior\n")
            failed = fixture.run(
                "update",
                port=0,
                AF_FIXTURE_VERSION="2.2.0",
                AF_FIXTURE_FAILURE="readiness",
                AF_EMIT_READINESS_RECORD="1",
                AF_READINESS_ATTEMPTS="1",
            )
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertEqual(sentinel.read_text(), "keep-prior\n")
            self.assertEqual((fixture.root / "opt/dispatcharr/.af-version").read_text().strip(), "2.1.0")
            self.assertEqual(_parse_probe_records(failed.stdout + failed.stderr), [])

    def test_proven_local_interface_ip_in_fib_trie_is_allowed_while_absent_ip_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            proc_dir = tmp_path / "proc/net"
            proc_dir.mkdir(parents=True)
            (proc_dir / "fib_trie").write_text(
                "Local:\n"
                "  +-- 0.0.0.0/1 3 0 5\n"
                "     +-- 192.0.2.0/24 2 0 2\n"
                "        |-- 192.0.2.45\n"
                "           /32 host LOCAL\n",
                encoding="utf-8",
            )
            curl_log = tmp_path / "curl.log"
            # When fib_trie proves 192.0.2.45 is local, curl IS invoked targeting it (exits 99 in sentinel)
            res = self._run_readiness_block(
                tmp_path,
                bind_host="192.0.2.45",
                port=9191,
                emit_record="1",
                extra_env={"AF_PROC_ROOT": str(tmp_path / "proc")},
                block_curl_with_log=curl_log,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertTrue(curl_log.exists())
            self.assertIn("http://192.0.2.45:9191/api/core/version/", curl_log.read_text())
            self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("curl"),
    "requires POSIX bash and curl",
)
class PaperlessManagedReadinessTests(unittest.TestCase):
    def _run_readiness_block(
        self,
        tmp_path: Path,
        *,
        conf_text: str,
        bind_host: str,
        port: int,
        emit_record: str = "1",
        inactive_units: set[str] | None = None,
        extra_env: dict[str, str] | None = None,
        block_curl_with_log: Path | None = None,
    ):
        bin_dir = tmp_path / "bin"
        _make_systemctl_and_sleep(bin_dir, inactive_units=inactive_units)
        if block_curl_with_log is not None:
            _make_curl_sentinel(bin_dir, block_curl_with_log)
        conf_file = tmp_path / "etc/paperless.conf"
        conf_file.parent.mkdir(parents=True, exist_ok=True)
        conf_file.write_text(conf_text, encoding="utf-8")

        raw_block = _extract_block(
            INSTALL_DIR / "installpackage-paperless-ngx",
            'PAPERLESS_READY_META="$(safe_config_python /etc/paperless.conf',
        )
        block = replace_paths_once(raw_block, [("/etc/paperless.conf", str(conf_file))])
        helpers = common_functions("safe_config_python", "af_emit_readiness_record")
        script = (
            "set -euo pipefail\n"
            f'PACKAGE_NAME="paperless-ngx"\n'
            f'PAPERLESS_BIND_HOST="{bind_host}"\n'
            f'APP_PORT="{port}"\n'
            f'BACKUP_DIR="{tmp_path / "backup"}"\n'
            f'mkdir -p "{tmp_path / "backup"}"\n'
            "SUCCESS=0\n"
            "af_logged() { \"$@\" >/dev/null 2>&1; }\n"
            "log_info() { :; }\n"
            "log_warn() { printf '[LOG_WARN] %s\\n' \"$*\" >&2; }\n"
            "print_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "log_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            "report_progress() { :; }\n"
            f'commit_app_versions() {{ touch "{tmp_path / "committed"}"; }}\n'
            f'write_lock() {{ touch "{tmp_path / "locked"}"; }}\n'
            f"{helpers}\n"
            f"{block}\n"
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "AF_EMIT_READINESS_RECORD": emit_record,
            "AF_READINESS_ATTEMPTS": "2",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_default_path_and_non_redirect_and_proxy_bypass(self):
        trap_srv, trap_port, trap_hits = _start_local_server()
        app_srv, app_port, app_hits = _start_local_server(
            status_fn=lambda req: 200 if req.path == "/accounts/login/" else 404,
        )
        sso_srv, sso_port, sso_hits = _start_local_server(
            status_fn=lambda req: 302 if req.path == "/accounts/login/" else 404,
            headers_fn=lambda _req: {"Location": f"http://127.0.0.1:{trap_port}/oidc-idp"},
        )
        try:
            proxy_env = {
                "HTTP_PROXY": f"http://127.0.0.1:{trap_port}",
                "ALL_PROXY": f"http://127.0.0.1:{trap_port}",
            }
            default_conf = (
                "PAPERLESS_BIND_ADDR=127.0.0.1\n"
                "PAPERLESS_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]\n"
                f"PAPERLESS_URL=http://localhost:{app_port}\n"
            )
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                silent = self._run_readiness_block(
                    tmp_path, conf_text=default_conf, bind_host="127.0.0.1", port=app_port,
                    emit_record="0", extra_env=proxy_env,
                )
                self.assertEqual(silent.returncode, 0, silent.stderr)
                self.assertEqual(_parse_probe_records(silent.stdout + silent.stderr), [])

                emitted = self._run_readiness_block(
                    tmp_path, conf_text=default_conf, bind_host="127.0.0.1", port=app_port,
                    emit_record="1", extra_env=proxy_env,
                )
                self.assertEqual(emitted.returncode, 0, emitted.stderr)
                self.assertEqual(_parse_probe_records(emitted.stdout), [])
                self.assertEqual(
                    _parse_probe_records(emitted.stderr),
                    [
                        {
                            "unit": "paperless-webserver.service",
                            "url": f"http://127.0.0.1:{app_port}/accounts/login/",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
                self.assertTrue(all(h["path"] == "/accounts/login/" for h in app_hits))

                # SSO/auto-login 302 redirect succeeds without following redirect
                sso_res = self._run_readiness_block(
                    tmp_path, conf_text=default_conf, bind_host="127.0.0.1", port=sso_port,
                    emit_record="1", extra_env=proxy_env,
                )
                self.assertEqual(sso_res.returncode, 0, sso_res.stderr)
                self.assertEqual(len(sso_hits), 1)
                self.assertEqual(trap_hits, [], "Must not follow SSO redirect or use proxy")
        finally:
            for srv in (trap_srv, app_srv, sso_srv):
                srv.shutdown()
                srv.server_close()

    def test_retained_allowed_hosts_switches_to_localhost_and_passes_host_validation(self):
        # Simulates Django DisallowedHost: rejects 127.0.0.1, accepts localhost.
        def django_host_status(req):
            host = req.headers.get("Host", "").split(":", 1)[0].lower()
            if host != "localhost":
                return 400
            return 200 if req.path == "/accounts/login/" else 404

        srv, port, hits = _start_local_server(status_fn=django_host_status)
        try:
            for label, conf_text in (
                ("allowed-hosts-domain-only", "PAPERLESS_BIND_ADDR=127.0.0.1\nPAPERLESS_ALLOWED_HOSTS=docs.example.com\n"),
                ("paperless-url-only", "PAPERLESS_BIND_ADDR=127.0.0.1\nPAPERLESS_URL=https://docs.example.com\n"),
                ("force-script-name-no-gunicorn-script-name", "PAPERLESS_BIND_ADDR=127.0.0.1\nPAPERLESS_ALLOWED_HOSTS=docs.example.com\nPAPERLESS_FORCE_SCRIPT_NAME=/paperless\n"),
            ):
                with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                    res = self._run_readiness_block(
                        Path(tmp), conf_text=conf_text, bind_host="127.0.0.1", port=port, emit_record="1",
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertEqual(
                        _parse_probe_records(res.stderr),
                        [
                            {
                                "unit": "paperless-webserver.service",
                                "url": f"http://localhost:{port}/accounts/login/",
                                "accept_auth": False,
                                "accept_409": False,
                            }
                        ],
                    )
            self.assertEqual(len(hits), 3)
            self.assertTrue(all(h["host"].startswith("localhost") for h in hits))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_retained_gunicorn_script_name_is_prepended_to_probe_and_record(self):
        srv, port, hits = _start_local_server(
            status_fn=lambda req: 200 if req.path == "/paperless/accounts/login/" else 400,
        )
        try:
            with tempfile.TemporaryDirectory() as tmp:
                conf = "PAPERLESS_BIND_ADDR=127.0.0.1\nPAPERLESS_ALLOWED_HOSTS=localhost,127.0.0.1\nSCRIPT_NAME=/paperless\n"
                res = self._run_readiness_block(
                    Path(tmp), conf_text=conf, bind_host="127.0.0.1", port=port, emit_record="1",
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(hits[0]["path"], "/paperless/accounts/login/")
                self.assertEqual(
                    _parse_probe_records(res.stderr),
                    [
                        {
                            "unit": "paperless-webserver.service",
                            "url": f"http://127.0.0.1:{port}/paperless/accounts/login/",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
        finally:
            srv.shutdown()
            srv.server_close()

    def test_secondary_loopback_excluded_from_allowed_hosts_checks_locally_with_host_header_and_omits_record(self):
        def host_enforcing_status(req):
            host = req.headers.get("Host", "").split(":", 1)[0].lower()
            return 200 if host == "localhost" and req.path == "/accounts/login/" else 400

        srv, port, hits = _start_local_server(bind_addr="127.0.0.2", status_fn=host_enforcing_status)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                conf = "PAPERLESS_BIND_ADDR=127.0.0.2\nPAPERLESS_ALLOWED_HOSTS=docs.example.com\n"
                res = self._run_readiness_block(
                    Path(tmp), conf_text=conf, bind_host="127.0.0.2", port=port, emit_record="1",
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["host"], "localhost")
                self.assertIn("Host: localhost", res.stderr)
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
        finally:
            srv.shutdown()
            srv.server_close()

    @unittest.skipUnless(shutil.which("openssl"), "requires openssl")
    def test_retained_gunicorn_tls_probes_loopback_https_and_records_https_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert, key = _generate_self_signed_cert(tmp_path)
            srv, port, hits = _start_local_server(
                status_fn=lambda req: 200 if req.path == "/accounts/login/" else 404,
                tls_pair=(cert, key),
            )
            try:
                conf = (
                    "PAPERLESS_BIND_ADDR=127.0.0.1\n"
                    "PAPERLESS_ALLOWED_HOSTS=localhost,127.0.0.1\n"
                    f'GUNICORN_CMD_ARGS="--certfile {cert} --keyfile {key}"\n'
                )
                res = self._run_readiness_block(
                    tmp_path, conf_text=conf, bind_host="127.0.0.1", port=port, emit_record="1",
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(len(hits), 1)
                self.assertEqual(
                    _parse_probe_records(res.stderr),
                    [
                        {
                            "unit": "paperless-webserver.service",
                            "url": f"https://127.0.0.1:{port}/accounts/login/",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
            finally:
                srv.shutdown()
                srv.server_close()

    def test_unproven_external_bind_or_custom_gunicorn_config_surfaces_boundary_without_probing(self):
        cases = (
            ("off-host-ip", "192.0.2.45", "PAPERLESS_BIND_ADDR=192.0.2.45\n", "not assigned to a local interface"),
            ("external-hostname", "paperless.remote.example", "PAPERLESS_BIND_ADDR=paperless.remote.example\n", "non-loopback hostname"),
            ("custom-gunicorn-config", "127.0.0.1", "PAPERLESS_BIND_ADDR=127.0.0.1\nGUNICORN_CMD_ARGS=--config /etc/gunicorn.py\n", "overrides Gunicorn listener/config"),
        )
        for label, bind_host, conf_text, expected_msg in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                curl_log = tmp_path / "curl.log"
                res = self._run_readiness_block(
                    tmp_path,
                    conf_text=conf_text,
                    bind_host=bind_host,
                    port=8010,
                    emit_record="1",
                    block_curl_with_log=curl_log,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertFalse(curl_log.exists(), "Must not probe unproven retained setup")
                self.assertIn(expected_msg, res.stderr)
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
                self.assertTrue((tmp_path / "committed").exists())

    def test_hard_http_failure_and_inactive_companions_fail_without_committing_or_emitting(self):
        srv_500, p_500, _ = _start_local_server(status_fn=lambda _req: 500)
        srv_400, p_400, _ = _start_local_server(status_fn=lambda _req: 400)
        srv_200, p_200, _ = _start_local_server(status_fn=lambda _req: 200)
        conf = "PAPERLESS_BIND_ADDR=127.0.0.1\nPAPERLESS_ALLOWED_HOSTS=localhost,127.0.0.1\n"
        try:
            for label, port, inactive in (
                ("http-500-active-units", p_500, set()),
                ("http-400-disallowed-host", p_400, set()),
                ("inactive-worker", p_200, {"paperless-worker"}),
                ("inactive-scheduler", p_200, {"paperless-scheduler"}),
            ):
                with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    res = self._run_readiness_block(
                        tmp_path, conf_text=conf, bind_host="127.0.0.1", port=port,
                        emit_record="1", inactive_units=inactive,
                    )
                    self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertFalse((tmp_path / "committed").exists())
                    self.assertFalse((tmp_path / "locked").exists())
                    self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
        finally:
            for srv in (srv_500, srv_400, srv_200):
                srv.shutdown()
                srv.server_close()

    def test_fixture_failed_readiness_rolls_back_paperless_state_and_emits_no_record(self):
        with InstallerFixture("paperless-ngx") as fixture:
            ok = fixture.run("install", port=18011, AF_EMIT_READINESS_RECORD="1")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertEqual(
                _parse_probe_records(ok.stderr),
                [
                    {
                        "unit": "paperless-webserver.service",
                        "url": "http://127.0.0.1:18011/accounts/login/",
                        "accept_auth": False,
                        "accept_409": False,
                    }
                ],
            )
            sentinel = fixture.file("opt/paperless/prior-release", "keep-prior\n")
            failed = fixture.run(
                "update",
                port=18012,
                AF_FIXTURE_VERSION="2.2.0",
                AF_FIXTURE_FAILURE="readiness",
                AF_EMIT_READINESS_RECORD="1",
                AF_READINESS_ATTEMPTS="1",
            )
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertEqual(sentinel.read_text(), "keep-prior\n")
            self.assertEqual((fixture.root / "opt/paperless/.af-version").read_text().strip(), "2.1.0")
            self.assertIn("PAPERLESS_PORT=18011", (fixture.root / "etc/paperless.conf").read_text())
            self.assertEqual(_parse_probe_records(failed.stdout + failed.stderr), [])


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("curl"),
    "requires POSIX bash and curl",
)
class CalibreWebManagedReadinessTests(unittest.TestCase):
    def _run_readiness_block(
        self,
        tmp_path: Path,
        *,
        app_port: int,
        prior_unit_text: str | None = None,
        db_settings: dict | None = None,
        emit_record: str = "1",
        inactive_units: set[str] | None = None,
        extra_env: dict[str, str] | None = None,
        block_curl_with_log: Path | None = None,
    ):
        bin_dir = tmp_path / "bin"
        _make_systemctl_and_sleep(bin_dir, inactive_units=inactive_units)
        if block_curl_with_log is not None:
            _make_curl_sentinel(bin_dir, block_curl_with_log)

        unit_file = tmp_path / "etc/systemd/system/calibreweb.service"
        unit_file.parent.mkdir(parents=True, exist_ok=True)
        if prior_unit_text is not None:
            unit_file.write_text(prior_unit_text, encoding="utf-8")

        app_db = tmp_path / "var/lib/calibre-web/app.db"
        app_db.parent.mkdir(parents=True, exist_ok=True)
        if db_settings is not None:
            with contextlib.closing(sqlite3.connect(str(app_db))) as conn, conn:
                cols = list(db_settings.keys())
                col_defs = ", ".join(
                    f"{c} INTEGER" if c == "config_port" else f"{c} TEXT" for c in cols
                )
                conn.execute(f"CREATE TABLE settings ({col_defs})")
                placeholders = ", ".join("?" for _ in cols)
                conn.execute(
                    f"INSERT INTO settings ({', '.join(cols)}) VALUES ({placeholders})",
                    [db_settings[c] for c in cols],
                )

        work_dir = tmp_path / "opt/calibre-web"
        work_dir.mkdir(parents=True, exist_ok=True)

        raw_block = _extract_block(
            INSTALL_DIR / "installpackage-calibreweb",
            'CALIBRE_BIND_HOST=""',
        )
        block = replace_paths_once(
            raw_block,
            [
                ("/etc/systemd/system/calibreweb.service", str(unit_file)),
                ("/var/lib/calibre-web/app.db", str(app_db)),
                ("/opt/calibre-web", str(work_dir)),
            ],
        )
        helpers = common_functions("safe_config_python", "af_emit_readiness_record")
        script = (
            "set -euo pipefail\n"
            f'PACKAGE_NAME="calibreweb"\n'
            f'APP_PORT="{app_port}"\n'
            f'BACKUP_DIR="{tmp_path / "backup"}"\n'
            f'mkdir -p "{tmp_path / "backup"}"\n'
            "UNIT_WRITTEN=0\n"
            "SUCCESS=0\n"
            "af_logged() { \"$@\" >/dev/null 2>&1; }\n"
            "log_info() { :; }\n"
            "log_warn() { printf '[LOG_WARN] %s\\n' \"$*\" >&2; }\n"
            "print_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "log_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            "report_progress() { :; }\n"
            f'commit_app_versions() {{ touch "{tmp_path / "committed"}"; }}\n'
            f'write_lock() {{ touch "{tmp_path / "locked"}"; }}\n'
            f"{helpers}\n"
            f"{block}\n"
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "AF_EMIT_READINESS_RECORD": emit_record,
            "AF_READINESS_ATTEMPTS": "2",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_default_http_probe_bypasses_proxy_does_not_follow_redirects_and_records_opt_in(self):
        trap_srv, trap_port, trap_hits = _start_local_server()
        app_srv, app_port, app_hits = _start_local_server(
            status_fn=lambda req: 200 if req.path == "/login" else 404,
        )
        redir_srv, redir_port, redir_hits = _start_local_server(
            status_fn=lambda req: 302 if req.path == "/login" else 404,
            headers_fn=lambda _req: {"Location": f"http://127.0.0.1:{trap_port}/never-follow"},
        )
        try:
            proxy_env = {
                "HTTP_PROXY": f"http://127.0.0.1:{trap_port}",
                "ALL_PROXY": f"http://127.0.0.1:{trap_port}",
            }
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                silent = self._run_readiness_block(
                    tmp_path, app_port=app_port, emit_record="0", extra_env=proxy_env,
                )
                self.assertEqual(silent.returncode, 0, silent.stderr)
                self.assertEqual(_parse_probe_records(silent.stdout + silent.stderr), [])

                emitted = self._run_readiness_block(
                    tmp_path, app_port=app_port, emit_record="1", extra_env=proxy_env,
                )
                self.assertEqual(emitted.returncode, 0, emitted.stderr)
                self.assertEqual(_parse_probe_records(emitted.stdout), [])
                self.assertEqual(
                    _parse_probe_records(emitted.stderr),
                    [
                        {
                            "unit": "calibreweb.service",
                            "url": f"http://127.0.0.1:{app_port}/login",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
                self.assertTrue(all(h["path"] == "/login" for h in app_hits))

                redir_res = self._run_readiness_block(
                    tmp_path, app_port=redir_port, emit_record="1", extra_env=proxy_env,
                )
                self.assertEqual(redir_res.returncode, 0, redir_res.stderr)
                self.assertEqual(len(redir_hits), 1)
                self.assertEqual(trap_hits, [])
        finally:
            for srv in (trap_srv, app_srv, redir_srv):
                srv.shutdown()
                srv.server_close()

    @unittest.skipUnless(shutil.which("openssl"), "requires openssl")
    def test_retained_db_port_and_tls_cert_key_probe_https_and_missing_cert_falls_back_to_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert, key = _generate_self_signed_cert(tmp_path)
            tls_srv, tls_port, tls_hits = _start_local_server(
                status_fn=lambda req: 200 if req.path == "/login" else 404,
                tls_pair=(cert, key),
            )
            http_srv, http_port, http_hits = _start_local_server(
                status_fn=lambda req: 200 if req.path == "/login" else 404,
            )
            try:
                # Retained config_port + valid certfile/keyfile in app.db even when APP_PORT defaults to 8083
                tls_res = self._run_readiness_block(
                    tmp_path / "tls-case",
                    app_port=8083,
                    db_settings={
                        "config_port": tls_port,
                        "config_certfile": str(cert),
                        "config_keyfile": str(key),
                    },
                    emit_record="1",
                )
                self.assertEqual(tls_res.returncode, 0, tls_res.stderr)
                self.assertEqual(len(tls_hits), 1)
                self.assertEqual(
                    _parse_probe_records(tls_res.stderr),
                    [
                        {
                            "unit": "calibreweb.service",
                            "url": f"https://127.0.0.1:{tls_port}/login",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )

                # Missing cert file causes Calibre-Web to ignore SSL and serve plain HTTP
                fallback_res = self._run_readiness_block(
                    tmp_path / "missing-cert-case",
                    app_port=8083,
                    db_settings={
                        "config_port": http_port,
                        "config_certfile": str(tmp_path / "does-not-exist.crt"),
                        "config_keyfile": str(key),
                    },
                    emit_record="1",
                )
                self.assertEqual(fallback_res.returncode, 0, fallback_res.stderr)
                self.assertEqual(len(http_hits), 1)
                self.assertEqual(
                    _parse_probe_records(fallback_res.stderr),
                    [
                        {
                            "unit": "calibreweb.service",
                            "url": f"http://127.0.0.1:{http_port}/login",
                            "accept_auth": False,
                            "accept_409": False,
                        }
                    ],
                )
            finally:
                for srv in (tls_srv, http_srv):
                    srv.shutdown()
                    srv.server_close()

    def test_ipv6_fallback_and_retained_bind_ip_preservation_and_external_boundary(self):
        if _ipv6_loopback_available():
            v6_srv, v6_port, v6_hits = _start_local_server(
                bind_addr="::1",
                family=socket.AF_INET6,
                status_fn=lambda req: 200 if req.path == "/login" else 404,
            )
            try:
                # Default (no -i): 127.0.0.1 refuses connect (rc=7) -> falls back to [::1] and emits [::1]
                with tempfile.TemporaryDirectory() as tmp:
                    fb_res = self._run_readiness_block(
                        Path(tmp), app_port=v6_port, emit_record="1",
                    )
                    self.assertEqual(fb_res.returncode, 0, fb_res.stderr)
                    self.assertEqual(
                        _parse_probe_records(fb_res.stderr),
                        [
                            {
                                "unit": "calibreweb.service",
                                "url": f"http://[::1]:{v6_port}/login",
                                "accept_auth": False,
                                "accept_409": False,
                            }
                        ],
                    )
                # Retained -i ::1 preserved in unit file and probed directly
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    prior = "[Service]\nExecStart=/opt/calibre-web/.venv/bin/python /opt/calibre-web/cps.py -p /var/lib/calibre-web/app.db -g /var/lib/calibre-web/gdrive.db -i ::1\n"
                    res = self._run_readiness_block(
                        tmp_path, app_port=v6_port, prior_unit_text=prior, emit_record="1",
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertIn("-i ::1", (tmp_path / "etc/systemd/system/calibreweb.service").read_text())
                    self.assertEqual(
                        _parse_probe_records(res.stderr),
                        [
                            {
                                "unit": "calibreweb.service",
                                "url": f"http://[::1]:{v6_port}/login",
                                "accept_auth": False,
                                "accept_409": False,
                            }
                        ],
                    )
                self.assertEqual(len(v6_hits), 2)
            finally:
                v6_srv.shutdown()
                v6_srv.server_close()

        # Unproven off-host retained -i 192.0.2.45: preserved in unit, boundary surfaced, no curl, no record
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            curl_log = tmp_path / "curl.log"
            prior = "[Service]\nExecStart=/opt/calibre-web/.venv/bin/python /opt/calibre-web/cps.py -p /var/lib/calibre-web/app.db -g /var/lib/calibre-web/gdrive.db -i 192.0.2.45\n"
            res = self._run_readiness_block(
                tmp_path,
                app_port=8083,
                prior_unit_text=prior,
                emit_record="1",
                block_curl_with_log=curl_log,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(curl_log.exists())
            self.assertIn("-i 192.0.2.45", (tmp_path / "etc/systemd/system/calibreweb.service").read_text())
            self.assertIn("not assigned to a local interface", res.stderr)
            self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
            self.assertTrue((tmp_path / "committed").exists())

    def test_hard_http_failure_with_active_unit_aborts_commit_without_emitting(self):
        fail_srv, fail_port, _ = _start_local_server(status_fn=lambda _req: 503)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                res = self._run_readiness_block(
                    tmp_path, app_port=fail_port, emit_record="1",
                )
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse((tmp_path / "committed").exists())
                self.assertFalse((tmp_path / "locked").exists())
                self.assertEqual(_parse_probe_records(res.stdout + res.stderr), [])
        finally:
            fail_srv.shutdown()
            fail_srv.server_close()

    def test_fixture_failed_readiness_rolls_back_calibreweb_state_and_emits_no_record(self):
        with InstallerFixture("calibreweb") as fixture:
            ok = fixture.run("install", port=8083, AF_EMIT_READINESS_RECORD="1")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertEqual(
                _parse_probe_records(ok.stderr),
                [
                    {
                        "unit": "calibreweb.service",
                        "url": "http://127.0.0.1:8083/login",
                        "accept_auth": False,
                        "accept_409": False,
                    }
                ],
            )
            sentinel = fixture.file("opt/calibre-web/prior-release", "keep-prior\n")
            failed = fixture.run(
                "update",
                port=8083,
                AF_FIXTURE_VERSION="2.2.0",
                AF_FIXTURE_FAILURE="readiness",
                AF_EMIT_READINESS_RECORD="1",
                AF_READINESS_ATTEMPTS="1",
            )
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertEqual(sentinel.read_text(), "keep-prior\n")
            self.assertEqual((fixture.root / "opt/calibre-web/.af-version").read_text().strip(), "2.1.0")
            self.assertEqual(_parse_probe_records(failed.stdout + failed.stderr), [])


if __name__ == "__main__":
    unittest.main()
