#!/usr/bin/env python3
"""Focused fixture regressions for shared Apache PHP application readiness and rollback."""

import base64
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from installer_test_helpers import common_functions


MOCK_HOST = r'''#!/usr/bin/python3 -B
import json, os, pathlib, shutil, subprocess, sys

root = pathlib.Path(os.environ["AF_TEST_ROOT"])
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([command, *args]) + "\n")

if command == "systemctl":
    op = args[0] if args else ""
    units = [a.removesuffix(".service") for a in args[1:] if not a.startswith("-") and a != "--"]
    if op == "is-active":
        ok = all((root / f"active-{u}").exists() for u in units)
        sys.exit(0 if ok else 3)
    elif op == "show":
        unit = units[-1] if units else "apache2"
        is_up = (root / f"active-{unit}").exists()
        print("LoadState=loaded")
        print(f"ActiveState={'active' if is_up else 'inactive'}")
        print(f"MainPID={'1234' if is_up else '0'}")
        print("UnitFileState=enabled")
        sys.exit(0)
    elif op in ("start", "restart", "reload") or (op == "enable" and "--now" in args):
        for u in units:
            (root / f"active-{u}").touch()
    elif op == "stop":
        for u in units:
            (root / f"active-{u}").unlink(missing_ok=True)
    sys.exit(0)
elif command == "a2ensite":
    avail = root / "etc/apache2/sites-available"
    enabled = root / "etc/apache2/sites-enabled"
    enabled.mkdir(parents=True, exist_ok=True)
    for site in args:
        if site.startswith("-"):
            continue
        name = site if site.endswith(".conf") else f"{site}.conf"
        target = avail / name
        if not target.exists():
            sys.stderr.write(f"ERROR: Site {site} does not exist!\n")
            sys.exit(1)
        link = enabled / name
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(f"../sites-available/{name}")
    sys.exit(0)
elif command == "apache2ctl":
    if args and args[0] == "configtest":
        # Mirror real Apache: dangling symlinks in sites-enabled or conf-enabled fail configtest.
        for sub in ("etc/apache2/sites-enabled", "etc/apache2/conf-enabled"):
            d = root / sub
            if d.is_dir():
                for entry in d.iterdir():
                    if entry.is_symlink() and not entry.exists():
                        sys.stderr.write(f"apache2: Syntax error: dangling config link {entry}\n")
                        sys.exit(1)
    sys.exit(0)
elif command == "git":
    if "ls-remote" in args:
        tag = os.environ.get("AF_FIXTURE_VERSION", "2.1.0")
        print(f"abcdef123456\trefs/tags/v{tag}")
    elif "clone" in args:
        dest = pathlib.Path(args[-1])
        dest.mkdir(parents=True, exist_ok=True)
        ver = os.environ.get("AF_FIXTURE_VERSION", "2.1.0")
        if any("ruTorrent" in a for a in args):
            (dest / "conf").mkdir(exist_ok=True)
            (dest / "conf/config.php").write_text('<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n')
            (dest / "js").mkdir(exist_ok=True)
            (dest / "js/webui.js").write_text(f"version: '{ver}'\n")
            (dest / "index.html").write_text(f"<!doctype html><title>ruTorrent {ver}</title>\n")
        elif any("Organizr" in a for a in args):
            (dest / "api/config").mkdir(parents=True, exist_ok=True)
            (dest / "api/config/default.php").write_text(f"<?php return '{ver}';\n")
            (dest / "index.php").write_text(f"<?php echo 'Organizr {ver}';\n")
    else:
        print("v" + os.environ.get("AF_FIXTURE_VERSION", "2.1.0"))
    sys.exit(0)
elif command == "htpasswd":
    print(f"{args[-1]}:$2y$05$fixturehash")
    sys.exit(0)
elif command == "mysql":
    query = args[args.index("-Nse") + 1] if "-Nse" in args else (args[args.index("-e") + 1] if "-e" in args else sys.stdin.read())
    marker = root / "mysql-nextcloud-present"
    if "INFORMATION_SCHEMA.SCHEMATA" in query and marker.exists():
        print("nextcloud")
    if "CREATE DATABASE nextcloud" in query:
        marker.touch()
    if "DROP DATABASE IF EXISTS nextcloud" in query:
        marker.unlink(missing_ok=True)
    sys.exit(0)
elif command == "mysqldump":
    print("-- fixture sql dump")
    sys.exit(0)
elif command == "sudo":
    if any("maintenance:install" == a for a in args):
        cfg = root / "var/www/nextcloud/config/config.php"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(
            "<?php $CONFIG = ['dbtype' => 'mysql', 'dbname' => 'nextcloud', "
            "'dbhost' => 'localhost', 'dbuser' => 'nextclouduser', "
            f"'dbpassword' => {os.environ.get('AF_NEXTCLOUD_DB_PASS', 'pw')!r}, "
            f"'datadirectory' => {str(root / 'var/lib/nextcloud/data')!r}];\n"
        )
    sys.exit(0)
elif command == "openssl":
    if "rand" in args:
        print("ab" * int(args[-1]))
    sys.exit(0)
elif command == "hostname":
    print("127.0.0.1" if "-I" in args else "fixture.local")
    sys.exit(0)
elif command == "install":
    cleaned = []
    i = 0
    while i < len(args):
        if args[i] in ("-o", "-g"):
            i += 2
        else:
            cleaned.append(args[i])
            i += 1
    os.execv("/usr/bin/install", ["/usr/bin/install", *cleaned])
elif command == "curl":
    # Intercept external downloads (e.g. Nextcloud archive) while routing
    # loopback HTTP readiness probes to the real local curl binary.
    url = next((a for a in args if a.startswith("http://") or a.startswith("https://")), "")
    if "download.nextcloud.com" in url and "-o" in args:
        dest = pathlib.Path(args[args.index("-o") + 1])
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / "nextcloud.zip", dest)
        import hashlib
        pathlib.Path(f"{dest}.sha256").write_text(hashlib.sha256(dest.read_bytes()).hexdigest() + "\n")
        sys.exit(0)
    real_curl = shutil.which("curl", path="/usr/bin:/bin")
    os.execv(real_curl, [real_curl, *args])
elif command in ("apt-get", "chown", "a2enmod", "a2dismod", "a2dissite", "sleep", "id", "getent"):
    sys.exit(0)
else:
    raise RuntimeError(f"Unexpected mock command: {command} {args}")
'''


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _LocalProbeServer:
    """Isolated 127.0.0.1 HTTP server recording known-target readiness probes."""

    def __init__(self, handler_fn):
        self.requests: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                req = {
                    "path": self.path,
                    "host": self.headers.get("Host", ""),
                    "authorization": self.headers.get("Authorization", ""),
                }
                outer.requests.append(req)
                status, headers, body = handler_fn(req)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
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


class ApacheAppReadinessFixture:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-apache-ready-")
        self.root = Path(self._tmp.name)
        for rel in (
            "mock-bin",
            "opt/AetherFlow/packages",
            "opt/AetherFlow/logs",
            "var/log/aetherflow",
            "var/www",
            "var/lib/aetherflow/recovery",
            "etc/apache2/sites-available",
            "etc/apache2/sites-enabled",
            "etc/apache2/conf-available",
            "etc/apache2/conf-enabled",
            "etc/systemd/system",
            "srv",
            "install",
            "tmp",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)

        for cmd in (
            "systemctl", "a2ensite", "a2dissite", "a2enmod", "a2dismod",
            "apache2ctl", "git", "htpasswd", "mysql", "mysqldump", "sudo",
            "openssl", "hostname", "install", "curl", "apt-get", "chown",
            "sleep", "id", "getent",
        ):
            p = self.root / "mock-bin" / cmd
            p.write_text(MOCK_HOST, encoding="utf-8")
            p.chmod(0o755)

        source = (ROOT / "packages/common.sh").read_text(encoding="utf-8")
        names = re.findall(r"(?m)^([a-zA-Z_][a-zA-Z0-9_-]*)\(\) [({]$", source)
        helpers = self.rebase(
            common_functions(*(n for n in names if n != "seed_jellyfin_master_user"))
        )
        overrides = r'''
set -euo pipefail
MASTER_USER="${MASTER_USER:-test-admin}"
MASTER_PASS="${MASTER_PASS:-test-password}"
LOCK_DIR="$AF_TEST_ROOT/install"
require_root() { :; }
load_master_credentials() { export MASTER_USER MASTER_PASS; }
log_info() { printf '%s\n' "$*" >> "${LOGFILE:-/dev/null}"; }
log_warn() { printf '%s\n' "$*" >> "${LOGFILE:-/dev/null}"; }
log_error() { printf '%s\n' "$*" >&2; }
print_error() { printf '%s\n' "$*" >&2; }
print_warn() { printf '%s\n' "$*" >&2; }
report_progress() { :; }
get_base_domain() { printf 'example.test\n'; }
write_lock() { touch "$AF_TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; }
lock_path() { printf '%s/install/.%s.lock\n' "$AF_TEST_ROOT" "$1"; }
remove_lock() { rm -f "$AF_TEST_ROOT/install/.$1.lock"; }
'''
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(
            helpers + "\n" + overrides, encoding="utf-8"
        )
        with zipfile.ZipFile(self.root / "nextcloud.zip", "w") as zf:
            zf.writestr("nextcloud/occ", "#!/usr/bin/env php\n")
            zf.writestr("nextcloud/version.php", "<?php $OC_VersionString = '32.0.1';\n")
            zf.writestr("nextcloud/status.php", "<?php echo json_encode(['installed'=>true]);\n")

    def cleanup(self):
        self._tmp.cleanup()

    def rebase(self, text: str) -> str:
        prefixes = (
            "/opt", "/var", "/etc", "/usr/local", "/srv", "/mnt",
            "/run", "/root", "/install", "/data", "/tmp", "/home",
        )
        pattern = re.compile(
            r"(?<![\w/.-])(" + "|".join(re.escape(p) for p in prefixes) + r")(?=/|[^\w.-]|$)"
        )
        return pattern.sub(lambda m: str(self.root) + m.group(0), text)

    def file(self, relative: str, content: str) -> Path:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_installer(self, app: str, port: int, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        src = (ROOT / f"packages/package/install/installpackage-{app}").read_text(encoding="utf-8")
        script_path = self.root / f"run-install-{app}.sh"
        script_path.write_text(self.rebase(src), encoding="utf-8")
        script_path.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AETHERFLOW_APACHE_ROOT": str(self.root / "etc/apache2"),
            "AF_APP_PORT": str(port),
            "AETHERFLOW_APP_PORT": str(port),
            "AF_READINESS_ATTEMPTS": "2",
            "AF_FIXTURE_VERSION": "2.1.0",
            "MASTER_USER": "test-admin",
            "MASTER_PASS": "test-password",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/bash", str(script_path)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def run_helper(self, snippet: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AETHERFLOW_APACHE_ROOT": str(self.root / "etc/apache2"),
            "LOGFILE": str(self.root / "var/log/aetherflow/helper.log"),
        }
        if extra_env:
            env.update(extra_env)
        script = f'source "{self.root}/opt/AetherFlow/packages/common.sh"\n{snippet}\n'
        return subprocess.run(
            ["/bin/bash", "-euo", "pipefail", "-c", script],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
        )


class ApacheAppReadinessTests(unittest.TestCase):
    def setUp(self):
        self.fx = ApacheAppReadinessFixture()
        self.addCleanup(self.fx.cleanup)

    def test_apache_app_readiness_target_resolves_vhost_config_and_rejects_symlink(self):
        self.fx.file(
            "etc/apache2/sites-available/rutorrent.conf",
            f"<VirtualHost 127.0.0.1:8087>\n"
            f"    DocumentRoot {self.fx.root}/var/www/rutorrent\n"
            f'    Alias /rutorrent "{self.fx.root}/var/www/rutorrent"\n'
            f"</VirtualHost>\n",
        )
        res = self.fx.run_helper("apache_app_readiness_target rutorrent 8087 /")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.splitlines(), ["http://127.0.0.1:8087/", ""])

        self.fx.file(
            "etc/apache2/sites-available/organizr.conf",
            f"<VirtualHost *:18086>\n"
            f"    ServerName organizr.example.test\n"
            f"    DocumentRoot {self.fx.root}/var/www/html\n"
            f'    Alias /organizr "{self.fx.root}/var/www/organizr"\n'
            f"</VirtualHost>\n",
        )
        res = self.fx.run_helper("apache_app_readiness_target organizr 18086 /")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(
            res.stdout.splitlines(),
            ["http://127.0.0.1:18086/organizr/", "organizr.example.test"],
        )

        self.fx.file(
            "etc/apache2/sites-available/nextcloud.conf",
            f"<VirtualHost [::1]:18088>\n"
            f"    SSLEngine on\n"
            f"    DocumentRoot {self.fx.root}/var/www/html\n"
            f'    Alias /nextcloud "{self.fx.root}/var/www/nextcloud/"\n'
            f"</VirtualHost>\n",
        )
        res = self.fx.run_helper("apache_app_readiness_target nextcloud 18088 /status.php")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.splitlines(), ["https://[::1]:18088/nextcloud/status.php", ""])

        # Symlinked vhost conf must fail closed.
        real_target = self.fx.file("tmp/evil.conf", "<VirtualHost 127.0.0.1:8086>\n</VirtualHost>\n")
        sym = self.fx.root / "etc/apache2/sites-available/organizr.conf"
        sym.unlink()
        sym.symlink_to(real_target)
        res_sym = self.fx.run_helper("apache_app_readiness_target organizr 8086 /")
        self.assertNotEqual(res_sym.returncode, 0)

    def test_rutorrent_installer_respects_auth_challenge_and_detects_post_auth_failure(self):
        expected_auth = "Basic " + base64.b64encode(b"test-admin:test-password").decode("ascii")

        # 1. Fresh install: 401 challenge followed by 200 HTML when MASTER_USER:MASTER_PASS authenticates.
        def fresh_auth_handler(req):
            if req["authorization"] == expected_auth:
                return 200, {"Content-Type": "text/html"}, "<!doctype html><title>ruTorrent</title>"
            return 401, {"WWW-Authenticate": 'Basic realm="ruTorrent"'}, "Unauthorized"

        with _LocalProbeServer(fresh_auth_handler) as srv:
            res = self.fx.run_installer("rutorrent", srv.port)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue((self.fx.root / "install/.rutorrent.lock").is_file())
            self.assertEqual((self.fx.root / "var/www/rutorrent/.af-version").read_text().strip(), "2.1.0")
            self.assertGreaterEqual(len(srv.requests), 2)
            self.assertEqual(srv.requests[0]["authorization"], "")
            self.assertEqual(srv.requests[-1]["authorization"], expected_auth)

        # 2. Update with custom operator htpasswd: 401 challenge even with master credentials is respected.
        self.fx.file("etc/apache2/AetherFlow/rutorrent.htpasswd", "operator:$2y$05$customhash\n")
        with _LocalProbeServer(
            lambda _req: (401, {"WWW-Authenticate": 'Basic realm="operator-access"'}, "Unauthorized")
        ) as srv:
            res = self.fx.run_installer("rutorrent", srv.port, {"AF_PACKAGE_ACTION": "update"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(
                (self.fx.root / "etc/apache2/AetherFlow/rutorrent.htpasswd").read_text(),
                "operator:$2y$05$customhash\n",
            )

        # 3. Post-auth backend failure (e.g. broken PHP or unreadable htpasswd -> 500) must fail & roll back.
        def broken_post_auth_handler(req):
            if req["authorization"] == expected_auth:
                return 500, {"Content-Type": "text/plain"}, "Internal Server Error"
            return 401, {"WWW-Authenticate": 'Basic realm="ruTorrent"'}, "Unauthorized"

        fx_fail = ApacheAppReadinessFixture()
        self.addCleanup(fx_fail.cleanup)
        with _LocalProbeServer(broken_post_auth_handler) as srv:
            res = fx_fail.run_installer("rutorrent", srv.port)
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertFalse((fx_fail.root / "install/.rutorrent.lock").exists())
            self.assertFalse((fx_fail.root / "etc/apache2/sites-enabled/rutorrent.conf").exists())
            self.assertFalse((fx_fail.root / "etc/apache2/sites-enabled/rutorrent.conf").is_symlink())
            self.assertFalse((fx_fail.root / "etc/apache2/conf-enabled/aetherflow-rutorrent-listen.conf").is_symlink())
            self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)

    def test_organizr_installer_accepts_200_setup_redirect_auth_and_alias_host(self):
        cases = [
            ("200-html", lambda _r: (200, {"Content-Type": "text/html"}, "<!doctype html><title>Organizr</title>")),
            ("302-setup-redirect", lambda _r: (302, {"Location": "/api/v2/login"}, "")),
            ("307-redirect", lambda _r: (307, {"Location": "https://organizr.example.test/setup"}, "")),
            ("401-auth-challenge", lambda _r: (401, {"WWW-Authenticate": 'Basic realm="Organizr"'}, "Auth required")),
        ]
        for label, handler in cases:
            with self.subTest(case=label):
                fx = ApacheAppReadinessFixture()
                self.addCleanup(fx.cleanup)
                with _LocalProbeServer(handler) as srv:
                    res = fx.run_installer("organizr", srv.port)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertTrue((fx.root / "install/.organizr.lock").is_file())
                    self.assertEqual((fx.root / "var/www/organizr/.af-version").read_text().strip(), "2.1.0")
                    self.assertGreaterEqual(len(srv.requests), 1)

        # Retained vhost with ServerName + Alias routes readiness probe to /organizr/ with matching Host header.
        fx_alias = ApacheAppReadinessFixture()
        self.addCleanup(fx_alias.cleanup)

        def alias_handler(req):
            if req["path"] == "/organizr/" and req["host"].startswith("organizr.example.test"):
                return 200, {"Content-Type": "text/html"}, "<!doctype html><title>Organizr</title>"
            return 404, {"Content-Type": "text/plain"}, "Wrong host or path"

        with _LocalProbeServer(alias_handler) as srv:
            fx_alias.file(
                "etc/apache2/sites-available/organizr.conf",
                f"<VirtualHost *:8086>\n"
                f"    ServerName organizr.example.test\n"
                f"    DocumentRoot {fx_alias.root}/var/www/html\n"
                f'    Alias /organizr "{fx_alias.root}/var/www/organizr"\n'
                f"</VirtualHost>\n",
            )
            res = fx_alias.run_installer("organizr", srv.port, {"AF_PACKAGE_ACTION": "update"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue((fx_alias.root / "install/.organizr.lock").is_file())
            self.assertTrue(
                any(r["path"] == "/organizr/" and r["host"].startswith("organizr.example.test") for r in srv.requests),
                srv.requests,
            )

    def test_healthy_apache_with_failing_app_fails_fresh_install_and_rolls_back_cleanly(self):
        failure_modes = [
            ("500-php-error", lambda _r: (500, {"Content-Type": "text/html"}, "Internal Server Error")),
            ("404-missing-route", lambda _r: (404, {"Content-Type": "text/html"}, "Not Found")),
            ("403-forbidden", lambda _r: (403, {"Content-Type": "text/html"}, "Forbidden")),
            ("200-raw-php", lambda _r: (200, {"Content-Type": "text/plain"}, "<?php require_once 'api/functions.php';")),
            ("200-php-fatal", lambda _r: (200, {"Content-Type": "text/html"}, "<br /><b>Fatal error</b>: Uncaught Error")),
            ("200-apache-default", lambda _r: (200, {"Content-Type": "text/html"}, "<title>Apache2 Debian Default Page: It works</title>")),
        ]
        for app in ("rutorrent", "organizr"):
            for label, handler in failure_modes:
                with self.subTest(app=app, mode=label):
                    fx = ApacheAppReadinessFixture()
                    self.addCleanup(fx.cleanup)
                    unrelated = fx.file("etc/apache2/sites-available/aetherflow-app-other.conf", "# other app\n")
                    with _LocalProbeServer(handler) as srv:
                        res = fx.run_installer(app, srv.port)
                    self.assertNotEqual(res.returncode, 0, f"{app}/{label} should have failed")
                    self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)
                    self.assertFalse((fx.root / f"install/.{app}.lock").exists())
                    self.assertFalse((fx.root / f"var/www/{app}").exists())
                    self.assertFalse((fx.root / f"etc/apache2/sites-available/{app}.conf").exists())
                    self.assertFalse((fx.root / f"etc/apache2/sites-enabled/{app}.conf").is_symlink())
                    self.assertFalse((fx.root / f"etc/apache2/conf-available/aetherflow-{app}-listen.conf").exists())
                    self.assertFalse((fx.root / f"etc/apache2/conf-enabled/aetherflow-{app}-listen.conf").is_symlink())
                    if app == "rutorrent":
                        self.assertFalse((fx.root / "srv/rutorrent").is_symlink())
                        self.assertFalse((fx.root / "etc/apache2/AetherFlow/rutorrent.htpasswd").exists())
                    self.assertTrue((fx.root / "active-apache2").exists())
                    self.assertEqual(unrelated.read_text(), "# other app\n")

            # Also verify active Apache process with unbound/closed app port fails cleanly.
            with self.subTest(app=app, mode="closed-port"):
                fx = ApacheAppReadinessFixture()
                self.addCleanup(fx.cleanup)
                closed_port = _free_loopback_port()
                res = fx.run_installer(app, closed_port)
                self.assertNotEqual(res.returncode, 0, f"{app}/closed-port should have failed")
                self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)
                self.assertFalse((fx.root / f"install/.{app}.lock").exists())
                self.assertFalse((fx.root / f"etc/apache2/sites-enabled/{app}.conf").is_symlink())
                self.assertTrue((fx.root / "active-apache2").exists())

    def test_failed_update_rolls_back_runtime_and_preserves_prior_routes(self):
        for app in ("rutorrent", "organizr"):
            with self.subTest(app=app):
                fx = ApacheAppReadinessFixture()
                self.addCleanup(fx.cleanup)
                # Pre-seed an existing working v1.0.0 installation + active managed ingress routes.
                lock = fx.file(f"install/.{app}.lock", "installed\n")
                old_ver = fx.file(f"var/www/{app}/.af-version", "1.0.0\n")
                old_code = fx.file(f"var/www/{app}/previous-release.txt", "v1.0.0-runtime\n")
                old_vhost_text = (
                    f"<VirtualHost 127.0.0.1:18080>\n"
                    f"    DocumentRoot {fx.root}/var/www/{app}\n"
                    f"</VirtualHost>\n"
                )
                old_vhost = fx.file(f"etc/apache2/sites-available/{app}.conf", old_vhost_text)
                enabled_vhost = fx.root / f"etc/apache2/sites-enabled/{app}.conf"
                enabled_vhost.symlink_to(f"../sites-available/{app}.conf")
                old_listen = fx.file(f"etc/apache2/conf-available/aetherflow-{app}-listen.conf", "Listen 127.0.0.1:18080\n")
                enabled_listen = fx.root / f"etc/apache2/conf-enabled/aetherflow-{app}-listen.conf"
                enabled_listen.symlink_to(f"../conf-available/aetherflow-{app}-listen.conf")
                if app == "rutorrent":
                    (fx.root / "srv/rutorrent").symlink_to(fx.root / "var/www/rutorrent")
                    fx.file("etc/apache2/AetherFlow/rutorrent.htpasswd", "operator:$2y$05$priorhash\n")
                # Pre-existing AetherFlow managed ingress routes that must stay intact.
                internal_route = fx.file(f"etc/apache2/sites-available/aetherflow-app-{app}.conf", "# prior internal route\n")
                external_route = fx.file(f"etc/apache2/sites-available/aetherflow-ext-{app}.conf", "# prior external route\n")
                (fx.root / "active-apache2").touch()

                with _LocalProbeServer(lambda _r: (500, {"Content-Type": "text/html"}, "PHP fatal")) as srv:
                    res = fx.run_installer(
                        app,
                        srv.port,
                        {"AF_PACKAGE_ACTION": "update", "AF_FIXTURE_VERSION": "2.2.0"},
                    )

                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)
                # Prior installation and version restored intact.
                self.assertTrue(lock.is_file())
                self.assertEqual(old_ver.read_text(), "1.0.0\n")
                self.assertEqual(old_code.read_text(), "v1.0.0-runtime\n")
                self.assertEqual(old_vhost.read_text(), old_vhost_text)
                self.assertTrue(enabled_vhost.is_symlink() and enabled_vhost.exists())
                self.assertEqual(old_listen.read_text(), "Listen 127.0.0.1:18080\n")
                self.assertTrue(enabled_listen.is_symlink() and enabled_listen.exists())
                if app == "rutorrent":
                    self.assertEqual(
                        (fx.root / "etc/apache2/AetherFlow/rutorrent.htpasswd").read_text(),
                        "operator:$2y$05$priorhash\n",
                    )
                # Prior ingress routes remain completely untouched and Apache is back up.
                self.assertEqual(internal_route.read_text(), "# prior internal route\n")
                self.assertEqual(external_route.read_text(), "# prior external route\n")
                self.assertTrue((fx.root / "active-apache2").exists())

    def test_nextcloud_rejects_raw_php_and_maintenance_mode_while_apache_is_active(self):
        for label, body in (
            ("raw-php", "<?php require_once 'lib/versioncheck.php';"),
            ("maintenance-true", '{"installed":true,"maintenance":true,"version":"32.0.1.0"}'),
            ("installed-false", '{"installed":false,"maintenance":false}'),
        ):
            with self.subTest(mode=label):
                fx = ApacheAppReadinessFixture()
                self.addCleanup(fx.cleanup)
                with _LocalProbeServer(lambda _r, b=body: (200, {"Content-Type": "application/json"}, b)) as srv:
                    res = fx.run_installer("nextcloud", srv.port)
                self.assertNotEqual(res.returncode, 0, f"nextcloud/{label} should have failed")
                self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)
                self.assertFalse((fx.root / "install/.nextcloud.lock").exists())
                self.assertFalse((fx.root / "etc/apache2/sites-enabled/nextcloud.conf").is_symlink())
                self.assertTrue((fx.root / "active-apache2").exists())

        # Healthy /status.php JSON succeeds.
        fx_ok = ApacheAppReadinessFixture()
        self.addCleanup(fx_ok.cleanup)
        with _LocalProbeServer(
            lambda r: (
                (200, {"Content-Type": "application/json"}, '{"installed":true,"maintenance":false,"version":"32.0.1.0"}')
                if r["path"] == "/status.php"
                else (404, {"Content-Type": "text/plain"}, "not found")
            )
        ) as srv:
            res = fx_ok.run_installer("nextcloud", srv.port)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue((fx_ok.root / "install/.nextcloud.lock").is_file())
            self.assertTrue(any(r["path"] == "/status.php" for r in srv.requests), srv.requests)

    def test_bounded_retry_recovers_from_transient_503_before_succeeding(self):
        attempts = {"count": 0}

        def transient_handler(_req):
            attempts["count"] += 1
            if attempts["count"] <= 2:
                return 503, {"Content-Type": "text/plain"}, "Starting up"
            return 200, {"Content-Type": "text/html"}, "<!doctype html><title>Organizr</title>"

        with _LocalProbeServer(transient_handler) as srv:
            res = self.fx.run_installer("organizr", srv.port, {"AF_READINESS_ATTEMPTS": "3"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue((self.fx.root / "install/.organizr.lock").is_file())
            self.assertGreaterEqual(attempts["count"], 3)


if __name__ == "__main__":
    unittest.main()
