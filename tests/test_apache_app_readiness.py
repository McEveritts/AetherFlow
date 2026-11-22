#!/usr/bin/env python3
"""Focused fixture regressions for shared Apache PHP application readiness and rollback."""

import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from installer_test_helpers import common_functions


def _php_with_simplexml():
    for candidate in (shutil.which("php"), *Path("/usr/bin").glob("php[0-9]*")):
        if candidate and subprocess.run([str(candidate), "-r", 'exit(extension_loaded("SimpleXML") ? 0 : 1);'],
                                        capture_output=True, timeout=3).returncode == 0:
            return str(candidate)
    return None


PHP_SIMPLEXML = _php_with_simplexml()
SCGI_VERSION_REPLY = (
    b"Status: 200 OK\r\nContent-Type: text/xml\r\n\r\n"
    b"<methodResponse><params><param><value><string>0.10.0</string></value></param></params></methodResponse>"
)


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
            (dest / "conf/config.php").write_text(
                "<?php\n$scgi_port = $_ENV['RU_SCGI_PORT'] ?? 5000;\n$scgi_host = '127.0.0.1';\n"
                "if (is_readable(__DIR__ . '/config.local.php')) { require __DIR__ . '/config.local.php'; }\n"
            )
            shutil.copytree(root / "rutorrent-php", dest / "php")
            (dest / "js").mkdir(exist_ok=True)
            (dest / "js/webui.js").write_text(f"version: '{ver}'\n")
            (dest / "index.html").write_text(f"<!doctype html><title>ruTorrent {ver}</title>\n")
        elif any("Organizr" in a for a in args):
            (dest / "api/config").mkdir(parents=True, exist_ok=True)
            (dest / "api/config/default.php").write_text(f"<?php return '{ver}';\n")
            (dest / "index.php").write_text(f"<?php echo 'Organizr {ver}';\n")
    elif "rev-parse" in args and any(tok in arg for arg in args for tok in (".rutorrent-build.", ".organizr-build.")):
        print("abcdef123456")
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


RUTORRENT_RUNUSER_FIXTURE = '''#!/usr/bin/python3 -B
import os, pathlib, sys

root = pathlib.Path(sys.argv[0]).resolve().parent.parent
args = sys.argv[1:]
assert args[:5] == ['-u', 'www-data', '--', 'php', '--']
assert args[5] == str(root / 'var/www/rutorrent')
assert 'MASTER_PASS' not in os.environ
probe_port = root / 'scgi-probe-port'
if probe_port.exists():
    os.environ['AF_TEST_ROOT'] = str(root)
    os.environ['AF_FIXTURE_SCGI_PORT'] = probe_port.read_text()
    os.execv((root / 'php-cli').read_text(), args[3:])
print('ready')  # HTTP-only cases isolate Apache behavior.
'''


# Minimal ruTorrent API double. The transport uses real confined sockets with
# a fixture-only wire format, rather than implementing upstream XML-RPC.
RUTORRENT_XMLRPC_FIXTURE = """<?php
require __DIR__ . '/../conf/config.php';
$userConfig = __DIR__ . '/../conf/users/' . $_SERVER['REMOTE_USER'] . '/config.php';
if (is_file($userConfig)) {
    require $userConfig;
}
class rXMLRPCRequest {
    public static function send($request) {
        global $scgi_host, $scgi_port;
        $allowedPort = (int) getenv('AF_FIXTURE_SCGI_PORT');
        if ($scgi_host === '127.0.0.1' && $scgi_port === 15000) {
            $scgi_port = $allowedPort; // Reserve no fixed port on the test host.
        }
        if (!(($scgi_host === '127.0.0.1' && $allowedPort > 0 && $scgi_port === $allowedPort)
            || ($scgi_port === 0 && str_starts_with($scgi_host, 'unix://' . getenv('AF_TEST_ROOT') . '/')))) {
            return false;
        }
        $socket = @fsockopen($scgi_host, $scgi_port, $errno, $error, 1);
        if (!$socket) {
            return false;
        }
        stream_set_timeout($socket, 1);
        fwrite($socket, $request . "\\n");
        $reply = stream_get_contents($socket, 65536);
        fclose($socket);
        return $reply;
    }
}
"""


class _LocalScgiResponder:
    def __init__(self, address, reply=SCGI_VERSION_REPLY):
        self.methods = []
        methods = self.methods

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(2)
                request = ET.fromstring(self.rfile.readline(512))
                methods.append(request.findtext("methodName"))
                self.wfile.write(reply)

        server_type = socketserver.TCPServer if isinstance(address, tuple) else socketserver.UnixStreamServer
        self.server = server_type(address, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


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
        self.file("rutorrent-php/xmlrpc.php", RUTORRENT_XMLRPC_FIXTURE)
        self.file("mock-bin/runuser", RUTORRENT_RUNUSER_FIXTURE).chmod(0o755)
        if PHP_SIMPLEXML:
            self.file("php-cli", PHP_SIMPLEXML)

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
        probe_port = env.pop("AF_FIXTURE_SCGI_PORT", None)
        if probe_port is not None:
            self.file("scgi-probe-port", probe_port)
        else:
            (self.root / "scgi-probe-port").unlink(missing_ok=True)
        return subprocess.run(
            ["/bin/bash", str(script_path)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
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

    @unittest.skipUnless(PHP_SIMPLEXML, "PHP CLI with SimpleXML required for the SCGI fixture")
    def test_rutorrent_fresh_install_requires_scgi_even_when_apache_is_ready(self):
        def healthy_web(_req):
            return 200, {"Content-Type": "text/html"}, "<!doctype html><title>ruTorrent</title>"

        with _LocalProbeServer(healthy_web) as web, socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))  # Keep the port reserved without listening.
            result = self.fx.run_installer("rutorrent", web.port, {"AF_FIXTURE_SCGI_PORT": str(closed.getsockname()[1])})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(web.requests)
            self.assertIn("install or start Marketplace rTorrent", result.stderr)
            receipt = next(line.removeprefix("AF_DIAG_FAILURE=") for line in result.stderr.splitlines()
                           if line.startswith("AF_DIAG_FAILURE="))
            self.assertEqual(json.loads(receipt)["category"], "dependency_unavailable")
            self.assertFalse((self.fx.root / "install/.rutorrent.lock").exists())
            self.assertFalse((self.fx.root / "var/www/rutorrent").exists())
            self.assertFalse((self.fx.root / "etc/apache2/sites-enabled/rutorrent.conf").is_symlink())

            with _LocalScgiResponder(("127.0.0.1", 0), b"HTTP/1.1 200 OK\r\n\r\n<html>Wrong service</html>") as backend:
                result = self.fx.run_installer("rutorrent", web.port, {"AF_FIXTURE_SCGI_PORT": str(backend.server.server_address[1])})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.fx.root / "install/.rutorrent.lock").exists())

            with _LocalScgiResponder(("127.0.0.1", 0)) as backend:
                result = self.fx.run_installer("rutorrent", web.port, {"AF_FIXTURE_SCGI_PORT": str(backend.server.server_address[1])})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(backend.methods, ["system.client_version"])
            self.assertIn("?? 15000;", (self.fx.root / "var/www/rutorrent/conf/config.php").read_text())
            self.assertTrue((self.fx.root / "install/.rutorrent.lock").is_file())

    @unittest.skipUnless(PHP_SIMPLEXML, "PHP CLI with SimpleXML required for the SCGI fixture")
    def test_rutorrent_retains_working_custom_endpoints_and_rolls_back_backend_failure(self):
        for transport in ("tcp", "unix"):
            with self.subTest(transport=transport):
                fx = ApacheAppReadinessFixture()
                self.addCleanup(fx.cleanup)
                socket_path = str(fx.root / "tmp/rpc.sock")
                address = ("127.0.0.1", 0) if transport == "tcp" else socket_path
                with _LocalProbeServer(lambda _: (200, {}, "<!doctype html><title>ruTorrent</title>")) as web:
                    with _LocalScgiResponder(address) as backend:
                        port = backend.server.server_address[1] if transport == "tcp" else 0
                        host = "127.0.0.1" if transport == "tcp" else f"unix://{socket_path}"
                        config_path = "var/www/rutorrent/conf/config.php"
                        if transport == "tcp":
                            override = "config.local.php"
                        else:
                            fx.file(config_path, "<?php $scgi_host = '127.0.0.1'; $scgi_port = 5000;\n")
                            override = "users/operator/config.php"
                        local_text = f"<?php $scgi_host = {host!r}; $scgi_port = {port}; // retained\n"
                        local = fx.file(f"var/www/rutorrent/conf/{override}", local_text)
                        fx.file("etc/apache2/AetherFlow/rutorrent.htpasswd", "operator:fixture-hash\n")
                        env = {"AF_FIXTURE_SCGI_PORT": str(port)}
                        result = fx.run_installer("rutorrent", web.port, env)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(backend.methods, ["system.client_version"])
                    config = fx.root / config_path
                    config_text = config.read_text()
                    self.assertIn("?? 15000;" if transport == "tcp" else "$scgi_port = 5000;", config_text)
                    vhost = fx.root / "etc/apache2/sites-available/rutorrent.conf"
                    old_vhost = vhost.read_text()
                    failed = fx.run_installer("rutorrent", web.port, {**env, "AF_PACKAGE_ACTION": "update", "AF_FIXTURE_VERSION": "3.0.0"})
                    self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                    self.assertIn("SCGI response", failed.stderr)
                    self.assertNotIn("Rollback incomplete", failed.stderr)
                    self.assertEqual(config.read_text(), config_text)
                    self.assertEqual(local.read_text(), local_text)
                    self.assertEqual(vhost.read_text(), old_vhost)
                    self.assertEqual((fx.root / "var/www/rutorrent/.af-version").read_text().strip(), "2.1.0")
                    self.assertTrue((fx.root / "install/.rutorrent.lock").is_file())
                    commands = [json.loads(line) for line in (fx.root / "commands.jsonl").read_text().splitlines()]
                    self.assertFalse(any(command[0] in ("systemctl", "apt-get") and "rtorrent" in command for command in commands))

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


REAL_APACHE_BIN = "/usr/sbin/apache2"
REAL_PHP_MODULES = sorted(Path("/usr/lib/apache2/modules").glob("libphp*.so"))


REAL_APACHE_MOCK_HOST = r'''#!/usr/bin/python3 -B
import json, os, pathlib, shutil, signal, subprocess, sys, time, urllib.error, urllib.request

root = pathlib.Path(os.environ["AF_TEST_ROOT"])
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "commands.jsonl").open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([command, *args]) + "\n")

apache_bin = os.environ["AF_REAL_APACHE_BIN"]
apache_conf = os.environ["AF_REAL_APACHE_CONF"]
pid_file = pathlib.Path(os.environ["AF_APACHE_PIDFILE"])

def apache_pid():
    if not pid_file.is_file():
        return None
    raw = pid_file.read_text(encoding="utf-8").strip()
    if not raw.isdigit():
        return None
    pid = int(raw)
    try:
        os.kill(pid, 0)
        return pid
    except OSError:
        return None

def record_mid_staging_probe():
    obs_path = root / "mid-staging-observations.json"
    if obs_path.exists():
        return
    direct_url = os.environ.get("AF_OBS_DIRECT_URL", "")
    proxy_url = os.environ.get("AF_OBS_PROXY_URL", "")
    other_url = os.environ.get("AF_OBS_OTHER_URL", "")
    if not (direct_url and other_url):
        return
    def fetch(url):
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                return {"status": resp.status, "maint": resp.headers.get("X-AetherFlow-Maintenance", ""), "body": resp.read().decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "maint": exc.headers.get("X-AetherFlow-Maintenance", ""), "body": exc.read().decode("utf-8", "replace")}
    obs = {
        "direct": fetch(direct_url),
        "proxy": fetch(proxy_url) if proxy_url else None,
        "other": fetch(other_url),
        "master_pid": apache_pid(),
    }
    obs_path.write_text(json.dumps(obs), encoding="utf-8")

if command == "systemctl":
    op = args[0] if args else ""
    units = [a.removesuffix(".service") for a in args[1:] if not a.startswith("-") and a != "--"]
    if "apache2" in units:
        pid = apache_pid()
        if op == "is-active":
            sys.exit(0 if pid else 3)
        elif op == "show":
            if "--value" in args and any("MainPID" in a for a in args):
                print(str(pid or 0))
                sys.exit(0)
            print("LoadState=loaded")
            print(f"ActiveState={'active' if pid else 'inactive'}")
            print(f"MainPID={pid or 0}")
            print("UnitFileState=enabled")
            sys.exit(0)
        elif op == "reload":
            if not pid:
                sys.exit(1)
            os.kill(pid, signal.SIGUSR1)
            time.sleep(0.15)
            sys.exit(0)
        elif op in ("start", "enable"):
            sys.exit(0 if pid else 1)
        elif op == "stop":
            # Should never be reached during supported per-app quiescence.
            if pid:
                os.kill(pid, signal.SIGTERM)
                for _ in range(30):
                    if not apache_pid():
                        break
                    time.sleep(0.05)
            sys.exit(0)
    else:
        if op == "is-active":
            sys.exit(0)
    sys.exit(0)
elif command == "apache2ctl":
    if args and args[0] == "configtest":
        res = subprocess.run([apache_bin, "-f", apache_conf, "-t"], capture_output=True, text=True)
        sys.stdout.write(res.stdout)
        sys.stderr.write(res.stderr)
        sys.exit(res.returncode)
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
        if link.is_symlink():
            if os.path.realpath(link) != os.path.realpath(target):
                sys.stderr.write(f"ERROR: {link} exists and points elsewhere!\n")
                sys.exit(1)
        elif link.exists():
            sys.stderr.write(f"ERROR: {link} is a real file!\n")
            sys.exit(1)
        else:
            link.symlink_to(f"../sites-available/{name}")
    sys.exit(0)
elif command == "a2dissite":
    enabled = root / "etc/apache2/sites-enabled"
    for site in args:
        if site.startswith("-"):
            continue
        name = site if site.endswith(".conf") else f"{site}.conf"
        link = enabled / name
        if link.is_symlink():
            link.unlink()
    sys.exit(0)
elif command == "git":
    ver = os.environ.get("AF_FIXTURE_VERSION", "2.1.0")
    broken = os.environ.get("AF_FIXTURE_BROKEN_PHP", "0") == "1"
    if "ls-remote" in args:
        print(f"abcdef123456\trefs/tags/v{ver}")
    elif "clone" in args:
        dest = pathlib.Path(args[-1])
        dest.mkdir(parents=True, exist_ok=True)
        if any("ruTorrent" in a for a in args):
            (dest / "conf").mkdir(exist_ok=True)
            (dest / "conf/config.php").write_text('<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n')
            if broken:
                (dest / "index.php").write_text("<?php http_response_code(500); echo 'ruTorrent broken'; ?>\n")
            else:
                (dest / "index.php").write_text(f"<?php echo '<!doctype html><title>ruTorrent {ver}</title>'; ?>\n")
        elif any("Organizr" in a for a in args):
            (dest / "api/config").mkdir(parents=True, exist_ok=True)
            (dest / "api/config/default.php").write_text(f"<?php return '{ver}';\n")
            if broken:
                (dest / "index.php").write_text("<?php http_response_code(500); echo 'Organizr broken'; ?>\n")
            else:
                (dest / "index.php").write_text(f"<?php echo '<!doctype html><title>Organizr {ver}</title>'; ?>\n")
    elif "rev-parse" in args and any(tok in arg for arg in args for tok in (".rutorrent-build.", ".organizr-build.")):
        print("abcdef123456")
    else:
        print("v" + ver)
    sys.exit(0)
elif command == "chown":
    if os.environ.get("AF_OBS_HOOK") == "chown":
        record_mid_staging_probe()
    sys.exit(0)
elif command == "sudo":
    if "upgrade" in args:
        if os.environ.get("AF_OBS_HOOK") == "occ-upgrade":
            record_mid_staging_probe()
        if os.environ.get("AF_FAIL_OCC_UPGRADE") == "1":
            sys.stderr.write("Simulated occ upgrade failure\n")
            sys.exit(1)
    sys.exit(0)
elif command == "mysql":
    sys.exit(0)
elif command == "mysqldump":
    print("-- real-apache fixture sql dump")
    sys.exit(0)
elif command == "htpasswd":
    import base64, hashlib
    pw = sys.stdin.read().strip()
    digest = base64.b64encode(hashlib.sha1(pw.encode("utf-8")).digest()).decode("ascii")
    print(f"{args[-1]}:{{SHA}}{digest}")
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
elif command in ("apt-get", "a2enmod", "a2dismod", "id", "getent"):
    sys.exit(0)
else:
    raise RuntimeError(f"Unexpected real-apache mock command: {command} {args}")
'''


class ApachePerAppQuiescenceTests(unittest.TestCase):
    def setUp(self):
        self.fx = ApacheAppReadinessFixture()
        self.addCleanup(self.fx.cleanup)

    def test_per_app_quiescence_handles_alias_vhost_external_exposure_fallback_and_symlink_rejection(self):
        # 1. Custom vhost with ServerName + DocumentRoot /var/www/html + Alias /organizr
        self.fx.file(
            "etc/apache2/sites-available/organizr.conf",
            f"<VirtualHost *:18086>\n"
            f"    ServerName organizr.example.test\n"
            f"    ServerAlias org.example.test\n"
            f"    DocumentRoot {self.fx.root}/var/www/html\n"
            f'    Alias /organizr "{self.fx.root}/var/www/organizr"\n'
            f"</VirtualHost>\n",
        )
        site_link = self.fx.root / "etc/apache2/sites-enabled/organizr.conf"
        site_link.symlink_to("../sites-available/organizr.conf")
        # An unrelated vhost with DocumentRoot /var/www/other must NOT block per-app quiescence.
        self.fx.file(
            "etc/apache2/sites-available/other.conf",
            f"<VirtualHost 127.0.0.1:18090>\n"
            f"    DocumentRoot {self.fx.root}/var/www/other\n"
            f"</VirtualHost>\n",
        )
        (self.fx.root / "etc/apache2/sites-enabled/other.conf").symlink_to("../sites-available/other.conf")

        res = self.fx.run_helper("apache_app_prepare_maintenance_vhost organizr 18086 /")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        lines = res.stdout.splitlines()
        self.assertIn("MODE=maintenance", lines)
        self.assertIn("HAS_SITE=1", lines)
        self.assertIn("PROBE=http://127.0.0.1:18086/organizr/\torganizr.example.test", lines)
        maint_text = (self.fx.root / "etc/apache2/sites-available/aetherflow-organizr-maintenance.conf").read_text()
        self.assertIn("ServerName organizr.example.test", maint_text)
        self.assertIn("ServerAlias org.example.test", maint_text)
        self.assertIn("RedirectMatch 503 ^", maint_text)
        self.assertIn('X-AetherFlow-Maintenance "organizr"', maint_text)
        self.assertNotIn("DocumentRoot", maint_text)
        self.assertNotIn("Alias /organizr", maint_text)

        # 2. External shared vhost aliasing /srv/rutorrent forces safe fallback and never mutates the unrelated vhost.
        self.fx.file(
            "etc/apache2/sites-available/rutorrent.conf",
            f"<VirtualHost 127.0.0.1:18087>\n"
            f"    DocumentRoot {self.fx.root}/var/www/rutorrent\n"
            f"</VirtualHost>\n",
        )
        (self.fx.root / "etc/apache2/sites-enabled/rutorrent.conf").symlink_to("../sites-available/rutorrent.conf")
        shared_seedbox = self.fx.file(
            "etc/apache2/sites-enabled/aliases-seedbox.conf",
            f'Alias /rutorrent "{self.fx.root}/srv/rutorrent"\n',
        )
        (self.fx.root / "active-apache2").touch()
        backup_dir = self.fx.root / "var/backups/aetherflow-recovery/fallback-test"
        backup_dir.mkdir(parents=True, exist_ok=True)
        res_ext = self.fx.run_helper(
            f'apache_app_enter_maintenance rutorrent 18087 / "{backup_dir}"\n'
            f'printf "MODE=%s STOPPED=%s\\n" "$AF_APACHE_QUIESCE_MODE" "${{APACHE_STOPPED:-false}}"'
        )
        self.assertEqual(res_ext.returncode, 0, res_ext.stdout + res_ext.stderr)
        self.assertIn("MODE=stopped STOPPED=true", res_ext.stdout)
        self.assertIn("aliases-seedbox.conf", res_ext.stderr)
        self.assertEqual(shared_seedbox.read_text(), f'Alias /rutorrent "{self.fx.root}/srv/rutorrent"\n')
        self.assertFalse((self.fx.root / "active-apache2").exists())
        shared_seedbox.unlink()

        # 3. Symlinked sites-available/<app>.conf or escaping sites-enabled/<app>.conf fails closed (no fallback bypass).
        evil = self.fx.file("tmp/evil-vhost.conf", "<VirtualHost 127.0.0.1:18086>\n</VirtualHost>\n")
        site_link.unlink()
        site_link.symlink_to(evil)
        (self.fx.root / "active-apache2").touch()
        res_sym = self.fx.run_helper(
            f'apache_app_enter_maintenance organizr 18086 / "{backup_dir}"'
        )
        self.assertNotEqual(res_sym.returncode, 0)
        self.assertTrue((self.fx.root / "active-apache2").exists())

        # 4. Legacy conf-enabled/<app>.conf alias is detached during maintenance and restored on activation.
        site_link.unlink()
        legacy_conf = self.fx.file(
            "etc/apache2/conf-enabled/organizr.conf",
            f'Alias /organizr "{self.fx.root}/var/www/organizr"\n',
        )
        legacy_backup = self.fx.root / "var/backups/aetherflow-recovery/legacy-conf-test"
        legacy_backup.mkdir(parents=True, exist_ok=True)
        res_legacy = self.fx.run_helper(
            f'apache_app_enter_maintenance organizr 18086 / "{legacy_backup}"\n'
            f'test ! -e "{legacy_conf}"\n'
            f'printf "QUIESCE=%s\\n" "$AF_APACHE_QUIESCE_MODE"\n'
            f'apache_app_resume_after_rollback organizr "{legacy_backup}"\n'
            f'test -f "{legacy_conf}"\n'
        )
        self.assertEqual(res_legacy.returncode, 0, res_legacy.stdout + res_legacy.stderr)
        self.assertIn("QUIESCE=maintenance", res_legacy.stdout)
        self.assertEqual(legacy_conf.read_text(), f'Alias /organizr "{self.fx.root}/var/www/organizr"\n')

    @unittest.skipUnless(
        os.path.isfile(REAL_APACHE_BIN) and os.access(REAL_APACHE_BIN, os.X_OK) and bool(REAL_PHP_MODULES),
        "Real nonprivileged Apache 2.4 + mod_php not available on host",
    )
    def test_real_apache_per_app_quiescence_update_and_rollback_keeps_unrelated_vhost_serving(self):
        php_mod = str(REAL_PHP_MODULES[-1])

        def http_get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
            req = urllib.request.Request(url, headers=headers or {})
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as exc:
                return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")

        def run_real_apache_case(app: str, mode: str):
            """Run update (success, readiness-rollback, or occ-upgrade-rollback) against real nonprivileged Apache 2.4."""
            fx = ApacheAppReadinessFixture()
            self.addCleanup(fx.cleanup)

            for cmd in (
                "systemctl", "apache2ctl", "a2ensite", "a2dissite", "a2enmod", "a2dismod",
                "git", "chown", "sudo", "mysql", "mysqldump", "htpasswd", "openssl",
                "hostname", "install", "curl", "apt-get", "id", "getent",
            ):
                p = fx.root / "mock-bin" / cmd
                p.write_text(REAL_APACHE_MOCK_HOST, encoding="utf-8")
                p.chmod(0o755)
            # Use real /bin/sleep for real-Apache reload drain/retry timing.
            (fx.root / "mock-bin" / "sleep").unlink(missing_ok=True)

            app_port = _free_loopback_port()
            proxy_port = _free_loopback_port()
            other_port = _free_loopback_port()

            for rel in ("run/apache2", "var/log/apache2", "var/www/unrelated", f"var/www/{app}"):
                (fx.root / rel).mkdir(parents=True, exist_ok=True)

            fx.file("var/www/unrelated/index.html", "OTHER-VHOST-OK")
            fx.file(
                "etc/apache2/sites-available/unrelated-other.conf",
                f"<VirtualHost 127.0.0.1:{other_port}>\n"
                f"    DocumentRoot {fx.root}/var/www/unrelated\n"
                f"    <Directory {fx.root}/var/www/unrelated>\n"
                f"        Require all granted\n"
                f"    </Directory>\n"
                f"</VirtualHost>\n",
            )
            (fx.root / "etc/apache2/sites-enabled/unrelated-other.conf").symlink_to(
                "../sites-available/unrelated-other.conf"
            )

            # Managed AetherFlow reverse-proxy ingress vhost for the target app (must stay intact & return 503 during maint).
            managed_ingress_text = (
                f"<VirtualHost 127.0.0.1:{proxy_port}>\n"
                f"    ServerName {app}.aether.local\n"
                f"    ProxyPreserveHost On\n"
                f"    ProxyRequests Off\n"
                f"    ProxyPass / http://127.0.0.1:{app_port}/\n"
                f"    ProxyPassReverse / http://127.0.0.1:{app_port}/\n"
                f"</VirtualHost>\n"
            )
            managed_ingress = fx.file(f"etc/apache2/sites-available/aetherflow-app-{app}.conf", managed_ingress_text)
            (fx.root / f"etc/apache2/sites-enabled/aetherflow-app-{app}.conf").symlink_to(
                f"../sites-available/aetherflow-app-{app}.conf"
            )

            # Pre-seed working v1.0.0 app runtime & vhost.
            fx.file(f"install/.{app}.lock", "installed\n")
            fx.file(f"var/www/{app}/.af-version", "1.0.0\n")
            fx.file(f"etc/apache2/conf-available/aetherflow-{app}-listen.conf", f"Listen 127.0.0.1:{app_port}\n")
            (fx.root / f"etc/apache2/conf-enabled/aetherflow-{app}-listen.conf").symlink_to(
                f"../conf-available/aetherflow-{app}-listen.conf"
            )

            auth_headers: dict[str, str] = {}
            readiness_path = "/"
            obs_hook = "chown"
            if app == "organizr":
                fx.file("var/www/organizr/index.php", "<?php echo '<!doctype html><title>Organizr 1.0.0</title>'; ?>\n")
                fx.file("var/www/organizr/api/config/config.php", "<?php return ['retained' => true];\n")
                fx.file("var/www/organizr/api/db/organizr.db", "v1-sqlite\n")
                app_vhost_text = (
                    f"<VirtualHost 127.0.0.1:{app_port}>\n"
                    f"    DocumentRoot {fx.root}/var/www/organizr\n"
                    f'    Alias /organizr "{fx.root}/var/www/organizr"\n'
                    f"    <Directory {fx.root}/var/www/organizr>\n"
                    f"        Options FollowSymLinks\n"
                    f"        AllowOverride All\n"
                    f"        Require all granted\n"
                    f"        DirectoryIndex index.php index.html\n"
                    f"    </Directory>\n"
                    f"</VirtualHost>\n"
                )
            elif app == "rutorrent":
                pw_sha = base64.b64encode(hashlib.sha1(b"test-password").digest()).decode("ascii")
                fx.file("etc/apache2/AetherFlow/rutorrent.htpasswd", f"test-admin:{{SHA}}{pw_sha}\n")
                fx.file("var/www/rutorrent/index.php", "<?php echo '<!doctype html><title>ruTorrent 1.0.0</title>'; ?>\n")
                fx.file("var/www/rutorrent/conf/config.php", '<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n')
                (fx.root / "srv/rutorrent").symlink_to(fx.root / "var/www/rutorrent")
                auth_headers = {
                    "Authorization": "Basic " + base64.b64encode(b"test-admin:test-password").decode("ascii")
                }
                app_vhost_text = (
                    f"<VirtualHost 127.0.0.1:{app_port}>\n"
                    f"    DocumentRoot {fx.root}/var/www/rutorrent\n"
                    f'    Alias /rutorrent "{fx.root}/var/www/rutorrent"\n'
                    f"    <Directory {fx.root}/var/www/rutorrent>\n"
                    f"        Options FollowSymLinks\n"
                    f"        AllowOverride All\n"
                    f"        AuthType Basic\n"
                    f'        AuthName "ruTorrent"\n'
                    f"        AuthUserFile {fx.root}/etc/apache2/AetherFlow/rutorrent.htpasswd\n"
                    f"        Require valid-user\n"
                    f"        DirectoryIndex index.php index.html\n"
                    f"    </Directory>\n"
                    f"</VirtualHost>\n"
                )
            else:  # nextcloud
                readiness_path = "/status.php"
                obs_hook = "occ-upgrade"
                fx.file(
                    "var/www/nextcloud/status.php",
                    '<?php header("Content-Type: application/json"); echo \'{"installed":true,"maintenance":false,"version":"1.0.0"}\'; ?>\n',
                )
                fx.file("var/www/nextcloud/occ", "#!/usr/bin/env php\n")
                fx.file("var/www/nextcloud/version.php", "<?php $OC_VersionString = '1.0.0';\n")
                fx.file(
                    "var/www/nextcloud/config/config.php",
                    f"<?php $CONFIG = ['dbtype' => 'mysql', 'dbname' => 'nextcloud', 'dbhost' => 'localhost', "
                    f"'dbuser' => 'nextclouduser', 'dbpassword' => 'pw', 'datadirectory' => '{fx.root}/var/lib/nextcloud/data'];\n",
                )
                fx.file("var/lib/nextcloud/data/user.txt", "retained-user-file\n")
                with zipfile.ZipFile(fx.root / "nextcloud.zip", "w") as zf:
                    zf.writestr("nextcloud/occ", "#!/usr/bin/env php\n")
                    zf.writestr("nextcloud/version.php", "<?php $OC_VersionString = '2.1.0';\n")
                    if mode == "readiness-rollback":
                        zf.writestr(
                            "nextcloud/status.php",
                            '<?php header("Content-Type: application/json"); echo \'{"installed":true,"maintenance":true,"version":"2.1.0"}\'; ?>\n',
                        )
                    else:
                        zf.writestr(
                            "nextcloud/status.php",
                            '<?php header("Content-Type: application/json"); echo \'{"installed":true,"maintenance":false,"version":"2.1.0"}\'; ?>\n',
                        )
                app_vhost_text = (
                    f"<VirtualHost 127.0.0.1:{app_port}>\n"
                    f"    DocumentRoot {fx.root}/var/www/nextcloud\n"
                    f'    Alias /nextcloud "{fx.root}/var/www/nextcloud/"\n'
                    f"    <Directory {fx.root}/var/www/nextcloud/>\n"
                    f"        Require all granted\n"
                    f"        AllowOverride All\n"
                    f"        Options FollowSymLinks\n"
                    f"    </Directory>\n"
                    f"</VirtualHost>\n"
                )

            app_vhost = fx.file(f"etc/apache2/sites-available/{app}.conf", app_vhost_text)
            (fx.root / f"etc/apache2/sites-enabled/{app}.conf").symlink_to(f"../sites-available/{app}.conf")

            pid_file = fx.root / "run/apache2/apache2.pid"
            apache_conf = fx.file(
                "etc/apache2/apache2.conf",
                f"ServerRoot {fx.root}/etc/apache2\n"
                f"DefaultRuntimeDir {fx.root}/run/apache2\n"
                f"ServerName 127.0.0.1\n"
                f"PidFile {pid_file}\n"
                f"Mutex file:{fx.root}/run/apache2 default\n"
                f"ErrorLog {fx.root}/var/log/apache2/error.log\n"
                f"LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so\n"
                f"LoadModule authn_core_module /usr/lib/apache2/modules/mod_authn_core.so\n"
                f"LoadModule authn_file_module /usr/lib/apache2/modules/mod_authn_file.so\n"
                f"LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so\n"
                f"LoadModule authz_user_module /usr/lib/apache2/modules/mod_authz_user.so\n"
                f"LoadModule auth_basic_module /usr/lib/apache2/modules/mod_auth_basic.so\n"
                f"LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so\n"
                f"LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so\n"
                f"LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so\n"
                f"LoadModule env_module /usr/lib/apache2/modules/mod_env.so\n"
                f"LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so\n"
                f"LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so\n"
                f"LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so\n"
                f"LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so\n"
                f"LoadModule php_module {php_mod}\n"
                f"TypesConfig /etc/mime.types\n"
                f"AddHandler application/x-httpd-php .php\n"
                f"DirectoryIndex index.php index.html\n"
                f"Listen 127.0.0.1:{other_port}\n"
                f"Listen 127.0.0.1:{proxy_port}\n"
                f"IncludeOptional {fx.root}/etc/apache2/conf-enabled/*.conf\n"
                f"IncludeOptional {fx.root}/etc/apache2/sites-enabled/*.conf\n",
            )

            cfg_check = subprocess.run([REAL_APACHE_BIN, "-f", str(apache_conf), "-t"], capture_output=True, text=True)
            self.assertEqual(cfg_check.returncode, 0, cfg_check.stdout + cfg_check.stderr)

            proc = subprocess.Popen(
                [REAL_APACHE_BIN, "-f", str(apache_conf), "-DFOREGROUND"],
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def stop_apache():
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)

            self.addCleanup(stop_apache)

            # Wait until real Apache is serving both v1 target app and unrelated vhost.
            for _ in range(40):
                try:
                    s_other, _, b_other = http_get(f"http://127.0.0.1:{other_port}/")
                    s_app, _, b_app = http_get(f"http://127.0.0.1:{app_port}{readiness_path}", auth_headers)
                    if s_other == 200 and b_other == "OTHER-VHOST-OK" and s_app == 200 and "1.0.0" in b_app:
                        break
                except Exception:
                    pass
                time.sleep(0.1)
            else:
                err_log = (fx.root / "var/log/apache2/error.log").read_text(errors="replace") if (fx.root / "var/log/apache2/error.log").exists() else ""
                self.fail(f"Real Apache did not start cleanly for {app}/{mode}: {err_log}")

            initial_master_pid = int(pid_file.read_text(encoding="utf-8").strip())

            # Continuously poll the unrelated vhost throughout the entire update and rollback.
            stop_polling = threading.Event()
            poll_stats = {"ok": 0, "errors": []}

            def poll_unrelated():
                while not stop_polling.is_set():
                    try:
                        code, _, body = http_get(f"http://127.0.0.1:{other_port}/")
                        if code == 200 and body == "OTHER-VHOST-OK":
                            poll_stats["ok"] += 1
                        else:
                            poll_stats["errors"].append(f"unexpected {code}: {body!r}")
                    except Exception as exc:
                        poll_stats["errors"].append(str(exc))
                    time.sleep(0.02)

            poller = threading.Thread(target=poll_unrelated, daemon=True)
            poller.start()
            try:
                extra_env = {
                    "AF_PACKAGE_ACTION": "update",
                    "AF_FIXTURE_VERSION": "2.1.0",
                    "AF_FIXTURE_BROKEN_PHP": "1" if mode == "readiness-rollback" else "0",
                    "AF_FAIL_OCC_UPGRADE": "1" if mode == "occ-upgrade-rollback" else "0",
                    "AF_READINESS_ATTEMPTS": "2",
                    "AF_QUIESCE_ATTEMPTS": "6",
                    "AF_REAL_APACHE_BIN": REAL_APACHE_BIN,
                    "AF_REAL_APACHE_CONF": str(apache_conf),
                    "AF_APACHE_PIDFILE": str(pid_file),
                    "AF_OBS_HOOK": obs_hook,
                    "AF_OBS_DIRECT_URL": f"http://127.0.0.1:{app_port}{readiness_path}",
                    "AF_OBS_PROXY_URL": f"http://127.0.0.1:{proxy_port}{readiness_path}",
                    "AF_OBS_OTHER_URL": f"http://127.0.0.1:{other_port}/",
                }
                res = fx.run_installer(app, app_port, extra_env)
            finally:
                stop_polling.set()
                poller.join(timeout=5)

            # Unrelated vhost MUST have served 200 OK continuously with ZERO failures and same master PID!
            self.assertGreater(poll_stats["ok"], 0, "Unrelated vhost poller did not execute")
            self.assertEqual(poll_stats["errors"], [], f"{app}/{mode} disrupted unrelated vhost: {poll_stats['errors']}")
            self.assertEqual(int(pid_file.read_text(encoding="utf-8").strip()), initial_master_pid)

            # Global Apache stop or restart MUST NEVER have been called.
            commands = [json.loads(line) for line in (fx.root / "commands.jsonl").read_text().splitlines() if line.strip()]
            self.assertFalse(
                any(c[0] == "systemctl" and len(c) >= 2 and c[1] in ("stop", "restart") and "apache2" in " ".join(c) for c in commands),
                f"{app}/{mode} unexpectedly stopped/restarted global apache2: {commands}",
            )

            # Mid-staging hook MUST have observed 503 maintenance on target app (direct + reverse proxy) and 200 on unrelated vhost.
            obs_file = fx.root / "mid-staging-observations.json"
            self.assertTrue(obs_file.is_file(), f"Mid-staging observation missing for {app}/{mode}: {res.stdout + res.stderr}")
            obs = json.loads(obs_file.read_text(encoding="utf-8"))
            self.assertEqual(obs["direct"]["status"], 503, obs)
            self.assertEqual(obs["direct"]["maint"], app, obs)
            self.assertEqual(obs["proxy"]["status"], 503, obs)
            self.assertEqual(obs["proxy"]["maint"], app, obs)
            self.assertEqual(obs["other"]["status"], 200, obs)
            self.assertEqual(obs["other"]["body"], "OTHER-VHOST-OK", obs)
            self.assertEqual(obs["master_pid"], initial_master_pid, obs)

            # Maintenance stub file MUST always be cleaned up and managed ingress untouched.
            self.assertFalse((fx.root / f"etc/apache2/sites-available/aetherflow-{app}-maintenance.conf").exists())
            self.assertEqual(managed_ingress.read_text(), managed_ingress_text)
            enabled_link = fx.root / f"etc/apache2/sites-enabled/{app}.conf"
            self.assertTrue(enabled_link.is_symlink() and os.path.realpath(enabled_link) == os.path.realpath(app_vhost))

            # Wait briefly for Apache graceful reload to settle before final live HTTP check.
            time.sleep(0.2)
            final_code, _, final_body = http_get(f"http://127.0.0.1:{app_port}{readiness_path}", auth_headers)
            if mode == "success":
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(final_code, 200, final_body)
                self.assertIn("2.1.0", final_body)
                self.assertEqual((fx.root / f"var/www/{app}/.af-version").read_text().strip(), "2.1.0")
            else:
                self.assertNotEqual(res.returncode, 0, f"{app}/{mode} should have failed")
                self.assertNotIn("Rollback incomplete", res.stdout + res.stderr)
                self.assertEqual(final_code, 200, final_body)
                self.assertIn("1.0.0", final_body)
                self.assertEqual((fx.root / f"var/www/{app}/.af-version").read_text().strip(), "1.0.0")
                self.assertEqual(app_vhost.read_text(), app_vhost_text)

        for app, mode in (
            ("organizr", "success"),
            ("organizr", "readiness-rollback"),
            ("rutorrent", "success"),
            ("rutorrent", "readiness-rollback"),
            ("nextcloud", "success"),
            ("nextcloud", "readiness-rollback"),
            ("nextcloud", "occ-upgrade-rollback"),
        ):
            with self.subTest(app=app, mode=mode):
                run_real_apache_case(app, mode)


if __name__ == "__main__":
    unittest.main()
