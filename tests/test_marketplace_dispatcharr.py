"""Run Dispatcharr's generated ASGI wrapper and provisioning code without host changes."""
import asyncio
import contextlib
import json
import os
import shutil
from email.utils import formatdate
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packages/package/install/installpackage-dispatcharr"
SOURCE = INSTALLER.read_text(encoding="utf-8")
WRAPPER = SOURCE.split('cat > "${INSTALL_DIR}/aetherflow_asgi.py" <<\'EOF\'\n', 1)[1].split('\nEOF', 1)[0]


class FakeStreamingHttpResponse:
    """Mirrors the parts of Django's StreamingHttpResponse the wrapper relies on."""

    def __init__(self, content):
        try:
            self._iterator = iter(content)
            self.is_async = False
        except TypeError:
            self._iterator = aiter(content)
            self.is_async = True

    def make_bytes(self, value):
        return bytes(value)

    @property
    def streaming_content(self):
        if self.is_async:
            async def wrapper():
                async for part in self._iterator:
                    yield self.make_bytes(part)
            return wrapper()
        return map(self.make_bytes, self._iterator)


def fake_dispatcharr_modules(application, runtime_roles=frozenset({"uwsgi", "gunicorn"})):
    """Return (sys.modules overrides, response class, runtime module) for loading the wrapper."""
    upstream = types.ModuleType("dispatcharr.asgi")
    upstream.application = application
    response_class = type("StreamingHttpResponse", (FakeStreamingHttpResponse,), {})
    django_http = types.ModuleType("django.http")
    django_http.StreamingHttpResponse = response_class
    modules = {
        "dispatcharr": types.ModuleType("dispatcharr"), "dispatcharr.asgi": upstream,
        "django": types.ModuleType("django"), "django.http": django_http,
    }
    runtime = None
    if runtime_roles is not None:
        names = ("apps", "apps.proxy", "apps.proxy.live_proxy", "apps.proxy.live_proxy.runtime")
        packages = [types.ModuleType(name) for name in names]
        for parent, child in zip(packages, packages[1:]):
            setattr(parent, child.__name__.rsplit(".", 1)[1], child)
        runtime = packages[-1]
        runtime._RUNTIME_ROLES = runtime_roles
        modules.update(zip(names, packages))
    return modules, response_class, runtime


def load_wrapper(path, modules, environment=None):
    namespace = {"__file__": str(path)}
    with patch.dict(sys.modules, modules), patch.dict(os.environ, environment or {}):
        exec(compile(WRAPPER, namespace["__file__"], "exec"), namespace)
    return namespace


class DispatcharrStaticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.install = self.root / "install"
        self.install.mkdir()
        self.forwarded = []

        async def django_application(scope, receive, send):
            self.forwarded.append(scope)
            await send({"type": "http.response.start", "status": 418, "headers": []})
            await send({"type": "http.response.body", "body": b"django"})

        modules, self.response_class, self.runtime = fake_dispatcharr_modules(django_application)
        self.wrapper = load_wrapper(self.install / "aetherflow_asgi.py", modules, {
            "DATA_DIR": str(self.root / "data"),
            "LOGOS_DIR": str(self.root / "custom-logos"),
        })
        self.wrapper["DATA_LOGO_DIR"] = self.root / "compat-data/logos"

    def file(self, relative, body):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def request(self, path, method="GET", scope_type="http"):
        messages = []

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            messages.append(message)

        asyncio.run(self.wrapper["application"]({
            "type": scope_type, "method": method, "path": path,
        }, receive, send))
        return messages

    def assert_file(self, path, body, content_type, method="GET"):
        messages = self.request(path, method)
        self.assertEqual(messages[0]["status"], 200)
        headers = dict(messages[0]["headers"])
        self.assertEqual(headers[b"content-type"], content_type.encode())
        self.assertEqual(headers[b"content-length"], str(len(body)).encode())
        self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
        self.assertEqual(b"".join(message["body"] for message in messages[1:]), body if method == "GET" else b"")
        self.assertFalse(messages[-1]["more_body"])
        self.assertEqual(self.forwarded, [])
        return messages

    def test_assets_use_collected_files_before_vite_dist(self):
        self.file("install/static/assets/app.js", b"collected")
        self.file("install/frontend/dist/assets/app.js", b"vite")
        self.assert_file("/assets/app.js", b"collected", "application/javascript")
        self.assert_file("/static/assets/app.js", b"collected", "application/javascript")
        (self.install / "static/assets/app.js").unlink()
        self.assert_file("/assets/app.js", b"vite", "application/javascript")

    def test_static_types_and_root_public_files(self):
        for relative, url, content_type in (
            ("static/admin/base.css", "/static/admin/base.css", "text/css"),
            ("static/site.webmanifest", "/static/site.webmanifest", "application/manifest+json"),
            ("frontend/dist/logo.png", "/logo.png", "image/png"),
            ("frontend/dist/favicon.ico", "/favicon.ico", "image/vnd.microsoft.icon"),
            ("static/site.webmanifest", "/site.webmanifest", "application/manifest+json"),
            ("static/assets/font.woff2", "/assets/font.woff2", "font/woff2"),
            ("static/assets/unknown.afbinary", "/assets/unknown.afbinary", "application/octet-stream"),
        ):
            with self.subTest(url=url):
                self.file("install/" + relative, b"file body")
                self.assert_file(url, b"file body", content_type)

    def test_logos_try_configured_data_and_compatibility_roots(self):
        custom = self.file("custom-logos/channel.svg", b"custom")
        data = self.file("data/logos/channel.svg", b"data")
        self.file("compat-data/logos/channel.svg", b"compatibility")
        self.assert_file("/logos/channel.svg", b"custom", "image/svg+xml")
        custom.unlink()
        self.assert_file("/logos/channel.svg", b"data", "image/svg+xml")
        data.unlink()
        self.assert_file("/logos/channel.svg", b"compatibility", "image/svg+xml")

    def test_get_streams_large_files_and_head_only_sends_headers(self):
        body = b"x" * (65536 * 3 + 17)
        self.file("data/logos/large.png", body)
        messages = self.assert_file("/logos/large.png", body, "image/png")
        chunks = [message["body"] for message in messages[1:] if message["body"]]
        self.assertGreater(len(chunks), 1)
        self.assertLessEqual(max(map(len, chunks)), 65536)
        messages = self.assert_file("/logos/large.png", body, "image/png", "HEAD")
        self.assertEqual(len(messages), 2)

    def test_logos_revalidate_while_static_assets_keep_long_cache(self):
        logo = self.file("data/logos/channel.png", b"logo")
        os.utime(logo, (1700000000, 1700000000))
        for method in ("GET", "HEAD"):
            headers = dict(self.request("/logos/channel.png", method)[0]["headers"])
            self.assertEqual(headers[b"cache-control"], b"public, max-age=300, must-revalidate")
            self.assertEqual(headers[b"last-modified"], formatdate(1700000000, usegmt=True).encode())
        self.file("install/static/assets/app.js", b"bundle")
        for url in ("/assets/app.js", "/static/assets/app.js"):
            headers = dict(self.request(url)[0]["headers"])
            self.assertEqual(headers[b"cache-control"], b"public, max-age=86400")
            self.assertNotIn(b"last-modified", headers)

    def test_empty_file_is_a_complete_response(self):
        self.file("install/static/empty.css", b"")
        self.assert_file("/static/empty.css", b"", "text/css")

    def test_traversal_absolute_paths_and_symlinks_do_not_escape_roots(self):
        secret = self.file("secret", b"secret")
        sibling = self.file("install/static-other/private.js", b"private")
        assets = self.install / "static/assets"
        assets.mkdir(parents=True)
        (assets / "secret.js").symlink_to(secret)
        (self.install / "static/sibling.js").symlink_to(sibling)
        self.file("data/private.png", b"private logo")
        for path in (
            "/assets/../../../secret", "/assets/secret.js", "/static/sibling.js",
            "/static/../../secret", "/assets//" + str(secret),
            "/logos/../private.png", "/static/\x00invalid", "/assets/",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0]["status"], 418)

    def test_asgi_paths_are_not_url_decoded_twice(self):
        self.file("install/static/assets/literal%20name.js", b"literal percent filename")
        self.assert_file("/assets/literal%20name.js", b"literal percent filename", "application/javascript")

    def test_missing_files_methods_and_routes_fall_through_to_django(self):
        self.file("install/static/assets/app.js", b"bundle")
        self.file("install/frontend/dist/index.html", b"index")
        for path, method, scope_type in (
            ("/assets/missing.js", "GET", "http"),
            ("/assets/app.js", "POST", "http"),
            ("/assets/app.js", "GET", "websocket"),
            ("/", "GET", "http"),
            ("/index.html", "GET", "http"),
            ("/api/accounts/me/", "GET", "http"),
            ("/channels", "HEAD", "http"),
        ):
            with self.subTest(path=path, method=method, scope_type=scope_type):
                self.assertEqual(self.request(path, method, scope_type)[0]["status"], 418)
        self.assertEqual(len(self.forwarded), 7)

    def test_file_disappearing_before_open_falls_through_without_static_headers(self):
        self.file("install/static/assets/app.js", b"bundle")
        with patch.object(Path, "open", side_effect=FileNotFoundError):
            messages = self.request("/assets/app.js")
        self.assertEqual([m["status"] for m in messages if m["type"] == "http.response.start"], [418])


class DispatcharrLiveStreamTests(unittest.TestCase):
    """Daphne must deliver Dispatcharr's endless sync TS generators chunk by chunk."""

    def setUp(self):
        async def django_application(scope, receive, send):
            raise AssertionError("not used")

        modules, self.response_class, self.runtime = fake_dispatcharr_modules(django_application)
        self.wrapper = load_wrapper(Path(tempfile.gettempdir()) / "aetherflow_asgi.py", modules)

    def test_endless_sync_generator_is_sent_incrementally_and_closed_on_disconnect(self):
        produced = []
        closed = threading.Event()

        def endless():
            try:
                while True:
                    produced.append(1)
                    yield b"chunk"
            finally:
                closed.set()

        async def client():
            body = self.response_class(endless()).__aiter__()
            parts = [await body.__anext__() for _ in range(3)]
            await body.aclose()  # Django's aclosing() on client disconnect
            return parts

        self.assertEqual(asyncio.run(client()), [b"chunk"] * 3)
        self.assertTrue(closed.wait(5), "generator cleanup (GeneratorExit) never ran")
        self.assertLess(len(produced), 10, "response body was drained instead of streamed")

    def test_disconnect_during_blocking_read_closes_generator_after_read_returns(self):
        reading, release, closed = threading.Event(), threading.Event(), threading.Event()

        def stream():
            try:
                yield b"first"
                reading.set()
                release.wait(5)
                yield b"second"
            finally:
                closed.set()

        async def client():
            body = self.response_class(stream()).__aiter__()
            first = await body.__anext__()
            blocked = asyncio.ensure_future(body.__anext__())
            await asyncio.to_thread(reading.wait, 5)
            blocked.cancel()  # Django cancels the response task on http.disconnect
            with contextlib.suppress(asyncio.CancelledError):
                await blocked
            await body.aclose()
            return first

        self.assertEqual(asyncio.run(client()), b"first")
        self.assertFalse(closed.is_set(), "closed a generator that was still executing")
        release.set()
        self.assertTrue(closed.wait(5))

    def test_async_streaming_content_passes_through(self):
        async def parts():
            yield b"a"
            yield b"b"

        async def client():
            return [part async for part in self.response_class(parts())]

        self.assertEqual(asyncio.run(client()), [b"a", b"b"])

    def test_generator_errors_propagate_to_the_handler(self):
        def broken():
            yield b"ok"
            raise RuntimeError("upstream failed")

        async def client():
            return [part async for part in self.response_class(broken())]

        with self.assertRaisesRegex(RuntimeError, "upstream failed"):
            asyncio.run(client())

    def test_daphne_runs_live_proxy_runtime_and_is_enabled_before_django_setup(self):
        self.assertEqual(self.runtime._RUNTIME_ROLES, frozenset({"uwsgi", "gunicorn", "daphne"}))
        self.assertLess(WRAPPER.index("_RUNTIME_ROLES"), WRAPPER.index("from dispatcharr.asgi import"))

    def test_wrapper_loads_when_dispatcharr_drops_the_runtime_module(self):
        async def django_application(scope, receive, send):
            raise AssertionError("not used")

        modules, _, runtime = fake_dispatcharr_modules(django_application, runtime_roles=None)
        self.assertIsNone(runtime)
        with self.assertLogs("aetherflow.asgi", "WARNING"):
            wrapper = load_wrapper(Path(tempfile.gettempdir()) / "aetherflow_asgi.py", modules)
        self.assertIn("application", wrapper)


class DispatcharrProvisioningTests(unittest.TestCase):
    def test_admin_credentials_survive_shell_and_python_boundaries(self):
        block = SOURCE.split('if [[ -f "${INSTALL_DIR}/manage.py" ]]; then\n', 1)[1].split('\nfi', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "env/bin").mkdir(parents=True)
            (root / "env/bin/python").symlink_to(sys.executable)
            (root / "dispatcharr.env").write_text("DJANGO_SETTINGS_MODULE=dispatcharr.settings\n")
            su = root / "su"
            su.write_text('#!/bin/bash\nexec bash -c "${@: -1}"\n')
            su.chmod(0o755)
            (root / "manage.py").write_text('''import contextlib, json, os, sys, types
if sys.argv[1] != "shell":
    sys.exit(0)
class User:
    is_active = False
    def set_password(self, password):
        self.password = password
    def save(self):
        with open(os.environ["RESULT"], "w") as result:
            json.dump(vars(self), result)
user = User()
def get_or_create(**kwargs):
    user.username = kwargs["username"]
    return user, False
model = types.SimpleNamespace(objects=types.SimpleNamespace(get_or_create=get_or_create))
auth = types.ModuleType("django.contrib.auth")
auth.get_user_model = lambda: model
db = types.ModuleType("django.db")
db.transaction = types.SimpleNamespace(atomic=contextlib.nullcontext)
sys.modules.update({"django": types.ModuleType("django"), "django.contrib": types.ModuleType("django.contrib"), "django.contrib.auth": auth, "django.db": db})
exec(sys.stdin.read())
''')
            credentials = {
                "ADMIN_USER": 'user\'"\\$`name',
                "ADMIN_EMAIL": 'mail\'"\\$@localhost',
                "ADMIN_PASS": f"single' double\" backslash\\ dollar$ `touch {root}/injected` $(touch {root}/injected)\nnewline",
            }
            result = subprocess.run(["bash", "-eu", "-c", block], text=True, capture_output=True, env={
                **os.environ, **credentials, "PATH": str(root) + ":" + os.environ["PATH"],
                "APP_USER": "dispatcharr", "INSTALL_DIR": str(root), "CONFIG_DIR": str(root),
                "LOGFILE": str(root / "log"), "RESULT": str(root / "result.json"),
            }, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr + (root / "log").read_text())
            user = json.loads((root / "result.json").read_text())
            self.assertEqual(user["username"], credentials["ADMIN_USER"])
            self.assertEqual(user["email"], credentials["ADMIN_EMAIL"])
            self.assertEqual(user["password"], credentials["ADMIN_PASS"])
            self.assertEqual(user["user_level"], 10)
            for flag in ("is_staff", "is_superuser", "is_active"):
                self.assertIs(user[flag], True)
            self.assertFalse((root / "injected").exists())


UPGRADE_MOCK = r'''#!/usr/bin/python3
import os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
command, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
failure = os.environ.get("FAIL_STAGE", "")
with (root / "commands").open("a") as log:
    log.write(command + " " + " ".join(args) + "\n")
if command == "git":
    if failure == "clone":
        sys.exit(1)
    sys.exit(subprocess.run(["/usr/bin/git", *args]).returncode)
elif command == "python3.13":
    if args[:2] == ["-m", "venv"]:
        if failure == "venv":
            sys.exit(1)
        venv = pathlib.Path(args[-1])
        (venv / "bin").mkdir(parents=True)
        for binary in ("python", "pip"):
            shutil.copyfile(__file__, venv / "bin" / binary)
            (venv / "bin" / binary).chmod(0o755)
        (venv / "bin/daphne").write_text("#!" + str(venv / "bin/python") + "\n")
elif command == "pip":
    if failure == "pip":
        sys.exit(1)
elif command == "python":
    if args[:2] == ["manage.py", "migrate"]:
        (root / "database").write_text("new-schema")
        if failure == "migrate":
            sys.exit(1)
    elif args[:2] == ["manage.py", "collectstatic"]:
        assert "--clear" in args
        if failure == "collectstatic":
            sys.exit(1)
        static = root / "opt/dispatcharr/static"
        static.mkdir()
        (static / "built").write_text("collected")
elif command == "npm":
    if failure == "npm" or failure == "build" and args == ["run", "build"]:
        sys.exit(1)
    if args == ["run", "build"]:
        dist = pathlib.Path.cwd() / "dist"
        assert not dist.exists(), "stale frontend output survived"
        dist.mkdir()
        (dist / "app.js").write_text("new-bundle")
elif command == "su":
    if args[:2] == ["-", "postgres"]:
        if "pg_dump" in args[-1]:
            print((root / "database").read_text(), end="")
        elif "pg_restore" in args[-1]:
            (root / "database").write_text(sys.stdin.read())
    else:
        sys.exit(subprocess.run(["bash", "-ec", args[-1]]).returncode)
elif command == "systemctl":
    units = [arg for arg in args[1:] if arg.endswith(".service")]
    if args[0] == "is-active":
        sys.exit(0 if (root / ("active-" + units[0])).exists() else 3)
    elif args[0] == "stop":
        for unit in units:
            (root / ("active-" + unit)).unlink(missing_ok=True)
    elif args[0] in ("start", "enable"):
        if failure == "systemctl" and args[0] == "enable" and "dispatcharr.service" in units:
            sys.exit(1)
        for unit in units:
            (root / ("active-" + unit)).touch()
elif command not in ("apt-get", "chown", "id", "useradd"):
    raise RuntimeError((command, args))
'''


class DispatcharrUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        self.git(self.upstream, "init", "--initial-branch=main")
        for relative in ("pyproject.toml", "requirements.txt", "manage.py", "frontend/package.json", "frontend/dist/stale"):
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("upstream-code")
        self.git(self.upstream, "add", ".")
        self.git(self.upstream, "commit", "-m", "new")
        self.git(self.upstream, "tag", "v0.33.0")
        self.target = self.git(self.upstream, "rev-parse", "HEAD").stdout.strip()
        commands = self.root / "bin"
        commands.mkdir()
        for name in ("git", "python3.13", "su", "npm", "systemctl", "apt-get", "chown", "id", "useradd"):
            binary = commands / name
            binary.write_text(UPGRADE_MOCK)
            binary.chmod(0o755)
        common = self.root / "opt/AetherFlow/packages/common.sh"
        common.parent.mkdir(parents=True)
        common.write_text('''require_root() { :; }
load_master_credentials() { MASTER_USER=admin; MASTER_PASS='testpass'; }
report_progress() { :; }
log_info() { :; }
log_warn() { :; }
log_error() { printf '%s\\n' "$*" >&2; }
ensure_node() { printf 'node %s\\n' "$1" >> "$TEST_ROOT/commands"; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
''')
        self.install = self.root / "opt/dispatcharr"
        self.config = self.root / "etc/dispatcharr"
        self.config.mkdir(parents=True)
        (self.config / "dispatcharr.env").write_text("old-env")
        (self.config / "db_pass").write_text("a" * 32)
        (self.config / "secret_key").write_text("b" * 64)
        (self.root / "database").write_text("old-schema")
        self.units = self.root / "etc/systemd/system"
        self.units.mkdir(parents=True)
        for unit in ("dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat"):
            (self.units / (unit + ".service")).write_text("old-unit")
            (self.root / ("active-" + unit + ".service")).touch()
        for relative in (".git/hooks/post-checkout", "env/bin/pip", "media/retained", "logo_cache/retained", "old-code"):
            path = self.install / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/bash\ntouch '" + str(self.root / "compromised") + "'\n" if relative in ("env/bin/pip", ".git/hooks/post-checkout") else "retained")
            path.chmod(0o755)

    def git(self, directory, *args):
        result = subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@localhost",
                                 "-C", str(directory), *args], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def run_install(self, **environment):
        source = SOURCE
        for prefix in ("/opt/", "/etc/", "/var/", "/data"):
            source = source.replace(prefix, str(self.root) + prefix)
        source = source.replace(" /install", " " + str(self.root / "install"))
        script = self.root / "installer.sh"
        script.write_text(source)
        result = subprocess.run(["bash", str(script)], text=True, capture_output=True, env={
            **os.environ, "PATH": str(self.root / "bin") + ":" + os.environ["PATH"],
            "TEST_ROOT": str(self.root), "AF_TARGET_VERSION": "v0.33.0", "AF_APP_PORT": "19200",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.{self.upstream}.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/Dispatcharr/Dispatcharr.git",
            **environment,
        }, timeout=30)
        return result

    def test_fresh_canonical_build_never_executes_old_hooks_or_pip(self):
        for attempt in range(2):
            old_env_inode = (self.config / "dispatcharr.env").stat().st_ino
            result = self.run_install()
            self.assertEqual(result.returncode, 0, result.stderr + (self.root / "var/log/aetherflow/install-dispatcharr.log").read_text())
            self.assertFalse((self.root / "compromised").exists())
            self.assertNotEqual((self.config / "dispatcharr.env").stat().st_ino, old_env_inode)
            self.assertEqual(self.git(self.install, "rev-parse", "HEAD").stdout.strip(), self.target)
            self.assertEqual((self.install / "media/retained").read_text(), "retained")
            self.assertEqual((self.install / "logo_cache/retained").read_text(), "retained")
            self.assertEqual((self.install / "env/bin/daphne").read_text().strip(), "#!" + str(self.install / "env/bin/python"))
            self.assertEqual((self.install / "frontend/dist/app.js").read_text(), "new-bundle")
            self.assertTrue((self.install / "static/built").exists())
        commands = (self.root / "commands").read_text()
        self.assertIn("node 22", commands)
        self.assertNotIn("-r " + str(self.install / "requirements.txt"), commands)
        self.assertNotIn("chown -R dispatcharr:dispatcharr " + str(self.install) + "\n", commands)
        service = (self.units / "dispatcharr.service").read_text()
        self.assertIn('"$${DISPATCHARR_PORT:-9191}"', service)
        self.assertIn("TimeoutStopSec=15", service)
        self.assertIn("-Q celery,dvr", (self.units / "dispatcharr-celery.service").read_text())

    def test_every_failed_stage_restores_tree_environment_database_and_services(self):
        for stage in ("clone", "venv", "pip", "npm", "build", "migrate", "collectstatic", "systemctl"):
            with self.subTest(stage=stage):
                result = self.run_install(FAIL_STAGE=stage)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.install / "old-code").read_text(), "retained")
                self.assertEqual((self.config / "dispatcharr.env").read_text(), "old-env")
                self.assertEqual((self.root / "database").read_text(), "old-schema")
                self.assertFalse((self.root / "install/.dispatcharr.lock").exists())
                for unit in self.units.iterdir():
                    self.assertEqual(unit.read_text(), "old-unit")
                    self.assertTrue((self.root / ("active-" + unit.name)).exists())
        self.assertFalse((self.root / "compromised").exists())

    def test_first_install_without_prior_tree_or_services_succeeds(self):
        shutil.rmtree(self.install)
        shutil.rmtree(self.config)
        for unit in self.units.iterdir():
            (self.root / ("active-" + unit.name)).unlink()
            unit.unlink()
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.install / ".af-version").read_text().strip(), "0.33.0")
        self.assertTrue((self.root / "install/.dispatcharr.lock").exists())
        self.assertNotIn("systemctl stop dispatcharr", (self.root / "commands").read_text())

    def test_missing_release_tag_keeps_existing_services_running(self):
        result = self.run_install(AF_TARGET_VERSION="v999.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.install / "old-code").read_text(), "retained")
        self.assertNotIn("systemctl stop dispatcharr", (self.root / "commands").read_text())

    def test_canonical_data_migrates_legacy_files_without_chowning_shared_root(self):
        legacy = self.root / "var/lib/dispatcharr"
        (legacy / "logos").mkdir(parents=True)
        (legacy / "logos/channel.png").write_text("legacy-logo")
        shared = self.root / "data"
        shared.symlink_to(legacy, target_is_directory=True)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(shared.is_symlink())
        self.assertEqual((shared / "logos/channel.png").resolve(), shared / "logos/channel.png")
        self.assertEqual((legacy / "logos/channel.png").read_text(), "legacy-logo")
        self.assertTrue((legacy / "logos").is_symlink())
        retained = shared / "unrelated"
        retained.write_text("other-app")
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual(retained.read_text(), "other-app")
        self.assertNotIn("chown -R dispatcharr:dispatcharr " + str(shared) + "\n", (self.root / "commands").read_text())

    def test_unrelated_data_symlinks_are_rejected_and_preserved(self):
        shared = self.root / "data"
        target = self.root / "other-app"
        target.mkdir()
        (target / "keep").write_text("untouched")
        shared.symlink_to(target, target_is_directory=True)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated symlink", result.stderr)
        self.assertTrue(shared.is_symlink())
        self.assertEqual((target / "keep").read_text(), "untouched")
        self.assertEqual((self.install / "old-code").read_text(), "retained")

    def test_invalid_port_is_rejected_before_writing_shell_environment(self):
        for port in ("70000", "0", "9191; touch injected", "$(touch injected)"):
            with self.subTest(port=port):
                result = self.run_install(AF_APP_PORT=port)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid Dispatcharr port", result.stderr)
                self.assertEqual((self.config / "dispatcharr.env").read_text(), "old-env")

    def test_canonical_data_subdirectory_symlinks_are_not_followed(self):
        target = self.root / "other-app"
        target.mkdir()
        (target / "keep").write_text("untouched")
        link = self.root / "data/logos"
        link.parent.mkdir()
        link.symlink_to(target)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a real directory", result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertEqual((target / "keep").read_text(), "untouched")

    def test_stored_secrets_are_whitespace_stripped_and_hex_validated(self):
        for db_pass, secret in (("  " + "A" * 32 + "\n", "\t" + "B" * 64 + "\n"), ("x'; touch /tmp/pwn; #", "not-hex"), ("f" * 129, "e" * 129)):
            with self.subTest(db_pass=db_pass):
                (self.config / "db_pass").write_text(db_pass)
                (self.config / "secret_key").write_text(secret)
                result = self.run_install()
                self.assertEqual(result.returncode, 0, result.stderr)
                stored_pass = (self.config / "db_pass").read_text().strip()
                stored_secret = (self.config / "secret_key").read_text().strip()
                self.assertRegex(stored_pass, r"^[a-fA-F0-9]{16,128}$")
                self.assertRegex(stored_secret, r"^[a-fA-F0-9]{32,128}$")
                if db_pass.strip() == "A" * 32:
                    self.assertEqual(stored_pass, db_pass.strip())
                    self.assertEqual(stored_secret, secret.strip())


if __name__ == "__main__":
    unittest.main()
