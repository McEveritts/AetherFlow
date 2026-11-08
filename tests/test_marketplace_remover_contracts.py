import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, replace_paths_once


REMOVE_DIR = ROOT / "packages/package/remove"

def production_functions(*names):
    if 'safe_rm_rf' in names:
        names = tuple(dict.fromkeys((*names, 'validate_config_paths', 'safe_config_python')))
    source = (ROOT / "packages/common.sh").read_text()
    functions = []
    for name in names:
        start = source.index(f"\n{name}() ") + 1
        function_lines = []
        in_heredoc = False
        for line in source[start:].splitlines(keepends=True):
            function_lines.append(line)
            if in_heredoc:
                if line.rstrip("\n") == "PYEOF":
                    in_heredoc = False
            elif "<<'PYEOF'" in line:
                in_heredoc = True
            elif line in ("}\n", ")\n"):
                break
        functions.append("".join(function_lines))
    return "\n".join(functions)


APT_APPS = {
    "plex": (("plexmediaserver",), ("var/lib/plexmediaserver/library.db", "etc/default/plexmediaserver")),
    "jellyfin": (("jellyfin-server", "jellyfin-web"), ("var/lib/jellyfin/data/library.db", "etc/jellyfin/system.xml")),
    "emby": (("emby-server",), ("var/lib/emby/library.db", "etc/emby-server.conf")),
    "qbittorrent": (("qbittorrent-nox",), ("var/lib/qbittorrent/qBittorrent.conf", "etc/qbittorrent/config")),
    "deluge": (("deluged", "deluge-web", "deluge-console", "deluge-common"), ("var/lib/deluge/core.conf", "etc/deluge/config")),
    "transmission": (("transmission-daemon", "transmission-cli", "transmission-common"), ("var/lib/transmission-daemon/resume/torrent", "etc/transmission-daemon/settings.json")),
    "syncthing": (("syncthing",), ("var/lib/syncthing/config.xml", "etc/syncthing/config")),
    "fail2ban": (("fail2ban",), ("var/lib/fail2ban/fail2ban.sqlite3", "etc/fail2ban/jail.local")),
    "znc": (("znc",), ("var/lib/znc/configs/znc.conf", "etc/znc/config")),
    "mergerfs": (("mergerfs",), ("var/lib/mergerfs/state", "etc/mergerfs/config")),
}

RUNTIME_APPS = {
    "overseerr": (
        ("opt/overseerr/dist/index.js", "opt/overseerr/node_modules/app/index.js", "opt/overseerr/.next/server/app.js"),
        ("opt/overseerr/config/settings.json", "var/lib/overseerr/db/db.sqlite3"),
    ),
    "jellyseerr": (
        ("opt/jellyseerr/dist/index.js", "opt/jellyseerr/node_modules/app/index.js", "opt/jellyseerr/.runtime/bin/node"),
        ("opt/jellyseerr/config/settings.json", "var/lib/jellyseerr/db/db.sqlite3"),
    ),
    "uptimekuma": (
        ("opt/uptime-kuma/server/server.js", "opt/uptime-kuma/node_modules/app/index.js", "opt/uptime-kuma/dist/index.html"),
        ("opt/uptime-kuma/data/kuma.db", "opt/uptime-kuma/.env"),
    ),
    "kavita": (
        ("opt/Kavita/Kavita", "opt/Kavita/Kavita.dll", "opt/Kavita/libhostfxr.so", "opt/Kavita/wwwroot/index.html"),
        ("opt/Kavita/config/kavita.db", "opt/Kavita/config/appsettings.json", "var/lib/kavita/library.db"),
    ),
    "librespeed": (
        ("opt/librespeed/speedtest-backend", "opt/librespeed/speedtest-go", "opt/librespeed/assets/index.html"),
        ("opt/librespeed/settings.toml", "opt/librespeed/speedtest.db", "opt/librespeed/speedtest.db-wal"),
    ),
    "scrutiny": (
        ("opt/scrutiny/bin/scrutiny-web", "opt/scrutiny/bin/scrutiny-collector"),
        ("var/lib/scrutiny/scrutiny.db", "etc/scrutiny/scrutiny.yaml"),
    ),
    "paperless-ngx": (
        ("opt/paperless/src/manage.py", "opt/paperless/.venv/bin/python", "opt/paperless/static/app.js"),
        ("opt/paperless/data/db.sqlite3", "opt/paperless/media/document.pdf", "opt/paperless/paperless.conf", "var/lib/paperless/consume/document.pdf", "etc/paperless.conf"),
    ),
    "adguardhome": (
        ("opt/AdGuardHome/AdGuardHome", "opt/AdGuardHome/.af-version"),
        ("opt/AdGuardHome/AdGuardHome.yaml", "opt/AdGuardHome/data/filters/filter.txt"),
    ),
    "vaultwarden": (
        ("opt/vaultwarden/vaultwarden", "opt/vaultwarden/web-vault/index.html"),
        ("var/lib/vaultwarden/db.sqlite3", "var/lib/vaultwarden/attachments/file", "etc/vaultwarden/vaultwarden.env"),
    ),
    "nextcloud": (
        ("var/www/nextcloud/index.php", "var/www/nextcloud/occ", "var/www/nextcloud/lib/runtime.php", "var/www/html/nextcloud/index.php"),
        ("var/www/nextcloud/config/config.php", "var/www/nextcloud/data/document.txt", "var/www/nextcloud/custom_apps/plugin/config.json", "var/www/nextcloud/themes/custom/logo.png", "var/www/html/nextcloud/config/config.php", "var/lib/nextcloud/data/document.txt"),
    ),
    "rutorrent": (
        ("var/www/rutorrent/index.html", "var/www/rutorrent/php/runtime.php", "var/www/rutorrent/js/app.js", "var/www/rutorrent/vendor/runtime.php", "srv/rutorrent/index.html", "srv/rutorrent/php/runtime.php"),
        ("var/www/rutorrent/share/settings/user.dat", "var/www/rutorrent/conf/config.php", "var/www/rutorrent/plugins/plugin/init.php", "var/www/rutorrent/plugins/plugin/conf.php", "srv/rutorrent/share/torrents/session", "etc/apache2/AetherFlow/rutorrent.htpasswd"),
    ),
    "organizr": (
        ("var/www/organizr/index.php", "var/www/organizr/api/router.php", "var/www/organizr/js/app.js", "var/www/organizr/vendor/runtime.php"),
        ("var/www/organizr/api/config/config.php", "var/www/organizr/api/db/organizr.db", "var/www/organizr/custom.db", "var/www/organizr/custom.db-wal", "var/www/organizr/backup/operator.db"),
    ),
}


FAKE_COMMAND = r'''#!/usr/bin/python3
import fnmatch
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(os.environ["TEST_ROOT"])
program = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with (root / "commands.jsonl").open("a") as output:
    output.write(json.dumps([program, *arguments]) + "\n")
operation = arguments[0] if program in ("systemctl", "pm2") and arguments else program
if operation == os.environ.get("FAIL_OPERATION"):
    sys.exit(1)
if program == "pm2" and operation == "jlist":
    print(os.environ.get("PM2_PROCESSES", '[{"name":"flood"}]'))
if program == "systemctl":
    if operation == "show":
        print(os.environ.get("UNIT_STATE", "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled"))
        sys.exit(int(os.environ.get("SHOW_STATUS", "0")))
    sys.exit(int(os.environ.get("SYSTEMCTL_" + operation.upper().replace("-", "_") + "_STATUS", "0")))
if program in ("apt-get", "dpkg"):
    if any(action in arguments for action in ("remove", "purge", "--remove", "--purge", "-r", "-P")):
        records = json.loads((root / "package-files.json").read_text())
        for package, paths in records.items():
            if any(fnmatch.fnmatchcase(package, argument) for argument in arguments):
                for relative in paths:
                    target = root / relative
                    if target.is_dir() and not target.is_symlink():
                        shutil.rmtree(target)
                    else:
                        target.unlink(missing_ok=True)
    sys.exit(0)
if program == "getent":
    sys.exit(2)
if program == "pgrep":
    sys.exit(1)
if program in ("mountpoint", "fusermount", "umount"):
    state_file = root / "mounts.json"
    mounted = json.loads(state_file.read_text()) if state_file.exists() else []
    target = arguments[-1]
    if program == "mountpoint":
        sys.exit(0 if target in mounted else 1)
    if target in mounted:
        mounted.remove(target)
    state_file.write_text(json.dumps(mounted))
if program == "curl":
    sys.exit(int(os.environ.get("CURL_STATUS", "0")))
if program == "rm":
    for argument in arguments:
        if not argument.startswith("-") and not argument.startswith(str(root) + "/"):
            raise RuntimeError("Refusing non-fixture removal: " + argument)
    sys.exit(subprocess.run(["/bin/rm", *arguments]).returncode)
'''


FAKE_PYTHON_HTTP = r'''#!/usr/bin/python3
import io
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
import urllib.error

if os.environ.get("MOCK_HTTP") != "1":
    os.execv("/usr/bin/python3", ["/usr/bin/python3", *sys.argv[1:]])
root = Path(os.environ["TEST_ROOT"])
config = json.loads((root / "http-config.json").read_text())
completed = bool(config.get("StartupWizardCompleted", False))

def open_request(request, timeout=None):
    global completed
    method = request.get_method()
    path = request.full_url.split("127.0.0.1:", 1)[1].split("/", 1)[1]
    record = {"method": method, "path": "/" + path, "body": json.loads(request.data) if request.data else None}
    with (root / "http-requests.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")
    if os.environ.get("HTTP_UNREACHABLE") == "1" or record["path"] == os.environ.get("HTTP_FAIL_PATH"):
        raise urllib.error.URLError("synthetic endpoint failure")
    if path.startswith("api/"):
        return io.BytesIO(json.dumps(config).encode())
    if path == "System/Info/Public":
        payload = {"StartupWizardCompleted": completed}
    elif path == "Startup/Complete":
        completed = os.environ.get("HTTP_INCOMPLETE") != "1"
        payload = {}
    else:
        payload = {}
    return io.BytesIO(json.dumps(payload).encode())

sys.argv = sys.argv[1:]
with patch("urllib.request.urlopen", side_effect=open_request), patch("time.sleep"):
    exec(compile(sys.stdin.read(), "<production-bootstrap>", "exec"), {"__name__": "__main__"})
'''


class MarketplaceRemoverContractsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "fake-bin"
        self.bin.mkdir()
        for command in ("systemctl", "apt-get", "dpkg", "userdel", "groupdel", "getent", "id", "rm", "killall", "pgrep", "a2dissite", "apache2ctl", "mysql", "mountpoint", "fusermount", "umount", "pm2", "npm", "curl", "sleep"):
            self.file("fake-bin/" + command, FAKE_COMMAND).chmod(0o755)
        self.file("fake-bin/python3", FAKE_PYTHON_HTTP).chmod(0o755)
        self.file("package-files.json", "{}")
        self.file("etc/systemd/system/placeholder.service", "service")
        self.file("var/lib/unrelated/operator-data", "unrelated-data")

    def file(self, relative, content="synthetic-user-data"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def rebase(self, source):
        return replace_paths_once(source, [(prefix, str(self.root) + prefix) for prefix in
                                          ("/etc/", "/var/", "/opt/", "/home/", "/install/", "/usr/local/", "/usr/bin/", "/usr/share/", "/usr/lib/", "/run/", "/srv/", "/mnt/")])

    def run_shell(self, source, helpers=(), **environment):
        preamble = '''set -euo pipefail
require_root() { :; }
log_info() { printf '%s\\n' "$*"; }
log_warn() { printf '%s\\n' "$*" >&2; }
print_info() { printf '%s\\n' "$*"; }
print_error() { printf '%s\\n' "$*" >&2; }
report_progress() { printf '[PROGRESS:%s] %s\\n' "$1" "$2"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
write_lock() { mkdir -p "$TEST_ROOT/install"; touch "$TEST_ROOT/install/.$1.lock"; }
'''
        common = preamble + self.rebase(production_functions(*helpers)) if helpers else preamble
        self.file("packages/common.sh", common)
        return subprocess.run(["bash", "-c", common + "\n" + source], env={
            **os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "TEST_ROOT": str(self.root),
            "LOGFILE": str(self.root / "test.log"), "MASTER_USER": "master-test-user", "MASTER_PASS": "master-test-password",
            **environment,
        }, capture_output=True, text=True, timeout=20)

    def run_remove(self, app, delete_data="false", **environment):
        self.file("packages/package/remove/removepackage-" + app,
                  self.rebase((REMOVE_DIR / ("removepackage-" + app)).read_text()))
        return self.run_shell('bash "$TEST_ROOT/packages/package/remove/removepackage-' + app + '"', helpers=(
            "command_exists", "systemd_unit_inactive", "stop_systemd_unit", "purge_systemd_unit",
            "purge_system_user", "remove_apache_app_listener", "purge_app_archive_backups", "safe_rm_rf",
        ), DELETE_DATA=delete_data, **environment)

    def commands(self):
        path = self.root / "commands.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_all_77_removers_have_safe_shell_and_completion_contracts(self):
        scripts = sorted(REMOVE_DIR.glob("removepackage-*"))
        self.assertEqual(len(scripts), 77)
        for script in scripts:
            with self.subTest(app=script.name):
                self.assertIn("set -euo pipefail", script.read_text())
                self.assertIn("common.sh", script.read_text())
                result = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_apt_binary_removal_and_data_retention_for_all_ten_affected_apps(self):
        for app, (packages, retained) in APT_APPS.items():
            for delete_data in ("false", "true"):
                with self.subTest(app=app, DELETE_DATA=delete_data):
                    records = {package: ["usr/bin/" + package] for package in packages}
                    self.file("package-files.json", json.dumps(records))
                    for paths in records.values():
                        for relative in paths:
                            self.file(relative, "executable-runtime")
                    for relative in retained:
                        self.file(relative)
                    marker = self.file(f"install/.{app}.lock", "installed")
                    before = len(self.commands())
                    result = self.run_remove(app, delete_data)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    commands = self.commands()[before:]
                    action = "purge" if delete_data == "true" else "remove"
                    self.assertTrue(any(command[:2] == ["apt-get", action] for command in commands))
                    for paths in records.values():
                        for relative in paths:
                            self.assertFalse((self.root / relative).exists(), relative)
                    for relative in retained:
                        path = self.root / relative
                        self.assertEqual(path.exists(), delete_data == "false", relative)
                        if path.exists():
                            self.assertEqual(path.read_text(), "synthetic-user-data")
                    self.assertFalse(marker.exists())
                    self.assertEqual((self.root / "var/lib/unrelated/operator-data").read_text(), "unrelated-data")

    def test_runtime_removed_but_all_twelve_apps_retain_state_until_explicit_purge(self):
        for app, (runtime, retained) in RUNTIME_APPS.items():
            for delete_data in ("false", "true"):
                with self.subTest(app=app, DELETE_DATA=delete_data):
                    for relative in runtime:
                        self.file(relative, "executable-runtime")
                    for relative in retained:
                        self.file(relative)
                    marker = self.file(f"install/.{app}.lock", "installed")
                    result = self.run_remove(app, delete_data)
                    if app == "nextcloud" and delete_data == "true":
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        for relative in runtime:
                            self.assertEqual((self.root / relative).read_text(), "executable-runtime", relative)
                        for relative in retained:
                            self.assertEqual((self.root / relative).read_text(), "synthetic-user-data", relative)
                        self.assertTrue(marker.exists())
                        self.assertEqual((self.root / "var/lib/unrelated/operator-data").read_text(), "unrelated-data")
                        continue
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    for relative in runtime:
                        self.assertFalse((self.root / relative).exists(), relative)
                    for relative in retained:
                        path = self.root / relative
                        self.assertEqual(path.exists(), delete_data == "false", relative)
                        if path.exists():
                            self.assertEqual(path.read_text(), "synthetic-user-data")
                    self.assertFalse(marker.exists())
                    self.assertEqual((self.root / "var/lib/unrelated/operator-data").read_text(), "unrelated-data")

    def test_audiobookshelf_cache_metadata_is_persistent_until_explicit_purge(self):
        metadata = ("var/cache/audiobookshelf/metadata/cover.jpg", "var/lib/audiobookshelf/config/settings.json", "etc/audiobookshelf/config")
        for delete_data in ("false", "true"):
            with self.subTest(DELETE_DATA=delete_data):
                for relative in metadata:
                    self.file(relative)
                self.file("usr/lib/audiobookshelf/server.js", "runtime")
                self.file("package-files.json", json.dumps({"audiobookshelf": ["usr/lib/audiobookshelf"]}))
                result = self.run_remove("audiobookshelf", delete_data)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for relative in metadata:
                    self.assertEqual((self.root / relative).exists(), delete_data == "false", relative)
                self.assertFalse((self.root / "usr/lib/audiobookshelf/server.js").exists())

    def test_nzbget_current_runtime_is_removed_without_erasing_legacy_state(self):
        for delete_data in ("false", "true"):
            with self.subTest(DELETE_DATA=delete_data):
                runtime = ("opt/nzbget/nzbget", "opt/nzbget/unrar", "opt/nzbget/webui/index.html")
                retained = ("opt/nzbget/nzbget.conf", "opt/nzbget/downloads/download", "var/lib/nzbget/nzbget.conf", "etc/nzbget.conf")
                for relative in runtime:
                    self.file(relative, "runtime")
                for relative in retained:
                    self.file(relative)
                result = self.run_remove("nzbget", delete_data)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for relative in runtime:
                    self.assertFalse((self.root / relative).exists(), relative)
                for relative in retained:
                    self.assertEqual((self.root / relative).exists(), delete_data == "false", relative)

    def test_static_companion_units_can_be_purged(self):
        for unit in ("scrutiny-collector.service", "recyclarr.service"):
            with self.subTest(unit=unit):
                unit_file = self.file("etc/systemd/system/" + unit, "static-unit")
                result = self.run_shell(f'purge_systemd_unit "{unit}"',
                                        helpers=("systemd_unit_inactive", "stop_systemd_unit", "purge_systemd_unit"),
                                        UNIT_STATE="LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=static",
                                        SYSTEMCTL_DISABLE_STATUS="1", SYSTEMCTL_RESET_FAILED_STATUS="1")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(unit_file.exists())

    def test_failed_units_without_a_main_process_allow_stop_and_purge(self):
        for helper in ("stop_systemd_unit", "purge_systemd_unit"):
            for stop_status in ("0", "1"):
                with self.subTest(helper=helper, stop_status=stop_status):
                    unit_file = self.file("etc/systemd/system/crashed.service", "crashed-unit")
                    before = len(self.commands())
                    result = self.run_shell(f'{helper} crashed.service',
                                            helpers=("systemd_unit_inactive", "stop_systemd_unit", "purge_systemd_unit"),
                                            UNIT_STATE="LoadState=loaded\nActiveState=failed\nMainPID=0\nUnitFileState=disabled",
                                            SYSTEMCTL_STOP_STATUS=stop_status, SYSTEMCTL_RESET_FAILED_STATUS="1")
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    operations = [command[1] for command in self.commands()[before:] if command[0] == "systemctl"]
                    self.assertLess(operations.index("stop"), operations.index("reset-failed"))
                    self.assertEqual(unit_file.exists(), helper == "stop_systemd_unit")

    def test_live_or_unknown_processes_and_enabled_units_still_block_teardown(self):
        for active, main_pid, file_state in (("failed", "1234", "disabled"), ("failed", "", "disabled"), ("active", "0", "disabled"), ("inactive", "0", "enabled")):
            with self.subTest(active=active, main_pid=main_pid, file_state=file_state):
                result = self.run_shell('systemd_unit_inactive unsafe.service true', helpers=("systemd_unit_inactive",),
                                        UNIT_STATE=f"LoadState=loaded\nActiveState={active}\nMainPID={main_pid}\nUnitFileState={file_state}")
                self.assertNotEqual(result.returncode, 0)

    def test_non_enableable_units_are_disabled_equivalents(self):
        for file_state in ("disabled", "static", "indirect", "generated", "masked", "not-found"):
            with self.subTest(file_state=file_state):
                result = self.run_shell('systemd_unit_inactive stopped.service true', helpers=("systemd_unit_inactive",),
                                        UNIT_STATE=f"LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState={file_state}")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_paperless_workers_and_scheduler_stop_before_the_webserver(self):
        result = self.run_remove("paperless-ngx")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        stopped = [command[-1] for command in self.commands() if command[:2] == ["systemctl", "stop"]]
        self.assertEqual(stopped, ["paperless-worker.service", "paperless-scheduler.service", "paperless-webserver.service"])

    def test_flood_pm2_teardown_precedes_removing_its_runtime(self):
        self.file("opt/flood/node_modules/flood/index.js", "runtime")
        result = self.run_remove("flood")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.commands()
        stop_index = commands.index(["pm2", "stop", "flood"])
        delete_index = commands.index(["pm2", "delete", "flood"])
        save_index = commands.index(["pm2", "save", "--force"])
        remove_index = next(index for index, command in enumerate(commands) if command[:2] == ["rm", "-rf"] and str(self.root / "opt/flood") in command)
        self.assertLess(stop_index, delete_index)
        self.assertLess(delete_index, save_index)
        self.assertLess(save_index, remove_index)

    def test_flood_pm2_discovery_failure_retains_runtime_and_install_marker(self):
        runtime = self.file("opt/flood/node_modules/flood/index.js", "runtime")
        marker = self.file("install/.flood.lock", "installed")
        result = self.run_remove("flood", FAIL_OPERATION="jlist")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(runtime.exists())
        self.assertTrue(marker.exists())

    def test_package_removal_failures_do_not_delete_data_or_installed_markers(self):
        for app in ("syncthing", "znc", "mergerfs"):
            with self.subTest(app=app):
                marker = self.file(f"install/.{app}.lock", "installed")
                data = self.file(f"var/lib/{app}/operator-data")
                result = self.run_remove(app, "true", FAIL_OPERATION="apt-get")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(marker.exists())
                self.assertTrue(data.exists())

    def test_mergerfs_unmounts_both_supported_mounts_before_removing_the_package(self):
        mounts = [str(self.root / relative) for relative in ("mnt/unionfs", "mnt/mergerfs")]
        self.file("mounts.json", json.dumps(mounts))
        result = self.run_remove("mergerfs")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.commands()
        remove_index = next(index for index, command in enumerate(commands) if command[:2] == ["apt-get", "remove"])
        for mount in mounts:
            self.assertLess(commands.index(["fusermount", "-u", mount]), remove_index)
        self.assertEqual(json.loads((self.root / "mounts.json").read_text()), [])

    def seed_servarr(self, config, api_version="v3", **environment):
        self.file("var/lib/sonarr/config.xml", "<Config><ApiKey>synthetic-api-key</ApiKey></Config>")
        self.file("http-config.json", json.dumps(config))
        (self.root / "http-requests.jsonl").unlink(missing_ok=True)
        result = self.run_shell(f'seed_servarr_credentials sonarr 8989 {api_version}',
                                helpers=("seed_servarr_master_user", "seed_servarr_credentials"), MOCK_HTTP="1", **environment)
        requests = [json.loads(line) for line in (self.root / "http-requests.jsonl").read_text().splitlines()]
        return result, requests

    def test_servarr_preserves_custom_operator_credentials_on_v1_and_v3(self):
        config = {"id": 1, "authenticationMethod": "forms", "username": "operator", "password": "operator-secret"}
        for version in ("v1", "v3"):
            with self.subTest(version=version):
                result, requests = self.seed_servarr(config, version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([request["method"] for request in requests], ["GET"])

    def test_servarr_explicit_keep_secrets_preserves_configured_accounts_and_seeds_missing_auth(self):
        for config in ({"id": 1, "authenticationMethod": "none", "username": ""},
                       {"id": 1, "authenticationMethod": "basic", "username": "operator"}):
            with self.subTest(config=config):
                result, requests = self.seed_servarr(config, AF_KEEP_EXISTING_SECRETS="1")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected_methods = ["GET", "PUT"] if config["authenticationMethod"] == "none" else ["GET"]
                self.assertEqual([request["method"] for request in requests], expected_methods)

    def test_servarr_initial_bootstrap_still_seeds_master_credentials(self):
        for method, username in (("none", ""), ("none", "old-default"), ("forms", "")):
            with self.subTest(method=method, username=username):
                result, requests = self.seed_servarr({"id": 1, "authenticationMethod": method, "username": username}, AF_KEEP_EXISTING_SECRETS="0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([request["method"] for request in requests], ["GET", "PUT"])
                self.assertEqual(requests[-1]["body"]["username"], "master-test-user")
                self.assertEqual(requests[-1]["body"]["password"], "master-test-password")
                self.assertEqual(requests[-1]["body"]["passwordConfirmation"], "master-test-password")

    def test_servarr_rotation_requires_both_explicit_credentials_and_permission(self):
        config = {"id": 1, "authenticationMethod": "forms", "username": "operator", "password": "operator-secret"}
        for environment, methods in (
            ({"AF_KEEP_EXISTING_SECRETS": "0", "AF_CONFIG_PASS": ""}, ["GET"]),
            ({"AF_KEEP_EXISTING_SECRETS": "1", "AF_CONFIG_PASS": "requested-password"}, ["GET"]),
            ({"AF_KEEP_EXISTING_SECRETS": "0", "AF_CONFIG_PASS": "requested-password"}, ["GET", "PUT"]),
        ):
            with self.subTest(environment=environment):
                result, requests = self.seed_servarr(config, **environment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([request["method"] for request in requests], methods)

    def test_jellyfin_unreachable_or_failed_initial_setup_never_writes_an_install_marker(self):
        for environment in ({"HTTP_UNREACHABLE": "1"}, {"HTTP_FAIL_PATH": "/Startup/User"}, {"HTTP_INCOMPLETE": "1"}):
            with self.subTest(environment=environment):
                self.file("http-config.json", json.dumps({"StartupWizardCompleted": False}))
                marker = self.root / "install/.media.lock"
                marker.unlink(missing_ok=True)
                result = self.run_shell('seed_jellyfin_master_user 8096\nwrite_lock media',
                                        helpers=("seed_jellyfin_master_user",), MOCK_HTTP="1", **environment)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("initial user setup failed", result.stderr)
                self.assertFalse(marker.exists())

    def test_jellyfin_initial_bootstrap_and_existing_setup_are_successful(self):
        for completed in (False, True):
            with self.subTest(completed=completed):
                self.file("http-config.json", json.dumps({"StartupWizardCompleted": completed}))
                (self.root / "http-requests.jsonl").unlink(missing_ok=True)
                result = self.run_shell('seed_jellyfin_master_user 8096\nwrite_lock media',
                                        helpers=("seed_jellyfin_master_user",), MOCK_HTTP="1")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((self.root / "install/.media.lock").exists())
                requests = [json.loads(line) for line in (self.root / "http-requests.jsonl").read_text().splitlines()]
                if completed:
                    self.assertEqual(len(requests), 1)
                else:
                    self.assertIn("/Startup/Complete", [request["path"] for request in requests])

    def test_service_readiness_requires_both_http_and_an_active_service(self):
        for active_status, http_status, expected in (("0", "0", 0), ("1", "0", 1), ("0", "22", 1)):
            with self.subTest(active_status=active_status, http_status=http_status):
                result = self.run_shell('wait_for_service_ready example.service 18080 /health 2', helpers=("wait_for_service_ready",),
                                        SYSTEMCTL_IS_ACTIVE_STATUS=active_status, CURL_STATUS=http_status)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_installer_template_uses_common_lifecycle_and_allocated_port_contracts(self):
        template = (ROOT / "packages/package/install/installpackage-template").read_text()
        self.assertIn('APP_PORT="${AF_APP_PORT:-8080}"', template)
        for helper in ("report_progress", "write_lock", "queue_app_version", "commit_app_versions", "stage_app_archive", "finish_app_archive_update"):
            self.assertIn(helper, template)
        self.assertLess(template.index('finish_app_archive_update "$PACKAGE_NAME"'), template.index('commit_app_versions'))
        self.assertLess(template.index('commit_app_versions'), template.index('write_lock "$PACKAGE_NAME"'))
        self.assertNotIn("touch ", template)
        self.assertNotIn("Skipping", template)
        self.assertNotIn("Go handler", template)
        self.assertNotIn("services/installer.go", template)


if __name__ == "__main__":
    unittest.main()
