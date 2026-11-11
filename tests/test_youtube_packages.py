import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import installer_common_functions as common_functions


REPO = Path(__file__).resolve().parents[1]
APPS = {"piped": 8280, "invidious": 8281}
HEAD = "a" * 40

PACKAGE_MANAGER = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["TEST_ROOT"])
command = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with (root / "commands").open("a") as output:
    output.write(command + " " + " ".join(arguments) + "\n")
state = root / "apt-packages.json"
packages = json.loads(state.read_text()) if state.exists() else {}
if command == "dpkg":
    assert len(arguments) == 4 and arguments[0] == "--compare-versions" and arguments[2] == "ge"
    current = tuple(int(part) for part in arguments[1].split("."))
    previous = tuple(int(part) for part in arguments[3].split("."))
    sys.exit(0 if current >= previous else 1)
elif command == "dpkg-query":
    if arguments[:1] != ["-W"]:
        sys.exit("Unexpected dpkg-query arguments")
    package = arguments[-1]
    if package not in packages:
        sys.exit(1)
    print("installed " + packages[package])
elif command == "apt-get":
    if arguments[:1] == ["update"]:
        sys.exit(0)
    if not arguments or arguments[0] not in ("install", "remove"):
        sys.exit("Unexpected apt-get arguments")
    for argument in arguments[1:]:
        if argument.startswith("-"):
            continue
        package, separator, version = argument.partition("=")
        if arguments[0] == "remove":
            packages.pop(package, None)
        else:
            packages[package] = version if separator else "2.0.0"
    state.write_text(json.dumps(packages))
else:
    sys.exit("Unexpected package manager")
'''

COMMON = r'''
record() { printf '%s\n' "$*" >> "$TEST_ROOT/commands"; }
require_root() { :; }
log_info() { :; }
log_warn() { printf '%s\n' "$*" >&2; }
print_warn() { printf '%s\n' "$*" >&2; }
get_base_domain() { printf '%s' "${MOCK_DOMAIN-example.com}"; }
print_error() { printf '%s\n' "$*" >&2; }
print_info() { printf '%s\n' "$*"; }
report_progress() { :; }
ensure_node() { record "ensure_node $*"; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
id() { return 0; }
chown() { :; }
stat() {
    if [[ "$1" == -c && "$2" == %u && ( "$3" == "$TEST_ROOT/mock-bin/cargo" || "$3" == "$TEST_ROOT/mock-bin/rustc" ) ]]; then
        printf '0\n'
    else
        command stat "$@"
    fi
}
sleep() { :; }
curl() { [[ "${MOCK_FAIL_HTTP:-0}" != 1 ]]; }
systemctl() {
    record "systemctl $*"
    if [[ "$1" == restart && "${MOCK_FAIL_START:-0}" == 1 ]]; then return 42; fi
    if [[ "$1" == stop && "${MOCK_FAIL_STOP:-0}" == 1 ]]; then return 42; fi
    if [[ "$1" == disable && "${MOCK_FAIL_REMOVE:-0}" == 1 ]]; then return 42; fi
    local action="$1" unit load_state=not-found active_state=inactive main_pid=0 unit_file_state=disabled
    shift
    if [[ "$action" == show && "$*" == '-p ExecMainPID --value '* ]]; then
        unit="${@: -1}"
        [[ ! -f "$TEST_ROOT/systemd-state/${unit%.service}.active" ]] || main_pid=123
        printf '%s\n' "$main_pid"
        return 0
    fi
    local units=()
    for unit in "$@"; do
        [[ "$unit" == -* ]] || units+=("${unit%.service}")
    done
    for unit in "${units[@]}"; do
        case "$action" in
            start|restart)
                touch "$TEST_ROOT/systemd-state/$unit.active"
                if [[ "$unit" == af-invidious ]]; then
                    touch "$TEST_ROOT/systemd-state/af-invidious-companion.active"
                elif [[ "$unit" == af-piped-proxy ]]; then
                    mkdir -p "$TEST_ROOT/proc/123"
                    local proxy="$TEST_ROOT/opt/piped/piped-proxy"
                    if [[ "${MOCK_STALE_PROXY:-0}" == 1 ]]; then
                        cp "$proxy" "$TEST_ROOT/stale-piped-proxy"
                        proxy="$TEST_ROOT/stale-piped-proxy"
                    fi
                    ln -sfn "$proxy" "$TEST_ROOT/proc/123/exe"
                fi
                ;;
            stop)
                rm -f "$TEST_ROOT/systemd-state/$unit.active"
                [[ "$unit" != af-piped-proxy ]] || rm -f "$TEST_ROOT/proc/123/exe"
                ;;
            enable) touch "$TEST_ROOT/systemd-state/$unit.enabled" ;;
            disable) rm -f "$TEST_ROOT/systemd-state/$unit.enabled" ;;
            is-active) [[ -f "$TEST_ROOT/systemd-state/$unit.active" ]] || return 3 ;;
            show)
                [[ ! -f "$TEST_ROOT/etc/systemd/system/$unit.service" ]] || load_state=loaded
                if [[ -f "$TEST_ROOT/systemd-state/$unit.active" ]]; then
                    active_state=active
                    main_pid=123
                fi
                [[ ! -f "$TEST_ROOT/systemd-state/$unit.enabled" ]] || unit_file_state=enabled
                printf '%s\n' "LoadState=$load_state" "ActiveState=$active_state" "MainPID=$main_pid" "UnitFileState=$unit_file_state"
                ;;
            daemon-reload|reset-failed) ;;
            *) return 1 ;;
        esac
    done
    return 0
}
install() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
runuser() {
    if [[ "$1" == --preserve-environment ]]; then shift; fi
    shift 3
    record "runuser $*"
    local clean_environment=false
    while [[ "${1:-}" == env ]]; do
        clean_environment=true
        shift
        [[ "${1:-}" != -i ]] || shift
        while [[ "${1:-}" == *=* ]]; do shift; done
    done
    if [[ "$1" == git ]]; then
        if [[ "$2" == clone ]]; then
            local target="${@: -1}"
            mkdir -p "$target/.git"
            if [[ "$target" == */backend ]]; then
                mkdir -p "$target/src/main/java/me/kavin/piped/server"
                printf '%s\n' 'new InetSocketAddress(Constants.PORT)' > "$target/src/main/java/me/kavin/piped/server/ServerLauncher.java"
            fi
        elif [[ " $* " == *' rev-parse '* ]]; then
            printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        fi
        return 0
    fi
    if [[ "$1" == psql ]]; then cat >/dev/null; return 0; fi
    if [[ "$1" == pg_dump ]]; then printf 'fixture SQL backup\n'; return 0; fi
    if [[ "$1" == cp ]]; then command cp "${@:2}"; return; fi
    if [[ "$clean_environment" == true ]]; then
        if [[ "${MOCK_FAIL_BUILD:-0}" == 1 ]]; then return 42; fi
        if [[ "$1" == rustc && "${2:-}" == --version ]]; then printf 'rustc 1.90.0 (fixture)\n'; return 0; fi
        if [[ "$1" == npm ]]; then return 0; fi
        if [[ "$1" == cargo ]]; then
            mkdir -p "$INSTALL_DIR/proxy/target/release"
            touch "$INSTALL_DIR/proxy/target/release/piped-proxy"
        elif [[ "$*" == *gradlew* ]]; then
            mkdir -p "${@: -1}/build/libs"
            touch "${@: -1}/build/libs/piped-1.0-all.jar"
        elif [[ "$*" == *pnpm* ]]; then
            mkdir -p "$INSTALL_DIR/frontend/dist"
            printf 'Piped frontend' > "$INSTALL_DIR/frontend/dist/index.html"
        elif [[ "$1" == bash && ( "$3" == 'cd "$1"; make' || "$3" == 'cd "$1"; ./invidious --migrate' ) ]]; then
            :
        else
            print_error "Unexpected clean-environment command: $*"
            return 1
        fi
        return 0
    fi
    print_error "Unexpected runuser command: $*"
    return 1
}
'''

OVERRIDES = r'''
youtube_asset() {
    if [[ "${MOCK_BAD_ASSET:-0}" == 1 ]]; then return 42; fi
    local fixture=companion
    [[ "$1" != crystal-lang/crystal ]] || fixture=crystal
    cp "$TEST_ROOT/$fixture.tar.gz" "$4"
}
'''


class YouTubeCatalogTest(unittest.TestCase):
    def test_catalog_contracts(self):
        catalog = json.loads((REPO / "backend/config/packages.json").read_text())
        automation = json.loads((REPO / "backend/config/package_automation.json").read_text())
        ports = [app["default_port"] for app in catalog if app.get("default_port")]
        self.assertEqual(len(ports), len(set(ports)))
        for name, port in APPS.items():
            app = next(item for item in catalog if item["name"] == name)
            self.assertEqual(app["default_port"], port)
            self.assertEqual(app["service_name"], "af-" + name)
            self.assertIn("Experimental", app["description"])
            self.assertEqual(automation[name]["update_source"], "git")
            self.assertIn(automation[name]["sandbox_profile"], ("java", "node"))
            self.assertGreater(len(automation[name]["sandbox_service_units"]), 1)
            self.assertTrue((REPO / f"frontend/public/img/{name}.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
            for action in ("install", "remove"):
                script = (REPO / f"packages/package/{action}/{action}package-{name}").read_text()
                self.assertNotRegex(script, r"(?m)^\s*(docker|podman)\b")
                self.assertIn("common.sh", script)


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires Linux Bash")
class YouTubeLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="af-youtube-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("etc/systemd/system", "var/lib", "var/log/aetherflow", "opt", "install", "tmp", "mock-bin", "systemd-state"):
            (self.root / directory).mkdir(parents=True)
        for command in ("apt-get", "dpkg-query", "dpkg"):
            executable = self.root / "mock-bin" / command
            executable.write_text(PACKAGE_MANAGER)
            executable.chmod(0o755)
        for command in ("cargo", "rustc"):
            executable = self.root / "mock-bin" / command
            executable.write_text("#!/bin/sh\nexit 99\n")
            executable.chmod(0o755)
        self.command_path = os.pathsep.join((str(self.root / "mock-bin"), str(Path(sys.executable).parent), os.environ.get("PATH", "")))
        helpers = common_functions("safe_config_python", "validate_config_paths", "write_config_file", "set_config_value", "node_build", "write_app_version", "systemd_unit_inactive", "stop_systemd_unit", "purge_systemd_unit", "safe_rm_rf", "backup_postgresql_database", "restore_postgresql_database")
        (self.root / "common.sh").write_text(COMMON + self.rewrite(helpers))
        (self.root / "overrides.sh").write_text(OVERRIDES)
        helper = self.rewrite((REPO / "packages/youtube-common.sh").read_text())
        (self.root / "youtube-common.sh").write_text(helper)
        for fixture, filename in (("crystal", "crystal/bin/crystal"), ("companion", "invidious_companion")):
            source = self.root / filename
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("#!/bin/sh\nexit 0\n")
            with tarfile.open(self.root / f"{fixture}.tar.gz", "w:gz") as archive:
                archive.add(source, arcname=filename)

    def rewrite(self, source):
        return re.sub(r"/(?:etc|opt|var/lib|var/log|tmp)/", lambda match: str(self.root) + match.group(), source)

    def run_script(self, app, action="install", **environment):
        source = (REPO / f"packages/package/{action}/{action}package-{app}").read_text()
        source = self.rewrite(source)
        source = source.replace('${SELF_DIR}/../../common.sh', str(self.root / "common.sh"))
        source = source.replace('${SELF_DIR}/../../youtube-common.sh', str(self.root / "youtube-common.sh"))
        source = source.replace("youtube_init " + app, 'source "$TEST_ROOT/overrides.sh"\nyoutube_init ' + app)
        path = self.root / "script.sh"
        path.write_text(source)
        return subprocess.run(["bash", str(path)], text=True, capture_output=True,
                              env=dict(os.environ, TEST_ROOT=str(self.root),
                                       AF_PROC_ROOT=str(self.root / "proc"),
                                       PATH=self.command_path,
                                       **environment))

    def test_private_package_commands_preserve_apt_rollback(self):
        packages = self.root / "apt-packages.json"
        packages.write_text(json.dumps({"fixture-existing": "1.0.0"}))
        script = f'source "{self.root}/common.sh"\n' + r'''
set -euo pipefail
LOGFILE="$TEST_ROOT/apt.log"
AF_TX_DIR="$TEST_ROOT/apt-transaction"
mkdir -p "$AF_TX_DIR"
record_apt_package_for_rollback fixture-existing fixture-new
AF_APT_TRANSACTION_PACKAGES=(fixture-existing fixture-new)
AF_APT_REINSTALL_PACKAGES=(fixture-existing)
apt-get install --no-remove -y fixture-new
[[ "$(installed_apt_package_version fixture-existing)" == 2.0.0 ]]
[[ "$(installed_apt_package_version fixture-new)" == 2.0.0 ]]
rollback_apt_packages
'''
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                env=dict(os.environ, TEST_ROOT=str(self.root), PATH=self.command_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(packages.read_text()), {"fixture-existing": "1.0.0"})
        commands = (self.root / "commands").read_text().splitlines()
        self.assertIn("apt-get install --reinstall --no-remove -y fixture-new fixture-existing", commands)
        self.assertIn("apt-get install -y --allow-downgrades --reinstall fixture-existing=1.0.0", commands)
        self.assertIn("apt-get remove -y --no-auto-remove fixture-new", commands)

    def test_install_reinstall_and_remove_preserve_data(self):
        for app in APPS:
            with self.subTest(app=app):
                result = self.run_script(app, AF_APP_PORT="18280")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                lock = self.root / f"install/.{app}.lock"
                self.assertTrue(lock.exists())
                config_dir = self.root / "etc" / app
                secrets = {path.name: path.read_text() for path in config_dir.glob("*-key")}
                secrets["database-password"] = (config_dir / "database-password").read_text()
                unit = (self.root / f"etc/systemd/system/af-{app}.service").read_text()
                self.assertNotIn(f"PartOf=af-{app}.service", unit)
                self.assertIn("ProtectSystem=strict", unit)
                if app == "piped":
                    config = config_dir / "config.properties"
                    config.write_text(config.read_text() + "BG_HELPER_URL:https://tokens.example.com\n")
                    apache = (config_dir / "httpd.conf").read_text()
                    self.assertIn("Listen 127.0.0.1:18280", apache)
                    self.assertIn("ProxyPass /api/", apache)
                    self.assertNotIn("mod_unixd.so", apache)
                    self.assertIn("HASH_SECRET=", (config_dir / "runtime.env").read_text())
                else:
                    self.assertNotIn("PORT=", (config_dir / "runtime.env").read_text())
                    companion_key = (config_dir / "companion-key").read_text().strip()
                    self.assertRegex(companion_key, r"^[a-zA-Z0-9]{16}$")
                    self.assertIn(f"SERVER_SECRET_KEY={companion_key}\n", (config_dir / "companion.env").read_text())
                result = self.run_script(app, AF_APP_PORT="18281")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name, value in secrets.items():
                    self.assertEqual((config_dir / name).read_text(), value)
                if app == "piped":
                    self.assertIn("BG_HELPER_URL:https://tokens.example.com", (config_dir / "config.properties").read_text())
                marker = self.root / f"var/lib/{app}/keep"
                marker.touch()
                units = list((self.root / "etc/systemd/system").glob(f"af-{app}*.service"))
                self.assertGreater(len(units), 1)
                for failure in ("MOCK_FAIL_STOP", "MOCK_FAIL_REMOVE"):
                    result = self.run_script(app, "remove", **{failure: "1"})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(lock.exists())
                    self.assertTrue(marker.exists())
                    self.assertTrue(all(unit.exists() for unit in units))
                result = self.run_script(app, "remove")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(lock.exists())
                self.assertTrue(marker.exists())
                self.assertTrue(config_dir.exists())
                self.assertFalse(list((self.root / "etc/systemd/system").glob(f"af-{app}*.service")))

    def test_failures_never_mark_new_install_complete(self):
        for app in APPS:
            for environment in ({"MOCK_FAIL_BUILD": "1"}, {"MOCK_FAIL_START": "1"}, {"MOCK_FAIL_HTTP": "1"},
                                {"AF_APP_PORT": "80"}, {"AF_APP_PORT": "65536"}, {"MOCK_DOMAIN": ""}):
                with self.subTest(app=app, environment=environment):
                    result = self.run_script(app, **environment)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse((self.root / f"install/.{app}.lock").exists())

    def test_companion_download_failure_is_fatal(self):
        result = self.run_script("invidious", MOCK_BAD_ASSET="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "install/.invidious.lock").exists())

    def test_piped_rejects_a_running_proxy_from_a_stale_path(self):
        result = self.run_script("piped", MOCK_STALE_PROXY="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("does not match deployed path", result.stdout + result.stderr)
        self.assertFalse((self.root / "install/.piped.lock").exists())

    def test_invalid_saved_companion_key_fails_without_rotation(self):
        config_dir = self.root / "etc/invidious"
        config_dir.mkdir()
        key_path = config_dir / "companion-key"
        invalid_key = "a" * 64 + "\n"
        key_path.write_text(invalid_key)
        result = self.run_script("invidious")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("16 alphanumeric characters", result.stdout + result.stderr)
        self.assertEqual(key_path.read_text(), invalid_key)
        self.assertFalse((self.root / "install/.invidious.lock").exists())

    def test_piped_apache_configuration_parses(self):
        result = self.run_script("piped")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = self.root / "etc/piped/httpd.conf"
        apache = shutil.which("apache2", path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")
        if apache:
            (self.root / "etc/apache2").mkdir()
            shutil.copyfile("/etc/mime.types", self.root / "etc/mime.types")
            result = subprocess.run([apache, "-t", "-f", str(config)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            text = config.read_text()
            depth = 0
            for line in text.splitlines():
                directive = line.strip()
                if directive.startswith("<VirtualHost"):
                    self.assertRegex(directive, r"^<VirtualHost\s+[^<>]+>$")
                    depth += 1
                    self.assertEqual(depth, 1, "Nested VirtualHost")
                elif directive.startswith("</VirtualHost"):
                    self.assertEqual(directive, "</VirtualHost>")
                    depth -= 1
                    self.assertEqual(depth, 0, "Unmatched VirtualHost close")
            self.assertEqual(depth, 0, "Unclosed VirtualHost")
            self.assertRegex(text, r"(?m)^Listen 127\.0\.0\.1:[0-9]+$")
            for route in ("api", "proxy"):
                for directive in ("ProxyPass", "ProxyPassReverse"):
                    self.assertRegex(text, rf"(?m)^{directive} /{route}/ http://127\.0\.0\.1:[0-9]+/$")
            for module in ("mpm_event", "authz_core", "dir", "mime", "proxy", "proxy_http"):
                self.assertRegex(text, rf"(?m)^LoadModule {module}_module /\S*/mod_{module}\.so$")

    def test_piped_apache_structural_parse_without_binary(self):
        from unittest.mock import patch
        with patch.object(shutil, "which", return_value=None):
            self.test_piped_apache_configuration_parses()

    @unittest.skipUnless(shutil.which("jq"), "Requires jq")
    def test_asset_digest_is_required_and_verified(self):
        import hashlib
        data = b"verified upstream binary"
        (self.root / "asset").write_bytes(data)
        metadata = {"assets": [{"name": "binary.tar.gz", "browser_download_url":
                    "https://github.com/iv-org/invidious-companion/releases/download/release-master/binary.tar.gz",
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest()}]}
        script = f'source "{self.root}/common.sh"\nsource "{self.root}/youtube-common.sh"\n' + r'''
curl() {
    if [[ "$*" == *api.github.com* ]]; then cat "$TEST_ROOT/metadata.json";
    else cp "$TEST_ROOT/asset" "${@: -1}"; fi
}
youtube_asset iv-org/invidious-companion release-master binary.tar.gz "$TEST_ROOT/output"
'''
        for digest, succeeds in ((metadata["assets"][0]["digest"], True), ("sha256:" + "0" * 64, False), (None, False)):
            with self.subTest(digest=digest):
                metadata["assets"][0]["digest"] = digest
                (self.root / "metadata.json").write_text(json.dumps(metadata))
                result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                        env=dict(os.environ, TEST_ROOT=str(self.root), PATH=self.command_path))
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
