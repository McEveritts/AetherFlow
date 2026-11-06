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

from installer_test_helpers import common_functions


REPO = Path(__file__).resolve().parents[1]
APPS = {"piped": 8280, "invidious": 8281}
HEAD = "a" * 40

COMMON = r'''
record() { printf '%s\n' "$*" >> "$TEST_ROOT/commands"; }
require_root() { :; }
get_base_domain() { printf '%s' "${MOCK_DOMAIN-example.com}"; }
print_error() { printf '%s\n' "$*" >&2; }
print_info() { printf '%s\n' "$*"; }
report_progress() { :; }
ensure_node() { record "ensure_node $*"; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
apt-get() { record "apt-get $*"; }
id() { return 0; }
chown() { :; }
sleep() { :; }
curl() { [[ "${MOCK_FAIL_HTTP:-0}" != 1 ]]; }
systemctl() {
    record "systemctl $*"
    if [[ "$1" == restart && "${MOCK_FAIL_START:-0}" == 1 ]]; then return 42; fi
    if [[ "$1" == stop && "${MOCK_FAIL_STOP:-0}" == 1 ]]; then return 42; fi
    if [[ "$1" == disable && "${MOCK_FAIL_REMOVE:-0}" == 1 ]]; then return 42; fi
}
install() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
runuser() {
    shift 3
    record "runuser $*"
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
    if [[ "$1" == env ]]; then
        shift
        while [[ "$1" == *=* ]]; do shift; done
        if [[ "${MOCK_FAIL_BUILD:-0}" == 1 ]]; then return 42; fi
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
        fi
        return 0
    fi
    "$@"
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
        for directory in ("etc/systemd/system", "var/lib", "var/log/aetherflow", "opt", "install", "tmp"):
            (self.root / directory).mkdir(parents=True)
        helpers = common_functions("node_build", "systemd_unit_inactive", "stop_systemd_unit", "purge_systemd_unit")
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
                                       PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
                                       **environment))

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

    @unittest.skipUnless(shutil.which("apache2"), "Requires Apache binary")
    def test_piped_apache_configuration_parses(self):
        result = self.run_script("piped")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (self.root / "etc/apache2").mkdir()
        shutil.copyfile("/etc/mime.types", self.root / "etc/mime.types")
        result = subprocess.run(["apache2", "-t", "-f", str(self.root / "etc/piped/httpd.conf")],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
                                        env=dict(os.environ, TEST_ROOT=str(self.root)))
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
