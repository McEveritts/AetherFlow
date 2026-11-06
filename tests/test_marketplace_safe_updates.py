#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from installer_test_helpers import common_functions, replace_paths_once

ROOT = Path(__file__).resolve().parents[1]

MOCK_SCRIPT = r"""#!/bin/bash
set -e
root="${TEST_ROOT}"
cmd="$(basename "$0")"
printf '%s %s\n' "$cmd" "$*" >> "${root}/mock_commands.log"

case "$cmd" in
    dpkg)
        echo "amd64"
        exit 0
        ;;
    uname)
        echo "x86_64"
        exit 0
        ;;
    flock)
        exit 0
        ;;
    jq)
        case "$*" in
            *token*)
                echo "mock-token"
                exit 0
                ;;
            *browser_download_url*)
                echo "https://github.com/kasmtech/KasmVNC/releases/download/v3.0.0/kasmvnc.deb"
                exit 0
                ;;
            *digest*)
                echo "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                exit 0
                ;;
            *tag_name*|*0*.name*)
                echo "v3.0.0"
                exit 0
                ;;
            *)
                echo "mock-jq"
                exit 0
                ;;
        esac
        ;;
    node)
        if [ "$1" = "-v" ]; then
            echo "${TEST_NODE_VERSION:-v20.18.0}"
            exit 0
        fi
        exit 0
        ;;
    curl)
        if [[ "$*" == *http_code* ]]; then echo 200; exit 0; fi
        if [ "${FAIL_STAGE:-}" = "download" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
            exit 22
        fi
        out=""
        prev=""
        for arg in "$@"; do
            if [ "$prev" = "-o" ]; then
                out="$arg"
                break
            fi
            prev="$arg"
        done
        if [ -n "$out" ]; then
            mkdir -p "$(dirname "$out")"
            echo "mock-data" > "$out"
        else
            printf '%s\n' '{"token":"mock-token","layers":[{"digest":"sha256:fixture"}]}'
        fi
        exit 0
        ;;
    git)
        if [ "$1" = "clone" ]; then
            if [ "${FAIL_STAGE:-}" = "download" ] || [ "${FAIL_STAGE:-}" = "clone" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
                exit 1
            fi
            dest="${!#}"
            mkdir -p "$dest"
            if echo "$*" | grep -q "cloudplow"; then
                cat <<'EOF' > "${dest}/cloudplow.py"
print("mock cloudplow")
EOF
                touch "${dest}/requirements.txt"
            elif echo "$*" | grep -q "overseerr"; then
                mkdir -p "${dest}/dist"
                touch "${dest}/dist/index.js"
                touch "${dest}/package.json"
            elif echo "$*" | grep -q "Tautulli"; then
                cat <<'EOF' > "${dest}/Tautulli.py"
print("mock tautulli")
EOF
            elif echo "$*" | grep -q "calibre-web"; then
                cat <<'EOF' > "${dest}/cps.py"
print("mock cps")
EOF
                touch "${dest}/requirements.txt"
            elif echo "$*" | grep -q "paperless-ngx"; then
                mkdir -p "${dest}/src"
                cat <<'EOF' > "${dest}/src/manage.py"
print("mock manage")
EOF
            elif echo "$*" | grep -q "McVNC"; then
                mkdir -p "${dest}/target/release"
                touch "${dest}/target/release/mcvnc"
                chmod +x "${dest}/target/release/mcvnc"
            fi
            exit 0
        elif [ "$1" = "describe" ] || [ "$1" = "tag" ] || [ "$1" = "-C" ]; then
            echo "v3.0.0"
            exit 0
        fi
        exit 0
        ;;
    yarn)
        if [ "${FAIL_STAGE:-}" = "build" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
            exit 1
        fi
        if [ "$1" = "build" ]; then
            mkdir -p dist
            touch dist/index.js
        fi
        exit 0
        ;;
    npm)
        if [ "${FAIL_STAGE:-}" = "npm" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
            exit 1
        fi
        echo "$*" >> "${root}/npm_installed.log"
        if [[ "$*" == *--prefix* && "$*" == *n8n* ]]; then
            while [[ "$1" != --prefix ]]; do shift; done
            mkdir -p "$2/node_modules/.bin"
            printf '#!/bin/bash\necho 2.1.0\n' > "$2/node_modules/.bin/n8n"
            chmod +x "$2/node_modules/.bin/n8n"
        fi
        exit 0
        ;;
    pip|pip3)
        if [ "${FAIL_STAGE:-}" = "pip" ] || [ "${FAIL_STAGE:-}" = "build" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
            exit 1
        fi
        exit 0
        ;;
    tar)
        c_dir="."
        prev=""
        for arg in "$@"; do
            if [ "$prev" = "-C" ]; then
                c_dir="$arg"
                break
            fi
            prev="$arg"
        done
        mkdir -p "$c_dir"
        case "$*" in
            *vaultwarden*)
                touch "${c_dir}/vaultwarden"
                chmod +x "${c_dir}/vaultwarden"
                mkdir -p "${c_dir}/web-vault"
                ;;
            *speedtest*|*librespeed*)
                touch "${c_dir}/speedtest-backend"
                chmod +x "${c_dir}/speedtest-backend"
                ;;
            *paperless*)
                mkdir -p "${c_dir}/src"
                touch "${c_dir}/src/manage.py"
                ;;
            *flaresolverr*)
                touch "${c_dir}/flaresolverr"
                chmod +x "${c_dir}/flaresolverr"
                ;;
            *sabnzbd*)
                printf 'print("fixture")\n' > "${c_dir}/SABnzbd.py"
                touch "${c_dir}/requirements.txt"
                ;;
        esac
        exit 0
        ;;
    python|python3)
        if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
            venv_dir="$3"
            mkdir -p "${venv_dir}/bin"
            cat <<'EOF' > "${venv_dir}/bin/python"
#!/bin/bash
if [[ "$1" == "-m" && "$2" == "pip" ]]; then
    shift 2
    exec "$TEST_ROOT/mock-bin/pip" "$@"
fi
if [[ "${1:-}" == *manage.py && "${2:-}" == "${FAIL_STAGE:-}" ]]; then
    printf 'injected failure %s\n' "$FAIL_STAGE" >> "$TEST_ROOT/mock_commands.log"
    exit 1
fi
exit 0
EOF
            chmod +x "${venv_dir}/bin/python"
            cp "${venv_dir}/bin/python" "${venv_dir}/bin/python3"
            cp "$0" "${venv_dir}/bin/pip"
            printf '#!%s/bin/python\n' "$venv_dir" > "${venv_dir}/bin/entrypoint"
            printf 'VIRTUAL_ENV=%s\n' "$venv_dir" > "${venv_dir}/bin/activate"
            cat <<'EOF' > "${venv_dir}/bin/hass"
#!/bin/sh
echo "2026.11.0"
exit 0
EOF
            chmod +x "${venv_dir}/bin/hass"
            exit 0
        else
            exec /usr/bin/python3 "$@"
        fi
        ;;
    systemctl)
        sub="$1"
        arguments="$*"
        shift
        while [[ "${1:-}" == -* ]]; do shift; done
        unit="${1:-}"
        if [ "$sub" = "is-active" ]; then
            if [ -f "${root}/service_active_${unit}" ]; then
                exit 0
            else
                exit 1
            fi
        elif [ "$sub" = "is-enabled" ]; then
            if [ -f "${root}/service_enabled_${unit}" ]; then
                exit 0
            else
                exit 1
            fi
        elif [ "$sub" = "start" ]; then
            touch "${root}/service_active_${unit}"
            echo "started ${unit}" >> "${root}/systemctl.log"
            exit 0
        elif [ "$sub" = "stop" ]; then
            rm -f "${root}/service_active_${unit}"
            echo "stopped ${unit}" >> "${root}/systemctl.log"
            exit 0
        elif [ "$sub" = "restart" ]; then
            touch "${root}/service_active_${unit}"
            echo "restarted ${unit}" >> "${root}/systemctl.log"
            exit 0
        elif [ "$sub" = "enable" ]; then
            for enabled_unit in "$@"; do
                [[ "$enabled_unit" == -* ]] && continue
                touch "${root}/service_enabled_${enabled_unit}"
                if [[ "$arguments" == *--now* ]]; then touch "${root}/service_active_${enabled_unit}"; fi
            done
            exit 0
        elif [ "$sub" = "daemon-reload" ]; then
            exit 0
        fi
        exit 0
        ;;
    openssl)
        echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        exit 0
        ;;
    sha256sum)
        exit 0
        ;;
    chmod)
        exec /bin/chmod "$@"
        ;;
    install)
        if [ "$1" = "-d" ]; then
            while [ "$#" -gt 0 ]; do
                case "$1" in -o|-g|-m) shift 2 ;; -d) shift ;; *) mkdir -p "$1"; shift ;; esac
            done
        else
            exec /usr/bin/install "$@"
        fi
        exit 0
        ;;
    kasmvncpasswd)
        touch "${!#}"
        exit 0
        ;;
    apt-get|chown|useradd|usermod|userdel|groupdel|id|cargo)
        exit 0
        ;;
    sudo)
        while [ "$#" -gt 0 ]; do
            case "$1" in -u) shift 2 ;; -H|-n|--) shift ;; *) break ;; esac
        done
        exec "$@"
        ;;
    su|runuser)
        shift
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -u|-c) shift ;;
                *) break ;;
            esac
        done
        "$@"
        exit $?
        ;;
    *)
        exit 0
        ;;
esac
"""


class SafeMarketplaceUpdatesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        for directory in (
            "mock-bin",
            "opt/AetherFlow/packages",
            "opt/AetherFlow/logs",
            "var/log/aetherflow",
            "var/backups",
            "etc/systemd/system",
            "etc/vaultwarden",
            "etc/mcvnc",
            "etc/kasmvnc",
            "run/lock",
            "install",
            "home",
            "srv",
            "mnt",
            "usr/local/bin",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)

        (self.root / "etc/os-release").write_text("ID=ubuntu\nVERSION_CODENAME=noble\n")

        for command in (
            "dpkg", "uname", "flock", "jq", "sha256sum", "node", "curl", "git", "yarn", "npm", "pip", "pip3",
            "tar", "python", "python3", "systemctl", "openssl", "apt-get", "chown", "chmod",
            "useradd", "usermod", "userdel", "groupdel", "id", "install", "sudo", "runuser", "cargo", "kasmvncpasswd"
        ):
            p = self.root / "mock-bin" / command
            p.write_text(MOCK_SCRIPT)
            p.chmod(0o755)

        common_content = r"""set -euo pipefail
MASTER_USER=admin
MASTER_PASS=testpass123
log_info() { printf '%s\n' "$*" >> "$LOGFILE"; }
log_error() { printf '%s\n' "$*" >&2; }
print_error() { printf '%s\n' "$*" >&2; }
report_progress() { :; }
require_root() { :; }
ensure_node() { :; }
sync_node_global_bins() { :; }
github_latest_tag() { printf '%s\n' "${2:-3.0.0}"; }
get_base_domain() { printf 'example.com\n'; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
purge_systemd_unit() { :; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
set_config_value() { :; }
"""
        common_content += common_functions("node_build", "install_npm_app", "replace_app_tree")
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(common_content)

    def run_script(self, package, action="install", **environment):
        script_path = ROOT / f"packages/package/{action}/{action}package-{package}"
        source = script_path.read_text()
        root_posix = str(self.root).replace("\\", "/")

        (self.root / "tmp").mkdir(exist_ok=True)
        replacements = [
            ("/tmp/", f"{root_posix}/tmp/"),
            ("/usr/bin/kasmvncpasswd", f"{root_posix}/mock-bin/kasmvncpasswd"),
            ("/mnt/", f"{root_posix}/mnt/"),
            ("/opt/", f"{root_posix}/opt/"),
            ("/var/", f"{root_posix}/var/"),
            ("/etc/", f"{root_posix}/etc/"),
            ("/usr/local/", f"{root_posix}/usr/local/"),
            ("/srv/", f"{root_posix}/srv/"),
            ("/srv ", f"{root_posix}/srv "),
            ("/home/", f"{root_posix}/home/"),
            ("/run/lock", f"{root_posix}/run/lock"),
            (" /install", f" {root_posix}/install"),
        ]
        source = replace_paths_once(source, replacements)

        staged_script = self.root / "run_test_script.sh"
        staged_script.write_text(source)
        staged_script.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:{os.environ['PATH']}",
            "TEST_ROOT": root_posix,
            "LOGFILE": f"{root_posix}/test.log",
            **environment,
        }

        bash_cmd = "bash"
        if os.name == "nt":
            git_bash = Path(r"C:\Users\armyw\AppData\Local\hermes\git\bin\bash.exe")
            if git_bash.exists():
                bash_cmd = str(git_bash)

        result = subprocess.run(
            [bash_cmd, str(staged_script).replace("\\", "/")],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if environment.get('FAIL_STAGE'):
            self.assertIn(f"injected failure {environment['FAIL_STAGE']}",
                          (self.root / 'mock_commands.log').read_text(),
                          f"Installer failed before reaching requested fault: {result.stderr}")
        return result

    def test_cloudplow_update_preserves_live_config_and_retains_state(self):
        app_dir = self.root / "opt/cloudplow"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("1.0.0\n")
        custom_cfg = json.dumps({"remotes": {"test": {"sync_remote": "custom:remote"}}})
        (app_dir / "config.json").write_text(custom_cfg)

        result = self.run_script("cloudplow")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((app_dir / "config.json").read_text(), custom_cfg)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "v3.0.0")

    def test_cloudplow_failed_download_preserves_old_version_and_restarts_service(self):
        app_dir = self.root / "opt/cloudplow"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("1.0.0\n")
        custom_cfg = json.dumps({"custom": "value"})
        (app_dir / "config.json").write_text(custom_cfg)
        (self.root / "etc/systemd/system/cloudplow.service").write_text("[Unit]\nDescription=Cloudplow\n")
        (self.root / "service_active_cloudplow").touch()

        result = self.run_script("cloudplow", FAIL_STAGE="download")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "1.0.0")
        self.assertEqual((app_dir / "config.json").read_text(), custom_cfg)
        self.assertTrue((self.root / "service_active_cloudplow").exists())

    def test_overseerr_failed_build_preserves_old_version_and_service(self):
        app_dir = self.root / "opt/overseerr"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("1.33.0\n")
        (app_dir / "dist").mkdir(parents=True, exist_ok=True)
        (app_dir / "dist/index.js").write_text("old code")
        (self.root / "etc/systemd/system/overseerr.service").write_text("[Unit]\nDescription=Overseerr\n")
        (self.root / "service_active_overseerr").touch()

        result = self.run_script("overseerr", FAIL_STAGE="build")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "1.33.0")
        self.assertEqual((app_dir / "dist/index.js").read_text(), "old code")
        self.assertTrue((self.root / "service_active_overseerr").exists())

    def test_tautulli_failed_clone_preserves_old_version_and_service(self):
        app_dir = self.root / "opt/Tautulli"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("2.10.0\n")
        (app_dir / "Tautulli.py").write_text("old tautulli")
        (self.root / "etc/systemd/system/tautulli.service").write_text("[Unit]\nDescription=Tautulli\n")
        (self.root / "service_active_tautulli").touch()

        result = self.run_script("tautulli", FAIL_STAGE="clone")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "2.10.0")
        self.assertEqual((app_dir / "Tautulli.py").read_text(), "old tautulli")
        self.assertTrue((self.root / "service_active_tautulli").exists())

    def test_flaresolverr_failed_download_preserves_old_version_and_service(self):
        app_dir = self.root / "opt/flaresolverr"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("3.3.0\n")
        (app_dir / "flaresolverr").write_text("old flaresolverr")
        (self.root / "etc/systemd/system/flaresolverr.service").write_text("[Unit]\nDescription=FlareSolverr\n")
        (self.root / "service_active_flaresolverr").touch()

        result = self.run_script("flaresolverr", FAIL_STAGE="download")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "3.3.0")
        self.assertEqual((app_dir / "flaresolverr").read_text(), "old flaresolverr")
        self.assertTrue((self.root / "service_active_flaresolverr").exists())

    def test_sabnzbd_failed_pip_preserves_old_version_and_service(self):
        app_dir = self.root / "opt/SABnzbd"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("4.2.0\n")
        (app_dir / "SABnzbd.py").write_text("old sab")
        (self.root / "etc/systemd/system/sabnzbd.service").write_text("[Unit]\nDescription=SABnzbd\n")
        (self.root / "service_active_sabnzbd").touch()

        result = self.run_script("sabnzbd", FAIL_STAGE="pip")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "4.2.0")
        self.assertEqual((app_dir / "SABnzbd.py").read_text(), "old sab")
        self.assertTrue((self.root / "service_active_sabnzbd").exists())

    def test_calibreweb_fresh_non_default_port_without_db_fails_early(self):
        result = self.run_script("calibreweb", AF_APP_PORT="17803")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Calibre-Web requires default port 8083 for initial setup", result.stderr)
        self.assertFalse((self.root / "opt/calibre-web").exists())

    def test_calibreweb_fresh_default_port_succeeds(self):
        result = self.run_script("calibreweb", AF_APP_PORT="8083")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "opt/calibre-web").exists())

    def test_calibreweb_existing_db_with_matching_port_succeeds(self):
        db_path = self.root / "var/lib/calibre-web/app.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("CREATE TABLE settings (config_port INTEGER);")
            conn.execute("INSERT INTO settings VALUES (17803);")

        result = self.run_script("calibreweb", AF_APP_PORT="17803")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_calibreweb_failed_clone_preserves_old_version_and_service(self):
        app_dir = self.root / "opt/calibre-web"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("0.6.20\n")
        (app_dir / "cps.py").write_text("old cps")
        (self.root / "etc/systemd/system/calibreweb.service").write_text("[Unit]\nDescription=CalibreWeb\n")
        (self.root / "service_active_calibreweb").touch()

        result = self.run_script("calibreweb", AF_APP_PORT="8083", FAIL_STAGE="clone")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "0.6.20")
        self.assertEqual((app_dir / "cps.py").read_text(), "old cps")
        self.assertTrue((self.root / "service_active_calibreweb").exists())

    def test_homeassistant_explicit_upgrade_and_failure_recovery(self):
        srv_dir = self.root / "srv/homeassistant"
        srv_dir.mkdir(parents=True, exist_ok=True)
        (srv_dir / ".af-version").write_text("2024.1.0\n")
        (self.root / "etc/systemd/system/home-assistant@homeassistant.service").write_text("[Unit]\n")
        (self.root / "service_active_home-assistant@homeassistant").touch()

        fail_result = self.run_script("homeassistant", FAIL_STAGE="pip")
        self.assertNotEqual(fail_result.returncode, 0)
        self.assertEqual((srv_dir / ".af-version").read_text().strip(), "2024.1.0")
        self.assertTrue((self.root / "service_active_home-assistant@homeassistant").exists())

        success_result = self.run_script("homeassistant", AF_TARGET_VERSION="2026.11.0")
        self.assertEqual(success_result.returncode, 0, success_result.stderr)
        self.assertEqual((srv_dir / ".af-version").read_text().strip(), "2026.11.0")

    def test_paperless_ngx_preserves_secret_key_and_backs_up_db(self):
        conf = self.root / "etc/paperless.conf"
        conf.write_text("PAPERLESS_SECRET_KEY=custom-user-secret\nPAPERLESS_PORT=8010\nPAPERLESS_CUSTOM_FLAG=true\n")
        db = self.root / "var/lib/paperless/data/db.sqlite3"
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_text("database contents")

        result = self.run_script("paperless-ngx", AF_APP_PORT="8015")
        self.assertEqual(result.returncode, 0, result.stderr)
        conf_after = conf.read_text()
        self.assertIn("PAPERLESS_SECRET_KEY=custom-user-secret", conf_after)
        self.assertIn("PAPERLESS_PORT=8015", conf_after)
        self.assertIn("PAPERLESS_CUSTOM_FLAG=true", conf_after)
        backups = list(self.root.glob("var/backups/aetherflow-paperless.*/db.sqlite3"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "database contents")

    def test_paperless_ngx_first_install_generates_secret(self):
        conf = self.root / "etc/paperless.conf"
        result = self.run_script("paperless-ngx", AF_APP_PORT="8010")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(conf.exists())
        self.assertIn("PAPERLESS_SECRET_KEY=", conf.read_text())

    def test_paperless_migration_and_static_failures_restore_previous_runtime(self):
        app = self.root / "opt/paperless"
        (app / "src").mkdir(parents=True)
        (app / "src/manage.py").write_text("old-code")
        (app / ".af-version").write_text("old-version")
        (self.root / "service_active_paperless-webserver").touch()
        for stage in ("migrate", "collectstatic"):
            with self.subTest(stage=stage):
                result = self.run_script("paperless-ngx", FAIL_STAGE=stage)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((app / "src/manage.py").read_text(), "old-code")
                self.assertEqual((app / ".af-version").read_text(), "old-version")
                self.assertTrue((self.root / "service_active_paperless-webserver").exists())

    def test_vaultwarden_update_preserves_admin_env_and_signup_policy(self):
        env_file = self.root / "etc/vaultwarden/vaultwarden.env"
        env_file.write_text(
            "ROCKET_PORT=8343\n"
            "SIGNUPS_ALLOWED=false\n"
            "INVITATIONS_ALLOWED=false\n"
            "ADMIN_TOKEN=existing-custom-admin-token\n"
            "SMTP_HOST=mail.custom.org\n"
        )
        token_txt = self.root / "opt/AetherFlow/logs/vaultwarden_admin_token.txt"
        token_txt.write_text("Vaultwarden Admin Token: existing-custom-admin-token\n")

        result = self.run_script("vaultwarden", AF_APP_PORT="8350")
        self.assertEqual(result.returncode, 0, result.stderr)

        env_after = env_file.read_text()
        self.assertIn("ROCKET_PORT=8350", env_after)
        self.assertIn("SIGNUPS_ALLOWED=false", env_after)
        self.assertIn("INVITATIONS_ALLOWED=false", env_after)
        self.assertIn("ADMIN_TOKEN=existing-custom-admin-token", env_after)
        self.assertIn("SMTP_HOST=mail.custom.org", env_after)
        self.assertEqual(token_txt.read_text().strip(), "Vaultwarden Admin Token: existing-custom-admin-token")

    def test_librespeed_update_preserves_tuning(self):
        toml_file = self.root / "opt/librespeed/settings.toml"
        toml_file.parent.mkdir(parents=True, exist_ok=True)
        toml_file.write_text(
            'listen_port=8988\n'
            'statistics_password="custom-stats-password"\n'
            'enable_tls=true\n'
            'tls_cert_file="/etc/ssl/mycert.pem"\n'
            'database_type="postgresql"\n'
        )

        result = self.run_script("librespeed", AF_APP_PORT="8999")
        self.assertEqual(result.returncode, 0, result.stderr)

        toml_after = toml_file.read_text()
        self.assertIn("listen_port=8999", toml_after)
        self.assertIn('statistics_password="custom-stats-password"', toml_after)
        self.assertIn("enable_tls=true", toml_after)
        self.assertIn('database_type="postgresql"', toml_after)

    def test_kasmvnc_update_preserves_custom_yaml(self):
        yaml_file = self.root / "var/lib/kasmvnc/.vnc/kasmvnc.yaml"
        yaml_file.parent.mkdir(parents=True, exist_ok=True)
        yaml_file.write_text(
            "network:\n"
            "  interface: 127.0.0.1\n"
            "  websocket_port: 6081\n"
            "desktop:\n"
            "  resolution: 2560x1440\n"
            "  depth: 24\n"
        )

        result = self.run_script("kasmvnc", AF_APP_PORT="6095")
        self.assertEqual(result.returncode, 0, result.stderr)

        yaml_after = yaml_file.read_text()
        self.assertIn("websocket_port: 6095", yaml_after)
        self.assertIn("resolution: 2560x1440", yaml_after)

    def test_kasmvnc_inserts_missing_port_without_duplicate_network_mapping(self):
        yaml_file = self.root / "var/lib/kasmvnc/.vnc/kasmvnc.yaml"
        yaml_file.parent.mkdir(parents=True, exist_ok=True)
        yaml_file.write_text("network:\n  interface: 127.0.0.1\ndesktop:\n  resolution: 2560x1440\n")
        result = self.run_script('kasmvnc', AF_APP_PORT='6095')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = yaml_file.read_text()
        self.assertEqual(text.count('network:'), 1)
        self.assertIn('network:\n  websocket_port: 6095\n  interface: 127.0.0.1', text)
        self.assertIn('resolution: 2560x1440', text)

    def test_mcvnc_update_preserves_tuning_and_uses_env_in_service(self):
        env_file = self.root / "etc/mcvnc/mcvnc.env"
        env_file.write_text(
            "MCVNC_BIND=127.0.0.1:6900\n"
            "MCVNC_DEVICE=/dev/dri/renderD129\n"
            "MCVNC_PRESET=4k\n"
            "MCVNC_FPS=120\n"
            "MCVNC_QP=18\n"
        )

        result = self.run_script("mcvnc", AF_APP_PORT="6950")
        self.assertEqual(result.returncode, 0, result.stderr)

        env_after = env_file.read_text()
        self.assertIn("MCVNC_BIND=127.0.0.1:6950", env_after)
        self.assertIn("MCVNC_DEVICE=/dev/dri/renderD129", env_after)
        self.assertIn("MCVNC_PRESET=4k", env_after)
        self.assertIn("MCVNC_FPS=120", env_after)
        self.assertIn("MCVNC_QP=18", env_after)

        unit_file = self.root / "etc/systemd/system/af-mcvnc.service"
        self.assertIn(f"ExecStart={self.root}/usr/local/bin/mcvnc play --bind ${{MCVNC_BIND}} --device ${{MCVNC_DEVICE}} --preset ${{MCVNC_PRESET}} --fps ${{MCVNC_FPS}} --qp ${{MCVNC_QP}}", unit_file.read_text())

    def test_virtualenv_paths_survive_activation_and_failed_pip_restores_runtime(self):
        for package, directory in (('cloudplow', 'opt/cloudplow/.venv'),
                                   ('sabnzbd', 'opt/SABnzbd/.venv'),
                                   ('calibreweb', 'opt/calibre-web/.venv'),
                                   ('homeassistant', 'srv/homeassistant'),
                                   ('paperless-ngx', 'opt/paperless/.venv')):
            with self.subTest(package=package):
                result = self.run_script(package)
                self.assertEqual(result.returncode, 0, result.stderr)
                virtualenv = self.root / directory
                self.assertEqual((virtualenv / 'bin/entrypoint').read_text(), f'#!{virtualenv}/bin/python\n')
                self.assertEqual((virtualenv / 'bin/activate').read_text(), f'VIRTUAL_ENV={virtualenv}\n')
                sentinel = virtualenv / 'retained-runtime'
                sentinel.write_text('previous-working-venv')
                failed = self.run_script(package, FAIL_STAGE='pip')
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(sentinel.read_text(), 'previous-working-venv')

    def test_n8n_version_channel_selection(self):
        res1 = self.run_script("n8n", TEST_NODE_VERSION="v20.18.0")
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("requires Node.js >= 24", res1.stderr)
        self.assertFalse((self.root / "npm_installed.log").exists())

        res2 = self.run_script("n8n", TEST_NODE_VERSION="v20.18.0", AF_TARGET_VERSION="2.1.0")
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("requires Node.js >= 24", res2.stderr)

        res3 = self.run_script("n8n", TEST_NODE_VERSION="v24.1.0", AF_TARGET_VERSION="2.1.0")
        self.assertEqual(res3.returncode, 0, res3.stderr)
        npm_log_after = (self.root / "npm_installed.log").read_text()
        self.assertIn("n8n@2.1.0", npm_log_after)
        self.assertIn("--prefix", npm_log_after)
        self.assertNotIn(" -g ", npm_log_after)
        self.assertEqual((self.root / "usr/local/bin/n8n").resolve(),
                         self.root / "opt/n8n/node_modules/.bin/n8n")


if __name__ == "__main__":
    unittest.main()
