#!/usr/bin/env python3
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions

ROOT = Path(__file__).resolve().parents[1]

MOCK_SCRIPT = r"""#!/bin/bash
set -e
root="${TEST_ROOT}"
cmd="$(basename "$0")"
printf '%s %s\n' "$cmd" "$*" >> "${root}/mock_commands.log"

case "$cmd" in
    dpkg)
        if [[ "$1" == "--compare-versions" ]]; then exec /usr/bin/dpkg "$@"; fi
        echo "amd64"
        exit 0
        ;;
    dpkg-deb)
        echo "3.0.0"
        exit 0
        ;;
    dpkg-query)
        if [[ "$*" == *db:Status-Status* ]]; then printf 'installed '; fi
        echo "3.0.0"
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
                printf '#!/bin/sh\nexit 0\n' | /usr/bin/sha256sum | awk '{print "sha256:" $1}'
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
    sha256sum)
        exec /usr/bin/sha256sum "$@"
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
        out=""
        prev=""
        for arg in "$@"; do
            if [ "$prev" = "-o" ]; then
                out="$arg"
                break
            fi
            prev="$arg"
        done
        if [[ "$*" == *github.com/*/releases/latest* ]]; then
            if [[ "$*" == *url_effective* ]]; then
                printf 'https://github.com/fixture/app/releases/tag/v3.0.0\n'
            elif [ -n "$out" ]; then
                mkdir -p "$(dirname "$out")"
                printf '{"tag_name":"v3.0.0"}\n' > "$out"
            else
                printf '{"tag_name":"v3.0.0"}\n'
            fi
            exit 0
        fi
        if [ "${FAIL_STAGE:-}" = "download" ]; then
            printf "injected failure %s\n" "$FAIL_STAGE" >> "${root}/mock_commands.log"
            exit 22
        fi
        if [ -n "$out" ]; then
            mkdir -p "$(dirname "$out")"
            if [[ "$* $out" == *speedtest* || "$* $out" == *librespeed* ]] && [[ "$out" == *.tar.gz || "$out" == *.tgz ]]; then
                /usr/bin/python3 - "$out" <<'PYEOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as tf:
    data = b"#!/bin/sh\nexit 0\n"
    info = tarfile.TarInfo(name="speedtest-backend")
    info.size = len(data)
    info.mode = 0o755
    tf.addfile(info, io.BytesIO(data))
PYEOF
            elif [[ "$* $out" == *radarr* ]] && [[ "$out" == *.tar.gz || "$out" == *.tgz ]]; then
                /usr/bin/python3 - "$out" <<'PYEOF'
import io, os, sys, tarfile
ver = os.environ.get("MOCK_RADARR_BIN_VERSION", "5.16.3.9541")
with tarfile.open(sys.argv[1], "w:gz") as tf:
    script = f"#!/bin/sh\necho 'Radarr version {ver}'\n".encode()
    info = tarfile.TarInfo(name="Radarr/Radarr")
    info.size = len(script)
    info.mode = 0o755
    tf.addfile(info, io.BytesIO(script))
PYEOF
            elif [[ "$* $out" == *sonarr* ]] && [[ "$out" == *.tar.gz || "$out" == *.tgz ]]; then
                /usr/bin/python3 - "$out" <<'PYEOF'
import io, os, sys, tarfile
ver = os.environ.get("MOCK_SONARR_BIN_VERSION", "4.0.12.2823")
with tarfile.open(sys.argv[1], "w:gz") as tf:
    script = f"#!/bin/sh\necho 'Sonarr version {ver}'\n".encode()
    info = tarfile.TarInfo(name="Sonarr/Sonarr")
    info.size = len(script)
    info.mode = 0o755
    tf.addfile(info, io.BytesIO(script))
PYEOF
            elif [[ "$* $out" == *prowlarr* ]] && [[ "$out" == *.tar.gz || "$out" == *.tgz ]]; then
                /usr/bin/python3 - "$out" <<'PYEOF'
import io, os, sys, tarfile
ver = os.environ.get("MOCK_PROWLARR_BIN_VERSION", "1.28.2.4885")
with tarfile.open(sys.argv[1], "w:gz") as tf:
    script = f"#!/bin/sh\necho 'Prowlarr version {ver}'\n".encode()
    info = tarfile.TarInfo(name="Prowlarr/Prowlarr")
    info.size = len(script)
    info.mode = 0o755
    tf.addfile(info, io.BytesIO(script))
PYEOF
            else
                printf '#!/bin/sh\nexit 0\n' > "$out"
            fi
            /usr/bin/sha256sum "$out" | awk '{print $1}' > "$out.sha256"
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
                printf '#!/bin/sh\nexit 0\n' > "${c_dir}/vaultwarden"
                chmod +x "${c_dir}/vaultwarden"
                mkdir -p "${c_dir}/web-vault"
                ;;
            *speedtest*|*librespeed*)
                printf '#!/bin/sh\nexit 0\n' > "${c_dir}/speedtest-backend"
                chmod +x "${c_dir}/speedtest-backend"
                ;;
            *paperless*)
                mkdir -p "${c_dir}/src"
                printf 'print("mock manage")\n' > "${c_dir}/src/manage.py"
                ;;
            *flaresolverr*)
                printf '#!/bin/sh\nexit 0\n' > "${c_dir}/flaresolverr"
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
        unit=""
        prev_arg=""
        for arg in "$@"; do
            case "$arg" in
                --property=*|-p=*) ;;
                -*) ;;
                *)
                    if [ "$prev_arg" != "-p" ] && [ "$prev_arg" != "--property" ]; then
                        unit="${arg%.service}"
                    fi
                    ;;
            esac
            prev_arg="$arg"
        done
        if [ "$sub" = "is-active" ]; then
            quiet=false
            if [[ " $arguments " =~ [[:space:]](--quiet|-q)[[:space:]] ]]; then
                quiet=true
            fi
            all_active=true
            has_units=false
            for u in "$@"; do
                [[ "$u" == -* ]] && continue
                u="${u%.service}"
                has_units=true
                if [ ! -f "${root}/service_active_${u}" ]; then
                    all_active=false
                    break
                fi
            done
            if [ "$has_units" = true ] && [ "$all_active" = true ]; then
                [ "$quiet" = false ] && echo "active"
                exit 0
            else
                [ "$quiet" = false ] && echo "inactive"
                exit 3
            fi
        elif [ "$sub" = "show" ]; then
            unit=""
            prev_arg=""
            for arg in "$@"; do
                case "$arg" in
                    --property=*|-p=*) ;;
                    -*) ;;
                    *)
                        if [ "$prev_arg" != "-p" ] && [ "$prev_arg" != "--property" ]; then
                            unit="${arg%.service}"
                            break
                        fi
                        ;;
                esac
                prev_arg="$arg"
            done
            if [ -n "$unit" ] && [ -f "${root}/service_active_${unit}" ]; then
                echo "LoadState=loaded"
                echo "ActiveState=active"
                echo "MainPID=0"
                echo "UnitFileState=enabled"
            else
                echo "LoadState=loaded"
                echo "ActiveState=inactive"
                echo "MainPID=0"
                echo "UnitFileState=enabled"
            fi
            exit 0
        elif [ "$sub" = "is-enabled" ]; then
            unit=""
            for u in "$@"; do
                [[ "$u" == -* ]] && continue
                unit="${u%.service}"
                break
            done
            if [ -n "$unit" ] && [ -f "${root}/service_enabled_${unit}" ]; then
                exit 0
            else
                exit 1
            fi
        elif [ "$sub" = "start" ]; then
            for u in "$@"; do
                [[ "$u" == -* ]] && continue
                u="${u%.service}"
                touch "${root}/service_active_${u}"
                echo "started ${u}" >> "${root}/systemctl.log"
            done
            exit 0
        elif [ "$sub" = "stop" ]; then
            for u in "$@"; do
                [[ "$u" == -* ]] && continue
                u="${u%.service}"
                rm -f "${root}/service_active_${u}"
                echo "stopped ${u}" >> "${root}/systemctl.log"
            done
            exit 0
        elif [ "$sub" = "restart" ]; then
            for u in "$@"; do
                [[ "$u" == -* ]] && continue
                u="${u%.service}"
                touch "${root}/service_active_${u}"
                echo "restarted ${u}" >> "${root}/systemctl.log"
            done
            exit 0
        elif [ "$sub" = "enable" ]; then
            for enabled_unit in "$@"; do
                [[ "$enabled_unit" == -* ]] && continue
                enabled_unit="${enabled_unit%.service}"
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
        if [[ "${1:-}" == req ]]; then
            previous=""
            for argument in "$@"; do
                if [[ "$previous" == -out || "$previous" == -keyout ]]; then
                    printf 'fixture TLS material\n' > "$argument"
                fi
                previous="$argument"
            done
            exit 0
        fi
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
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -u) shift 2 ;;
                -c) shift ;;
                --) shift ;;
                *)
                    if [ "$#" -gt 1 ] && { [ "$2" = "-c" ] || [ "$2" = "--" ]; }; then
                        shift
                    else
                        break
                    fi
                    ;;
            esac
        done
        exec "$@"
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
            "usr/bin",
            "usr/sbin",
            "usr/lib",
            "usr/share",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)

        (self.root / "etc/os-release").write_text("ID=ubuntu\nVERSION_CODENAME=noble\n")

        for command in (
            "dpkg", "dpkg-deb", "dpkg-query", "uname", "flock", "jq", "sha256sum", "node", "curl", "git", "yarn", "npm", "pip", "pip3",
            "tar", "python", "python3", "systemctl", "openssl", "apt-get", "chown", "chmod",
            "useradd", "usermod", "userdel", "groupdel", "id", "install", "sudo", "runuser", "cargo", "kasmvncpasswd"
        ):
            p = self.root / "mock-bin" / command
            p.write_text(MOCK_SCRIPT)
            p.chmod(0o755)
            shutil.copy2(p, self.root / 'usr/bin' / command)

        common_content = r"""set -euo pipefail
MASTER_USER=admin
MASTER_PASS=testpass123
log_info() { printf '%s\n' "$*" >> "$LOGFILE"; }
log_warn() { printf '%s\n' "$*" >> "$LOGFILE"; }
log_error() { printf '%s\n' "$*" >&2; }
print_warn() { printf '%s\n' "$*" >&2; }
print_error() { printf '%s\n' "$*" >&2; }
report_progress() { :; }
require_root() { :; }
ensure_node() { :; }
sync_node_global_bins() { :; }
get_base_domain() { printf 'example.com\n'; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f "$AF_ARCHIVE_BACKUP/.af-archive-pending"; }
lock_path() { printf '%s/install/.%s.lock\n' "$TEST_ROOT" "$1"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
purge_systemd_unit() { :; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
seed_servarr_master_user() { :; }
application_readiness_url() { printf 'http://127.0.0.1:%s/\n' "${2:-7878}"; }
"""
        common_content += common_functions(
            "systemd_unit_inactive",
            "stop_systemd_unit",
            "github_latest_tag",
            "node_build",
            "install_npm_app",
            "replace_app_tree",
            "write_app_version",
            "resolve_installed_binary_version",
            "queue_app_version",
            "commit_app_versions",
            "safe_restore_path_from_backup",
            "snapshot_state_dirs",
            "restore_state_snapshot",
            "begin_state_transaction",
            "cleanup_state_transaction",
            "verify_systemd_service_active",
            "wait_for_service_ready",
            "verify_download_sha256",
            "download_file",
            "git_checkout_version",
            "verify_deb_installed",
            "safe_rm_rf",
            "snapshot_app_state",
            "restore_app_state",
            "safe_config_python",
            "validate_config_paths",
            "write_config_file",
            "set_config_file_mode",
            "verify_sha256",
            "set_config_value",
            "stage_app_archive",
            "rollback_app_archive_update",
            "finish_app_archive_update",
            "af_cleanup_job_scratch",
            "af_prepare_job_scratch",
            "_af_redact_awk",
            "_af_redact_sed",
            "_af_redact_without_python",
            "_af_redact_ascii_fallback",
            "_af_truncate_receipt_field",
            "af_write_failure_receipt",
            "report_progress",
            "check_disk_space",
        )
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(self.rebase(common_content))

    def rebase(self, source):
        prefixes = ('/usr/local', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/share', '/opt', '/var', '/etc', '/srv', '/mnt', '/run', '/install', '/tmp', '/home', '/root', '/data')
        pattern = re.compile(r'(?<![\w/.-])(' + '|'.join(re.escape(prefix) for prefix in prefixes) + r')(?=/|[^\w.-]|$)')
        return pattern.sub(lambda match: str(self.root) + match.group(0), source)

    def run_script(self, package, action="install", **environment):
        script_path = ROOT / f"packages/package/{action}/{action}package-{package}"
        source = script_path.read_text()
        root_posix = str(self.root).replace("\\", "/")

        (self.root / "tmp").mkdir(exist_ok=True)
        source = self.rebase(source)

        staged_script = self.root / "run_test_script.sh"
        staged_script.write_text(source)
        staged_script.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:{os.environ['PATH']}",
            "HOME": f"{root_posix}/home",
            "TEST_ROOT": root_posix,
            "TMPDIR": f"{root_posix}/tmp",
            "AETHERFLOW_INSTALL_ROOT": root_posix,
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

    def test_paperless_ngx_preserves_secret_key_and_discards_committed_snapshot(self):
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
        self.assertEqual(backups, [])
        self.assertEqual(db.read_text(), "database contents")

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

    def test_mcvnc_fixture_never_sources_host_cargo_environment(self):
        host_home = self.root / "host-home"
        host_cargo = host_home / ".cargo"
        host_cargo.mkdir(parents=True)
        (host_cargo / "env").write_text(f'printf sourced > "{self.root}/host-cargo-sourced"\nexit 101\n')
        with mock.patch.dict(os.environ, {"HOME": str(host_home)}):
            result = self.run_script("mcvnc")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "host-cargo-sourced").exists())
        self.assertIn("cargo build --release", (self.root / "mock_commands.log").read_text())

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

    def test_af_cleanup_job_scratch_preserves_dir_when_requested_or_error(self):
        """Regression test: calling af_cleanup_job_scratch after declare -F af_cleanup_job_scratch
        with AF_PRESERVE_SCRATCH=1 (or non-zero $rc) preserves $AF_JOB_SCRATCH_DIR.
        """
        # Case 1: AF_PRESERVE_SCRATCH=1 after declare -F (which sets $? to 0)
        scratch_dir_1 = self.root / "tmp/scratch-preserve-flag"
        scratch_dir_1.mkdir(parents=True, exist_ok=True)
        (scratch_dir_1 / "data.txt").write_text("recovery-data")
        script_1 = f"""
source "{self.root}/opt/AetherFlow/packages/common.sh"
AF_JOB_SCRATCH_DIR="{scratch_dir_1}"
export AF_JOB_SCRATCH_DIR
export AF_PRESERVE_SCRATCH=1
declare -F af_cleanup_job_scratch >/dev/null 2>&1 && af_cleanup_job_scratch
"""
        res_1 = subprocess.run(["bash", "-c", script_1], capture_output=True, text=True)
        self.assertEqual(res_1.returncode, 0)
        self.assertTrue(scratch_dir_1.exists(), "AF_JOB_SCRATCH_DIR must be preserved when AF_PRESERVE_SCRATCH=1")
        self.assertTrue((scratch_dir_1 / "data.txt").exists())

        # Case 2: Explicit non-zero rc passed to af_cleanup_job_scratch with backup directory
        scratch_dir_2 = self.root / "tmp/scratch-preserve-rc"
        scratch_dir_2.mkdir(parents=True, exist_ok=True)
        (scratch_dir_2 / "backup").mkdir(parents=True, exist_ok=True)
        (scratch_dir_2 / "backup/data.txt").write_text("backup-data")
        script_2 = f"""
source "{self.root}/opt/AetherFlow/packages/common.sh"
AF_JOB_SCRATCH_DIR="{scratch_dir_2}"
export AF_JOB_SCRATCH_DIR
rc=2
declare -F af_cleanup_job_scratch >/dev/null 2>&1 && af_cleanup_job_scratch "$rc" || true
"""
        res_2 = subprocess.run(["bash", "-c", script_2], capture_output=True, text=True)
        self.assertTrue(scratch_dir_2.exists(), "AF_JOB_SCRATCH_DIR must be preserved on non-zero exit with backup")
        self.assertTrue((scratch_dir_2 / "backup/data.txt").exists())

        # Case 3: When exit code is 0 and AF_PRESERVE_SCRATCH is not 1, scratch dir is cleaned up
        scratch_dir_3 = self.root / "tmp/scratch-normal-cleanup"
        scratch_dir_3.mkdir(parents=True, exist_ok=True)
        (scratch_dir_3 / "data.txt").write_text("temp-data")
        script_3 = f"""
source "{self.root}/opt/AetherFlow/packages/common.sh"
AF_JOB_SCRATCH_DIR="{scratch_dir_3}"
export AF_JOB_SCRATCH_DIR
declare -F af_cleanup_job_scratch >/dev/null 2>&1 && af_cleanup_job_scratch 0
"""
        res_3 = subprocess.run(["bash", "-c", script_3], capture_output=True, text=True)
        self.assertEqual(res_3.returncode, 0)
        self.assertFalse(scratch_dir_3.exists(), "AF_JOB_SCRATCH_DIR should be removed on successful completion")

    def test_piped_failed_rollback_preserves_scratch_recovery_backup(self):
        """Regression test: installpackage-piped preserves recovery backup in
        $AF_JOB_SCRATCH_DIR when restart/rollback fails during cleanup.
        """
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        start = piped_script.index("cleanup_piped_install() {")
        end = piped_script.index("\n}\n", start) + 3
        cleanup_piped = piped_script[start:end]

        scratch_dir = self.root / "tmp/piped-scratch-recovery"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = scratch_dir / "af-piped-runtime-999999"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "saved-piped-state.dat").write_text("retained-piped-database")

        test_script = f"""
set +e
LOGFILE="{self.root}/test.log"
af_write_failure_receipt() {{ :; }}
print_error() {{ printf "%s\\n" "$*" >&2; }}
print_warn() {{ printf "%s\\n" "$*" >&2; }}
source "{self.root}/opt/AetherFlow/packages/common.sh"
{cleanup_piped}

AF_JOB_SCRATCH_DIR="{scratch_dir}"
RUNTIME_BACKUP="{backup_dir}"
PIPED_INSTALL_COMPLETED=0
RUNTIME_HAD_PREVIOUS=true
RUNTIME_CHANGED=false
SERVICE_STOPPED=true
BUILD_DIR=""
INSTALL_COMMITTED=false
systemctl() {{ return 1; }}

cleanup_piped_install
exit_status=$?
printf 'RESULT=%d\\n' "$exit_status"
"""
        res = subprocess.run(["bash", "-c", test_script], capture_output=True, text=True)
        self.assertIn("RESULT=1", res.stdout)
        self.assertTrue(scratch_dir.exists(), "Piped scratch dir must be preserved when restart fails")
        self.assertTrue(backup_dir.exists(), "Piped backup dir must be preserved in scratch dir")
        self.assertEqual((backup_dir / "saved-piped-state.dat").read_text(), "retained-piped-database")
        self.assertIn("Rollback incomplete; recovery backup preserved", res.stderr)

    def test_invidious_failed_rollback_preserves_scratch_recovery_backup(self):
        """Regression test: installpackage-invidious preserves recovery backup in
        $AF_JOB_SCRATCH_DIR when restart/rollback fails during cleanup.
        """
        invidious_script = (ROOT / "packages/package/install/installpackage-invidious").read_text()
        start = invidious_script.index("cleanup_invidious_install() {")
        end = invidious_script.index("\n}\n", start) + 3
        cleanup_invidious = invidious_script[start:end]

        scratch_dir = self.root / "tmp/invidious-scratch-recovery"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = scratch_dir / "af-invidious-runtime.999999"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "saved-invidious-state.dat").write_text("retained-invidious-database")

        test_script = f"""
set +e
LOGFILE="{self.root}/test.log"
af_write_failure_receipt() {{ :; }}
print_error() {{ printf "%s\\n" "$*" >&2; }}
print_warn() {{ printf "%s\\n" "$*" >&2; }}
source "{self.root}/opt/AetherFlow/packages/common.sh"
{cleanup_invidious}

AF_JOB_SCRATCH_DIR="{scratch_dir}"
RUNTIME_BACKUP="{backup_dir}"
INVIDIOUS_INSTALL_COMPLETED=0
PREVIOUS_UNITS=(af-invidious.service)
RUNTIME_CHANGED=false
TMP_DIR=""
INSTALL_COMMITTED=false
systemctl() {{ return 1; }}

cleanup_invidious_install
exit_status=$?
printf 'RESULT=%d\\n' "$exit_status"
"""
        res = subprocess.run(["bash", "-c", test_script], capture_output=True, text=True)
        self.assertIn("RESULT=1", res.stdout)
        self.assertTrue(scratch_dir.exists(), "Invidious scratch dir must be preserved when restart fails")
        self.assertTrue(backup_dir.exists(), "Invidious backup dir must be preserved in scratch dir")
        self.assertEqual((backup_dir / "saved-invidious-state.dat").read_text(), "retained-invidious-database")
        self.assertIn("Rollback incomplete; recovery backup preserved", res.stderr)


    def test_check_disk_space_fails_closed(self):
        """Verify check_disk_space fails closed on df errors, empty/non-numeric output,
        insufficient disk space, insufficient free inodes, and tmpfs staging."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_cases = [
            # 1. df fails completely (fails closed on df -PT)
            ("df() { return 1; }; check_disk_space /opt 512", False, "is on tmpfs filesystem or filesystem type is unknown"),
            # 2. df returns empty output (fails closed on df -PT)
            ("df() { echo ''; }; check_disk_space /opt 512", False, "is on tmpfs filesystem or filesystem type is unknown"),
            # 2b. df -Pk fails when df -PT succeeds
            (
                "df() { if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 ext4 10000000 1000 9999000 1%% /\\n'; else return 1; fi; }; check_disk_space /opt 512",
                False,
                "Unable to determine free disk space",
            ),
            # 2c. df -Pk returns empty output when df -PT succeeds
            (
                "df() { if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 ext4 10000000 1000 9999000 1%% /\\n'; else echo ''; fi; }; check_disk_space /opt 512",
                False,
                "Unable to determine free disk space",
            ),
            # 3. df returns non-numeric output
            (
                "df() { if [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 1000 500 N/A 50%% /\\n'; else command df \"$@\"; fi; }; check_disk_space /opt 512",
                False,
                "Unable to determine free disk space",
            ),
            # 4. df returns insufficient free disk space
            (
                "df() { if [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 1000 900 100 90%% /\\n'; else command df \"$@\"; fi; }; check_disk_space /opt 512",
                False,
                "Insufficient free disk space",
            ),
            # 5. df returns insufficient free inodes
            (
                "df() { if [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% /\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 10000 9990 10 99%% /\\n'; else command df \"$@\"; fi; }; check_disk_space /opt 512",
                False,
                "Insufficient or unknown free inodes",
            ),
            # 6. df returns empty/unknown inodes
            (
                "df() { if [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% /\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 10000 9990 - - /\\n'; else command df \"$@\"; fi; }; check_disk_space /opt 512",
                False,
                "Insufficient or unknown free inodes",
            ),
            # 7. tmpfs staging rejection when AF_REJECT_TMPFS_STAGING=1
            (
                "export AF_REJECT_TMPFS_STAGING=1; df() { if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\ntmpfs tmpfs 10000000 1000 9999000 1%% /staging\\n'; else command df \"$@\"; fi; }; check_disk_space /staging 512",
                False,
                "is on tmpfs filesystem",
            ),
            # 7b. df -PT fails (exits 1) when AF_REJECT_TMPFS_STAGING=1 -> fails closed
            (
                "export AF_REJECT_TMPFS_STAGING=1; df() { if [[ \"$*\" == *-PT* ]]; then return 1; elif [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% /staging\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% /staging\\n'; else command df \"$@\"; fi; }; check_disk_space /staging 512",
                False,
                "is on tmpfs filesystem or filesystem type is unknown",
            ),
            # 7c. df -PT outputs nothing when AF_REJECT_TMPFS_STAGING=1 -> fails closed
            (
                "export AF_REJECT_TMPFS_STAGING=1; df() { if [[ \"$*\" == *-PT* ]]; then echo ''; elif [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% /staging\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% /staging\\n'; else command df \"$@\"; fi; }; check_disk_space /staging 512",
                False,
                "is on tmpfs filesystem or filesystem type is unknown",
            ),
            # 7d. df -PT fails on rebased /var/tmp with AF_REJECT_TMPFS_STAGING unset -> fails closed
            (
                f"df() {{ if [[ \"$*\" == *-PT* ]]; then return 1; elif [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% {self.root}/var/tmp\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% {self.root}/var/tmp\\n'; else command df \"$@\"; fi; }}; check_disk_space '{self.root}/var/tmp' 512",
                False,
                "is on tmpfs filesystem or filesystem type is unknown",
            ),
            # 7e. df -PT outputs nothing on rebased /var/tmp with AF_REJECT_TMPFS_STAGING unset -> fails closed
            (
                f"df() {{ if [[ \"$*\" == *-PT* ]]; then echo ''; elif [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% {self.root}/var/tmp\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% {self.root}/var/tmp\\n'; else command df \"$@\"; fi; }}; check_disk_space '{self.root}/var/tmp' 512",
                False,
                "is on tmpfs filesystem or filesystem type is unknown",
            ),
            # 7f. df -PT missing fs_type on rebased /var/tmp with AF_REJECT_TMPFS_STAGING unset -> fails closed
            (
                f"df() {{ if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1\\n'; elif [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% {self.root}/var/tmp\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% {self.root}/var/tmp\\n'; else command df \"$@\"; fi; }}; check_disk_space '{self.root}/var/tmp' 512",
                False,
                "is on tmpfs filesystem or filesystem type is unknown",
            ),
            # 7g. tmpfs staging rejection on rebased /var/tmp with AF_REJECT_TMPFS_STAGING unset
            (
                f"df() {{ if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\ntmpfs tmpfs 10000000 1000 9999000 1%% {self.root}/var/tmp\\n'; else command df \"$@\"; fi; }}; check_disk_space '{self.root}/var/tmp' 512",
                False,
                "is on tmpfs filesystem",
            ),
            # 7h. ramfs staging rejection on rebased /var/tmp with AF_REJECT_TMPFS_STAGING unset
            (
                f"df() {{ if [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\nramfs ramfs 10000000 1000 9999000 1%% {self.root}/var/tmp\\n'; else command df \"$@\"; fi; }}; check_disk_space '{self.root}/var/tmp' 512",
                False,
                "is on tmpfs filesystem",
            ),
            # 8. Success when disk space and inodes are ample
            (
                "df() { if [[ \"$*\" == *-Pk* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 10000000 1000 9999000 1%% /\\n'; elif [[ \"$*\" == *-Pi* ]]; then printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\\n/dev/sda1 100000 1000 99000 1%% /\\n'; elif [[ \"$*\" == *-PT* ]]; then printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\\n/dev/sda1 ext4 10000000 1000 9999000 1%% /\\n'; else command df \"$@\"; fi; }; check_disk_space /opt 512",
                True,
                "",
            ),
        ]

        for snippet, expect_success, expected_err in test_cases:
            with self.subTest(snippet=snippet[:40]):
                cmd = f"""
source "{common_script}"
{snippet}
"""
                res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                if expect_success:
                    self.assertEqual(res.returncode, 0, f"Expected success but got rc={res.returncode}: {res.stderr}")
                else:
                    self.assertNotEqual(res.returncode, 0, f"Expected failure but got rc=0 for: {snippet}")
                    if expected_err:
                        self.assertIn(expected_err, res.stderr)

    def test_kasmvnc_and_rclone_stage_in_scratch_and_check_disk_space(self):
        """Verify installpackage-kasmvnc and installpackage-rclone prepare scratch
        and check disk space before mutations and stage in AF_JOB_SCRATCH_DIR."""
        kasmvnc_text = (ROOT / "packages/package/install/installpackage-kasmvnc").read_text()
        rclone_text = (ROOT / "packages/package/install/installpackage-rclone").read_text()

        # KasmVNC checks
        self.assertIn('af_prepare_job_scratch "${PACKAGE_NAME}"', kasmvnc_text)
        self.assertIn('check_disk_space "${AF_JOB_SCRATCH_DIR}" 512', kasmvnc_text)
        self.assertIn('check_disk_space "/opt" 512', kasmvnc_text)
        self.assertIn('TMP_DIR="$(mktemp -d "${AF_JOB_SCRATCH_DIR}/kasmvnc.XXXXXX")"', kasmvnc_text)
        self.assertNotIn('mktemp -d /tmp/', kasmvnc_text)
        self.assertIn('af_cleanup_job_scratch "$rc"', kasmvnc_text)

        # Ensure scratch & check_disk_space occur BEFORE apt-get in KasmVNC
        idx_scratch_kasm = kasmvnc_text.index("af_prepare_job_scratch")
        idx_disk_kasm = kasmvnc_text.index("check_disk_space")
        idx_apt_kasm = kasmvnc_text.index("apt-get update")
        self.assertLess(idx_scratch_kasm, idx_apt_kasm)
        self.assertLess(idx_disk_kasm, idx_apt_kasm)

        # Rclone checks
        self.assertIn('af_prepare_job_scratch "${PACKAGE_NAME}"', rclone_text)
        self.assertIn('check_disk_space "${AF_JOB_SCRATCH_DIR}" 512', rclone_text)
        self.assertIn('check_disk_space "/usr/bin" 512', rclone_text)
        self.assertIn('TMP_ZIP=$(mktemp "${AF_JOB_SCRATCH_DIR}/rclone-XXXXXX.zip")', rclone_text)
        self.assertIn('TMP_DIR=$(mktemp -d "${AF_JOB_SCRATCH_DIR}/rclone-extract-XXXXXX")', rclone_text)
        self.assertNotIn('mktemp /tmp/', rclone_text)
        self.assertNotIn('mktemp -d /tmp/', rclone_text)
        self.assertIn('af_cleanup_job_scratch "$rc"', rclone_text)

        # Ensure scratch & check_disk_space occur BEFORE apt-get in Rclone
        idx_scratch_rc = rclone_text.index("af_prepare_job_scratch")
        idx_disk_rc = rclone_text.index("check_disk_space")
        idx_apt_rc = rclone_text.index("apt-get update")
        self.assertLess(idx_scratch_rc, idx_apt_rc)
        self.assertLess(idx_disk_rc, idx_apt_rc)

        # Ensure rclone.env exports both RCLONE_RC_* and RCLONE_* vars
        self.assertIn('RCLONE_RC_USER="${FINAL_USER}"', rclone_text)
        self.assertIn('RCLONE_RC_PASS="${FINAL_PASS}"', rclone_text)
        self.assertIn('RCLONE_USER="${FINAL_USER}"', rclone_text)
        self.assertIn('RCLONE_PASS="${FINAL_PASS}"', rclone_text)

    def test_piped_target_version_manifest_formats(self):
        """Verify installpackage-piped supports both = and : manifest delimiters
        for PIPED_TARGET_VERSION and AF_TARGET_VERSION."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        self.assertIn("frontend=*)", piped_script)
        self.assertIn("backend=*)", piped_script)
        self.assertIn("proxy=*)", piped_script)
        self.assertIn("frontend:*)", piped_script)
        self.assertIn("backend:*)", piped_script)
        self.assertIn("proxy:*)", piped_script)

        # Test bash extraction logic with = delimiter
        cmd_equals = """
PIPED_TARGET_VERSION="frontend=fe-v123,backend=be-v456,proxy=pr-v789"
""" + piped_script[piped_script.index("TARGET_FRONTEND_REF=\"\""):piped_script.index("youtube_init piped")] + """
echo "fe=$PIPED_FRONTEND_REF;be=$PIPED_BACKEND_REF;pr=$PIPED_PROXY_REF"
"""
        res_eq = subprocess.run(["bash", "-c", cmd_equals], capture_output=True, text=True)
        self.assertEqual(res_eq.returncode, 0, res_eq.stderr)
        self.assertIn("fe=fe-v123;be=be-v456;pr=pr-v789", res_eq.stdout)

        # Test bash extraction logic with : delimiter
        cmd_colon = """
AF_TARGET_VERSION="frontend:fe-tag,backend:be-tag,proxy:pr-tag"
""" + piped_script[piped_script.index("TARGET_FRONTEND_REF=\"\""):piped_script.index("youtube_init piped")] + """
echo "fe=$PIPED_FRONTEND_REF;be=$PIPED_BACKEND_REF;pr=$PIPED_PROXY_REF"
"""
        res_co = subprocess.run(["bash", "-c", cmd_colon], capture_output=True, text=True)
        self.assertEqual(res_co.returncode, 0, res_co.stderr)
        self.assertIn("fe=fe-tag;be=be-tag;pr=pr-tag", res_co.stdout)

    def test_piped_rejects_partial_manifests(self):
        """Verify installpackage-piped rejects partial manifests
        (such as frontend=1.0,backend=2.0 and frontend:1.0,backend:2.0,proxy:)
        with a non-zero exit code."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        extraction_block = piped_script[
            piped_script.index('TARGET_FRONTEND_REF=""') : piped_script.index("youtube_init piped")
        ]

        partial_targets = [
            'PIPED_TARGET_VERSION="frontend=1.0,backend=2.0"',
            'AF_TARGET_VERSION="frontend:1.0,backend:2.0,proxy:"',
            'PIPED_TARGET_VERSION="backend=2.0,proxy=3.0"',
            'PIPED_TARGET_VERSION="frontend=1.0"',
            'PIPED_TARGET_VERSION="frontend=1.0,unknown=2.0,proxy=3.0"',
        ]

        for env_target in partial_targets:
            cmd = f"""
set -e
print_error() {{ printf "%s\\n" "$*" >&2; }}
{env_target}
{extraction_block}
echo "should not reach here"
"""
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(
                res.returncode,
                0,
                f"Expected non-zero exit code for partial target {env_target}, but got 0. stdout: {res.stdout}",
            )
            self.assertNotIn("should not reach here", res.stdout)

    def test_piped_certification_retains_backup_on_failure_and_removes_on_success(self):
        """Verify installpackage-piped retains $backup_dir on certification failure
        and only removes $backup_dir after component certification passes."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()

        cleanup_start = piped_script.index("cleanup_piped_install() {")
        cleanup_end = piped_script.index("\n}\n", cleanup_start) + 3
        cleanup_func = piped_script[cleanup_start:cleanup_end]

        cert_start = piped_script.index("certify_piped() {")
        cert_end = piped_script.index("\n}\n", cert_start) + 3
        cert_func = piped_script[cert_start:cert_end]

        scratch_dir = self.root / "tmp/piped-cert-test"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = scratch_dir / "af-piped-runtime-111111"
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "retained.txt").write_text("must-survive-failed-cert")

        install_dir = self.root / "opt/piped"
        install_dir.mkdir(parents=True, exist_ok=True)

        # 1. Certification fails (e.g. missing component repositories or readiness fails)
        fail_script = f"""
set +e
LOGFILE="{self.root}/test.log"
af_write_failure_receipt() {{ :; }}
print_error() {{ printf "%s\\n" "$*" >&2; }}
print_warn() {{ printf "%s\\n" "$*" >&2; }}
source "{self.root}/opt/AetherFlow/packages/common.sh"

APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
AF_JOB_SCRATCH_DIR="{scratch_dir}"
RUNTIME_BACKUP="{backup_dir}"
backup_dir="$RUNTIME_BACKUP"
PIPED_INSTALL_COMPLETED=0
PIPED_CERTIFIED=0
RUNTIME_CHANGED=false
SERVICE_STOPPED=false
BUILD_DIR=""
INSTALL_COMMITTED=false

{cleanup_func}
{cert_func}

# Force readiness or repos to fail
youtube_ready() {{ return 1; }}
systemctl() {{ return 0; }}

if ! certify_piped; then
    cleanup_piped_install 1
    exit_code=$?
    printf 'EXIT_CODE=%d\\n' "$exit_code"
else
    PIPED_CERTIFIED=1
    PIPED_INSTALL_COMPLETED=1
    cleanup_piped_install 0
fi
"""
        res_fail = subprocess.run(["bash", "-c", fail_script], capture_output=True, text=True)
        self.assertIn("EXIT_CODE=1", res_fail.stdout)
        self.assertTrue(backup_dir.exists(), "$backup_dir must NOT be deleted when certification fails")
        self.assertEqual((backup_dir / "retained.txt").read_text(), "must-survive-failed-cert")

        # 2. Certification succeeds -> $backup_dir removed
        # Set up mock git repos for frontend, backend, proxy
        for comp in ("frontend", "backend", "proxy"):
            comp_dir = install_dir / comp
            comp_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", str(comp_dir)], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.email", "test@example.com"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.name", "Test"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "commit", "--allow-empty", "-m", "init"], capture_output=True, check=True)

        jar_file = install_dir / "piped.jar"
        jar_file.write_text("MOCK_PIPED_JAR")
        proxy_file = install_dir / "piped-proxy"
        proxy_file.write_text("MOCK_PIPED_PROXY")
        proxy_file.chmod(0o755)

        import hashlib
        jar_sha = hashlib.sha256(b"MOCK_PIPED_JAR").hexdigest()
        proxy_sha = hashlib.sha256(b"MOCK_PIPED_PROXY").hexdigest()

        mock_proc = scratch_dir / "proc"
        mock_pid_dir = mock_proc / "12345"
        mock_pid_dir.mkdir(parents=True, exist_ok=True)
        (mock_pid_dir / "exe").symlink_to(proxy_file.resolve())

        success_script = f"""
set +e
LOGFILE="{self.root}/test.log"
af_write_failure_receipt() {{ :; }}
print_error() {{ printf "%s\\n" "$*" >&2; }}
print_warn() {{ printf "%s\\n" "$*" >&2; }}
source "{self.root}/opt/AetherFlow/packages/common.sh"

APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
DEPLOYED_BACKEND_SHA256="{jar_sha}"
DEPLOYED_PROXY_SHA256="{proxy_sha}"
AF_JOB_SCRATCH_DIR="{scratch_dir}"
RUNTIME_BACKUP="{backup_dir}"
backup_dir="$RUNTIME_BACKUP"
PIPED_INSTALL_COMPLETED=0
PIPED_CERTIFIED=0
RUNTIME_CHANGED=false
SERVICE_STOPPED=false
BUILD_DIR=""
INSTALL_COMMITTED=false
export AF_PROC_ROOT="{mock_proc}"

{cleanup_func}
{cert_func}

youtube_ready() {{ return 0; }}
systemctl() {{
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "12345"
        return 0
    fi
    return 0
}}

if certify_piped; then
    PIPED_CERTIFIED=1
    PIPED_INSTALL_COMPLETED=1
    cleanup_piped_install 0
    exit_code=$?
    printf 'EXIT_CODE=%d\\n' "$exit_code"
else
    cleanup_piped_install 1
    exit_code=$?
    printf 'EXIT_CODE=%d\\n' "$exit_code"
fi
"""
        res_succ = subprocess.run(["bash", "-c", success_script], capture_output=True, text=True)
        self.assertIn("EXIT_CODE=0", res_succ.stdout)
        self.assertFalse(backup_dir.exists(), "$backup_dir must be removed after component certification passes")

    def test_rclone_readiness_split_port_and_auth_verification(self):
        """Verify rclone wait_for_service_ready:
        - Detects and fails on authentication bypass (unauthenticated request returns 200).
        - Authenticates RC endpoint via curl -K - via stdin.
        - Independently verifies split-port GUI listener returns 200/3xx."""
        rclone_script = (ROOT / "packages/package/install/installpackage-rclone").read_text()
        self.assertIn("Authentication bypass detected on Rclone RC listener", rclone_script)
        self.assertIn("curl -K -", rclone_script)
        self.assertIn("POST", rclone_script)
        self.assertIn("/core/version", rclone_script)

        # Extract wait_for_service_ready function definition
        start = rclone_script.index("wait_for_service_ready() {")
        end = rclone_script.index("\n}\n", start) + 3
        fn_code = rclone_script[start:end]

        env_file = self.root / "rclone.env"
        env_file.write_text("RCLONE_RC_USER=admin\nRCLONE_RC_PASS=supersecret\n")

        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # 1. Unauthenticated request returning 200 fails immediately as auth bypass
        test_bypass = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}"
curl() {{
    if [[ "$*" == *"/core/version"* && "$*" != *"-K"* ]]; then
        printf '200'
    else
        printf '401'
    fi
}}
wait_for_service_ready rclone 5572 / 2
"""
        res_bypass = subprocess.run(["bash", "-c", test_bypass], capture_output=True, text=True)
        self.assertNotEqual(res_bypass.returncode, 0)
        self.assertIn("Authentication bypass detected", res_bypass.stderr)

        # 2. rcd single-port mode: unauth 401, auth 200 -> succeeds
        test_rcd_ok = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}" RCLONE_MODE="rcd" RCLONE_API_PORT="5572"
curl() {{
    if [[ "$*" == *"-K"* && ( "$*" == *"/core/version"* || "$*" == *"/metrics"* ) ]]; then
        printf '200'
    elif [[ "$*" == *"/core/version"* || "$*" == *"/metrics"* ]]; then
        printf '401'
    else
        printf '404'
    fi
}}
wait_for_service_ready rclone 5572 / 2
"""
        res_rcd = subprocess.run(["bash", "-c", test_rcd_ok], capture_output=True, text=True)
        self.assertEqual(res_rcd.returncode, 0, res_rcd.stderr)

        # 3. gui split-port mode (5573 != 5572): unauth 401, auth 200, but GUI returns 500 -> fails
        test_gui_fail = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}" RCLONE_MODE="gui" RCLONE_API_PORT="5573"
curl() {{
    if [[ "$*" == *":5572/"* ]]; then
        printf '500'
    elif [[ "$*" == *"-K"* && ( "$*" == *":5573/core/version"* || "$*" == *":5573/metrics"* ) ]]; then
        printf '200'
    elif [[ "$*" == *":5573/core/version"* || "$*" == *":5573/metrics"* ]]; then
        printf '401'
    else
        printf '000'
    fi
}}
wait_for_service_ready rclone 5572 / 1
"""
        res_gui_fail = subprocess.run(["bash", "-c", test_gui_fail], capture_output=True, text=True)
        self.assertNotEqual(res_gui_fail.returncode, 0)

        # 4. gui split-port mode: unauth 401, auth 200, GUI returns 200 -> succeeds
        test_gui_ok = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}" RCLONE_MODE="gui" RCLONE_API_PORT="5573"
curl() {{
    if [[ "$*" == *":5572/"* ]]; then
        printf '200'
    elif [[ "$*" == *"-K"* && ( "$*" == *":5573/core/version"* || "$*" == *":5573/metrics"* ) ]]; then
        printf '200'
    elif [[ "$*" == *":5573/core/version"* || "$*" == *":5573/metrics"* ]]; then
        printf '401'
    else
        printf '000'
    fi
}}
wait_for_service_ready rclone 5572 / 2
"""
        res_gui_ok = subprocess.run(["bash", "-c", test_gui_ok], capture_output=True, text=True)
        self.assertEqual(res_gui_ok.returncode, 0, res_gui_ok.stderr)

        # 5. Unauthenticated /metrics returning 206 fails immediately as auth bypass
        test_metrics_206 = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}"
curl() {{
    if [[ "$*" == *"/core/version"* && "$*" != *"-K"* ]]; then
        printf '401'
    elif [[ "$*" == *"/metrics"* && "$*" != *"-K"* ]]; then
        printf '206'
    elif [[ "$*" == *"-K"* ]]; then
        printf '200'
    else
        printf '401'
    fi
}}
wait_for_service_ready rclone 5572 / 2
"""
        res_metrics_206 = subprocess.run(["bash", "-c", test_metrics_206], capture_output=True, text=True)
        self.assertNotEqual(res_metrics_206.returncode, 0)
        self.assertIn("Authentication bypass detected", res_metrics_206.stderr)

        # 6. Unauthenticated /metrics returning 500 fails readiness
        test_metrics_500 = f"""
source "{common_script}"
{fn_code}
systemctl() {{ return 0; }}
export RCLONE_ENV_FILE="{env_file}"
curl() {{
    if [[ "$*" == *"/core/version"* && "$*" != *"-K"* ]]; then
        printf '401'
    elif [[ "$*" == *"/metrics"* && "$*" != *"-K"* ]]; then
        printf '500'
    elif [[ "$*" == *"-K"* ]]; then
        printf '200'
    else
        printf '401'
    fi
}}
wait_for_service_ready rclone 5572 / 2
"""
        res_metrics_500 = subprocess.run(["bash", "-c", test_metrics_500], capture_output=True, text=True)
        self.assertNotEqual(res_metrics_500.returncode, 0)
        self.assertIn("did not become ready", res_metrics_500.stderr)

    def test_maintainerr_and_github_latest_tag_unprefixed_target(self):
        """Verify github_latest_tag handles unprefixed AF_TARGET_VERSION when strip_v is false,
        and installpackage-maintainerr accepts unprefixed AF_TARGET_VERSION=1.2.3."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # 1. 2-arg call github_latest_tag "Maintainerr/Maintainerr" false
        cmd2 = f"""
source "{common_script}"
AF_TARGET_VERSION="1.2.3"
github_latest_tag "Maintainerr/Maintainerr" false
"""
        res2 = subprocess.run(["bash", "-c", cmd2], capture_output=True, text=True)
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertEqual(res2.stdout.strip(), "v1.2.3")

        # 2. 3-arg call github_latest_tag "Maintainerr/Maintainerr" "" false
        cmd3 = f"""
source "{common_script}"
AF_TARGET_VERSION="1.2.3"
github_latest_tag "Maintainerr/Maintainerr" "" false
"""
        res3 = subprocess.run(["bash", "-c", cmd3], capture_output=True, text=True)
        self.assertEqual(res3.returncode, 0, res3.stderr)
        self.assertEqual(res3.stdout.strip(), "v1.2.3")

        # 3. installpackage-maintainerr tag resolution logic accepts AF_TARGET_VERSION=1.2.3
        maintainerr_script = (ROOT / "packages/package/install/installpackage-maintainerr").read_text()
        start = maintainerr_script.index('RELEASE_TAG="$(github_latest_tag "Maintainerr/Maintainerr"')
        end = maintainerr_script.index("\nif ! id -u maintainerr", start)
        tag_resolution_block = maintainerr_script[start:end]

        cmd_maint = f"""
set -e
source "{common_script}"
AF_TARGET_VERSION="1.2.3"
{tag_resolution_block}
echo "LATEST_TAG=$LATEST_TAG;RELEASE_TAG=$RELEASE_TAG"
"""
        res_maint = subprocess.run(["bash", "-c", cmd_maint], capture_output=True, text=True)
        self.assertEqual(res_maint.returncode, 0, res_maint.stderr)
        self.assertIn("LATEST_TAG=v1.2.3", res_maint.stdout)
        self.assertIn("RELEASE_TAG=v1.2.3", res_maint.stdout)

    def test_piped_rejects_duplicate_and_empty_manifest_segments(self):
        """Verify installpackage-piped rejects duplicate manifest components and empty comma segments."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        extraction_block = piped_script[
            piped_script.index('TARGET_FRONTEND_REF=""') : piped_script.index("youtube_init piped")
        ]

        invalid_targets = [
            'PIPED_TARGET_VERSION="frontend=1.0,frontend=2.0,backend=2.0,proxy=3.0"',
            'PIPED_TARGET_VERSION="frontend=1.0,,backend=2.0,proxy=3.0"',
            'PIPED_TARGET_VERSION=",frontend=1.0,backend=2.0,proxy=3.0"',
            'PIPED_TARGET_VERSION="frontend=1.0,backend=2.0,proxy=3.0,"',
            'AF_TARGET_VERSION="frontend:1.0,backend:2.0,backend:3.0,proxy:3.0"',
            'AF_TARGET_VERSION="frontend:1.0,proxy:2.0,proxy:3.0,backend:1.0"',
        ]

        for env_target in invalid_targets:
            cmd = f"""
set -e
print_error() {{ printf "%s\\n" "$*" >&2; }}
{env_target}
{extraction_block}
echo "should not reach here"
"""
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(
                res.returncode,
                0,
                f"Expected non-zero exit code for invalid target {env_target}, but got 0. stdout: {res.stdout}",
            )
            self.assertNotIn("should not reach here", res.stdout)
            if "frontend=2.0" in env_target or "backend:3.0" in env_target or "proxy:3.0" in env_target:
                self.assertIn("Duplicate component in Piped target manifest", res.stderr)

    def test_piped_certify_rejects_short_ref_and_inactive_proxy(self):
        """Verify installpackage-piped certify_piped:
        - Rejects short <7 char unresolvable refs (e.g. 'abc')
        - Fails closed when piped-backend.service is active (0) but piped-proxy.service is inactive (3)."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        cert_start = piped_script.index("certify_piped() {")
        cert_end = piped_script.index("\n}\n", cert_start) + 3
        cert_func = piped_script[cert_start:cert_end]

        install_dir = self.root / "opt/piped-test-cert"
        install_dir.mkdir(parents=True, exist_ok=True)

        for comp in ("frontend", "backend", "proxy"):
            comp_dir = install_dir / comp
            comp_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", str(comp_dir)], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.email", "test@example.com"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.name", "Test"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "commit", "--allow-empty", "-m", "init"], capture_output=True, check=True)

        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # 1. Reject short <7 char unresolvable ref (e.g. 'abc')
        test_short_ref = f"""
source "{common_script}"
APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
PIPED_FRONTEND_REF="abc"
youtube_ready() {{ return 0; }}
systemctl() {{ return 0; }}
{cert_func}
certify_piped
"""
        res_short = subprocess.run(["bash", "-c", test_short_ref], capture_output=True, text=True)
        self.assertNotEqual(res_short.returncode, 0, "Expected certify_piped to reject 'abc' short ref, but got 0")
        self.assertIn("not a valid 7-40 hex SHA", res_short.stderr)

        # 2. Fails closed when piped-backend.service is active (0) but piped-proxy.service is inactive (3)
        test_inactive_proxy = f"""
source "{common_script}"
APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
PIPED_FRONTEND_REF=""
PIPED_BACKEND_REF=""
PIPED_PROXY_REF=""
youtube_ready() {{ return 0; }}
systemctl() {{
    case "$*" in
        *"piped-backend.service"*) return 0 ;;
        *"piped-proxy.service"*) return 3 ;;
        *) return 1 ;;
    esac
}}
{cert_func}
certify_piped
"""
        res_proxy = subprocess.run(["bash", "-c", test_inactive_proxy], capture_output=True, text=True)
        self.assertNotEqual(res_proxy.returncode, 0, "Expected certify_piped to fail when proxy is inactive, but got 0")
        self.assertIn("piped-proxy.service is not active during certification", res_proxy.stderr)

    def test_af_prepare_job_scratch_rejects_unknown_fs_type(self):
        """Verify af_prepare_job_scratch fails closed when stat -f -c '%T' returns UNKNOWN (0xdeadbeef)."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/scratch-unknown-fs-test"
        test_dir.mkdir(parents=True, exist_ok=True)

        cmd = f"""
source "{common_script}"
export AF_JOB_SCRATCH_ROOT="{test_dir}"
stat() {{
    if [[ "$*" == *"-f"* && "$*" == *"%T"* ]]; then
        printf 'UNKNOWN (0xdeadbeef)\\n'
        return 0
    fi
    command stat "$@"
}}
af_prepare_job_scratch "testapp" 512 1024
"""
        res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, f"Expected non-zero return code for unknown fs type, but got 0. stdout: {res.stdout}")
        self.assertTrue(
            "unknown" in res.stderr.lower() or "not allowed" in res.stderr.lower(),
            f"Expected error message indicating unknown/unsupported fs type, got: {res.stderr}"
        )

    def test_piped_rejects_preplaced_symlink_receipt(self):
        """Verify installpackage-piped rejects a pre-placed symlink at ${PIPED_ROOT}/.af-components.json
        without modifying the symlink target."""
        piped_root = self.root / "opt/piped-symlink-test"
        piped_root.mkdir(parents=True, exist_ok=True)
        target_file = self.root / "opt/victim-secret.txt"
        target_file.write_text("unmodified-canary-content")

        symlink_receipt = piped_root / ".af-components.json"
        symlink_receipt.symlink_to(target_file)

        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # 1. Test initial path validation loop in installpackage-piped
        val_start = piped_script.index('PIPED_ROOT="${PIPED_ROOT:-')
        val_end = piped_script.index("done\n", val_start) + 5
        val_block = piped_script[val_start:val_end]

        test_val = f"""
source "{common_script}"
export PIPED_ROOT="{piped_root}"
{val_block}
"""
        res_val = subprocess.run(["bash", "-c", test_val], capture_output=True, text=True)
        self.assertNotEqual(res_val.returncode, 0, "Initial validation loop must fail on symlink")
        self.assertTrue(
            "symlink" in res_val.stderr.lower() or "pre-existing" in res_val.stderr.lower(),
            f"Expected error message indicating symlink rejection, got: {res_val.stderr}"
        )
        self.assertEqual(target_file.read_text(), "unmodified-canary-content", "Target was modified!")

        # 2. Test write_piped_receipt_safely helper refuses to overwrite symlink
        helper_start = piped_script.index("write_piped_receipt_safely() {")
        helper_end = piped_script.index("\n}\n", helper_start) + 3
        helper_code = piped_script[helper_start:helper_end]

        test_helper = f"""
{helper_code}
printf 'malicious-data' | write_piped_receipt_safely "{piped_root}" ".af-components.json" "root" "root" "0644"
"""
        res_helper = subprocess.run(["bash", "-c", test_helper], capture_output=True, text=True)
        self.assertNotEqual(res_helper.returncode, 0, "write_piped_receipt_safely must fail on symlink target")
        self.assertEqual(target_file.read_text(), "unmodified-canary-content", "Symlink target was clobbered by write_piped_receipt_safely!")

        # 3. Test write_piped_receipt_safely succeeds on safe file
        safe_file = piped_root / "safe-receipt.json"
        test_safe = f"""
{helper_code}
printf '{{"status":"ok"}}' | write_piped_receipt_safely "{piped_root}" "safe-receipt.json" "root" "root" "0644"
"""
        res_safe = subprocess.run(["bash", "-c", test_safe], capture_output=True, text=True)
        self.assertEqual(res_safe.returncode, 0, f"write_piped_receipt_safely failed on safe file: {res_safe.stderr}")
        self.assertEqual(safe_file.read_text().strip(), '{"status":"ok"}')

    def test_piped_receipt_rejects_symlinked_intermediate_ancestor_and_succeeds_on_real_directories(self):
        """Verify write_piped_receipt_safely rejects a symlinked intermediate ancestor
        directory via stepwise dir_fd traversal with O_NOFOLLOW and succeeds when all
        ancestor directories are real directories."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        helper_start = piped_script.index("write_piped_receipt_safely() {")
        helper_end = piped_script.index("\n}\n", helper_start) + 3
        helper_code = piped_script[helper_start:helper_end]

        # 1. Symlinked intermediate ancestor directory must be rejected
        real_target = self.root / "opt/piped-ancestor-target"
        nested_dir = real_target / "sub/leaf"
        nested_dir.mkdir(parents=True, exist_ok=True)

        sym_parent = self.root / "opt/piped-ancestor-parent"
        sym_parent.mkdir(parents=True, exist_ok=True)
        symlink_intermediate = sym_parent / "symlink_dir"
        symlink_intermediate.symlink_to(real_target)

        # target_path traverses through the intermediate symlink
        target_path = symlink_intermediate / "sub/leaf"
        canary_file = nested_dir / ".af-components.json"

        test_intermediate_symlink = f"""
{helper_code}
printf '{{"frontend":"malicious"}}' | write_piped_receipt_safely "{target_path}" ".af-components.json" "root" "root" "0644"
"""
        res_sym = subprocess.run(["bash", "-c", test_intermediate_symlink], capture_output=True, text=True)
        self.assertNotEqual(res_sym.returncode, 0, "write_piped_receipt_safely must reject symlinked intermediate ancestor")
        self.assertFalse(canary_file.exists(), "Canary receipt must not be created through intermediate symlink")

        # 2. Path with '..' must be rejected
        dotdot_path = f"{nested_dir}/../leaf"
        test_dotdot = f"""
{helper_code}
printf '{{"frontend":"malicious"}}' | write_piped_receipt_safely "{dotdot_path}" ".af-components.json" "root" "root" "0644"
"""
        res_dotdot = subprocess.run(["bash", "-c", test_dotdot], capture_output=True, text=True)
        self.assertNotEqual(res_dotdot.returncode, 0, "write_piped_receipt_safely must reject '..' in path")

        # 3. All ancestor directories are real directories -> must succeed
        safe_ancestor_dir = self.root / "opt/piped-safe-ancestors/level1/level2"
        safe_ancestor_dir.mkdir(parents=True, exist_ok=True)
        safe_receipt = safe_ancestor_dir / ".af-components.json"

        test_safe_ancestors = f"""
{helper_code}
printf '{{"frontend":"safe_sha","backend":"safe_sha","proxy":"safe_sha"}}' | write_piped_receipt_safely "{safe_ancestor_dir}" ".af-components.json" "root" "root" "0644"
"""
        res_safe = subprocess.run(["bash", "-c", test_safe_ancestors], capture_output=True, text=True)
        self.assertEqual(res_safe.returncode, 0, f"write_piped_receipt_safely failed on real ancestor directories: {res_safe.stderr}")
        self.assertTrue(safe_receipt.exists(), "Receipt file must be created when all ancestors are real directories")
        self.assertIn('"frontend":"safe_sha"', safe_receipt.read_text())

    def test_af_prepare_job_scratch_allow_tmpfs_still_rejects_unknown_fs_type(self):
        """Verify af_prepare_job_scratch with AF_ALLOW_TMPFS_SCRATCH=1 still rejects UNKNOWN (0xdeadbeef) while permitting tmpfs."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/scratch-allow-tmpfs-test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # 1. AF_ALLOW_TMPFS_SCRATCH=1 still rejects UNKNOWN (0xdeadbeef)
        cmd_unknown = f"""
source "{common_script}"
export AF_JOB_SCRATCH_ROOT="{test_dir}"
export AF_ALLOW_TMPFS_SCRATCH=1
stat() {{
    if [[ "$*" == *"-f"* && "$*" == *"%T"* ]]; then
        printf 'UNKNOWN (0xdeadbeef)\\n'
        return 0
    fi
    command stat "$@"
}}
af_prepare_job_scratch "testapp" 512 1024
"""
        res_unknown = subprocess.run(["bash", "-c", cmd_unknown], capture_output=True, text=True)
        self.assertNotEqual(res_unknown.returncode, 0, f"Expected non-zero exit for unknown fs with AF_ALLOW_TMPFS_SCRATCH=1, stdout: {res_unknown.stdout}")
        self.assertTrue(
            "unknown" in res_unknown.stderr.lower() or "not allowed" in res_unknown.stderr.lower(),
            f"Expected error message indicating unknown/unsupported fs type, got: {res_unknown.stderr}"
        )

        # 2. AF_ALLOW_TMPFS_SCRATCH=1 permits tmpfs
        cmd_tmpfs = f"""
source "{common_script}"
export AF_JOB_SCRATCH_ROOT="{test_dir}"
export AF_ALLOW_TMPFS_SCRATCH=1
stat() {{
    if [[ "$*" == *"-f"* && "$*" == *"%T"* ]]; then
        printf 'tmpfs\\n'
        return 0
    fi
    command stat "$@"
}}
check_disk_space() {{ return 0; }}
df() {{
    if [[ "$*" == *"-Pm"* ]]; then
        printf 'Filesystem 1048576 1024 1047552 1%% /tmp\\nFilesystem 1048576 1024 1047552 1%% /tmp\\n'
        return 0
    elif [[ "$*" == *"-Pi"* ]]; then
        printf 'Filesystem 1000000 100 999900 1%% /tmp\\nFilesystem 1000000 100 999900 1%% /tmp\\n'
        return 0
    fi
    command df "$@"
}}
af_prepare_job_scratch "testapp" 512 1024
echo "SCRATCH_DIR=$AF_JOB_SCRATCH_DIR"
"""
        res_tmpfs = subprocess.run(["bash", "-c", cmd_tmpfs], capture_output=True, text=True)
        self.assertEqual(res_tmpfs.returncode, 0, f"Expected tmpfs to be permitted when AF_ALLOW_TMPFS_SCRATCH=1, got: {res_tmpfs.stderr}")
        self.assertIn("SCRATCH_DIR=", res_tmpfs.stdout)

    def test_piped_receipt_short_writes_and_atomic_cleanup_on_failure(self):
        """Verify write_piped_receipt_safely:
        a) Loops until all bytes are written when os.write performs short/chunked writes.
        b) Cleans up temporary .tmp_* file and exits non-zero when os.replace, os.fsync, or os.write fails with OSError.
        """
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        helper_start = piped_script.index("write_piped_receipt_safely() {")
        helper_end = piped_script.index("\n}\n", helper_start) + 3
        helper_code = piped_script[helper_start:helper_end]

        target_dir = self.root / "opt/piped-atomic-receipt"
        target_dir.mkdir(parents=True, exist_ok=True)
        receipt_data = '{"frontend":"safe_sha_1234567890abcdef","backend":"safe_sha_0987654321fedcba","proxy":"safe_sha_abcdef1234567890"}'

        # a) Short/chunked writes (5 bytes at a time)
        site_short = self.root / "site_short"
        site_short.mkdir(parents=True, exist_ok=True)
        (site_short / "sitecustomize.py").write_text("""
import os
_orig_write = os.write
def short_write(fd, data):
    view = memoryview(data)
    to_write = min(5, len(view))
    return _orig_write(fd, view[:to_write])
os.write = short_write
""")
        cmd_short = f"""
{helper_code}
printf '%s' '{receipt_data}' | write_piped_receipt_safely "{target_dir}" ".af-components.json" "root" "root" "0644"
"""
        res_short = subprocess.run(
            ["bash", "-c", cmd_short],
            env={**os.environ, "PYTHONPATH": str(site_short)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_short.returncode, 0, f"write_piped_receipt_safely failed on short writes: {res_short.stderr}")
        receipt_file = target_dir / ".af-components.json"
        self.assertTrue(receipt_file.exists(), "Receipt file was not created on short writes")
        self.assertEqual(receipt_file.read_text(), receipt_data, "Receipt file content did not match expected data on short writes")

        # b) Cleanup on failure: os.replace, os.fsync, and os.write failing with OSError
        failure_scenarios = [
            (
                "replace",
                """
import os
def fail_replace(src, dst, *args, **kwargs):
    raise OSError("simulated replace error")
os.replace = fail_replace
""",
            ),
            (
                "fsync",
                """
import os
def fail_fsync(fd):
    raise OSError("simulated fsync error")
os.fsync = fail_fsync
""",
            ),
            (
                "write",
                """
import os
def fail_write(fd, data):
    raise OSError("simulated write error")
os.write = fail_write
""",
            ),
            (
                "fchown",
                """
import os
def fail_fchown(fd, uid, gid):
    raise PermissionError("simulated fchown permission error")
os.fchown = fail_fchown
""",
            ),
        ]

        for name, hook_code in failure_scenarios:
            with self.subTest(failure=name):
                site_fail = self.root / f"site_fail_{name}"
                site_fail.mkdir(parents=True, exist_ok=True)
                (site_fail / "sitecustomize.py").write_text(hook_code)
                filename = f"failed_receipt_{name}.json"

                cmd_fail = f"""
{helper_code}
printf '%s' '{receipt_data}' | write_piped_receipt_safely "{target_dir}" "{filename}" "root" "root" "0644"
"""
                res_fail = subprocess.run(
                    ["bash", "-c", cmd_fail],
                    env={**os.environ, "PYTHONPATH": str(site_fail)},
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(res_fail.returncode, 0, f"write_piped_receipt_safely should fail when {name} raises OSError")
                self.assertFalse((target_dir / filename).exists(), f"Target file {filename} should not exist on {name} failure")
                tmp_files = [f.name for f in target_dir.iterdir() if f.name.startswith(f".tmp_{filename}")]
                self.assertEqual(tmp_files, [], f"Temporary file was not cleaned up on {name} failure: {tmp_files}")

    def test_rclone_cleanup_and_rollback_trap_under_errexit_with_rc17(self):
        """Verify Rclone cleanup_and_rollback EXIT trap executes completely under set -e
        when an error exits with status 17 after candidate activation (ROLLBACK_NEEDED=1),
        ensuring service quiescence, archive rollback, and scratch cleanup execute and exit with 17."""
        rclone_script = (ROOT / "packages/package/install/installpackage-rclone").read_text()
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # Extract cleanup_and_rollback definition
        start = rclone_script.index("cleanup_and_rollback() {")
        end = rclone_script.index("\n}\n", start) + 3
        cleanup_func = rclone_script[start:end]

        scratch_dir = self.root / "tmp/rclone-scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = self.root / "tmp/rclone-backup"
        backup_dir.mkdir(parents=True, exist_ok=True)

        trace_log = self.root / "rclone_rollback_trace.log"

        test_script = f"""
set -e
source "{common_script}"

export AF_JOB_SCRATCH_DIR="{scratch_dir}"
export AF_ARCHIVE_BACKUP="{backup_dir}"
export AF_ARCHIVE_UNIT="rclone"
export LOGFILE="{self.root}/test-rclone.log"
export ROLLBACK_NEEDED=1
export INSTALL_COMMITTED=false
export VFS_WAS_ACTIVE=0

# Track executed operations
quiesce_services_for_rollback() {{
    printf 'QUIESCE:%s\\n' "$*" >> "{trace_log}"
    return 0
}}
rollback_app_archive_update() {{
    printf 'ROLLBACK_APP_ARCHIVE:%s\\n' "$*" >> "{trace_log}"
    return 0
}}
safe_restore_path_from_backup() {{
    printf 'RESTORE:%s\\n' "$*" >> "{trace_log}"
    return 0
}}
systemctl() {{
    printf 'SYSTEMCTL:%s\\n' "$*" >> "{trace_log}"
    return 0
}}

{cleanup_func}
trap cleanup_and_rollback EXIT

# Trigger exit 17 under set -e
(exit 17)
"""
        res = subprocess.run(["bash", "-c", test_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 17, f"Expected trap handler to exit with status 17, got {res.returncode}. Stderr: {res.stderr}")
        self.assertTrue(trace_log.exists(), "Rollback trace log was not created; trap aborted before logging!")
        trace_content = trace_log.read_text()
        self.assertIn("QUIESCE:rclone-vfs rclone", trace_content, "Service quiescence was not executed during rollback!")
        self.assertIn("ROLLBACK_APP_ARCHIVE:17", trace_content, "Archive rollback was not executed with status 17!")

    def test_piped_publish_artifact_safely_rejects_symlink_and_hardlink_canary(self):
        """Verify publish_piped_artifact_safely refuses to publish artifacts that are
        symlinks or hardlinks to private canary files, failing closed with non-zero exit."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        start = piped_script.index("publish_piped_artifact_safely() {")
        end = piped_script.index("\n}\n", start) + 3
        publish_func = piped_script[start:end]

        test_dir = self.root / "opt/piped-publish-test"
        src_dir = test_dir / "build/libs"
        dst_dir = test_dir / "dest"
        src_dir.mkdir(parents=True, exist_ok=True)
        dst_dir.mkdir(parents=True, exist_ok=True)

        canary_file = self.root / "opt/root_secret_canary.txt"
        canary_content = "SUPER_SECRET_CANARY_ROOT_KEY_0600"
        canary_file.write_text(canary_content)
        canary_file.chmod(0o600)

        dst_jar = dst_dir / "piped.jar"

        # 1. Symlink to canary file
        symlink_jar = src_dir / "piped-symlink.jar"
        symlink_jar.symlink_to(canary_file)

        cmd_symlink = f"""
{publish_func}
publish_piped_artifact_safely "{symlink_jar}" "{dst_jar}" 0644 "root" "piped"
"""
        res_sym = subprocess.run(["bash", "-c", cmd_symlink], capture_output=True, text=True)
        self.assertNotEqual(res_sym.returncode, 0, "publish_piped_artifact_safely must fail on symlink artifact")
        self.assertFalse(dst_jar.exists(), "Destination JAR must not be created from symlink!")

        # 2. Hardlink to canary file
        hardlink_jar = src_dir / "piped-hardlink.jar"
        os.link(canary_file, hardlink_jar)
        self.assertGreater(hardlink_jar.stat().st_nlink, 1)

        cmd_hardlink = f"""
{publish_func}
publish_piped_artifact_safely "{hardlink_jar}" "{dst_jar}" 0644 "root" "piped"
"""
        res_hard = subprocess.run(["bash", "-c", cmd_hardlink], capture_output=True, text=True)
        self.assertNotEqual(res_hard.returncode, 0, "publish_piped_artifact_safely must fail on hardlink artifact")
        self.assertFalse(dst_jar.exists(), "Destination JAR must not be created from hardlink!")

        # 3. Legitimate regular file (nlink == 1) publishes successfully
        valid_jar = src_dir / "piped-valid.jar"
        valid_jar.write_text("VALID_PIPED_JAR_BYTECODE")
        valid_jar.chmod(0o644)

        cmd_valid = f"""
{publish_func}
publish_piped_artifact_safely "{valid_jar}" "{dst_jar}" 0644 "root" "piped"
"""
        res_valid = subprocess.run(["bash", "-c", cmd_valid], capture_output=True, text=True)
        self.assertEqual(res_valid.returncode, 0, f"publish_piped_artifact_safely failed on valid jar: {res_valid.stderr}")
        self.assertTrue(dst_jar.exists(), "Destination JAR was not published!")
        self.assertEqual(dst_jar.read_text(), "VALID_PIPED_JAR_BYTECODE")

    def test_piped_clean_env_and_node_build_do_not_leak_privileged_tokens(self):
        """Verify node_build and run_as_piped_clean_env sanitize sensitive tokens
        (AF_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, RCLONE_PASS, etc.) preventing leaks to child scripts."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()

        start = piped_script.index("run_as_piped_clean_env() {")
        end = piped_script.index("\n}\n", start) + 3
        clean_env_func = piped_script[start:end]

        test_env = {
            "AF_GITHUB_TOKEN": "secret-af-github-token-12345",
            "GITHUB_TOKEN": "secret-github-token-67890",
            "GH_TOKEN": "secret-gh-token-abcde",
            "RCLONE_PASS": "secret-rclone-pass-xyz",
            "MASTER_PASS": "secret-master-pass-root",
            "DB_PASSWORD": "secret-db-pass-postgres",
            "SECRET_KEY": "secret-app-key-priv",
        }

        # 1. Verify node_build strips secrets
        cmd_node_build = f"""
source "{common_script}"
node_build python3 -c 'import os; print([k for k in ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "RCLONE_PASS", "MASTER_PASS", "DB_PASSWORD", "SECRET_KEY"] if k in os.environ])'
"""
        res_nb = subprocess.run(
            ["bash", "-c", cmd_node_build],
            env={**os.environ, **test_env},
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_nb.returncode, 0, f"node_build test failed: {res_nb.stderr}")
        self.assertEqual(res_nb.stdout.strip(), "[]", f"node_build leaked tokens: {res_nb.stdout}")

        # 2. Verify run_as_piped_clean_env runs in env -i without leaking secrets
        test_home = self.root / "tmp/piped-clean-home"
        test_home.mkdir(parents=True, exist_ok=True)

        cmd_clean_env = f"""
{clean_env_func}
# Mock runuser to exec command directly if unprivileged
if ! command -v runuser >/dev/null 2>&1 || [[ "$(id -u)" -ne 0 ]]; then
    runuser() {{
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -u) shift 2 ;;
                --) shift ;;
                *) break ;;
            esac
        done
        exec "$@"
    }}
fi
run_as_piped_clean_env "{test_home}" python3 -c 'import os; print([k for k in ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "RCLONE_PASS", "MASTER_PASS", "DB_PASSWORD", "SECRET_KEY"] if k in os.environ])'
"""
        res_ce = subprocess.run(
            ["bash", "-c", cmd_clean_env],
            env={**os.environ, **test_env},
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_ce.returncode, 0, f"run_as_piped_clean_env test failed: {res_ce.stderr}")
        self.assertEqual(res_ce.stdout.strip(), "[]", f"run_as_piped_clean_env leaked tokens: {res_ce.stdout}")

    def test_piped_receipt_fchown_error_fails_and_cleans_up(self):
        """Verify write_piped_receipt_safely does not ignore os.fchown errors:
        when os.fchown raises PermissionError, the function fails closed with non-zero exit code,
        unlinks any .tmp_* temporary file, and does not publish the receipt."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        start = piped_script.index("write_piped_receipt_safely() {")
        end = piped_script.index("\n}\n", start) + 3
        helper_code = piped_script[start:end]

        target_dir = self.root / "opt/piped-fchown-fail-test"
        target_dir.mkdir(parents=True, exist_ok=True)
        receipt_filename = "receipt.json"
        target_file = target_dir / receipt_filename

        site_fchown = self.root / "site_fchown_fail"
        site_fchown.mkdir(parents=True, exist_ok=True)
        (site_fchown / "sitecustomize.py").write_text("""
import os
def fail_fchown(fd, uid, gid):
    raise PermissionError("injected fchown PermissionError")
os.fchown = fail_fchown
""")

        cmd = f"""
{helper_code}
printf '{{"fchown_test":"failed"}}' | write_piped_receipt_safely "{target_dir}" "{receipt_filename}" "root" "root" "0644"
"""
        res = subprocess.run(
            ["bash", "-c", cmd],
            env={**os.environ, "PYTHONPATH": str(site_fchown)},
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0, f"write_piped_receipt_safely should exit non-zero on fchown PermissionError, but got 0. stdout: {res.stdout}")
        self.assertFalse(target_file.exists(), "Receipt file must NOT be published when fchown raises PermissionError!")
        tmp_files = [f.name for f in target_dir.iterdir() if f.name.startswith(f".tmp_{receipt_filename}")]
        self.assertEqual(tmp_files, [], f"Temporary file was not cleaned up on fchown failure: {tmp_files}")

    def test_piped_build_missing_proxy_binary_fails_closed_and_never_writes_components_json(self):
        """Verify that if piped-proxy build directory exists with an old piped-proxy
        already on disk, but cargo build produces no new piped-proxy binary in the
        target release directory, installpackage-piped fails closed (non-zero exit)
        and NEVER writes the new proxy SHA to .af-components.json."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()

        install_dir = self.root / "opt/piped-old-proxy-test"
        install_dir.mkdir(parents=True, exist_ok=True)
        old_proxy_bin = install_dir / "piped-proxy"
        old_proxy_bin.write_text("OLD_STALE_PROXY_BINARY_ON_DISK")
        old_proxy_bin.chmod(0o755)

        components_json = install_dir / ".af-components.json"
        old_components_content = '{"frontend":"old_fe","backend":"old_be","proxy":"old_proxy_sha"}\n'
        components_json.write_text(old_components_content)

        # Set up git repos for components so git HEAD lookups succeed
        for comp in ("frontend", "backend", "proxy"):
            comp_dir = install_dir / comp
            comp_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", str(comp_dir)], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.email", "test@example.com"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.name", "Test"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "commit", "--allow-empty", "-m", f"init-{comp}"], capture_output=True, check=True)

        new_proxy_sha = subprocess.run(
            ["git", "-C", str(install_dir / "proxy"), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        # Build directory for backend produces a valid JAR
        build_dir = self.root / "tmp/piped-backend-build"
        libs_dir = build_dir / "build/libs"
        libs_dir.mkdir(parents=True, exist_ok=True)
        built_jar = libs_dir / "piped-1.0-all.jar"
        built_jar.write_text("NEW_VALID_PIPED_JAR")

        # Proxy target release directory exists, but cargo build produced NO piped-proxy binary
        proxy_target_dir = install_dir / "proxy/target/release"
        proxy_target_dir.mkdir(parents=True, exist_ok=True)
        self.assertFalse((proxy_target_dir / "piped-proxy").exists())

        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        publish_start = piped_script.index("publish_piped_artifact_safely() {")
        publish_end = piped_script.index("\n}\n", publish_start) + 3
        publish_func = piped_script[publish_start:publish_end]

        receipt_start = piped_script.index("write_piped_receipt_safely() {")
        receipt_end = piped_script.index("\n}\n", receipt_start) + 3
        receipt_func = piped_script[receipt_start:receipt_end]

        cert_start = piped_script.index("certify_piped() {")
        cert_end = piped_script.index("\n}\n", cert_start) + 3
        cert_func = piped_script[cert_start:cert_end]

        exec_block_start = piped_script.index('BUILT_JAR="$(find "${BUILD_DIR}/build/libs"')
        exec_block_end = piped_script.index('commit_app_versions\n') + len('commit_app_versions\n')
        exec_block = piped_script[exec_block_start:exec_block_end]

        test_script = f"""
source "{common_script}"
set +e
APP_NAME="piped"
APP_PORT="8280"
DATA_DIR="{self.root}/tmp/data"
mkdir -p "$DATA_DIR"
INSTALL_DIR="{install_dir}"
BUILD_DIR="{build_dir}"
PIPED_BACKEND_DIR="{install_dir}"
PIPED_PROXY_DIR="{install_dir}"
PIPED_FRONTEND_REF=""
PIPED_BACKEND_REF=""
PIPED_PROXY_REF=""
LOGFILE="{self.root}/test.log"
af_set_stage() {{ :; }}
report_progress() {{ :; }}
write_config_file() {{ :; }}
safe_config_python() {{ :; }}
youtube_unit() {{ :; }}
youtube_ready() {{ return 0; }}
systemctl() {{ return 0; }}
rollback_piped_runtime() {{ :; }}
queue_app_version() {{ :; }}
commit_app_versions() {{ :; }}
write_lock() {{ :; }}

{receipt_func}
{publish_func}
{cert_func}

{exec_block}
exit_code=$?
echo "FINAL_EXIT_CODE=$exit_code"
"""
        res = subprocess.run(["bash", "-c", test_script], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, f"Expected non-zero exit when proxy binary is missing, but got returncode {res.returncode}. stdout: {res.stdout}")
        self.assertIn("Built piped-proxy binary not found after cargo build", res.stderr)
        self.assertNotIn("FINAL_EXIT_CODE=0", res.stdout)

        components_after = components_json.read_text()
        self.assertEqual(components_after, old_components_content, ".af-components.json was modified despite missing proxy binary!")
        self.assertNotIn(new_proxy_sha, components_after, "New proxy SHA was recorded in .af-components.json!")
        self.assertEqual(old_proxy_bin.read_text(), "OLD_STALE_PROXY_BINARY_ON_DISK")

        jar_sha = hashlib.sha256(b"NEW_VALID_PIPED_JAR").hexdigest()
        cert_test_script = f"""
source "{common_script}"
set +e
APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
PIPED_BACKEND_DIR="{install_dir}"
PIPED_PROXY_DIR="{install_dir}"
PIPED_FRONTEND_REF=""
PIPED_BACKEND_REF=""
PIPED_PROXY_REF=""
DEPLOYED_BACKEND_SHA256="{jar_sha}"
DEPLOYED_PROXY_SHA256="expected_new_proxy_sha_12345"
youtube_ready() {{ return 0; }}
systemctl() {{ return 0; }}

{cert_func}
certify_piped
"""
        res_cert = subprocess.run(["bash", "-c", cert_test_script], capture_output=True, text=True)
        self.assertNotEqual(res_cert.returncode, 0, "certify_piped must reject old proxy binary mismatch")
        self.assertIn("Piped certification failed: deployed proxy binary SHA-256", res_cert.stderr)

    def test_piped_publish_artifact_safely_rejects_fifo_immediately_without_hanging(self):
        """Verify publish_piped_artifact_safely rejects a FIFO (mkfifo) at the source
        artifact path immediately (< 1 second, non-zero exit code) without hanging."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        start = piped_script.index("publish_piped_artifact_safely() {")
        end = piped_script.index("\n}\n", start) + 3
        publish_func = piped_script[start:end]

        test_dir = self.root / "opt/piped-fifo-test"
        src_dir = test_dir / "build/libs"
        dst_dir = test_dir / "dest"
        src_dir.mkdir(parents=True, exist_ok=True)
        dst_dir.mkdir(parents=True, exist_ok=True)

        fifo_path = src_dir / "piped.jar"
        os.mkfifo(str(fifo_path))
        dst_jar = dst_dir / "piped.jar"

        cmd = f"""
{publish_func}
publish_piped_artifact_safely "{fifo_path}" "{dst_jar}" 0644 "root" "piped"
"""
        import time
        t0 = time.monotonic()
        try:
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=2.0)
            elapsed = time.monotonic() - t0
        except subprocess.TimeoutExpired:
            self.fail("publish_piped_artifact_safely hung indefinitely on FIFO source artifact!")

        self.assertLess(elapsed, 1.0, f"publish_piped_artifact_safely took {elapsed:.2f}s, expected < 1.0s")
        self.assertNotEqual(res.returncode, 0, "publish_piped_artifact_safely must fail on FIFO source artifact")
        self.assertFalse(dst_jar.exists(), "Destination JAR must not be created from FIFO source!")

    def test_rclone_rollback_gated_on_successful_quiescence(self):
        """Verify Rclone cleanup_and_rollback gates rollback on successful quiescence:
        - When quiesce_rclone_services fails (returns 1):
          neither rollback_app_archive_update nor VFS unit restoration/removal is invoked,
          recovery material is preserved, and an incomplete-rollback error is emitted.
        - Conversely, when quiesce_rclone_services succeeds (returns 0):
          both archive rollback and VFS unit restoration execute as expected.
        """
        rclone_script = (ROOT / "packages/package/install/installpackage-rclone").read_text()
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        cleanup_start = rclone_script.index("cleanup_and_rollback() {")
        cleanup_end = rclone_script.index("\n}\n", cleanup_start) + 3
        cleanup_func = rclone_script[cleanup_start:cleanup_end]

        scratch_dir = self.root / "tmp/rclone-quiesce-test-scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        backup_dir_fail = self.root / "tmp/rclone-quiesce-test-backup-fail"
        backup_dir_fail.mkdir(parents=True, exist_ok=True)
        vfs_backup_file = backup_dir_fail / "vfs-unit"
        vfs_backup_file.write_text("RECOVERY_VFS_UNIT_MATERIAL")

        # 1. When quiesce_rclone_services fails (returns 1)
        trace_fail = self.root / "rclone_quiesce_fail_trace.log"
        test_fail_script = f"""
set +e
source "{common_script}"

export AF_JOB_SCRATCH_DIR="{scratch_dir}"
export AF_ARCHIVE_BACKUP="{backup_dir_fail}"
export RCLONE_BACKUP_ARCHIVE="{backup_dir_fail}"
export AF_ARCHIVE_UNIT="rclone"
export LOGFILE="{self.root}/test-rclone-fail.log"
export ROLLBACK_NEEDED=1
export INSTALL_COMMITTED=false
export VFS_WAS_ACTIVE=0

quiesce_rclone_services() {{
    printf 'QUIESCE_CALLED\\n' >> "{trace_fail}"
    return 1
}}
rollback_app_archive_update() {{
    printf 'ROLLBACK_APP_ARCHIVE_CALLED\\n' >> "{trace_fail}"
    return 0
}}
safe_restore_path_from_backup() {{
    printf 'SAFE_RESTORE_CALLED:%s\\n' "$*" >> "{trace_fail}"
    return 0
}}
rm() {{
    printf 'RM_CALLED:%s\\n' "$*" >> "{trace_fail}"
    command rm "$@"
}}
systemctl() {{
    printf 'SYSTEMCTL_CALLED:%s\\n' "$*" >> "{trace_fail}"
    return 0
}}

{cleanup_func}

cleanup_and_rollback
"""
        res_fail = subprocess.run(["bash", "-c", test_fail_script], capture_output=True, text=True)
        self.assertNotEqual(res_fail.returncode, 0, f"Expected non-zero exit when quiesce fails, got: {res_fail.returncode}")
        self.assertEqual(res_fail.returncode, 1)
        self.assertTrue(trace_fail.exists(), "Trace log was not created")
        trace_fail_content = trace_fail.read_text()
        self.assertIn("QUIESCE_CALLED", trace_fail_content, "quiesce_rclone_services was not called")
        self.assertNotIn("ROLLBACK_APP_ARCHIVE_CALLED", trace_fail_content, "rollback_app_archive_update MUST NOT be invoked when quiesce fails")
        self.assertNotIn("SAFE_RESTORE_CALLED", trace_fail_content, "safe_restore_path_from_backup MUST NOT be invoked when quiesce fails")
        self.assertNotIn("rclone-vfs.service", trace_fail_content, "VFS unit removal/restoration MUST NOT be invoked when quiesce fails")
        self.assertTrue(vfs_backup_file.exists(), "Recovery material MUST be preserved on disk")
        self.assertEqual(vfs_backup_file.read_text(), "RECOVERY_VFS_UNIT_MATERIAL")
        self.assertIn("ERROR: Rclone rollback aborted because service quiescence failed; preserving recovery archive at", res_fail.stderr)
        self.assertIn("(incomplete-rollback)", res_fail.stderr)
        self.assertIn("AF_DIAG_FAILURE=", res_fail.stderr)
        self.assertIn('"category":"incomplete_rollback"', res_fail.stderr)
        self.assertIn('"stage":"rollback"', res_fail.stderr)

        # 2. When quiesce_rclone_services succeeds (returns 0)
        backup_dir_succ = self.root / "tmp/rclone-quiesce-test-backup-succ"
        backup_dir_succ.mkdir(parents=True, exist_ok=True)
        vfs_succ_file = backup_dir_succ / "vfs-unit"
        vfs_succ_file.write_text("RECOVERY_VFS_UNIT_MATERIAL_SUCC")

        trace_succ = self.root / "rclone_quiesce_succ_trace.log"
        test_succ_script = f"""
set +e
source "{common_script}"

export AF_JOB_SCRATCH_DIR="{scratch_dir}"
export AF_ARCHIVE_BACKUP="{backup_dir_succ}"
export RCLONE_BACKUP_ARCHIVE="{backup_dir_succ}"
export AF_ARCHIVE_UNIT="rclone"
export LOGFILE="{self.root}/test-rclone-succ.log"
export ROLLBACK_NEEDED=1
export INSTALL_COMMITTED=false
export VFS_WAS_ACTIVE=0

quiesce_rclone_services() {{
    printf 'QUIESCE_CALLED\\n' >> "{trace_succ}"
    return 0
}}
rollback_app_archive_update() {{
    printf 'ROLLBACK_APP_ARCHIVE_CALLED\\n' >> "{trace_succ}"
    return 0
}}
safe_restore_path_from_backup() {{
    printf 'SAFE_RESTORE_CALLED:%s\\n' "$*" >> "{trace_succ}"
    return 0
}}
rm() {{
    printf 'RM_CALLED:%s\\n' "$*" >> "{trace_succ}"
    command rm "$@"
}}
systemctl() {{
    printf 'SYSTEMCTL_CALLED:%s\\n' "$*" >> "{trace_succ}"
    return 0
}}

{cleanup_func}

cleanup_and_rollback
"""
        res_succ = subprocess.run(["bash", "-c", test_succ_script], capture_output=True, text=True)
        self.assertEqual(res_succ.returncode, 0, f"Expected 0 exit when quiesce succeeds, got: {res_succ.returncode}, stderr: {res_succ.stderr}")
        self.assertTrue(trace_succ.exists(), "Success trace log was not created")
        trace_succ_content = trace_succ.read_text()
        self.assertIn("QUIESCE_CALLED", trace_succ_content, "quiesce_rclone_services was not called")
        self.assertIn("ROLLBACK_APP_ARCHIVE_CALLED", trace_succ_content, "rollback_app_archive_update MUST be invoked when quiesce succeeds")
        self.assertIn("SAFE_RESTORE_CALLED", trace_succ_content, "safe_restore_path_from_backup MUST be invoked when quiesce succeeds")

    def test_piped_sha256_regular_file_nofollow_rejects_fifo_and_no_raw_sha256sum(self):
        """Verify installpackage-piped contains zero raw sha256sum calls on build/install paths
        and sha256_regular_file_nofollow rejects a FIFO immediately (< 1 second) without blocking,
        as well as rejecting symlinks and hardlinks while computing valid regular file digests."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()

        # 1. installpackage-piped contains zero raw sha256sum calls
        self.assertNotIn("sha256sum", piped_script, "installpackage-piped must contain zero raw sha256sum calls")

        # 2. Extract sha256_regular_file_nofollow definition
        sha_start = piped_script.index("sha256_regular_file_nofollow() {")
        sha_end = piped_script.index("\n}\n", sha_start) + 3
        sha_func = piped_script[sha_start:sha_end]

        test_dir = self.root / "tmp/piped-sha-nofollow-test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # 3. FIFO rejection: must exit non-zero immediately (< 1s) without blocking
        fifo_file = test_dir / "fifo.sock"
        os.mkfifo(str(fifo_file))

        cmd_fifo = f"""
{sha_func}
sha256_regular_file_nofollow "{fifo_file}"
"""
        import time
        t0 = time.monotonic()
        try:
            res_fifo = subprocess.run(["bash", "-c", cmd_fifo], capture_output=True, text=True, timeout=2.0)
            elapsed = time.monotonic() - t0
        except subprocess.TimeoutExpired:
            self.fail("sha256_regular_file_nofollow hung indefinitely on FIFO target!")

        self.assertLess(elapsed, 1.0, f"sha256_regular_file_nofollow took {elapsed:.2f}s, expected < 1.0s")
        self.assertNotEqual(res_fifo.returncode, 0, "sha256_regular_file_nofollow must reject FIFO with non-zero exit")

        # 4. Valid regular file: computes correct digest
        valid_file = test_dir / "valid.bin"
        test_content = b"VALID_PIPED_ARTIFACT_CONTENT_BYTES_12345"
        valid_file.write_bytes(test_content)
        expected_sha = hashlib.sha256(test_content).hexdigest()

        cmd_valid = f"""
{sha_func}
sha256_regular_file_nofollow "{valid_file}"
"""
        res_valid = subprocess.run(["bash", "-c", cmd_valid], capture_output=True, text=True)
        self.assertEqual(res_valid.returncode, 0, f"sha256_regular_file_nofollow failed on valid file: {res_valid.stderr}")
        self.assertEqual(res_valid.stdout.strip(), expected_sha)

        # 5. Symlink to regular file: rejected
        symlink_file = test_dir / "symlink.bin"
        symlink_file.symlink_to(valid_file)
        cmd_sym = f"""
{sha_func}
sha256_regular_file_nofollow "{symlink_file}"
"""
        res_sym = subprocess.run(["bash", "-c", cmd_sym], capture_output=True, text=True)
        self.assertNotEqual(res_sym.returncode, 0, "sha256_regular_file_nofollow must reject symlink")

        # 6. Hardlink to regular file: rejected
        hardlink_file = test_dir / "hardlink.bin"
        os.link(valid_file, hardlink_file)
        cmd_hard = f"""
{sha_func}
sha256_regular_file_nofollow "{hardlink_file}"
"""
        res_hard = subprocess.run(["bash", "-c", cmd_hard], capture_output=True, text=True)
        self.assertNotEqual(res_hard.returncode, 0, "sha256_regular_file_nofollow must reject hardlink with nlink > 1")

        # 7. Symlinked intermediate directory: rejected
        sym_dir = test_dir / "sym_parent"
        sym_dir.symlink_to(test_dir)
        cmd_sym_dir = f"""
{sha_func}
sha256_regular_file_nofollow "{sym_dir}/valid.bin"
"""
        res_sym_dir = subprocess.run(["bash", "-c", cmd_sym_dir], capture_output=True, text=True)
        self.assertNotEqual(res_sym_dir.returncode, 0, "sha256_regular_file_nofollow must reject symlinked ancestor dir")

    def test_rclone_and_common_incomplete_rollback_receipts(self):
        """Verify AF_DIAG_FAILURE with category incomplete_rollback is emitted on:
        1. installpackage-rclone cleanup_and_rollback restore failure
        2. packages/common.sh rollback_app_archive_update quiesce failure
        3. packages/common.sh rollback_app_archive_update restore incomplete
        4. packages/common.sh cleanup_state_transaction restore failure
        """
        rclone_script = (ROOT / "packages/package/install/installpackage-rclone").read_text()
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        cleanup_start = rclone_script.index("cleanup_and_rollback() {")
        cleanup_end = rclone_script.index("\n}\n", cleanup_start) + 3
        cleanup_func = rclone_script[cleanup_start:cleanup_end]

        test_dir = self.root / "tmp/rollback-receipt-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = test_dir / "backup"
        backup_dir.mkdir(parents=True, exist_ok=True)

        # 1. installpackage-rclone restore failure (when quiesce succeeds but restore fails)
        rclone_restore_fail_script = f"""
set +e
source "{common_script}"
export AF_JOB_SCRATCH_DIR="{test_dir}/scratch"
export AF_ARCHIVE_BACKUP="{backup_dir}"
export RCLONE_BACKUP_ARCHIVE="{backup_dir}"
export AF_ARCHIVE_UNIT="rclone"
export LOGFILE="{test_dir}/rclone-restore-fail.log"
export ROLLBACK_NEEDED=1
export INSTALL_COMMITTED=false
export VFS_WAS_ACTIVE=0

quiesce_rclone_services() {{ return 0; }}
rollback_app_archive_update() {{ return 1; }}
safe_restore_path_from_backup() {{ return 1; }}
systemctl() {{ return 1; }}

{cleanup_func}

cleanup_and_rollback
"""
        res_rclone_rf = subprocess.run(["bash", "-c", rclone_restore_fail_script], capture_output=True, text=True)
        self.assertNotEqual(res_rclone_rf.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_rclone_rf.stderr)
        self.assertIn('"category":"incomplete_rollback"', res_rclone_rf.stderr)
        self.assertIn('"stage":"rollback"', res_rclone_rf.stderr)

        # 2. common.sh rollback_app_archive_update quiesce failure
        common_quiesce_fail_script = f"""
set +e
source "{common_script}"
export AF_ARCHIVE_ACTIVATED=true
export AF_ARCHIVE_ORIGINAL_PRESENT=false
export AF_ARCHIVE_BACKUP="{backup_dir}"
export AF_ARCHIVE_UNIT="test-app"
export LOGFILE="{test_dir}/common-quiesce-fail.log"
export INSTALL_COMMITTED=false
export AF_ARCHIVE_STOPPED=false
export AF_ARCHIVE_PREVIOUS=false
quiesce_services_for_rollback() {{ return 1; }}

rollback_app_archive_update 1
"""
        res_cqf = subprocess.run(["bash", "-c", common_quiesce_fail_script], capture_output=True, text=True)
        self.assertNotEqual(res_cqf.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_cqf.stderr)
        self.assertIn('"category":"incomplete_rollback"', res_cqf.stderr)
        self.assertIn('"stage":"rollback"', res_cqf.stderr)
        self.assertIn("Application archive rollback aborted because service quiescence failed", res_cqf.stderr)

        # 3. common.sh rollback_app_archive_update incomplete restore
        (backup_dir / "app").write_text("old_app_data")
        common_restore_fail_script = f"""
set +e
source "{common_script}"
export AF_ARCHIVE_ACTIVATED=true
export AF_ARCHIVE_ORIGINAL_PRESENT=true
export AF_ARCHIVE_BACKUP="{backup_dir}"
export AF_ARCHIVE_UNIT="test-app"
export AF_ARCHIVE_DESTINATION="{test_dir}/dest"
export LOGFILE="{test_dir}/common-restore-fail.log"
export INSTALL_COMMITTED=false
export AF_ARCHIVE_STOPPED=false
export AF_ARCHIVE_PREVIOUS=false
export AF_ARCHIVE_ARCHIVE=""
quiesce_services_for_rollback() {{ return 0; }}
safe_restore_path_from_backup() {{ return 1; }}
systemctl() {{ return 0; }}

rollback_app_archive_update 1
"""
        res_crf = subprocess.run(["bash", "-c", common_restore_fail_script], capture_output=True, text=True)
        self.assertNotEqual(res_crf.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_crf.stderr)
        self.assertIn('"category":"incomplete_rollback"', res_crf.stderr)
        self.assertIn('"stage":"rollback"', res_crf.stderr)
        self.assertIn("Application recovery is incomplete", res_crf.stderr)

        # 4. common.sh cleanup_state_transaction restore failure
        tx_fail_dir = test_dir / "tx-backup"
        tx_fail_dir.mkdir(parents=True, exist_ok=True)
        common_tx_fail_script = f"""
set +e
source "{common_script}"
export AF_STATE_BACKUP="{tx_fail_dir}"
export AF_STATE_SNAPSHOT_READY=true
export INSTALL_COMMITTED=false
export LOGFILE="{test_dir}/tx-fail.log"
quiesce_services_for_rollback() {{ return 1; }}

cleanup_state_transaction 1
"""
        res_txf = subprocess.run(["bash", "-c", common_tx_fail_script], capture_output=True, text=True)
        self.assertNotEqual(res_txf.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_txf.stderr)
        self.assertIn('"category":"incomplete_rollback"', res_txf.stderr)
        self.assertIn('"stage":"rollback"', res_txf.stderr)
        self.assertIn("Rollback incomplete; recovery backup preserved", res_txf.stderr)

    def test_piped_certify_mandatory_running_proxy_verification(self):
        """Verify certify_piped fails closed for:
        1. Missing or empty ExecMainPID
        2. ExecMainPID = 0
        3. Missing /proc/<pid>/exe
        4. /proc/<pid>/exe marked as (deleted)
        5. Running executable path mismatch with deployed proxy path
        6. Running executable SHA-256 mismatch with DEPLOYED_PROXY_SHA256
        7. Passes when valid PID, path, and digest match
        """
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        cert_start = piped_script.index("certify_piped() {")
        cert_end = piped_script.index("\n}\n", cert_start) + 3
        cert_func = piped_script[cert_start:cert_end]

        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/piped-mandatory-proxy-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        install_dir = test_dir / "opt/piped"
        install_dir.mkdir(parents=True, exist_ok=True)

        for comp in ("frontend", "backend", "proxy"):
            comp_dir = install_dir / comp
            comp_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", str(comp_dir)], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.email", "test@example.com"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "config", "user.name", "Test"], capture_output=True, check=True)
            subprocess.run(["git", "-C", str(comp_dir), "commit", "--allow-empty", "-m", "init"], capture_output=True, check=True)

        jar_file = install_dir / "piped.jar"
        jar_file.write_text("VALID_PIPED_JAR_CONTENT")
        proxy_file = install_dir / "piped-proxy"
        proxy_file.write_text("VALID_PIPED_PROXY_CONTENT")
        proxy_file.chmod(0o755)

        jar_sha = hashlib.sha256(b"VALID_PIPED_JAR_CONTENT").hexdigest()
        proxy_sha = hashlib.sha256(b"VALID_PIPED_PROXY_CONTENT").hexdigest()

        proc_dir = test_dir / "proc"
        proc_dir.mkdir(parents=True, exist_ok=True)

        def run_cert(mock_systemctl_body, extra_env="", extra_funcs=""):
            script = f"""
source "{common_script}"
set +e
APP_NAME="piped"
APP_PORT="8280"
INSTALL_DIR="{install_dir}"
PIPED_BACKEND_DIR="{install_dir}"
PIPED_PROXY_DIR="{install_dir}"
PIPED_FRONTEND_REF=""
PIPED_BACKEND_REF=""
PIPED_PROXY_REF=""
DEPLOYED_BACKEND_SHA256="{jar_sha}"
DEPLOYED_PROXY_SHA256="{proxy_sha}"
export AF_PROC_ROOT="{proc_dir}"
{extra_env}

youtube_ready() {{ return 0; }}
systemctl() {{
{mock_systemctl_body}
}}
{extra_funcs}

{cert_func}
certify_piped
"""
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

        # 1. Missing or empty ExecMainPID -> fails closed
        res_empty = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo ""
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_empty.returncode, 0)
        self.assertIn("unable to resolve valid running ExecMainPID", res_empty.stderr)

        # 2. ExecMainPID = 0 -> fails closed
        res_zero = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "0"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_zero.returncode, 0)
        self.assertIn("unable to resolve valid running ExecMainPID", res_zero.stderr)

        # 3. Missing /proc/<pid>/exe -> fails closed
        pid_9999 = proc_dir / "9999"
        pid_9999.mkdir(parents=True, exist_ok=True)
        res_no_exe = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "9999"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_no_exe.returncode, 0)
        self.assertIn("is missing, deleted, or not a regular file", res_no_exe.stderr)

        # 4. /proc/<pid>/exe points to deleted file -> fails closed
        pid_8888 = proc_dir / "8888"
        pid_8888.mkdir(parents=True, exist_ok=True)
        (pid_8888 / "exe").symlink_to(str(proxy_file.resolve()) + " (deleted)")
        res_deleted = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "8888"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_deleted.returncode, 0)
        self.assertIn("is missing, deleted, or not a regular file", res_deleted.stderr)

        # 5. Running executable path mismatch with deployed proxy path -> fails closed
        other_bin = test_dir / "other-bin"
        other_bin.write_text("VALID_PIPED_PROXY_CONTENT")
        other_bin.chmod(0o755)
        pid_7777 = proc_dir / "7777"
        pid_7777.mkdir(parents=True, exist_ok=True)
        (pid_7777 / "exe").symlink_to(other_bin.resolve())
        res_path_mismatch = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "7777"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_path_mismatch.returncode, 0)
        self.assertIn("does not match deployed path", res_path_mismatch.stderr)

        # 6. Running executable SHA mismatch -> fails closed
        pid_6666 = proc_dir / "6666"
        pid_6666.mkdir(parents=True, exist_ok=True)
        (pid_6666 / "exe").symlink_to(proxy_file.resolve())
        mock_sha_mismatch = """
sha256_proc_exe_matching_file() {
    echo "mismatched_running_sha_6666"
    return 0
}
"""
        res_sha_mismatch = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "6666"
        return 0
    fi
    return 0
""", extra_funcs=mock_sha_mismatch)
        self.assertNotEqual(res_sha_mismatch.returncode, 0)
        self.assertIn("does not match newly published binary", res_sha_mismatch.stderr)

        # 7. Valid ExecMainPID, valid path, and matching digest -> returns 0
        pid_5555 = proc_dir / "5555"
        pid_5555.mkdir(parents=True, exist_ok=True)
        (pid_5555 / "exe").symlink_to(proxy_file.resolve())
        res_valid = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "5555"
        return 0
    fi
    return 0
""")
        self.assertEqual(res_valid.returncode, 0, f"Expected certify_piped to succeed, but got: {res_valid.stderr}")

        # 8. /proc/<pid>/exe inode mismatch against deployed proxy -> fails closed
        other_proxy_binary = test_dir / "other_proxy_binary"
        other_proxy_binary.write_text("VALID_PIPED_PROXY_CONTENT")
        other_proxy_binary.chmod(0o755)
        pid_4444 = proc_dir / "4444"
        pid_4444.mkdir(parents=True, exist_ok=True)
        (pid_4444 / "exe").symlink_to(other_proxy_binary.resolve())
        mock_path_same_inode_diff = f"""
readlink() {{
    if [[ "$*" == *"-f "* && "$*" == *"/4444/exe"* ]]; then
        echo "{proxy_file.resolve()}"
        return 0
    fi
    command readlink "$@"
}}
"""
        res_inode_mismatch = run_cert("""
    if [[ "$*" == *"show -p ExecMainPID"* ]]; then
        echo "4444"
        return 0
    fi
    return 0
""", extra_funcs=mock_path_same_inode_diff)
        self.assertNotEqual(res_inode_mismatch.returncode, 0)
        self.assertIn("failed inode identity verification", res_inode_mismatch.stderr)

    def test_quiesce_services_for_rollback_status_query_failures_and_transitional_states(self):
        """Verify quiesce_services_for_rollback in packages/common.sh fails closed:
        1. When systemctl is-active fails with exit status 1 (failed status query / broken bus).
        2. When systemctl is-active returns exit 3 but outputs 'deactivating'.
        3. When systemctl show returns ActiveState=deactivating (transitional state).
        4. When systemctl show returns ActiveState=active (unit still running).
        5. Successfully quiesces when unit is verified inactive (ActiveState=inactive, MainPID=0).
        """
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/quiesce-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        logfile = test_dir / "quiesce.log"

        def run_quiesce(mock_systemctl_body):
            script = f"""
source "{common_script}"
set +e
export LOGFILE="{logfile}"
export AF_ROLLBACK_BACKUP="{test_dir}/backup"

print_error() {{
    printf 'ERROR:%s\\n' "$*" >&2
}}

systemctl() {{
{mock_systemctl_body}
}}

quiesce_services_for_rollback test-service
"""
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

        # 1. systemctl is-active fails with exit status 1 (failed status query) -> fails closed
        res_query_fail = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        echo "Failed to connect to bus: Connection refused" >&2
        return 1
    elif [ "$sub" = "show" ]; then
        return 1
    fi
    return 0
""")
        self.assertNotEqual(res_query_fail.returncode, 0, "quiesce_services_for_rollback must fail when is-active exits 1")
        self.assertIn("failed to stop test-service", res_query_fail.stderr)

        # 2. systemctl is-active returns exit 3 but outputs 'deactivating' -> fails closed
        res_deact_output = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        echo "deactivating"
        return 3
    elif [ "$sub" = "show" ]; then
        echo "LoadState=loaded"
        echo "ActiveState=deactivating"
        echo "MainPID=123"
        echo "UnitFileState=enabled"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_deact_output.returncode, 0, "quiesce_services_for_rollback must fail when unit is deactivating")
        self.assertIn("failed to stop test-service", res_deact_output.stderr)

        # 3. systemctl show returns ActiveState=deactivating -> fails closed
        res_show_deact = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        echo "inactive"
        return 3
    elif [ "$sub" = "show" ]; then
        echo "LoadState=loaded"
        echo "ActiveState=deactivating"
        echo "MainPID=0"
        echo "UnitFileState=enabled"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_show_deact.returncode, 0, "quiesce_services_for_rollback must fail when show reports deactivating")
        self.assertIn("failed to stop test-service", res_show_deact.stderr)

        # 4. systemctl show returns ActiveState=active -> fails closed
        res_show_active = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        echo "inactive"
        return 3
    elif [ "$sub" = "show" ]; then
        echo "LoadState=loaded"
        echo "ActiveState=active"
        echo "MainPID=456"
        echo "UnitFileState=enabled"
        return 0
    fi
    return 0
""")
        self.assertNotEqual(res_show_active.returncode, 0, "quiesce_services_for_rollback must fail when show reports active")
        self.assertIn("failed to stop test-service", res_show_active.stderr)

        # 5. Verified inactive state -> succeeds (returns 0)
        res_succ = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        echo "inactive"
        return 3
    elif [ "$sub" = "show" ]; then
        echo "LoadState=loaded"
        echo "ActiveState=inactive"
        echo "MainPID=0"
        echo "UnitFileState=enabled"
        return 0
    fi
    return 0
""")
        self.assertEqual(res_succ.returncode, 0, f"Expected quiesce_services_for_rollback to succeed, got: {res_succ.stderr}")

        # 6. stop exit 0 + is-active exit 3 with empty output + failed show -> fails closed (Finding 2)
        res_empty_active = run_quiesce("""
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        return 3
    elif [ "$sub" = "show" ]; then
        return 1
    fi
    return 0
""")
        self.assertNotEqual(res_empty_active.returncode, 0, "quiesce_services_for_rollback must fail when is-active has empty output and show fails")
        self.assertIn("failed to stop test-service", res_empty_active.stderr)

    def test_sha256_proc_exe_matching_file_inode_verification(self):
        """Verify sha256_proc_exe_matching_file verifies (st_dev, st_ino) identity,
        rejects unlinked files or separate files with identical content, and hashes directly from fd."""
        piped_script = (ROOT / "packages/package/install/installpackage-piped").read_text()
        fn_start = piped_script.index("sha256_proc_exe_matching_file() {")
        fn_end = piped_script.index("\n}\n", fn_start) + 3
        helper_code = piped_script[fn_start:fn_end]

        test_dir = self.root / "tmp/sha256-proc-exe-test"
        test_dir.mkdir(parents=True, exist_ok=True)

        target_file = test_dir / "target_binary"
        target_file.write_text("PROXY_BINARY_PAYLOAD_ABC")
        target_file.chmod(0o755)

        identical_file = test_dir / "identical_binary"
        identical_file.write_text("PROXY_BINARY_PAYLOAD_ABC")
        identical_file.chmod(0o755)

        symlink_to_target = test_dir / "proc_exe_symlink"
        symlink_to_target.symlink_to(target_file.resolve())

        symlink_to_identical = test_dir / "proc_exe_diff_inode"
        symlink_to_identical.symlink_to(identical_file.resolve())

        expected_sha = hashlib.sha256(b"PROXY_BINARY_PAYLOAD_ABC").hexdigest()

        def call_helper(proc_path, dest_path):
            script = f"""
{helper_code}
sha256_proc_exe_matching_file "{proc_path}" "{dest_path}"
"""
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

        # 1. Matching inode -> succeeds and outputs digest
        res_match = call_helper(symlink_to_target, target_file)
        self.assertEqual(res_match.returncode, 0, f"Expected success, got {res_match.stderr}")
        self.assertEqual(res_match.stdout.strip(), expected_sha)

        # 2. Inode mismatch with same content -> fails
        res_diff = call_helper(symlink_to_identical, target_file)
        self.assertNotEqual(res_diff.returncode, 0, "Must fail on inode mismatch even with identical bytes")

        # 3. Unlinked destination file -> fails
        unlinked_target = test_dir / "unlinked_binary"
        unlinked_target.write_text("TEMP_UNLINKED")
        unlinked_target.unlink()
        res_unlinked = call_helper(symlink_to_target, unlinked_target)
        self.assertNotEqual(res_unlinked.returncode, 0, "Must fail if dest file does not exist")

    def test_af_write_failure_receipt_escapes_backslashes_and_control_chars(self):
        r"""Verify calling af_write_failure_receipt with backslashes (\q, C:\temp\path)
        and control characters produces valid JSON parsed by json.loads()."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/receipt-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        script = f"""
source "{common_script}"
af_write_failure_receipt 1 "install_stage" "installer" 'Failed at \\q with path C:\\temp\\path and control'$'\\t''chars'
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertIn("AF_DIAG_FAILURE=", res.stderr)
        diag_lines = [l for l in res.stderr.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines) > 0, "AF_DIAG_FAILURE line not found in stderr")
        json_str = diag_lines[0].split("AF_DIAG_FAILURE=", 1)[1]
        data = json.loads(json_str)
        self.assertEqual(data["stage"], "install_stage")
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual(data["category"], "installer")
        self.assertIn(r"\q", data["summary"])
        self.assertIn(r"C:\temp\path", data["summary"])

    def test_commit_app_versions_target_version_mismatch_fails_closed(self):
        """Verify commit_app_versions rejects staged version mismatch against AF_TARGET_VERSION
        and returns non-zero before writing version files."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/commit-ver-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        ver_file = test_dir / ".af-version"

        script = f"""
source "{common_script}"
set -e
export AF_TARGET_VERSION="5.16.3.9541"
queue_app_version "{ver_file}" "9.99.9.9999"
commit_app_versions
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "commit_app_versions must fail when queued version does not match target")
        self.assertIn("does not match requested target version", res.stderr)
        self.assertFalse(ver_file.exists(), ".af-version must not be written on mismatch")

    def test_radarr_target_version_mismatch_fails_before_write_lock_and_rolls_back(self):
        """Verify that when AF_TARGET_VERSION is set for Radarr and the downloaded archive
        contains a binary reporting a different version (9.99.9.9999), the installer exits
        non-zero BEFORE write_lock and rolls back /opt/Radarr to previous application archive."""
        app_dir = self.root / "opt/Radarr"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("5.15.0.0\n")
        (app_dir / "canary.txt").write_text("previous-radarr-archive-material\n")
        radarr_bin = app_dir / "Radarr"
        radarr_bin.write_text("#!/bin/sh\necho 'Radarr version 5.15.0.0'\n")
        radarr_bin.chmod(0o755)

        (self.root / "var/lib/radarr").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/radarr/config.xml").write_text("<Config><Port>7878</Port></Config>")

        (self.root / "etc/systemd/system/radarr.service").write_text("[Unit]\nDescription=Radarr\n")
        (self.root / "service_active_radarr").touch()
        (self.root / "service_enabled_radarr").touch()

        result = self.run_script("radarr", AF_TARGET_VERSION="5.16.3.9541", MOCK_RADARR_BIN_VERSION="9.99.9.9999")
        self.assertNotEqual(result.returncode, 0, f"Installer should fail on version mismatch, stderr: {result.stderr}")
        self.assertFalse((self.root / "install/.radarr.lock").exists(), "write_lock must not have been called")
        self.assertTrue((app_dir / "canary.txt").exists(), "Previous application archive material must be restored")
        self.assertEqual((app_dir / "canary.txt").read_text().strip(), "previous-radarr-archive-material")
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "5.15.0.0")
        self.assertIn("does not match", result.stderr)

    def test_sonarr_target_version_mismatch_fails_before_write_lock_and_rolls_back(self):
        """Verify that when AF_TARGET_VERSION is set for Sonarr and the downloaded archive
        contains a binary reporting a different version (9.99.9.9999), the installer exits
        non-zero BEFORE write_lock and rolls back /opt/Sonarr to previous application archive."""
        app_dir = self.root / "opt/Sonarr"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("4.0.11.0\n")
        (app_dir / "canary.txt").write_text("previous-sonarr-archive-material\n")
        sonarr_bin = app_dir / "Sonarr"
        sonarr_bin.write_text("#!/bin/sh\necho 'Sonarr version 4.0.11.0'\n")
        sonarr_bin.chmod(0o755)

        (self.root / "var/lib/sonarr").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/sonarr/config.xml").write_text("<Config><Port>8989</Port></Config>")

        (self.root / "etc/systemd/system/sonarr.service").write_text("[Unit]\nDescription=Sonarr\n")
        (self.root / "service_active_sonarr").touch()
        (self.root / "service_enabled_sonarr").touch()

        result = self.run_script("sonarr", AF_TARGET_VERSION="4.0.12.2823", MOCK_SONARR_BIN_VERSION="9.99.9.9999")
        self.assertNotEqual(result.returncode, 0, f"Installer should fail on version mismatch, stderr: {result.stderr}")
        self.assertFalse((self.root / "install/.sonarr.lock").exists(), "write_lock must not have been called")
        self.assertTrue((app_dir / "canary.txt").exists(), "Previous application archive material must be restored")
        self.assertEqual((app_dir / "canary.txt").read_text().strip(), "previous-sonarr-archive-material")
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "4.0.11.0")
        self.assertIn("does not match", result.stderr)

    def test_prowlarr_target_version_mismatch_fails_before_write_lock_and_rolls_back(self):
        """Verify that when AF_TARGET_VERSION is set for Prowlarr and the downloaded archive
        contains a binary reporting a different version (9.99.9.9999), the installer exits
        non-zero BEFORE write_lock and rolls back /opt/Prowlarr to previous application archive."""
        app_dir = self.root / "opt/Prowlarr"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / ".af-version").write_text("1.27.0.0\n")
        (app_dir / "canary.txt").write_text("previous-prowlarr-archive-material\n")
        prowlarr_bin = app_dir / "Prowlarr"
        prowlarr_bin.write_text("#!/bin/sh\necho 'Prowlarr version 1.27.0.0'\n")
        prowlarr_bin.chmod(0o755)

        (self.root / "var/lib/prowlarr").mkdir(parents=True, exist_ok=True)
        (self.root / "var/lib/prowlarr/config.xml").write_text("<Config><Port>9696</Port></Config>")

        (self.root / "etc/systemd/system/prowlarr.service").write_text("[Unit]\nDescription=Prowlarr\n")
        (self.root / "service_active_prowlarr").touch()
        (self.root / "service_enabled_prowlarr").touch()

        result = self.run_script("prowlarr", AF_TARGET_VERSION="1.28.2.4885", MOCK_PROWLARR_BIN_VERSION="9.99.9.9999")
        self.assertNotEqual(result.returncode, 0, f"Installer should fail on version mismatch, stderr: {result.stderr}")
        self.assertFalse((self.root / "install/.prowlarr.lock").exists(), "write_lock must not have been called")
        self.assertTrue((app_dir / "canary.txt").exists(), "Previous application archive material must be restored")
        self.assertEqual((app_dir / "canary.txt").read_text().strip(), "previous-prowlarr-archive-material")
        self.assertEqual((app_dir / ".af-version").read_text().strip(), "1.27.0.0")
        self.assertIn("does not match", result.stderr)

    def test_quiesce_services_for_rollback_empty_is_active_output_fails_closed(self):
        """Verify quiesce_services_for_rollback fails closed when stop exits 0,
        is-active exits 3 with empty stdout, and show fails."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/quiesce-empty-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        logfile = test_dir / "quiesce.log"

        script = f"""
source "{common_script}"
set +e
export LOGFILE="{logfile}"
export AF_ROLLBACK_BACKUP="{test_dir}/backup"

print_error() {{
    printf 'ERROR:%s\\n' "$*" >&2
}}

systemctl() {{
    sub="$1"
    shift
    if [ "$sub" = "stop" ]; then
        return 0
    elif [ "$sub" = "is-active" ]; then
        if [[ "$*" == *"--quiet"* ]]; then
            return 1
        fi
        return 3
    elif [ "$sub" = "show" ]; then
        return 1
    fi
    return 0
}}

quiesce_services_for_rollback test-service
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "quiesce_services_for_rollback must fail when is-active has empty output and show fails")
        self.assertIn("failed to stop test-service", res.stderr)

    def test_commit_app_versions_filebot_multi_receipt_target_version(self):
        """Verify multi-receipt commit_app_versions with FileBot (0.4.8.1 + 5.1.6)
        succeeds when AF_TARGET_VERSION=0.4.8.1 and fails when AF_TARGET_VERSION=9.9.9."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/filebot-multi-receipt-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        node_dir = test_dir / "node"
        fb_dir = test_dir / "fb"
        node_dir.mkdir(parents=True, exist_ok=True)
        fb_dir.mkdir(parents=True, exist_ok=True)
        node_ver = node_dir / ".af-version"
        fb_ver = fb_dir / ".af-version"

        # Case 1: AF_TARGET_VERSION=0.4.8.1 matches node receipt -> succeeds
        script_success = f"""
source "{common_script}"
set -e
export AF_TARGET_VERSION="0.4.8.1"
queue_app_version "{node_ver}" "0.4.8.1"
queue_app_version "{fb_ver}" "5.1.6"
commit_app_versions
"""
        res_success = subprocess.run(["bash", "-c", script_success], capture_output=True, text=True)
        self.assertEqual(res_success.returncode, 0, f"Expected success, got stderr: {res_success.stderr}")
        self.assertTrue(node_ver.exists())
        self.assertTrue(fb_ver.exists())
        self.assertEqual(node_ver.read_text().strip(), "0.4.8.1")
        self.assertEqual(fb_ver.read_text().strip(), "5.1.6")

        # Clean up files for failure test
        node_ver.unlink()
        fb_ver.unlink()

        # Case 2: AF_TARGET_VERSION=9.9.9 matches neither receipt -> fails before writing receipts
        script_fail = f"""
source "{common_script}"
set -e
export AF_TARGET_VERSION="9.9.9"
queue_app_version "{node_ver}" "0.4.8.1"
queue_app_version "{fb_ver}" "5.1.6"
commit_app_versions
"""
        res_fail = subprocess.run(["bash", "-c", script_fail], capture_output=True, text=True)
        self.assertNotEqual(res_fail.returncode, 0, "commit_app_versions must fail when AF_TARGET_VERSION matches neither receipt")
        self.assertIn("do not match requested target version", res_fail.stderr)
        self.assertFalse(node_ver.exists(), ".af-version must not be written on mismatch")
        self.assertFalse(fb_ver.exists(), ".af-version must not be written on mismatch")

        # Case 3: AF_TARGET_VERSION=5.1.6 matches secondary CLI version instead of primary receipt -> fails before writing receipts
        script_fail_secondary = f"""
source "{common_script}"
set -e
export AF_TARGET_VERSION="5.1.6"
queue_app_version "{node_ver}" "0.4.8.1"
queue_app_version "{fb_ver}" "5.1.6"
commit_app_versions
"""
        res_fail_sec = subprocess.run(["bash", "-c", script_fail_secondary], capture_output=True, text=True)
        self.assertNotEqual(res_fail_sec.returncode, 0, "commit_app_versions must fail when AF_TARGET_VERSION matches secondary receipt rather than primary")
        self.assertIn("do not match requested target version", res_fail_sec.stderr)
        self.assertFalse(node_ver.exists(), ".af-version must not be written on secondary match")
        self.assertFalse(fb_ver.exists(), ".af-version must not be written on secondary match")

    def test_af_write_failure_receipt_escapes_quotes_backslashes_tabs_newlines_in_all_fields(self):
        """Verify af_write_failure_receipt escapes quotes, backslashes, tabs, and newlines
        in stage (AF_CURRENT_STAGE), category, and summary to produce valid JSON parsed by json.loads."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/receipt-escaping-test"
        test_dir.mkdir(parents=True, exist_ok=True)
        script = f"""
source "{common_script}"
export AF_CURRENT_STAGE=$'stage"name\\\\with\\\\backslashes\\\\tand\\\\nnewline'
af_write_failure_receipt 1 $'stage"name\\\\with\\\\backslashes\\\\tand\\\\nnewline' $'cat"egory\\\\with\\\\backslashes\\\\tand\\\\nnewline' $'sum"mary\\\\with\\\\backslashes\\\\tand\\\\nnewline'
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertIn("AF_DIAG_FAILURE=", res.stderr)
        diag_lines = [l for l in res.stderr.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines) > 0, "AF_DIAG_FAILURE line not found in stderr")
        json_str = diag_lines[0].split("AF_DIAG_FAILURE=", 1)[1]
        data = json.loads(json_str)
        self.assertEqual(data["exit_code"], 1)
        self.assertIn(r'\"', json_str)
        self.assertIn('"', data["stage"])
        self.assertIn('"', data["category"])
        self.assertIn('"', data["summary"])
        self.assertNotIn('\n', data["stage"])
        self.assertNotIn('\t', data["stage"])
        self.assertNotIn('\n', data["category"])
        self.assertNotIn('\t', data["category"])
        self.assertNotIn('\n', data["summary"])
        self.assertNotIn('\t', data["summary"])
        self.assertIn("with", data["stage"])
        self.assertIn("backslashes", data["stage"])

    def test_af_write_failure_receipt_multibyte_utf8_boundary_truncation_and_scalar_redaction(self):
        """Verify af_write_failure_receipt safely truncates multibyte UTF-8 characters at byte boundaries
        without emitting invalid UTF-8 bytes and redacts sensitive credentials."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/receipt-utf8-test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # 1. Truncate at boundary: "a" * 299 + "é" drops incomplete "é" to keep 299 "a" bytes
        #    stage "s" * 119 + "é" drops "é" to 119 "s" bytes, cat "c" * 119 + "é" drops "é" to 119 "c" bytes
        s_119 = "s" * 119 + "é"
        c_119 = "c" * 119 + "é"
        a_299 = "a" * 299 + "é"
        script1 = f"""
source "{common_script}"
af_write_failure_receipt 1 "{s_119}" "{c_119}" "{a_299}"
"""
        res1 = subprocess.run(["bash", "-c", script1], capture_output=True, text=False)
        self.assertEqual(res1.returncode, 0)
        stderr1 = res1.stderr.decode("utf-8")
        diag_lines1 = [l for l in stderr1.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines1) > 0, "AF_DIAG_FAILURE line not found in stderr")
        data1 = json.loads(diag_lines1[0].split("AF_DIAG_FAILURE=", 1)[1])
        self.assertEqual(data1["stage"], "s" * 119)
        self.assertEqual(len(data1["stage"].encode("utf-8")), 119)
        self.assertEqual(data1["category"], "c" * 119)
        self.assertEqual(len(data1["category"].encode("utf-8")), 119)
        self.assertEqual(data1["summary"], "a" * 299)
        self.assertEqual(len(data1["summary"].encode("utf-8")), 299)

        # 2. Boundary where multibyte fits within byte budget:
        #    "a" * 298 + "é" + "z" keeps "é" and truncates "z" -> 300 bytes
        #    "s" * 118 + "é" + "z" keeps "é" and truncates "z" -> 120 bytes
        #    "c" * 118 + "é" + "z" keeps "é" and truncates "z" -> 120 bytes
        s_118 = "s" * 118 + "é" + "z"
        c_118 = "c" * 118 + "é" + "z"
        a_298 = "a" * 298 + "é" + "z"
        script2 = f"""
source "{common_script}"
af_write_failure_receipt 1 "{s_118}" "{c_118}" "{a_298}"
"""
        res2 = subprocess.run(["bash", "-c", script2], capture_output=True, text=False)
        self.assertEqual(res2.returncode, 0)
        stderr2 = res2.stderr.decode("utf-8")
        diag_lines2 = [l for l in stderr2.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines2) > 0, "AF_DIAG_FAILURE line not found in stderr")
        data2 = json.loads(diag_lines2[0].split("AF_DIAG_FAILURE=", 1)[1])
        self.assertEqual(data2["stage"], "s" * 118 + "é")
        self.assertEqual(len(data2["stage"].encode("utf-8")), 120)
        self.assertEqual(data2["category"], "c" * 118 + "é")
        self.assertEqual(len(data2["category"].encode("utf-8")), 120)
        self.assertEqual(data2["summary"], "a" * 298 + "é")
        self.assertEqual(len(data2["summary"].encode("utf-8")), 300)

        # 3. Scalar credential redactions
        for canary in (
            "Cookie: session=CANARY_COOKIE",
            "session=CANARY_SESSION",
            '{"webhook_url":"https://example.test/CANARY_HOOK"}',
            "pass=CANARY_PASSWORD",
        ):
            script_canary = f"""
source "{common_script}"
af_write_failure_receipt 1 "install_stage" "installer" 'Failure with {canary}'
"""
            res_c = subprocess.run(["bash", "-c", script_canary], capture_output=True, text=False)
            self.assertEqual(res_c.returncode, 0)
            stderr_c = res_c.stderr.decode("utf-8")
            self.assertNotIn("CANARY_", stderr_c, f"Canary leaked in stderr: {stderr_c}")
            diag_lines_c = [l for l in stderr_c.splitlines() if "AF_DIAG_FAILURE=" in l]
            self.assertTrue(len(diag_lines_c) > 0, "AF_DIAG_FAILURE line not found in stderr")
            data_c = json.loads(diag_lines_c[0].split("AF_DIAG_FAILURE=", 1)[1])
            self.assertNotIn("CANARY_", data_c["summary"])

    def test_wave23_failure_receipt_redacts_quoted_scalars_and_escaped_headers_python(self):
        """Verify af_write_failure_receipt redacts quoted scalar credentials, single-quoted credentials,
        escaped-quote credentials, and escaped HTTP header quotes in the Python branch,
        while preserving boundary-safe benign keys such as bypass=visible and passed=true."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"

        # 1. Quoted scalars, single-quoted scalars, escaped-quote scalars, and boundary-safe keys
        script_scalars = f"""
source "{common_script}"
af_write_failure_receipt 1 "install_stage" "installer" 'pass="SHELL_CANARY" session="SHELL_CANARY_2" token="SHELL_CANARY_3" pass2=\x27SINGLE_CANARY\x27 pass3="ESC_\\"CANARY\\"" bypass=visible passed=true'
"""
        res_scalars = subprocess.run(["bash", "-c", script_scalars], capture_output=True, text=True)
        self.assertEqual(res_scalars.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_scalars.stderr)
        diag_lines = [l for l in res_scalars.stderr.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines) > 0)
        data_scalars = json.loads(diag_lines[0].split("AF_DIAG_FAILURE=", 1)[1])
        summary_scalars = data_scalars["summary"]
        self.assertNotIn("CANARY", summary_scalars)
        self.assertIn("bypass=visible", summary_scalars)
        self.assertIn("passed=true", summary_scalars)

        # 2. Escaped header quotes, unquoted headers with inner quotes/semicolons, and multiple -H headers
        script_headers = f"""
source "{common_script}"
af_write_failure_receipt 1 "install_stage" "installer" 'Cookie: sid="UNQUOTED_COOKIE_CANARY"; csrf=COOKIE_CANARY_B | Set-Cookie: sid="SET_CANARY"; HttpOnly | curl -H "Cookie: sid=\\"COOKIE_CANARY\\"" -H "Proxy-Authorization: Bearer PROXY_CANARY" -H "X-Api-Key: API_CANARY" https://example.invalid'
"""
        res_headers = subprocess.run(["bash", "-c", script_headers], capture_output=True, text=True)
        self.assertEqual(res_headers.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res_headers.stderr)
        diag_lines_h = [l for l in res_headers.stderr.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertTrue(len(diag_lines_h) > 0)
        data_headers = json.loads(diag_lines_h[0].split("AF_DIAG_FAILURE=", 1)[1])
        summary_headers = data_headers["summary"]
        self.assertNotIn("CANARY", summary_headers)

    def test_wave23_failure_receipt_no_python_fallback_redacts_headers_quoted_scalars_and_preserves_bypass(self):
        """Verify af_write_failure_receipt in no-Python fallback branch redacts headers,
        quoted scalar credentials, and preserves boundary-safe keys such as bypass=visible."""
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        test_dir = self.root / "tmp/fallback-test-bin"
        test_dir.mkdir(parents=True, exist_ok=True)
        temp_bin = test_dir / "bin"
        temp_bin.mkdir(parents=True, exist_ok=True)
        for tool in ("bash", "awk", "sed", "tr", "head", "cat", "rm", "mkdir"):
            tool_path = shutil.which(tool)
            if tool_path:
                (temp_bin / tool).symlink_to(tool_path)

        script = f"""
source "{common_script}"
PATH="{temp_bin}"
af_write_failure_receipt 1 "stage" "cat" 'pass="SHELL_CANARY" session="SHELL_CANARY_2" token="SHELL_CANARY_3" bypass=visible'
af_write_failure_receipt 1 "stage" "cat" 'Cookie: sid="UNQUOTED_COOKIE_CANARY"; csrf=COOKIE_CANARY_B | Proxy-Authorization: PROXY_CANARY | X-Api-Key: KEY_CANARY | curl -H "Cookie: sid=\\"COOKIE_CANARY\\"" https://example.invalid'
"""
        res = subprocess.run([str(temp_bin / "bash"), "-c", script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("AF_DIAG_FAILURE=", res.stderr)
        diag_lines = [l for l in res.stderr.splitlines() if "AF_DIAG_FAILURE=" in l]
        self.assertEqual(len(diag_lines), 2)

        data1 = json.loads(diag_lines[0].split("AF_DIAG_FAILURE=", 1)[1])
        self.assertNotIn("CANARY", json.dumps(data1))
        self.assertIn("bypass=visible", data1["summary"])
        self.assertNotIn("bypass=[REDACTED]", data1["summary"])

        data2 = json.loads(diag_lines[1].split("AF_DIAG_FAILURE=", 1)[1])
        self.assertNotIn("CANARY", json.dumps(data2))
        self.assertNotIn("PROXY_CANARY", data2["summary"])
        self.assertNotIn("KEY_CANARY", data2["summary"])
        self.assertNotIn("COOKIE_CANARY", data2["summary"])

    def test_wave24_failure_receipt_masks_secrets_in_python_and_fallback(self):
        """Mask secrets in both python3 and no-Python fallback receipt paths.

        Covers the structured diagnostic matrix (key=value, --flag forms, headers,
        nested JSON containers, escaped --user) in each mode, including the
        boundary tokens bypass/passed/monkey and JSON-parseable AF_DIAG_FAILURE lines.
        """
        import base64

        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        boundary = "bypass=visible passed=true monkey=1"
        cases = []
        for key in ("password", "api_key", "client_secret", "session", "webhook", "rclone_rc_pass"):
            cases.append(f"{key}=CANARY")
            cases.append(f'{key}="CANARY words"')
            cases.append(f"{key}='CANARY words'")
            cases.append(key + r'=\"CANARY words\"')
        for flag in ("password", "token", "api-key", "cookie", "session", "webhook"):
            for separator in ("=", " "):
                cases.append(f"--{flag}{separator}CANARY")
                cases.append(f'--{flag}{separator}"CANARY words"')
                cases.append(f"--{flag}{separator}'CANARY words'")
                cases.append(f"--{flag}{separator}" + r'\"CANARY words\"')
        for header in ("Cookie", "Set-Cookie", "Authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token"):
            cases.append('curl -H "' + header + r': secret=\"CANARY\""')
        cases.append(
            r'curl -H "Cookie: a=\"CANARY\"" -H "Set-Cookie: b=\"CANARY\"" '
            r'-H "Authorization: Bearer CANARY" -H "Proxy-Authorization: Basic CANARY" '
            r'-H "X-Api-Key: CANARY" -H "X-Auth-Token: CANARY"'
        )
        cases.append(
            r'{"command":"curl -H \"Cookie: sid=\\\"CANARY\\\"\" -H \"Authorization: Bearer CANARY\" -H \"X-Api-Key: CANARY\""}'
        )
        cases.append('{"password":{"nested":"CANARY"}}')
        cases.append('{"credentials":["CANARY"]}')
        cases.append(r'--user=\"user:CANARY words\"')
        for key in ("credentials", "credential", "bearer", "jwt_secret", "jwt-secret", "master_pass", "masterpass", "rclone_pass"):
            cases.append(key + r'=\"CANARY words\"')

        self.assertGreaterEqual(len(cases), 71)
        for case in cases:
            payload = f"{boundary} {case}"
            self.assertLessEqual(len(payload.encode()), 250, payload)
            self.assertIn("CANARY", payload)

        script = r"""
source "$COMMON"
if [[ "${MODE}" == fallback ]]; then
  command() {
    if [[ "${1:-}" == -v && "${2:-}" == python3 ]]; then
      return 1
    fi
    builtin command "$@"
  }
  python3() {
    printf 'PYTHON_INVOKED\n' >&2
    return 99
  }
fi
while IFS= read -r encoded || [[ -n "${encoded:-}" ]]; do
  [[ -n "${encoded:-}" ]] || continue
  summary=$(printf '%s' "$encoded" | base64 -d)
  af_write_failure_receipt 1 "$summary" "$summary" "$summary"
done
"""
        encoded_cases = "\n".join(base64.b64encode(f"{boundary} {case}".encode()).decode() for case in cases) + "\n"
        executed = 0
        for mode in ("python", "fallback"):
            result = subprocess.run(
                ["bash", "-c", script],
                input=encoded_cases,
                capture_output=True,
                text=True,
                env={**os.environ, "COMMON": str(common_script), "MODE": mode, "LOGFILE": str(self.root / "receipt.log")},
            )
            self.assertEqual(result.returncode, 0, f"{mode} stderr:\n{result.stderr}")
            self.assertNotIn("PYTHON_INVOKED", result.stderr)
            diag_lines = [line for line in result.stderr.splitlines() if "AF_DIAG_FAILURE=" in line]
            self.assertEqual(len(diag_lines), len(cases), f"{mode} emitted {len(diag_lines)} receipts for {len(cases)} cases")
            for case, line in zip(cases, diag_lines):
                executed += 1
                data = json.loads(line.split("AF_DIAG_FAILURE=", 1)[1])
                blob = json.dumps(data)
                self.assertNotIn("CANARY", blob, f"{mode} leaked secret for {case!r}: {blob}")
                self.assertNotIn("CANARY", line)
                self.assertIn("[REDACTED]", data["summary"], f"{mode} did not redact {case!r}: {data['summary']}")
                for field in ("stage", "category", "summary"):
                    self.assertIn(boundary, data[field], f"{mode} dropped boundary in {field} for {case!r}: {data[field]!r}")
                    self.assertNotIn("bypass=[REDACTED]", data[field])
                    self.assertNotIn("passed=[REDACTED]", data[field])
                    self.assertNotIn("monkey=[REDACTED]", data[field])
                self.assertEqual(data["exit_code"], 1)
        self.assertEqual(executed, len(cases) * 2)
        self.assertGreaterEqual(executed, 142)

    def test_wave25_failure_receipt_python_fallback_parity(self):
        """Python and no-Python receipt masking agree on the Wave 24 review corpus.

        Each scenario is written through af_write_failure_receipt with python3
        available and again with command -v python3 forced to fail. Receipts must
        stay valid JSON, drop W24_REVIEW_SENTINEL and 123456789, and match exactly.
        """
        import base64

        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        boundary = "bypass=visible passed=true monkey=1"
        sentinel = "W24_REVIEW_SENTINEL"
        cases = [
            f"password=[REDACTED]{sentinel}",
            f'password=" {sentinel}"',
            f'password=prefix" {sentinel}"',
            f'curl --user operator:" {sentinel}" --verbose',
            f"password='prefix\n{sentinel}'",
            f'password=[REDACTED]" {sentinel}"',
            f'{{"password":\n "{sentinel}"}}',
            f'{{"password"\r\n:\r\n "{sentinel}"}}',
            f'{{"credentials":\n{{"plain":"{sentinel}"}}}}',
            f'password=[{sentinel}',
            f'{{"credentials":{{"plain":"{sentinel}"',
            f'{{"credentials":{{"plain":]"{sentinel}"}}}}',
            f'"databasePasswordEncoded":"{sentinel}"',
            '"databasePass\\u0077ordEncoded":"' + sentinel + '"',
            '"databasePass\\\\u0077ordEncoded":"' + sentinel + '"',
            '{"databasePass\\u0077ordEncoded":"' + sentinel + '"}',
            '"databasePass\\u0077ordEncoded":{"plain":"' + sentinel + '"}',
            '"databasePass\\u0077ordEncoded":["' + sentinel + '"',
            f'Cookie: [REDACTED] sid={sentinel}',
            f'Authorization: [REDACTED] {sentinel}',
            f'X-Api-Key: [REDACTED] {sentinel}',
            f'curl --password {{"plain":"{sentinel}"',
            f"curl --password [REDACTED]{sentinel} --verbose",
            f"curl -uoperator:{sentinel} https://example.invalid",
            f"curl -fsSLu admin:{sentinel} https://example.invalid",
            f"curl -uadmin:{sentinel} https://example.invalid",
            '{"password":123456789}',
            '{"password":true}',
            '{"token":false}',
            '{"Credentials":{"plain":"' + sentinel + '"}}',
            '{"credentials":{"a":{"b":{"c":{"plain":"' + sentinel + '"}}}}}',
            f"password:'{sentinel}'",
            f'password: "{sentinel}"',
            f"password: {sentinel}",
            "curl --password prefix\\ " + sentinel + " --verbose",
            "curl --user operator:prefix\\ " + sentinel + " https://example.invalid",
            "password=prefix\\;" + sentinel,
            "curl --password $'" + sentinel + "' https://example.invalid",
            'curl --password prefix"' + sentinel + '" https://example.invalid',
            '{"command":"curl --password prefix\\\\ ' + sentinel + ' --verbose"}',
            '{"pass\\u0077ord":"' + sentinel + '"}',
            'curl -H \\"Cookie: sid=\\"' + sentinel + '\\"\\" https://example.invalid',
            'curl -H \\"Cookie: sid="' + sentinel + '\\" https://example.invalid',
            "password=already," + sentinel,
            'password=[REDACTED]"' + sentinel + '"',
            "curl -uadmin",
            "sort -u file",
        ]
        for escape_depth in (1, 2, 4, 8):
            fragment = '"databasePass' + "\\" * escape_depth + 'u0077ordEncoded":"' + sentinel + '"'
            for _ in range(3):
                cases.append(fragment)
                fragment = "AF_DIAG_FAILURE=" + json.dumps({"summary": fragment}, separators=(",", ":"))
        for value in ({"value": sentinel}, [sentinel]):
            fragment = '"databasePass\\\\\\\\u0077ordEncoded":' + json.dumps(value, separators=(",", ":"))
            for _ in range(3):
                cases.append(fragment)
                fragment = "AF_DIAG_FAILURE=" + json.dumps({"summary": fragment}, separators=(",", ":"))
        for key in ("Cookie", "Session", "Webhook", "Authorization", "Password"):
            for prefix, escape_depth in (("database", 0), ("x" * 125, 4)):
                encoded_key = key if not escape_depth else "\\" * escape_depth + f"u00{ord(key[0]):02x}" + key[1:]
                fragment = f'"{prefix}{encoded_key}Encoded":"{sentinel}"'
                for _ in range(3):
                    cases.append(fragment)
                    fragment = "AF_DIAG_FAILURE=" + json.dumps({"summary": fragment}, separators=(",", ":"))
        self.assertGreaterEqual(len(cases), 18)

        script = r"""
source "$COMMON"
if [[ "${MODE}" == fallback ]]; then
  command() {
    if [[ "${1:-}" == -v && "${2:-}" == python3 ]]; then
      return 1
    fi
    builtin command "$@"
  }
  python3() {
    printf 'PYTHON_INVOKED\n' >&2
    return 99
  }
fi
while IFS= read -r encoded || [[ -n "${encoded:-}" ]]; do
  [[ -n "${encoded:-}" ]] || continue
  summary=$(printf '%s' "$encoded" | base64 -d)
  af_write_failure_receipt 1 "$summary" "$summary" "$summary"
done
"""
        encoded_cases = "\n".join(
            base64.b64encode(f"{boundary} {case}".encode()).decode() for case in cases
        ) + "\n"
        receipts = {}
        for mode in ("python", "fallback"):
            result = subprocess.run(
                ["bash", "-c", script],
                input=encoded_cases,
                capture_output=True,
                text=True,
                env={**os.environ, "COMMON": str(common_script), "MODE": mode, "LOGFILE": str(self.root / "receipt.log")},
            )
            self.assertEqual(result.returncode, 0, f"{mode} stderr:\n{result.stderr}")
            self.assertNotIn("PYTHON_INVOKED", result.stderr)
            diag_lines = [line for line in result.stderr.splitlines() if "AF_DIAG_FAILURE=" in line]
            self.assertEqual(len(diag_lines), len(cases), f"{mode} emitted {len(diag_lines)} receipts")
            parsed = []
            for case, line in zip(cases, diag_lines):
                data = json.loads(line.split("AF_DIAG_FAILURE=", 1)[1])
                parsed.append(data)
                for field in ("stage", "category", "summary"):
                    self.assertNotIn(sentinel, data[field], f"{mode} leaked sentinel in {field} for {case!r}: {data[field]!r}")
                    self.assertNotIn("123456789", data[field], f"{mode} leaked number in {field} for {case!r}: {data[field]!r}")
                    self.assertIn(boundary, data[field], f"{mode} dropped boundary in {field} for {case!r}")
                    self.assertNotIn("bypass=[REDACTED]", data[field])
                    self.assertNotIn("passed=[REDACTED]", data[field])
                    self.assertNotIn("monkey=[REDACTED]", data[field])
                if case == "sort -u file":
                    self.assertIn("sort -u file", data["summary"])
                else:
                    self.assertIn("[REDACTED]", data["summary"], f"{mode} did not redact {case!r}: {data['summary']}")
                self.assertEqual(data["exit_code"], 1)
            receipts[mode] = diag_lines
        self.assertEqual(receipts["python"], receipts["fallback"])

    def test_failure_receipt_long_fields_remain_bounded_and_return_normally(self):
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        script = r'''
source "$COMMON"
set -euo pipefail
if [[ "$MODE" == fallback ]]; then
  command() {
    if [[ "${1:-}" == -v && "${2:-}" == python3 ]]; then return 1; fi
    builtin command "$@"
  }
fi
IFS= read -r summary
af_write_failure_receipt 7 "$summary" "$summary" "$summary"
printf 'AFTER_RECEIPT\n'
'''
        for mode, size in (("python", 140000), ("fallback", 8000), ("fallback", 40000)):
            with self.subTest(mode=mode, size=size):
                result = subprocess.run(
                    ["bash", "-c", script],
                    input='password=" LONG_FIELD_CANARY" ' + "x" * size + "\n",
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={**os.environ, "COMMON": str(common_script), "MODE": mode},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("AFTER_RECEIPT", result.stdout)
                receipts = [line for line in result.stderr.splitlines() if "AF_DIAG_FAILURE=" in line]
                self.assertEqual(len(receipts), 1, result.stderr)
                self.assertNotIn("LONG_FIELD_CANARY", result.stderr)
                data = json.loads(receipts[0].split("AF_DIAG_FAILURE=", 1)[1])
                self.assertEqual(data["exit_code"], 7)
                for field, limit in (("stage", 120), ("category", 120), ("summary", 300)):
                    self.assertLessEqual(len(data[field].encode()), limit)

    def test_failure_receipt_without_python_or_awk_fails_closed(self):
        common_script = self.root / "opt/AetherFlow/packages/common.sh"
        script = r"""
source "$COMMON"
command() {
  if [[ "${1:-}" == -v && ( "${2:-}" == python3 || "${2:-}" == awk ) ]]; then
    return 1
  fi
  builtin command "$@"
}
python3() { return 99; }
awk() { return 99; }
while IFS= read -r summary || [[ -n "$summary" ]]; do
  af_write_failure_receipt 1 "$summary" "$summary" "$summary"
done
"""
        sentinel = "W24_REVIEW_SENTINEL"
        cases = [
            "",
            "ordinary diagnostic without credentials",
            "password=prefix\\ " + sentinel,
            'curl --password prefix"' + sentinel + '" --verbose',
            '{"pass\\u0077ord":"' + sentinel + '"}',
            '{"credentials":' + '[' * 12 + '"' + sentinel + '"' + ']' * 12 + '}',
            'curl -H \\"Cookie: sid=\\"' + sentinel + '\\"\\"',
            "password=[REDACTED]" + sentinel,
        ]
        result = subprocess.run(
            ["bash", "-c", script],
            input="\n".join(cases) + "\n",
            capture_output=True,
            text=True,
            env={**os.environ, "COMMON": str(common_script)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        receipts = [line for line in result.stderr.splitlines() if "AF_DIAG_FAILURE=" in line]
        self.assertEqual(len(receipts), len(cases))
        for receipt in receipts:
            self.assertEqual(json.loads(receipt.split("AF_DIAG_FAILURE=", 1)[1]), {
                "stage": "[REDACTED]",
                "exit_code": 1,
                "category": "[REDACTED]",
                "summary": "[REDACTED]",
            })


if __name__ == "__main__":
    unittest.main()
