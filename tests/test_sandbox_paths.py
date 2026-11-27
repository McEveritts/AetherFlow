import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires Linux shell tools")
class SandboxPathTests(unittest.TestCase):
    def run_functions(self, commands):
        source = (ROOT / "packages/system/af-systemd-sandbox").read_text()
        functions = source[source.index("usage() {"):source.index('command_name="${1:-}"')]
        result = subprocess.run(
            ["bash", "-c", "set -euo pipefail\n" + functions + "\n" + commands],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_master_and_service_paths_are_resolved_separately(self):
        output = self.run_functions("""
resolve_master_user() { printf 'media_owner\\n'; }
expand_rw_path '-/home/{{MASTER_USER}}/Google/Media/Music Import' sonarr /var/lib/sonarr
expand_rw_path '-{{SERVICE_HOME}}/{{SERVICE_USER}}' sonarr /var/lib/sonarr
""")
        self.assertEqual(output, [
            '"-/home/media_owner/Google/Media/Music Import"',
            '-/var/lib/sonarr/sonarr',
        ])

    def test_timer_does_not_receive_a_service_sandbox(self):
        output = self.run_functions("""
remove_sandbox_dropin() { printf 'removed:%s\\n' "$1"; }
apply_sandbox_dropin native recyclarr.timer /var/lib/recyclarr
""")
        self.assertEqual(output, ['removed:recyclarr.timer'])

    def test_socket_and_novnc_session_are_exempt_from_sandbox_and_not_restarted(self):
        output = self.run_functions("""
log_info() { :; }
remove_sandbox_dropin() { printf 'removed:%s\\n' "$1"; }
is_exempt_unit novnc-session.service && printf 'exempt:novnc-session.service\\n'
is_exempt_unit novnc-xvnc.service && printf 'exempt:novnc-xvnc.service\\n'
is_exempt_unit librespeed.service || printf 'sandboxed:librespeed.service\\n'
apply_sandbox_dropin native librespeed.socket /var/www/librespeed
apply_sandbox_dropin native novnc-session.service /var/lib/novnc
""")
        self.assertEqual(
            output,
            [
                'exempt:novnc-session.service',
                'exempt:novnc-xvnc.service',
                'sandboxed:librespeed.service',
                'removed:librespeed.socket',
                'removed:novnc-session.service',
            ],
        )

    def test_common_sh_stops_sockets_and_timers_before_workers(self):
        common_sh = ROOT / "packages/common.sh"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            calls_file = tmp_path / "systemctl.calls"
            log_file = tmp_path / "install.log"
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                f"""#!/bin/bash
if [[ "${{1:-}}" == "is-active" ]]; then
    printf 'inactive\\n'
    exit 3
fi
if [[ "${{1:-}}" == "show" ]]; then
    printf 'LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\nUnitFileState=enabled\\n'
    exit 0
fi
if [[ "${{1:-}}" == "stop" ]]; then
    printf 'systemctl %s\\n' "$*" >> "{calls_file}"
fi
exit 0
"""
            )
            fake_systemctl.chmod(0o755)
            script = f"""
set -euo pipefail
export LOCK_DIR="{tmp_path}/install"
export LOGFILE=/dev/null
export AETHERFLOW_DISABLE_HOST_ENV_FILE=1
source "{common_sh}"
export PATH="{fake_bin}:$PATH"
stop_systemd_unit librespeed librespeed.socket
printf -- '---\\n' >> "{calls_file}"
quiesce_services_for_rollback recyclarr recyclarr.timer librespeed librespeed.socket
"""
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = calls_file.read_text().splitlines()
            sep = lines.index("---")
            stop_lines = lines[:sep]
            quiesce_lines = lines[sep + 1:]
            self.assertEqual(
                stop_lines,
                [
                    "systemctl stop -- librespeed.socket",
                    "systemctl stop -- librespeed",
                ],
            )
            self.assertEqual(
                quiesce_lines,
                [
                    "systemctl stop -- recyclarr.timer",
                    "systemctl stop -- librespeed.socket",
                    "systemctl stop -- recyclarr",
                    "systemctl stop -- librespeed",
                ],
            )

    def test_master_credentials_support_current_and_legacy_formats(self):
        for content in ['{"username":"media_owner","password":"secret"}', 'username=media_owner\npassword=secret', 'media_owner:secret']:
            with self.subTest(content=content), tempfile.NamedTemporaryFile(mode="w") as credentials:
                credentials.write(content)
                credentials.flush()
                output = self.run_functions(
                    'AETHERFLOW_MASTER_CREDS_FILE="' + credentials.name + '"\nresolve_master_user'
                )
                self.assertEqual(output, ['media_owner'])

    def _run_standalone_sandbox(self, tmp_path, args, fake_systemctl_body):
        source = (ROOT / "packages/system/af-systemd-sandbox").read_text()
        source = source.replace("/etc/systemd/system", str(tmp_path / "etc/systemd/system"))
        script_dir = tmp_path / "packages/system"
        script_dir.mkdir(parents=True, exist_ok=True)
        (tmp_path / "packages/common.sh").write_text(
            'log_info() { printf "[INFO] %s\\n" "$*"; }\n'
            'log_error() { printf "[ERROR] %s\\n" "$*" >&2; }\n'
        )
        script = script_dir / "af-systemd-sandbox"
        script.write_text(source)
        script.chmod(0o755)

        fake_bin = tmp_path / "bin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_systemctl = fake_bin / "systemctl"
        fake_systemctl.write_text("#!/bin/bash\n" + fake_systemctl_body)
        fake_systemctl.chmod(0o755)
        fake_getent = fake_bin / "getent"
        fake_getent.write_text("#!/bin/bash\necho 'filebot:x:999:999::/var/lib/filebot:/usr/sbin/nologin'\n")
        fake_getent.chmod(0o755)

        env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
        return subprocess.run(
            ["bash", str(script), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    def test_standalone_sandbox_propagates_restart_and_reload_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # 1. Failing restart on active unit must fail non-zero
            res = self._run_standalone_sandbox(
                tmp_path,
                ["apply", "--profile", "java", "--rw", "/var/lib/filebot", "filebot.service"],
                """
case "${1:-}" in
    show) echo "filebot"; exit 0 ;;
    daemon-reload) exit 0 ;;
    is-active) exit 0 ;;
    restart) echo "Job for filebot.service failed" >&2; exit 1 ;;
esac
exit 0
""",
            )
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("Failed to restart active unit filebot.service", res.stderr)

            # 2. Restart exits 0 but Type=simple unit immediately dies (inactive on post-restart check)
            state_file = tmp_path / "restarted"
            res = self._run_standalone_sandbox(
                tmp_path,
                ["apply", "--profile", "java", "--rw", "/var/lib/filebot", "filebot.service"],
                f"""
case "${{1:-}}" in
    show)
        if [[ "$*" == "show -p Type --value -- filebot.service" ]]; then
            echo "simple"
        elif [[ "$*" == *"Type"* ]]; then
            exit 2
        else
            echo "filebot"
        fi
        exit 0
        ;;
    daemon-reload) exit 0 ;;
    is-active)
        if [[ -f "{state_file}" ]]; then exit 3; fi
        exit 0
        ;;
    restart)
        touch "{state_file}"
        exit 0
        ;;
esac
exit 0
""",
            )
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("not active after sandbox restart", res.stderr)

            # 3. Inactive unit (exit 3) is not restarted and succeeds
            restart_marker = tmp_path / "should_not_restart"
            res = self._run_standalone_sandbox(
                tmp_path,
                ["apply", "--profile", "java", "--rw", "/var/lib/filebot", "filebot.service"],
                f"""
case "${{1:-}}" in
    show) echo "filebot"; exit 0 ;;
    daemon-reload) exit 0 ;;
    is-active) exit 3 ;;
    restart) touch "{restart_marker}"; exit 1 ;;
esac
exit 0
""",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertFalse(restart_marker.exists())

            # 4. Active Type=oneshot unit that exits cleanly after restart succeeds
            oneshot_state = tmp_path / "oneshot_done"
            res = self._run_standalone_sandbox(
                tmp_path,
                ["apply", "--profile", "dotnet", "--rw", "/var/lib/recyclarr", "recyclarr.service"],
                f"""
case "${{1:-}}" in
    show)
        if [[ "$*" == "show -p Type --value -- recyclarr.service" ]]; then
            echo "oneshot"
        elif [[ "$*" == *"Type"* ]]; then
            exit 2
        else
            echo "recyclarr"
        fi
        exit 0
        ;;
    daemon-reload) exit 0 ;;
    is-active)
        if [[ -f "{oneshot_state}" ]]; then exit 3; fi
        exit 0
        ;;
    restart)
        touch "{oneshot_state}"
        exit 0
        ;;
esac
exit 0
""",
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            # 5. systemctl is-active bus error (exit 1) fails closed
            res = self._run_standalone_sandbox(
                tmp_path,
                ["apply", "--profile", "java", "--rw", "/var/lib/filebot", "filebot.service"],
                """
case "${1:-}" in
    show) echo "filebot"; exit 0 ;;
    daemon-reload) exit 0 ;;
    is-active) exit 1 ;;
esac
exit 0
""",
            )
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("Unable to inspect active state", res.stderr)

            # 6. Failing daemon-reload fails closed on both apply and remove
            for cmd_args in (
                ["apply", "--profile", "java", "--rw", "/var/lib/filebot", "filebot.service"],
                ["remove", "filebot.service"],
            ):
                res = self._run_standalone_sandbox(
                    tmp_path,
                    cmd_args,
                    """
case "${1:-}" in
    show) echo "filebot"; exit 0 ;;
    daemon-reload) echo "Failed to reload daemon" >&2; exit 1 ;;
esac
exit 0
""",
                )
                self.assertNotEqual(res.returncode, 0, f"{cmd_args}: {res.stdout}{res.stderr}")
                self.assertIn("Failed to reload systemd daemon", res.stderr)

    def test_profile_block_uses_0002_for_shared_media_units_and_0077_for_isolated_units(self):
        media_out = "\n".join(
            self.run_functions("profile_block native qbittorrent.service")
        )
        self.assertIn("UMask=0002", media_out)
        self.assertNotIn("UMask=0077", media_out)

        arr_out = "\n".join(
            self.run_functions("profile_block dotnet sonarr.service")
        )
        self.assertIn("UMask=0002", arr_out)

        isolated_out = "\n".join(
            self.run_functions("profile_block native librespeed.service")
        )
        self.assertIn("UMask=0077", isolated_out)
        self.assertNotIn("UMask=0002", isolated_out)


if __name__ == "__main__":
    unittest.main()
