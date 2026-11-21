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


if __name__ == "__main__":
    unittest.main()
