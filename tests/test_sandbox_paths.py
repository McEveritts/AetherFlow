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
