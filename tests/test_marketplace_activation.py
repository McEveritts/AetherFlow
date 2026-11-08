"""Real Emby installer activation with disposable paths and fake host commands."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_marketplace_lifecycle as lifecycle


class MarketplaceActivationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.MarketplaceLifecycleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        with self.fixture.common.open('a') as common:
            common.write('''\nseed_jellyfin_master_user() { :; }
report_progress() { printf '%s %s\\n' "$1" "$2" >> "$TEST_ROOT/progress"; }
''')
        systemctl = self.root / 'mock-bin/systemctl'
        systemctl.write_text('''#!/usr/bin/python3
import os,pathlib,sys
root=pathlib.Path(os.environ['TEST_ROOT'])
with (root/'activation-commands').open('a') as log: log.write(' '.join(sys.argv[1:])+'\\n')
if sys.argv[1] == os.environ.get('FAIL_ACTIVATION'): sys.exit(73)
operation = sys.argv[1]
units = [argument for argument in sys.argv[2:] if not argument.startswith('-')]
if operation == 'is-active':
    sys.exit(0 if all((root / ('active-' + unit)).exists() for unit in units) else 3)
if operation in ('start', 'restart'):
    for unit in units: (root / ('active-' + unit)).touch()
if operation == 'stop':
    for unit in units: (root / ('active-' + unit)).unlink(missing_ok=True)
''')
        systemctl.chmod(0o755)

    def test_required_restart_failure_is_not_install_success(self):
        result = self.fixture.run_script('emby', FAIL_ACTIVATION='restart')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / 'install/.emby.lock').exists())
        self.assertNotIn('100 ', (self.root / 'progress').read_text())

    def test_required_restart_failure_preserves_existing_install_marker(self):
        marker = self.fixture.file('install/.emby.lock', 'existing-receipt')
        result = self.fixture.run_script('emby', FAIL_ACTIVATION='restart')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'existing-receipt')
        self.assertNotIn('100 ', (self.root / 'progress').read_text())

    def test_enable_failure_never_reaches_restart_or_completion(self):
        result = self.fixture.run_script('emby', FAIL_ACTIVATION='enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('restart', (self.root / 'activation-commands').read_text())
        self.assertFalse((self.root / 'install/.emby.lock').exists())

    def test_successful_activation_keeps_configured_port_and_marks_completion(self):
        result = self.fixture.run_script('emby', AF_APP_PORT='18097')
        self.fixture.assert_success(result)
        config = (self.root / 'var/lib/emby/config/system.xml').read_text()
        self.assertIn('<HttpServerPortNumber>18097</HttpServerPortNumber>', config)
        self.assertIn('<PublicPort>18097</PublicPort>', config)
        self.assertTrue((self.root / 'install/.emby.lock').exists())
        self.assertIn('100 ', (self.root / 'progress').read_text())


if __name__ == '__main__':
    unittest.main()
