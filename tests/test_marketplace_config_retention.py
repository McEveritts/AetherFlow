"""Whole package scripts retain operator config under fake host commands."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from installer_test_helpers import replace_paths_once

ROOT = Path(__file__).resolve().parents[1]


class MarketplaceConfigRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('bin', 'opt/AetherFlow/packages', 'var/log/aetherflow', 'install',
                     'etc/systemd/system', 'etc/ssh', 'run/rtorrent'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'opt/AetherFlow/packages/common.sh').write_text('''set -euo pipefail
require_root() { :; }
log_info() { printf '%s\\n' "$*" >> "$LOGFILE"; }
log_error() { printf '%s\\n' "$*" >&2; }
report_progress() { printf '%s\\n' "$*" >> "$TEST_ROOT/progress"; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
''')
        for command in ('apt-get', 'systemctl', 'id', 'usermod', 'chown', 'useradd'):
            path = self.root / 'bin' / command
            path.write_text('''#!/bin/bash
printf '%s %s\n' "${0##*/}" "$*" >> "$TEST_ROOT/commands"
if [[ "${0##*/}" == systemctl && "$1" == "${FAIL_ACTIVATION:-}" ]]; then exit 73; fi
''')
            path.chmod(0o755)
        (self.root / 'etc/ssh/sshd_config').write_text('Port 2200\n')

    def file(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_installer(self, package, action='install', **environment):
        source = (ROOT / f'packages/package/install/installpackage-{package}').read_text()
        source = replace_paths_once(source, [(prefix, str(self.root) + prefix) for prefix in
            ('/opt/', '/var/', '/etc/', '/usr/', '/install', '/run/')])
        script = self.root / 'installer.sh'
        script.write_text(source)
        return subprocess.run(['bash', str(script)], capture_output=True, text=True, timeout=15,
            env={**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'],
                 'TEST_ROOT': str(self.root), 'AF_PACKAGE_ACTION': action, **environment})

    def assert_preserved(self, package, name, content, action):
        config = self.file(name, content)
        inode = config.stat().st_ino
        if action == 'update':
            self.file(f'install/.{package}.lock', 'prior-install')
        result = self.run_installer(package, action)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text(), content)
        self.assertEqual(config.stat().st_ino, inode)
        self.assertTrue((self.root / f'install/.{package}.lock').exists())
        self.assertIn('100 ', (self.root / 'progress').read_text())

    def test_rtorrent_update_retains_paths_port_and_throttles(self):
        self.assert_preserved('rtorrent', 'var/lib/rtorrent/.rtorrent.rc',
            'directory.default.set = /srv/retained\nnetwork.scgi.open_port = 127.0.0.1:15123\n'
            'throttle.global_down.max_rate.set = 777\nschedule2 = custom,5,5,load.start=/srv/watch/*.torrent\n', 'update')

    def test_rtorrent_reinstall_retains_configuration_without_installed_marker(self):
        self.assert_preserved('rtorrent', 'var/lib/rtorrent/.rtorrent.rc',
            'directory.default.set = /srv/retained\nnetwork.port_range.set = 55123-55123\n', 'install')

    def test_fail2ban_update_retains_local_jails_and_policy(self):
        self.assert_preserved('fail2ban', 'etc/fail2ban/jail.local',
            '[DEFAULT]\nbantime = 7d\n[sshd]\nenabled = false\nport = 2200\n'
            '[custom-application]\nenabled = true\nfilter = custom-application\n', 'update')
        self.assertFalse((self.root / 'etc/fail2ban/jail.d/10-aetherflow.local').exists())

    def test_fail2ban_reinstall_retains_jail_local(self):
        self.assert_preserved('fail2ban', 'etc/fail2ban/jail.local',
            '[DEFAULT]\nbantime = 14d\n[custom-application]\nenabled = true\n', 'install')

    def test_fail2ban_existing_local_fragment_is_not_overridden_by_bootstrap(self):
        self.assert_preserved('fail2ban', 'etc/fail2ban/jail.d/99-operator.local',
            '[sshd]\nenabled = false\n[custom]\nenabled = true\n', 'install')
        self.assertFalse((self.root / 'etc/fail2ban/jail.local').exists())
        self.assertFalse((self.root / 'etc/fail2ban/jail.d/10-aetherflow.local').exists())

    def test_fail2ban_existing_managed_fragment_is_retained(self):
        self.assert_preserved('fail2ban', 'etc/fail2ban/jail.d/10-aetherflow.local',
            '[DEFAULT]\nbantime = 3d\n[sshd]\nport = 2222\n', 'update')

    def test_fresh_fail2ban_uses_a_separate_default_fragment(self):
        result = self.run_installer('fail2ban')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc/fail2ban/jail.local').exists())
        fragment = self.root / 'etc/fail2ban/jail.d/10-aetherflow.local'
        self.assertIn('port    = 2200,ssh', fragment.read_text())
        self.assertIn('enabled = true', fragment.read_text())

    def test_fresh_rtorrent_creates_defaults_only_once(self):
        result = self.run_installer('rtorrent')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.root / 'var/lib/rtorrent/.rtorrent.rc'
        self.assertIn('network.scgi.open_port = 127.0.0.1:15000', config.read_text())
        config.write_text('directory.default.set = /srv/new\n')
        result = self.run_installer('rtorrent', 'update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text(), 'directory.default.set = /srv/new\n')

    def test_failed_activation_preserves_operator_configuration(self):
        for package, name in [('rtorrent', 'var/lib/rtorrent/.rtorrent.rc'),
                              ('fail2ban', 'etc/fail2ban/jail.local')]:
            with self.subTest(package=package):
                config = self.file(name, 'retained-policy\n')
                result = self.run_installer(package, 'update', FAIL_ACTIVATION='enable')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(config.read_text(), 'retained-policy\n')
                self.assertFalse((self.root / f'install/.{package}.lock').exists())


if __name__ == '__main__':
    unittest.main()
