import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, common_functions, replace_paths_once


FAKE_COMMAND = '''#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['TEST_ROOT'])
program = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with (root / 'commands').open('a') as output:
    output.write(program + ' ' + ' '.join(arguments) + '\\n')
operation = arguments[0] if program == 'systemctl' and arguments else program
if program == 'apt-get' and 'autoremove' in arguments:
    operation = 'autoremove'
if operation == 'show':
    print(os.environ.get('UNIT_STATE', ''))
    sys.exit(int(os.environ.get('STATE_EXIT', '1')))
if operation == os.environ.get('FAIL_OPERATION') and (not os.environ.get('FAIL_UNIT') or os.environ['FAIL_UNIT'] in arguments):
    sys.exit(1)
if program == 'su' and os.environ.get('FAIL_SQL') and os.environ['FAIL_SQL'] in ' '.join(arguments):
    sys.exit(42)
if program == 'getent':
    sys.exit(int(os.environ.get('ACCOUNT_EXIT', '0')))
if program == 'pgrep':
    sys.exit(int(os.environ.get('PROCESS_EXIT', '1')))
if program in ('runuser', 'mysql'):
    with (root / 'sql').open('a') as output:
        output.write(sys.stdin.read())
if program == 'rm':
    for argument in arguments:
        if not argument.startswith('-') and not argument.startswith(str(root) + '/'):
            raise RuntimeError('refusing non-fixture removal: ' + argument)
    if os.environ.get('FAIL_PATH') in arguments:
        sys.exit(1)
    sys.exit(subprocess.run(['/bin/rm', *arguments]).returncode)
'''


class MarketplaceTeardownTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / 'fake-bin'
        self.bin.mkdir()
        for command in ('systemctl', 'apt-get', 'userdel', 'groupdel', 'getent', 'id', 'runuser', 'rm', 'killall', 'pgrep', 'a2dissite', 'apache2ctl', 'mysql', 'su'):
            path = self.bin / command
            path.write_text(FAKE_COMMAND)
            path.chmod(0o755)
        self.file('install/.syncthing.lock', 'installed')
        self.file('etc/systemd/system/syncthing.service', 'unit')
        self.file('var/lib/syncthing/config.xml', 'configuration')

    def file(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def rebase(self, source):
        return replace_paths_once(source, [(prefix, str(self.root) + prefix) for prefix in
                                          ('/etc/', '/var/', '/opt/', '/home/', '/install/', '/usr/local/', '/usr/bin/', '/run/', '/srv/', '/data')])

    def run_remove(self, package='syncthing', **environment):
        names = ('purge_systemd_unit', 'purge_system_user', 'remove_apache_app_listener', 'command_exists', 'purge_app_archive_backups', 'safe_rm_rf')
        source = (ROOT / 'packages/common.sh').read_text()
        names += tuple(name for name in ('systemd_unit_inactive', 'stop_systemd_unit', 'purge_systemd_units')
                       if f'\n{name}() ' in source)
        helpers = self.rebase(common_functions(*names))
        common = '''set -euo pipefail
require_root() { :; }
log_info() { printf '%s\\n' "$*"; }
print_info() { printf '%s\\n' "$*"; }
print_error() { printf '%s\\n' "$*" >&2; }
report_progress() { printf '[PROGRESS:%s] %s\\n' "$1" "$2"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
'''
        self.file('packages/common.sh', common + helpers)
        self.file('packages/youtube-common.sh', self.rebase((ROOT / 'packages/youtube-common.sh').read_text()))
        script = self.file(f'packages/package/remove/removepackage-{package}', self.rebase(
            (ROOT / f'packages/package/remove/removepackage-{package}').read_text()))
        return subprocess.run(['bash', str(script)], env={
            **os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'TEST_ROOT': str(self.root),
            **environment,
        }, capture_output=True, text=True, timeout=15)

    def test_dispatcharr_sql_failure_retains_recovery_material_and_never_completes(self):
        for statement in ('DROP DATABASE', 'DROP USER'):
            with self.subTest(statement=statement):
                self.file('install/.dispatcharr.lock', 'installed')
                self.file('etc/dispatcharr/db_pass', 'synthetic-db-password')
                self.file('var/lib/dispatcharr/backup', 'retained-data')
                ownership = self.file('var/lib/dispatcharr/.aetherflow-data-owner', f'aetherflow-dispatcharr-data-v1:{self.root}/var/lib/dispatcharr\n')
                ownership.chmod(0o600)
                ownership.parent.chmod(0o755)
                result = self.run_remove(package='dispatcharr', DELETE_DATA='true', FAIL_SQL=statement)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in ('install/.dispatcharr.lock', 'etc/dispatcharr/db_pass', 'var/lib/dispatcharr/backup'):
                    self.assertTrue((self.root / path).is_file(), path)
                self.assertNotIn('PROGRESS:100', result.stdout)

    def test_dispatcharr_only_purges_data_after_both_sql_steps_succeed(self):
        for purge in ('false', 'true'):
            with self.subTest(purge=purge):
                self.file('install/.dispatcharr.lock', 'installed')
                self.file('etc/dispatcharr/db_pass', 'synthetic-db-password')
                self.file('var/lib/dispatcharr/backup', 'retained-data')
                ownership = self.file('var/lib/dispatcharr/.aetherflow-data-owner', f'aetherflow-dispatcharr-data-v1:{self.root}/var/lib/dispatcharr\n')
                ownership.chmod(0o600)
                ownership.parent.chmod(0o755)
                (self.root / 'commands').write_text('')
                result = self.run_remove(package='dispatcharr', DELETE_DATA=purge)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'install/.dispatcharr.lock').exists())
                self.assertEqual((self.root / 'etc/dispatcharr/db_pass').exists(), purge == 'false')
                calls = (self.root / 'commands').read_text()
                if purge == 'true':
                    command_lines = calls.splitlines()
                    removal_index = next(index for index, command in enumerate(command_lines) if command.split()[:2] == ['rm', '-rf'] and str(self.root / 'etc/dispatcharr') in command.split()[2:])
                    for statement in ('DROP DATABASE', 'DROP USER'):
                        self.assertLess(next(index for index, command in enumerate(command_lines) if statement in command), removal_index)
                else:
                    self.assertNotIn('DROP DATABASE', calls)
                    self.assertNotIn('DROP USER', calls)
                self.assertIn('PROGRESS:100', result.stdout)

    def test_failed_stop_blocks_ordinary_remove_and_explicit_purge(self):
        for purge in ('false', 'true'):
            with self.subTest(purge=purge):
                result = self.run_remove(DELETE_DATA=purge, FAIL_OPERATION='stop')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in ('install/.syncthing.lock', 'etc/systemd/system/syncthing.service',
                             'var/lib/syncthing/config.xml'):
                    self.assertTrue((self.root / path).is_file(), path)
                commands = (self.root / 'commands').read_text()
                self.assertNotIn('apt-get ', commands)
                self.assertNotIn('userdel ', commands)
                self.assertNotIn('PROGRESS:100', result.stdout)

    def test_required_command_failures_retain_marker_and_never_complete(self):
        for operation in ('disable', 'reset-failed', 'apt-get', 'autoremove', 'userdel', 'groupdel', 'daemon-reload'):
            with self.subTest(operation=operation):
                self.file('install/.syncthing.lock', 'installed')
                self.file('etc/systemd/system/syncthing.service', 'unit')
                self.file('var/lib/syncthing/config.xml', 'data')
                result = self.run_remove(DELETE_DATA='true', FAIL_OPERATION=operation)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((self.root / 'install/.syncthing.lock').is_file())
                self.assertNotIn('PROGRESS:100', result.stdout)
                if operation not in ('userdel', 'groupdel'):
                    self.assertTrue((self.root / 'var/lib/syncthing/config.xml').is_file())

    def test_verified_inactive_and_absent_states_allow_idempotent_removal(self):
        for load_state in ('loaded', 'not-found'):
            with self.subTest(load_state=load_state):
                self.file('install/.syncthing.lock', 'installed')
                result = self.run_remove(FAIL_OPERATION='stop', UNIT_STATE=f'LoadState={load_state}\nActiveState=inactive', STATE_EXIT='0')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'install/.syncthing.lock').exists())
                self.assertTrue((self.root / 'var/lib/syncthing/config.xml').is_file())

    def test_absent_unit_allows_failed_disable_or_reset_without_masking_real_errors(self):
        for operation in ('disable', 'reset-failed'):
            with self.subTest(operation=operation):
                self.file('install/.syncthing.lock', 'installed')
                result = self.run_remove(FAIL_OPERATION=operation, UNIT_STATE='LoadState=not-found\nActiveState=inactive', STATE_EXIT='0')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_successful_remove_and_explicit_purge_clear_marker_last(self):
        for purge in ('false', 'true'):
            with self.subTest(purge=purge):
                self.file('install/.syncthing.lock', 'installed')
                self.file('var/lib/syncthing/config.xml', 'configuration')
                result = self.run_remove(DELETE_DATA=purge)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / 'install/.syncthing.lock').exists())
                self.assertEqual((self.root / 'var/lib/syncthing/config.xml').exists(), purge == 'false')
                self.assertIn('PROGRESS:100', result.stdout)
                commands = (self.root / 'commands').read_text().splitlines()
                self.assertEqual(commands[-1], f'rm -f {self.root}/install/.syncthing.lock')

    def test_active_failed_or_unreadable_state_rejects_stop_failure(self):
        for active_state, state_exit in (('active', '0'), ('failed', '0'), ('inactive', '1')):
            with self.subTest(active_state=active_state, state_exit=state_exit):
                result = self.run_remove(DELETE_DATA='true', FAIL_OPERATION='stop', UNIT_STATE=f'LoadState=loaded\nActiveState={active_state}', STATE_EXIT=state_exit)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((self.root / 'install/.syncthing.lock').is_file())
                self.assertTrue((self.root / 'var/lib/syncthing/config.xml').is_file())

    def test_disabled_state_cannot_be_inferred_from_inactivity(self):
        result = self.run_remove(DELETE_DATA='true', FAIL_OPERATION='disable', UNIT_STATE='LoadState=loaded\nActiveState=inactive', STATE_EXIT='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'etc/systemd/system/syncthing.service').is_file())
        self.assertTrue((self.root / 'var/lib/syncthing/config.xml').is_file())

    def test_unit_unlink_failure_blocks_purge(self):
        result = self.run_remove(DELETE_DATA='true', FAIL_PATH=str(self.root / 'etc/systemd/system/syncthing.service'))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'var/lib/syncthing/config.xml').is_file())
        self.assertTrue((self.root / 'install/.syncthing.lock').is_file())

    def test_absent_account_is_allowed_but_lookup_error_is_not(self):
        for account_exit, expected_status in (('1', 1), ('2', 0)):
            with self.subTest(account_exit=account_exit):
                self.file('install/.syncthing.lock', 'installed')
                self.file('var/lib/syncthing/config.xml', 'configuration')
                result = self.run_remove(DELETE_DATA='true', ACCOUNT_EXIT=account_exit)
                self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)

    def test_rtorrent_processes_must_be_proven_absent_after_kill(self):
        for process_exit in ('0', '2', '1'):
            with self.subTest(process_exit=process_exit):
                self.file('install/.rtorrent.lock', 'installed')
                self.file('var/lib/rtorrent/sentinel', 'data')
                result = self.run_remove('rtorrent', DELETE_DATA='true', FAIL_OPERATION='killall', PROCESS_EXIT=process_exit)
                if process_exit == '1':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse((self.root / 'install/.rtorrent.lock').exists())
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((self.root / 'install/.rtorrent.lock').is_file())
                    self.assertTrue((self.root / 'var/lib/rtorrent/sentinel').is_file())

    def test_final_marker_unlink_failure_is_not_success(self):
        result = self.run_remove(FAIL_PATH=str(self.root / 'install/.syncthing.lock'))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'install/.syncthing.lock').is_file())
        self.assertNotIn('PROGRESS:100', result.stdout)

    def test_multi_unit_callers_stop_every_unit_before_unlinking(self):
        for package, failed_unit, units in (
            ('rclone', 'rclone.service', ('rclone-vfs', 'rclone')),
            ('xrdp', 'xrdp-sesman.service', ('xrdp', 'xrdp-sesman')),
        ):
            with self.subTest(package=package):
                self.file(f'install/.{package}.lock', 'installed')
                self.file(f'var/lib/{package}/sentinel', 'data')
                for unit in units:
                    self.file(f'etc/systemd/system/{unit}.service', 'unit')
                result = self.run_remove(package, DELETE_DATA='true', FAIL_OPERATION='stop', FAIL_UNIT=failed_unit)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                for unit in units:
                    self.assertTrue((self.root / f'etc/systemd/system/{unit}.service').is_file())
                self.assertTrue((self.root / f'install/.{package}.lock').is_file())
                self.assertTrue((self.root / f'var/lib/{package}/sentinel').is_file())

    def test_youtube_remove_preserves_and_explicit_purge_removes_owned_state(self):
        unrelated = self.file('var/lib/unrelated/sentinel', 'unrelated data')
        for package in ('piped', 'invidious'):
            with self.subTest(package=package):
                paths = (f'opt/{package}/source', f'etc/{package}/config', f'var/lib/{package}/sentinel')
                for path in paths:
                    self.file(path, 'retained')
                self.file(f'install/.{package}.lock', 'installed')
                result = self.run_remove(package)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in paths:
                    self.assertTrue((self.root / path).is_file())
                self.assertFalse((self.root / 'sql').exists())
                self.file(f'install/.{package}.lock', 'installed')
                result = self.run_remove(package, DELETE_DATA='true')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in paths:
                    self.assertFalse((self.root / path).exists())
                self.assertFalse((self.root / f'install/.{package}.lock').exists())
                sql = self.root / 'sql'
                self.assertIn("DROP DATABASE IF EXISTS %I", sql.read_text())
                self.assertIn("DROP ROLE IF EXISTS %I", sql.read_text())
                sql.unlink()
                self.assertTrue(unrelated.is_file())

    def test_youtube_failed_companion_stop_or_database_cleanup_blocks_purge(self):
        for package, companion in (('piped', 'af-piped-proxy.service'), ('invidious', 'af-invidious-companion.service')):
            for operation in ('stop', 'runuser'):
                with self.subTest(package=package, operation=operation):
                    self.file(f'install/.{package}.lock', 'installed')
                    self.file(f'var/lib/{package}/sentinel', 'data')
                    result = self.run_remove(package, DELETE_DATA='true', FAIL_OPERATION=operation, FAIL_UNIT=companion if operation == 'stop' else '')
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((self.root / f'install/.{package}.lock').is_file())
                    self.assertTrue((self.root / f'var/lib/{package}/sentinel').is_file())

    def prepare_shared_web_app(self, package):
        self.file(f'install/.{package}.lock', 'installed')
        self.file(f'var/www/{package}/sentinel', 'application data')
        self.file(f'etc/apache2/sites-available/{package}.conf', 'VirtualHost')
        self.file(f'etc/apache2/sites-enabled/{package}.conf', 'VirtualHost')
        if package == 'nextcloud':
            self.file('var/lib/nextcloud/sentinel', 'database-dependent data')
            self.file('opt/AetherFlow/logs/nextcloud_credentials.txt', 'credentials')

    def test_shared_apache_reload_failure_blocks_purge_and_sql(self):
        for package in ('nextcloud', 'rutorrent', 'organizr'):
            for operation in ('reload', 'apache2ctl'):
                with self.subTest(package=package, operation=operation):
                    self.prepare_shared_web_app(package)
                    (self.root / 'sql').unlink(missing_ok=True)
                    result = self.run_remove(package, DELETE_DATA='true', FAIL_OPERATION=operation)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((self.root / f'var/www/{package}/sentinel').is_file())
                    self.assertTrue((self.root / f'install/.{package}.lock').is_file())
                    self.assertNotIn('PROGRESS:100', result.stdout)
                    self.assertFalse((self.root / 'sql').exists())

    def test_nextcloud_database_failure_blocks_remaining_purge(self):
        self.prepare_shared_web_app('nextcloud')
        result = self.run_remove('nextcloud', DELETE_DATA='true', FAIL_OPERATION='mysql')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in ('var/www/nextcloud/sentinel', 'var/lib/nextcloud/sentinel',
                     'opt/AetherFlow/logs/nextcloud_credentials.txt', 'install/.nextcloud.lock'):
            self.assertTrue((self.root / path).is_file(), path)
        self.assertNotIn('PROGRESS:100', result.stdout)

    def test_shared_apache_detaches_before_data_and_keeps_shared_server(self):
        unrelated = self.file('var/www/unrelated/sentinel', 'other app data')
        for package in ('nextcloud', 'rutorrent', 'organizr'):
            for purge in ('false', 'true'):
                with self.subTest(package=package, purge=purge):
                    self.prepare_shared_web_app(package)
                    if package == 'rutorrent':
                        self.file('var/www/rutorrent/share/sentinel', 'retained ruTorrent state')
                    (self.root / 'commands').unlink(missing_ok=True)
                    (self.root / 'sql').unlink(missing_ok=True)
                    result = self.run_remove(package, DELETE_DATA=purge)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    commands = (self.root / 'commands').read_text().splitlines()
                    reload_index = commands.index('systemctl reload apache2')
                    if purge == 'true':
                        data_index = next(i for i, line in enumerate(commands) if line.startswith('rm -rf ') and f'/var/www/{package}' in line)
                        self.assertLess(reload_index, data_index)
                        if package == 'nextcloud':
                            sql_index = next(i for i, line in enumerate(commands) if line.startswith('mysql '))
                            self.assertLess(reload_index, sql_index)
                            self.assertLess(sql_index, data_index)
                    self.assertEqual((self.root / f'var/www/{package}/sentinel').exists(), purge == 'false' and package != 'rutorrent')
                    if package == 'rutorrent':
                        self.assertEqual((self.root / 'var/www/rutorrent/share/sentinel').exists(), purge == 'false')
                    self.assertFalse((self.root / f'install/.{package}.lock').exists())
                    self.assertEqual(commands[-1], f'rm -f {self.root}/install/.{package}.lock')
                    self.assertFalse(any(line.startswith('systemctl stop ') for line in commands))
                    self.assertTrue(unrelated.is_file())

    def test_shipped_remove_callers_do_not_ignore_required_teardown_errors(self):
        for script in (ROOT / 'packages/package/remove').glob('*'):
            source = script.read_text()
            with self.subTest(script=script.name):
                if 'purge_systemd_unit ' in source or 'youtube_remove ' in source:
                    self.assertIn('set -euo pipefail', source)
                for line in source.splitlines():
                    if line.startswith(('purge_systemd_unit ', 'systemctl daemon-reload', 'DEBIAN_FRONTEND=')):
                        self.assertNotIn('|| true', line)


if __name__ == '__main__':
    unittest.main()
