#!/usr/bin/env python3
"""Exercise Marketplace scripts with real files and mocked host commands."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/python3
import os, pathlib, shutil, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
command, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / 'commands').open('a') as log:
    log.write(command + ' ' + ' '.join(args) + '\n')
if command == 'dpkg':
    print('amd64')
elif command == 'curl':
    target = pathlib.Path(args[args.index('-o') + 1])
    if os.environ.get('FAIL_STAGE') == 'download':
        sys.exit(22)
    if any('nextcloud' in arg for arg in args):
        shutil.copyfile(root / 'nextcloud.zip', target)
    elif os.environ.get('FAIL_STAGE') == 'invalid-binary':
        target.write_text('not a binary')
    else:
        shutil.copyfile('/bin/true', target)
elif command == 'git':
    if args[0] == 'clone':
        target = pathlib.Path(args[-1])
        target.mkdir(parents=True, exist_ok=True)
        (target / 'new-code').write_text('new-code')
        if any('ruTorrent' in arg for arg in args):
            (target / 'conf').mkdir()
            (target / 'conf/config.php').write_text('<?php $scgi_port = 15000;')
        elif any('Organizr' in arg for arg in args):
            (target / 'api/config').mkdir(parents=True)
            (target / 'api/config/default.php').write_text('2.1.0')
    else:
        print('v2.1.0')
elif command == 'npm':
    if os.environ.get('FAIL_STAGE') == 'build':
        sys.exit(1)
elif command == 'mysql':
    if '-Nse' in args:
        if os.environ.get('TEST_DB_EXISTS') == '1':
            print('nextcloud')
    else:
        with (root / 'sql').open('a') as output:
            output.write(sys.stdin.read())
elif command == 'sudo':
    if 'upgrade' in args and os.environ.get('FAIL_STAGE') == 'upgrade':
        sys.exit(1)
elif command == 'systemctl':
    if args[0] == 'stop':
        (root / 'stopped').touch()
elif command == 'apache2ctl':
    if os.environ.get('FAIL_STAGE') == 'apache-config':
        sys.exit(1)
elif command == 'openssl':
    print('test-database-password')
elif command in ('apt-get', 'id', 'chown', 'a2enmod', 'a2ensite', 'a2dissite', 'apache2ctl', 'useradd', 'userdel', 'groupdel', 'su'):
    pass
else:
    raise RuntimeError((command, args))
'''


class MarketplaceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ('mock-bin', 'opt/AetherFlow/packages', 'opt/AetherFlow/logs',
                          'var/log/aetherflow', 'var/www', 'etc/systemd/system',
                          'etc/apache2/sites-available', 'usr/local/bin', 'srv', 'install'):
            (self.root / directory).mkdir(parents=True)
        for command in ('dpkg', 'curl', 'git', 'npm', 'mysql', 'sudo', 'systemctl',
                        'openssl', 'apt-get', 'id', 'chown', 'a2enmod', 'a2ensite', 'a2dissite', 'apache2ctl', 'useradd', 'userdel', 'groupdel', 'su'):
            path = self.root / 'mock-bin' / command
            path.write_text(MOCK)
            path.chmod(0o755)
        source = (ROOT / 'packages/common.sh').read_text()
        helpers = source[source.index('command_exists()'):source.index('lock_path()')]
        user_helper = source[source.index('purge_system_user()'):source.index('load_master_credentials()')]
        user_helper = user_helper.replace('/home/', str(self.root) + '/home/')
        common = '''set -euo pipefail
MASTER_USER=test-admin
MASTER_PASS=test-password
log_info() { printf '%s\\n' "$*" >> "$LOGFILE"; }
print_error() { printf '%s\\n' "$*" >&2; }
report_progress() { :; }
require_root() { :; }
ensure_node() { :; }
github_latest_tag() { printf '2.1.0\\n'; }
get_base_domain() { :; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
purge_systemd_unit() { :; }
'''
        self.common = self.root / 'opt/AetherFlow/packages/common.sh'
        self.common.write_text(common + helpers + user_helper)
        with zipfile.ZipFile(self.root / 'nextcloud.zip', 'w') as archive:
            archive.writestr('nextcloud/occ', 'new-code')
            archive.writestr('nextcloud/version.php', "<?php $OC_VersionString = '32.0.1';")
            archive.writestr('nextcloud/config/sample.php', 'new-default')

    def file(self, relative, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def run_script(self, package, action='install', **environment):
        source = (ROOT / f'packages/package/{action}/{action}package-{package}').read_text()
        for prefix in ('/opt/', '/var/', '/etc/', '/usr/local/', '/srv/', '/install'):
            source = source.replace(prefix, str(self.root) + prefix)
        script = self.root / 'script'
        script.write_text(source)
        return subprocess.run(['bash', str(script)], env={
            **os.environ, 'PATH': f"{self.root}/mock-bin:{os.environ['PATH']}",
            'TEST_ROOT': str(self.root), 'AETHERFLOW_APACHE_ROOT': str(self.root / 'etc/apache2'), 'AF_PACKAGE_ACTION': 'update', **environment,
        }, text=True, capture_output=True, timeout=30)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gitea_retains_database_and_applies_allocated_port(self):
        database = self.file('var/lib/gitea/data/gitea.db', 'existing repositories')
        config = self.file('etc/gitea/app.ini', 'RUN_USER = gitea\n[server]\nHTTP_PORT = 3002\nROOT_URL = https://git.example/\n[database]\nDB_TYPE = sqlite3\n')
        self.assert_success(self.run_script('gitea', AF_APP_PORT='17654'))
        self.assertEqual(database.read_text(), 'existing repositories')
        self.assertIn('HTTP_PORT = 17654', config.read_text())
        self.assertIn('ROOT_URL = https://git.example/', config.read_text())
        self.assertIn('gitea migrate', (self.root / 'commands').read_text())
        self.assertEqual((self.root / 'var/lib/gitea/.af-version').read_text(), '2.1.0\n')
        self.assertNotIn('--port 3002', (self.root / 'etc/systemd/system/gitea.service').read_text())

    def test_gitea_failed_download_retains_old_binary(self):
        binary = self.file('usr/local/bin/gitea', 'old executable')
        for failure in ('download', 'invalid-binary'):
            with self.subTest(failure=failure):
                result = self.run_script('gitea', FAIL_STAGE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(binary.read_text(), 'old executable')
                self.assertFalse((self.root / 'install/.gitea.lock').exists())

    def test_atomic_binary_replacement_while_old_inode_is_running(self):
        binary = self.root / 'sleep'
        shutil.copyfile('/bin/sleep', binary)
        binary.chmod(0o755)
        process = subprocess.Popen([str(binary), '30'])
        self.addCleanup(lambda: process.wait(timeout=5))
        self.addCleanup(process.terminate)
        old_inode = binary.stat().st_ino
        replacement = self.root / 'replacement'
        shutil.copyfile('/bin/true', replacement)
        result = subprocess.run(['bash', '-c', 'source "$1"; install_binary_atomic "$2" "$3"',
                                 'test', str(self.common), str(replacement), str(binary)],
                                env={**os.environ, 'LOGFILE': str(self.root / 'log')}, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(binary.stat().st_ino, old_inode)
        self.assertIsNone(process.poll())

    def test_uptime_kuma_update_keeps_monitors_and_history(self):
        database = self.file('opt/uptime-kuma/data/kuma.db', 'monitors and history')
        self.assert_success(self.run_script('uptimekuma', AF_APP_PORT='17700'))
        self.assertEqual(database.read_text(), 'monitors and history')
        backups = list((self.root / 'opt').glob('uptime-kuma.af-backup.*/app/data/kuma.db'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'monitors and history')
        self.assertIn('PORT=17700', (self.root / 'etc/systemd/system/uptime-kuma.service').read_text())

    def test_uptime_kuma_failed_build_keeps_existing_installation(self):
        database = self.file('opt/uptime-kuma/data/kuma.db', 'keep')
        code = self.file('opt/uptime-kuma/server.js', 'old code')
        result = self.run_script('uptimekuma', FAIL_STAGE='build')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database.read_text(), 'keep')
        self.assertEqual(code.read_text(), 'old code')
        self.assertFalse((self.root / 'install/.uptimekuma.lock').exists())

    def test_php_application_updates_keep_settings(self):
        for package, relative in [('rutorrent', 'share/settings/torrents.dat'),
                                  ('organizr', 'api/config/organizr.db')]:
            with self.subTest(package=package):
                data = self.file(f'var/www/{package}/{relative}', 'settings and history')
                self.assert_success(self.run_script(package, AF_APP_PORT='17701'))
                self.assertEqual(data.read_text(), 'settings and history')
                self.assertTrue((self.root / f'var/www/{package}/new-code').exists())
                self.assertIn('*:17701', (self.root / f'etc/apache2/sites-available/{package}.conf').read_text())

    def test_helper_cohort_removal_retains_data_unless_purge_is_explicit(self):
        for package in ('dispatcharr', 'duplicati', 'novnc'):
            for purge in (False, True):
                with self.subTest(package=package, purge=purge):
                    config = self.file(f'etc/{package}/retained-secret', 'keep-secret')
                    data = self.file(f'var/lib/{package}/retained-state', 'keep-state')
                    result = self.run_script(package, 'remove', DELETE_DATA=str(purge).lower())
                    self.assert_success(result)
                    self.assertEqual(config.exists(), not purge)
                    self.assertEqual(data.exists(), not purge)
                    if not purge:
                        self.assertEqual(config.read_text(), 'keep-secret')
                        self.assertEqual(data.read_text(), 'keep-state')

    def test_port_configuration_preserves_other_settings(self):
        cases = [
            ('yaml', 'port', 'general', 'general:\n  port: 6767\n  password: keep\nother:\n  port: 1234\n'),
            ('ini', 'port', 'server', '[server]\nport = 7474\nsecret = keep\n[other]\nport = 1234\n'),
            ('xml', 'Port', 'Config', '<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>'),
            ('json', 'main.port', '', '{"main":{"port":5055,"apiKey":"keep"},"other":1234}'),
        ]
        for kind, key, section, content in cases:
            with self.subTest(kind=kind):
                config = self.file('config', content)
                result = subprocess.run([
                    'bash', '-c', 'source "$1"; set_config_value "$2" "$3" "$4" "$5" "$6"',
                    'test', str(self.common), str(config), kind, key, '17800', section,
                ], env={**os.environ, 'LOGFILE': str(self.root / 'log')}, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                updated = config.read_text()
                self.assertIn('17800', updated)
                self.assertIn('keep', updated)
                if kind != 'xml':
                    self.assertIn('1234', updated)

    def test_nextcloud_uninstall_preserves_database_and_user_files(self):
        data = self.file('var/lib/nextcloud/data/user/document', 'keep')
        config = self.file('var/www/nextcloud/config/config.php', 'database credentials')
        self.assert_success(self.run_script('nextcloud', action='remove'))
        self.assertEqual(data.read_text(), 'keep')
        self.assertEqual(config.read_text(), 'database credentials')
        self.assertFalse((self.root / 'sql').exists())

    def test_nextcloud_update_preserves_configuration_and_files(self):
        config = self.file('var/www/nextcloud/config/config.php', '<?php /* existing DB credentials */')
        data = self.file('var/lib/nextcloud/data/user/document', 'user document')
        self.assert_success(self.run_script('nextcloud', AF_APP_PORT='17702'))
        self.assertEqual(config.read_text(), '<?php /* existing DB credentials */')
        self.assertEqual(data.read_text(), 'user document')
        commands = (self.root / 'commands').read_text()
        self.assertIn('occ upgrade', commands)
        self.assertNotIn('maintenance:install', commands)
        self.assertFalse((self.root / 'sql').exists())

    def test_nextcloud_refuses_reinitialization_without_existing_config(self):
        data = self.file('var/lib/nextcloud/data/user/document', 'keep')
        result = self.run_script('nextcloud', TEST_DB_EXISTS='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(data.read_text(), 'keep')
        self.assertFalse((self.root / 'sql').exists())

    def test_gitea_removal_keeps_data_unless_purge_is_explicit(self):
        data = self.file('var/lib/gitea/data/gitea.db', 'keep')
        config = self.file('etc/gitea/app.ini', 'keep config')
        self.assert_success(self.run_script('gitea', action='remove'))
        self.assertEqual(data.read_text(), 'keep')
        self.assertEqual(config.read_text(), 'keep config')
        self.assert_success(self.run_script('gitea', action='remove', DELETE_DATA='true'))
        self.assertFalse(data.exists())
        self.assertFalse(config.exists())


    def test_php_apps_never_restart_shared_apache(self):
        for app in ('rutorrent', 'organizr'):
            with self.subTest(app=app):
                self.assert_success(self.run_script(app, AF_APP_PORT='17899'))
                commands = (self.root / 'commands').read_text()
                self.assertNotIn('systemctl restart apache2', commands)
                self.assertIn('apache2ctl configtest', commands)
                listener = self.root / f'etc/apache2/conf-available/aetherflow-{app}-listen.conf'
                self.assertEqual(listener.read_text(), 'Listen 17899\n')

    def test_apache_config_failure_does_not_fallback_to_restart(self):
        result = self.run_script('organizr', FAIL_STAGE='apache-config')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl restart apache2', (self.root / 'commands').read_text())
        self.assertFalse((self.root / 'install/.organizr.lock').exists())

    def test_apache_removal_preserves_shared_listener_and_hardening(self):
        for app in ('nextcloud', 'rutorrent', 'organizr'):
            with self.subTest(app=app):
                ports = self.file('etc/apache2/ports.conf', 'Listen 80\nListen 8088\nListen 17899\n')
                sandbox = self.file('etc/systemd/system/apache2.service.d/10-aetherflow-sandbox.conf', 'shared hardening')
                owned = self.file(f'etc/apache2/conf-available/aetherflow-{app}-listen.conf', 'Listen 17899\n')
                self.assert_success(self.run_script(app, action='remove'))
                self.assertEqual(ports.read_text(), 'Listen 80\nListen 8088\nListen 17899\n')
                self.assertEqual(sandbox.read_text(), 'shared hardening')
                self.assertFalse(owned.exists())


if __name__ == '__main__':
    unittest.main()
