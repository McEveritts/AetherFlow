import hashlib
import json
import os
from pathlib import Path
import sqlite3
import unittest

from test_marketplace_catalog_lifecycle_matrix import InstallerFixture


MYSQL_RECORDER = r'''#!/usr/bin/python3 -B
import json, os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
query = arguments[arguments.index('-Nse') + 1] if '-Nse' in arguments else arguments[arguments.index('-e') + 1] if '-e' in arguments else sys.stdin.read()
with (root / 'mysql-queries.jsonl').open('a') as output:
    output.write(json.dumps({'arguments': arguments, 'query': query}) + '\n')
if os.environ.get('AF_TEST_EXISTING_MYSQL_USER') == '1' and 'FROM mysql.user' in query:
    print('nextclouduser')
if os.environ.get('AF_TEST_FAIL_CREATE_USER') == '1' and query.startswith('CREATE USER'):
    sys.exit(86)
if os.environ.get('AF_TEST_FAIL_PURGE') == '1' and query.startswith('DROP'):
    sys.exit(87)
'''


class NextcloudPurgeTests(unittest.TestCase):
    config_path = 'var/www/nextcloud/config/config.php'
    ownership_path = 'opt/AetherFlow/logs/nextcloud_database_owner.json'

    def configure(self, fixture, **changes):
        values = {
            'dbtype': 'mysql', 'dbname': 'operator_nc', 'dbhost': 'localhost',
            'dbuser': 'operator_nc_user', 'dbpassword': 'private-fixture-password',
            'datadirectory': str(fixture.root / 'var/lib/nextcloud/data'),
        }
        values.update(changes)
        contents = '<?php $CONFIG = [' + ', '.join(json.dumps(key) + ' => ' + json.dumps(value)
                                                  for key, value in values.items()) + '];\n'
        config = fixture.file(self.config_path, contents)
        fixture.file('install/.nextcloud.lock', 'installed\n')
        fixture.file('var/lib/nextcloud/data/operator-document', 'operator-data\n')
        fixture.file('etc/apache2/sites-available/nextcloud.conf', 'operator-vhost\n')
        fixture.file('mock-bin/mysql', MYSQL_RECORDER).chmod(0o755)
        return config, values

    def ownership(self, fixture, values):
        contents = {
            'format': 1, 'application': 'nextcloud', 'backend': values['dbtype'],
            'database': values['dbname'], 'host': values['dbhost'], 'username': values['dbuser'],
            'password_sha256': hashlib.sha256(values['dbpassword'].encode()).hexdigest(),
            'data_directory': values['datadirectory'],
        }
        marker = fixture.file(self.ownership_path, json.dumps(contents) + '\n')
        marker.parent.chmod(0o700)
        marker.chmod(0o600)
        return marker

    def queries(self, fixture):
        path = fixture.root / 'mysql-queries.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_refused(self, fixture, config):
        previous_config = config.read_bytes()
        previous_vhost = (fixture.root / 'etc/apache2/sites-available/nextcloud.conf').read_bytes()
        result = fixture.run('uninstall', DELETE_DATA='true')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('command not found', result.stderr)
        self.assertNotIn('SyntaxError', result.stderr)
        self.assertEqual(config.read_bytes(), previous_config)
        self.assertEqual((fixture.root / 'etc/apache2/sites-available/nextcloud.conf').read_bytes(), previous_vhost)
        self.assertEqual((fixture.root / 'var/lib/nextcloud/data/operator-document').read_text(), 'operator-data\n')
        self.assertTrue(fixture.lock.exists())
        self.assertEqual(self.queries(fixture), [])
        return result

    def test_unproven_local_and_remote_sql_databases_refuse_before_detachment(self):
        for backend in ('mysql', 'mariadb', 'postgres', 'pgsql'):
            for host in ('localhost', 'operator-db.invalid:5432'):
                with self.subTest(backend=backend, host=host), InstallerFixture('nextcloud') as fixture:
                    config, values = self.configure(fixture, dbtype=backend, dbhost=host)
                    self.assert_refused(fixture, config)

    def test_verified_purge_targets_only_the_recorded_database_and_account(self):
        with InstallerFixture('nextcloud') as fixture:
            config, values = self.configure(fixture)
            marker = self.ownership(fixture, values)
            unrelated = fixture.file('unrelated-mysql-nextcloud', 'unrelated-database\n')
            result = fixture.run('uninstall', DELETE_DATA='true')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            queries = self.queries(fixture)
            self.assertEqual(len(queries), 1)
            self.assertIn('DROP DATABASE IF EXISTS operator_nc;', queries[0]['query'])
            self.assertIn("DROP USER IF EXISTS 'operator_nc_user'@'localhost';", queries[0]['query'])
            self.assertNotIn('DROP DATABASE IF EXISTS nextcloud;', queries[0]['query'])
            self.assertIn('--protocol=SOCKET', queries[0]['arguments'])
            self.assertNotIn(values['dbpassword'], json.dumps(queries))
            self.assertFalse(config.exists())
            self.assertFalse(marker.exists())
            self.assertFalse(fixture.lock.exists())
            self.assertEqual(unrelated.read_text(), 'unrelated-database\n')

    def test_stale_or_retargeted_ownership_refuses_without_sql(self):
        for setting, value in (('dbname', 'another_database'), ('dbhost', 'remote.invalid'),
                               ('dbuser', 'another_user'), ('dbpassword', 'changed-password'),
                               ('dbtype', 'pgsql')):
            with self.subTest(setting=setting), InstallerFixture('nextcloud') as fixture:
                config, values = self.configure(fixture)
                marker = self.ownership(fixture, values)
                config, changed = self.configure(fixture, **{setting: value})
                previous_marker = marker.read_bytes()
                self.assert_refused(fixture, config)
                self.assertEqual(marker.read_bytes(), previous_marker)

    def test_receipt_and_parent_link_or_permission_attacks_refuse(self):
        for variant in ('symlink', 'hardlink', 'public-file', 'public-parent', 'parent-symlink'):
            with self.subTest(variant=variant), InstallerFixture('nextcloud') as fixture:
                config, values = self.configure(fixture)
                marker = self.ownership(fixture, values)
                external = fixture.file('operator-marker', marker.read_text())
                external.chmod(0o600)
                if variant in ('symlink', 'hardlink'):
                    marker.unlink()
                    if variant == 'symlink':
                        marker.symlink_to(external)
                    else:
                        os.link(external, marker)
                elif variant == 'public-file':
                    marker.chmod(0o644)
                elif variant == 'public-parent':
                    marker.parent.chmod(0o777)
                else:
                    directory = fixture.root / 'operator-logs'
                    marker.parent.rename(directory)
                    marker.parent.symlink_to(directory, target_is_directory=True)
                original = external.read_bytes()
                self.assert_refused(fixture, config)
                self.assertEqual(external.read_bytes(), original)

    def test_sql_failure_retains_configuration_data_receipt_and_install_marker(self):
        with InstallerFixture('nextcloud') as fixture:
            config, values = self.configure(fixture)
            marker = self.ownership(fixture, values)
            previous_config, previous_marker = config.read_bytes(), marker.read_bytes()
            result = fixture.run('uninstall', DELETE_DATA='true', AF_TEST_FAIL_PURGE='1')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(config.read_bytes(), previous_config)
            self.assertEqual(marker.read_bytes(), previous_marker)
            self.assertTrue(fixture.lock.exists())
            self.assertEqual((fixture.root / 'var/lib/nextcloud/data/operator-document').read_text(), 'operator-data\n')
            self.assertEqual(len(self.queries(fixture)), 1)

    def test_sqlite_purge_never_calls_mysql_or_touches_an_unrelated_database(self):
        with InstallerFixture('nextcloud') as fixture:
            config, values = self.configure(fixture, dbtype='sqlite3')
            database = fixture.root / 'var/lib/nextcloud/data/owncloud.db'
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE operator_data (value TEXT)')
            unrelated = fixture.file('unrelated-mysql-nextcloud', 'unrelated-database\n')
            result = fixture.run('uninstall', DELETE_DATA='true')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(database.exists())
            self.assertFalse(config.exists())
            self.assertEqual(self.queries(fixture), [])
            self.assertEqual(unrelated.read_text(), 'unrelated-database\n')

    def test_external_sqlite_storage_is_not_adopted_or_deleted(self):
        with InstallerFixture('nextcloud') as fixture:
            external = fixture.file('srv/operator-storage/owncloud.db', 'operator-data\n')
            config, values = self.configure(fixture, dbtype='sqlite3', datadirectory=str(external.parent))
            self.assert_refused(fixture, config)
            self.assertEqual(external.read_text(), 'operator-data\n')

    def test_missing_ambiguous_or_dynamic_configuration_fails_closed(self):
        for variant in ('missing', 'ambiguous', 'dynamic'):
            with self.subTest(variant=variant), InstallerFixture('nextcloud') as fixture:
                config, values = self.configure(fixture)
                self.ownership(fixture, values)
                if variant == 'missing':
                    config.unlink()
                    result = fixture.run('uninstall', DELETE_DATA='true')
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(fixture.lock.exists())
                    self.assertEqual(self.queries(fixture), [])
                    self.assertTrue((fixture.root / 'var/lib/nextcloud/data/operator-document').is_file())
                else:
                    if variant == 'ambiguous':
                        fixture.file('var/www/html/nextcloud/config/config.php', config.read_text())
                    else:
                        config.write_text('<?php $CONFIG = require "/operator/config.php";\n')
                    self.assert_refused(fixture, config)

    def test_retained_uninstall_does_not_require_or_delete_database_ownership(self):
        with InstallerFixture('nextcloud') as fixture:
            config, values = self.configure(fixture)
            marker = self.ownership(fixture, values)
            previous = config.read_bytes(), marker.read_bytes()
            result = fixture.run('uninstall', DELETE_DATA='false')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((config.read_bytes(), marker.read_bytes()), previous)
            self.assertEqual(self.queries(fixture), [])

    def test_fresh_install_records_provenance_and_allows_verified_purge(self):
        with InstallerFixture('nextcloud') as fixture:
            result = fixture.run('install')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            marker = fixture.root / self.ownership_path
            contents = json.loads(marker.read_text())
            self.assertEqual(contents['application'], 'nextcloud')
            self.assertEqual(contents['database'], 'nextcloud')
            self.assertEqual(contents['username'], 'nextclouduser')
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('dbpassword', contents)
            for query in self.queries(fixture):
                self.assertIn('--host=localhost', query['arguments'])
                self.assertIn('--protocol=SOCKET', query['arguments'])
            result = fixture.run('uninstall', DELETE_DATA='true')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse((fixture.root / 'mysql-nextcloud-present').exists())

    def test_fresh_install_does_not_adopt_or_reset_an_existing_account(self):
        with InstallerFixture('nextcloud') as fixture:
            fixture.file('mock-bin/mysql', MYSQL_RECORDER).chmod(0o755)
            result = fixture.run('install', AF_TEST_EXISTING_MYSQL_USER='1')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(fixture.lock.exists())
            self.assertFalse((fixture.root / self.ownership_path).exists())
            self.assertTrue(all('CREATE' not in item['query'] and 'ALTER' not in item['query']
                                for item in self.queries(fixture)))

    def test_failed_account_creation_does_not_drop_the_uncreated_account(self):
        with InstallerFixture('nextcloud') as fixture:
            fixture.file('mock-bin/mysql', MYSQL_RECORDER).chmod(0o755)
            result = fixture.run('install', AF_TEST_FAIL_CREATE_USER='1')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            queries = [item['query'] for item in self.queries(fixture)]
            self.assertTrue(any(item.startswith('DROP DATABASE IF EXISTS nextcloud;') for item in queries))
            self.assertTrue(all('DROP USER' not in item for item in queries))
            self.assertFalse((fixture.root / self.ownership_path).exists())
            self.assertFalse(fixture.lock.exists())


if __name__ == '__main__':
    unittest.main()
