import json
import os
from pathlib import Path
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import test_marketplace_catalog_lifecycle_matrix as lifecycle_fixture
from test_marketplace_catalog_lifecycle_matrix import InstallerFixture, ROOT


class RetainedNavidromeTests(unittest.TestCase):
    shell = lifecycle_fixture.R15SharedInstallerRegressions.shell

    def test_regression_control_detects_the_previous_hardcoded_database_snapshot(self):
        with InstallerFixture('navidrome') as fixture:
            database = fixture.file('srv/navidrome-data/navidrome.db', 'operator-schema-v1\n')
            fixture.file('var/lib/navidrome/navidrome.toml', f'DataFolder = "{database.parent}"\nPort = 4533\n')
            fixture.file('opt/navidrome/navidrome', '#!/bin/sh\nexit 0\n').chmod(0o755)
            fixture.file('opt/navidrome/.af-version', '1.0.0\n')
            fixture.file('etc/systemd/system/navidrome.service', '[Service]\nExecStart=/old/navidrome\n')
            fixture.file('active-navidrome.service', '')
            relative = 'packages/package/install/installpackage-navidrome'
            source = (ROOT / relative).read_text()
            target = '"." "$ND_DATABASE" ""'
            self.assertEqual(source.count(target), 1)
            counterfactual = source.replace(target, '"." "/var/lib/navidrome/navidrome.db" ""')
            fixture.file('counterfactual-source/' + relative, counterfactual)
            with patch.object(lifecycle_fixture, 'ROOT', fixture.root / 'counterfactual-source'):
                result = fixture.run('update', AF_FIXTURE_VERSION='2.2.0', AF_FIXTURE_FAILURE='readiness',
                                     AF_FIXTURE_MIGRATION_STATE='srv/navidrome-data/navidrome.db',
                                     AF_FIXTURE_MIGRATION_RUNTIME='opt/navidrome/navidrome')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(database.read_text(), 'schema-v2-migrated\n')
            self.assertEqual((fixture.root / 'opt/navidrome/.af-version').read_text(), '1.0.0\n')
            self.assertTrue((fixture.root / 'active-navidrome.service').exists())

    def test_configured_database_is_restored_before_old_runtime_restart(self):
        for action in ('update', 'reinstall'):
            with self.subTest(action=action), InstallerFixture('navidrome') as fixture:
                database = fixture.file('srv/navidrome-data/navidrome.db', '')
                with sqlite3.connect(database) as connection:
                    connection.execute('CREATE TABLE operator_data (value TEXT)')
                    connection.execute("INSERT INTO operator_data VALUES ('retained')")
                database.chmod(0o640)
                sidecars = [fixture.file('srv/navidrome-data/navidrome.db' + suffix, suffix)
                            for suffix in ('-wal', '-shm')]
                config = fixture.file('var/lib/navidrome/navidrome.toml',
                                      f'DataFolder = "{database.parent}"\nPort = 4533\n')
                original = database.read_bytes()
                fixture.file('opt/navidrome/navidrome', '#!/bin/sh\nexit 0\n').chmod(0o755)
                fixture.file('opt/navidrome/.af-version', '1.0.0\n')
                fixture.file('etc/systemd/system/navidrome.service', '[Service]\nExecStart=/old/navidrome\n')
                fixture.file('install/.navidrome.lock', 'installed\n')
                fixture.file('active-navidrome.service', '')
                result = fixture.run(action, AF_FIXTURE_VERSION='2.2.0', AF_FIXTURE_FAILURE='readiness',
                                     AF_FIXTURE_MIGRATION_STATE='srv/navidrome-data/navidrome.db',
                                     AF_FIXTURE_MIGRATION_RUNTIME='opt/navidrome/navidrome')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(database.read_bytes(), original)
                self.assertEqual(database.stat().st_mode & 0o777, 0o640)
                self.assertEqual([path.read_text() for path in sidecars], ['-wal', '-shm'])
                for path in sidecars:
                    path.unlink()
                with sqlite3.connect(database) as connection:
                    self.assertEqual(connection.execute('SELECT value FROM operator_data').fetchone(), ('retained',))
                    self.assertEqual(connection.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                self.assertEqual((fixture.root / 'opt/navidrome/.af-version').read_text(), '1.0.0\n')
                self.assertTrue((fixture.root / 'active-navidrome.service').exists())
                migrations = [json.loads(line) for line in (fixture.root / 'migration-writes.jsonl').read_text().splitlines()]
                self.assertEqual(migrations, [['systemctl', 'restart', 'navidrome']])
                self.assertIn(str(database.parent), config.read_text())
                recovery = next(fixture.root.glob('opt/navidrome.af-backup.*/recovery.json'))
                self.assertIn(str(database), json.loads(recovery.read_text())['state_paths'])

    def test_datafolder_parser_handles_supported_toml_and_relative_paths(self):
        with InstallerFixture('navidrome') as fixture:
            config = fixture.root / 'var/lib/navidrome/navidrome.toml'
            cases = (
                ('', fixture.root / 'var/lib/navidrome/navidrome.db'),
                ('datafolder = "operator-data"\n', fixture.root / 'var/lib/navidrome/operator-data/navidrome.db'),
                (f"DataFolder = '{fixture.root}/srv/music data' # retained\n",
                 fixture.root / 'srv/music data/navidrome.db'),
            )
            for text, expected in cases:
                with self.subTest(text=text):
                    fixture.file('var/lib/navidrome/navidrome.toml', text)
                    result = self.shell(fixture, 'read_navidrome_database_path "$AF_FIXTURE_ROOT/var/lib/navidrome/navidrome.toml"')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), str(expected))
            config.unlink()
            result = self.shell(fixture, 'read_navidrome_database_path "$AF_FIXTURE_ROOT/var/lib/navidrome/navidrome.toml"')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), str(fixture.root / 'var/lib/navidrome/navidrome.db'))

    def test_invalid_or_aliased_database_is_rejected_before_runtime_or_service_mutation(self):
        for failure in ('config-link', 'parent-link', 'database-link', 'wal-link', 'database-hardlink',
                        'invalid-toml', 'ambiguous-folder', 'invalid-folder'):
            with self.subTest(failure=failure), InstallerFixture('navidrome') as fixture:
                database = fixture.file('srv/navidrome-data/navidrome.db', 'operator data\n')
                config = fixture.file('var/lib/navidrome/navidrome.toml', f'DataFolder = "{database.parent}"\n')
                if failure == 'config-link':
                    target = fixture.file('srv/operator.toml', config.read_text())
                    config.unlink()
                    config.symlink_to(target)
                elif failure == 'parent-link':
                    alias = fixture.root / 'srv/aliased-data'
                    alias.symlink_to(database.parent, target_is_directory=True)
                    config.write_text(f'DataFolder = "{alias}"\n')
                elif failure in ('database-link', 'wal-link'):
                    target = fixture.file('srv/operator-target', 'unrelated\n')
                    link = database if failure == 'database-link' else Path(str(database) + '-wal')
                    link.unlink(missing_ok=True)
                    link.symlink_to(target)
                elif failure == 'database-hardlink':
                    os.link(database, fixture.root / 'srv/database-alias')
                else:
                    config.write_text({'invalid-toml': 'DataFolder = [',
                                       'ambiguous-folder': 'DataFolder = "one"\ndatafolder = "two"\n',
                                       'invalid-folder': 'DataFolder = 123\n'}[failure])
                result = fixture.run('update')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                commands = fixture.root / 'commands.jsonl'
                invoked = [json.loads(line)[0] for line in commands.read_text().splitlines()] if commands.exists() else []
                self.assertNotIn('systemctl', invoked)
                self.assertNotIn('useradd', invoked)
                self.assertFalse((fixture.root / 'opt/navidrome').exists())
                self.assertEqual(database.read_text(), 'unrelated\n' if failure == 'database-link' else 'operator data\n')


class SuccessfulBackupRetentionTests(unittest.TestCase):
    shell = lifecycle_fixture.R15SharedInstallerRegressions.shell

    def test_only_success_marked_private_backups_are_pruned(self):
        for app in ('jellyseerr', 'maintainerr'):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                parent = fixture.root / 'var/backups'
                retained = []
                marker_content = f'aetherflow completed backup v1\n{app}\n'
                for suffix in ('failed', 'legacy', 'linked', 'public', 'pendng', 'badmrk', 'hlinks'):
                    backup = parent / f'aetherflow-{app}.{suffix}'
                    backup.mkdir(mode=0o700)
                    fixture.file(str(backup.relative_to(fixture.root)) + '/operator-data', suffix)
                    retained.append(backup)
                    if suffix == 'linked':
                        target = fixture.file('srv/operator-marker', marker_content)
                        (backup / '.af-successful-backup').symlink_to(target)
                    elif suffix not in ('failed', 'legacy'):
                        marker = fixture.file(str(backup.relative_to(fixture.root)) + '/.af-successful-backup', marker_content)
                        marker.chmod(0o600)
                        if suffix == 'public':
                            backup.chmod(0o755)
                        elif suffix == 'pendng':
                            (backup / '.af-archive-pending').touch()
                        elif suffix == 'badmrk':
                            marker.write_text('not a completion receipt\n')
                        elif suffix == 'hlinks':
                            os.link(marker, fixture.root / 'srv/marker-hardlink')
                for index in range(4):
                    relative = f'var/backups/aetherflow-{app}.ok{index:04d}'
                    backup = fixture.root / relative
                    backup.mkdir(mode=0o700)
                    fixture.file(relative + '/state/complete', '')
                    fixture.file(relative + '/app/runtime', f'previous-{index}\n')
                    result = self.shell(fixture, f'retain_successful_app_backups {app} "$AF_FIXTURE_ROOT/{relative}"')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                successful = sorted(path.name for path in parent.glob(f'aetherflow-{app}.ok*'))
                self.assertEqual(successful, [f'aetherflow-{app}.ok0002', f'aetherflow-{app}.ok0003'])
                for path in retained:
                    self.assertEqual((path / 'operator-data').read_text(), path.suffix[1:])
                current = parent / f'aetherflow-{app}.ok0003'
                self.assertEqual((current / '.af-successful-backup').read_text(), marker_content)
                self.assertEqual((current / '.af-successful-backup').stat().st_mode & 0o777, 0o600)

    def test_incomplete_current_backup_cannot_trigger_pruning(self):
        with InstallerFixture('jellyseerr') as fixture:
            backup = fixture.root / 'var/backups/aetherflow-jellyseerr.currnt'
            backup.mkdir(mode=0o700)
            result = self.shell(fixture, 'retain_successful_app_backups jellyseerr "$AF_FIXTURE_ROOT/var/backups/aetherflow-jellyseerr.currnt"')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((backup / '.af-successful-backup').exists())


class InteractiveRemovalTests(unittest.TestCase):
    def test_normal_remove_never_inherits_ambient_purge_or_lifecycle_action(self):
        source = (ROOT / 'packages/system/af').read_text()
        start = source.index('function _remove() {')
        end = source.index('\nfunction _cli()', start)
        with InstallerFixture('threadfin') as fixture:
            fixture.file('install/.threadfin.lock', '')
            sentinel = fixture.file('operator-data', 'retained\n')
            fixture.file('remove/removepackage-threadfin',
                         'printf "%s|%s|%s\\n" "$AF_LIFECYCLE_ACTION" "$AF_PACKAGE_ACTION" "$DELETE_DATA" > "$AF_FIXTURE_ROOT/remove-contract"\n'
                         'if [[ "$DELETE_DATA" == true ]]; then rm -f "$AF_FIXTURE_ROOT/operator-data"; fi\n')
            program = '''set -euo pipefail
package_root() { printf '%s/remove\\n' "$AF_FIXTURE_ROOT"; }
package_script() { printf '%s/remove/removepackage-%s\\n' "$AF_FIXTURE_ROOT" "$2"; }
whiptail() { printf 'threadfin\\n' >&2; }
_function() { :; }
'''
            program += fixture.rewrite(source[start:end]) + '\n_remove\n'
            for purge in ('true', 'false'):
                with self.subTest(ambient_purge=purge):
                    result = subprocess.run(['bash', '-euc', program], text=True, capture_output=True, timeout=15,
                                            env={**os.environ, 'AF_FIXTURE_ROOT': str(fixture.root),
                                                 'DELETE_DATA': purge, 'AF_LIFECYCLE_ACTION': 'purge', 'AF_PACKAGE_ACTION': 'purge'})
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((fixture.root / 'remove-contract').read_text(), 'remove|remove|false\n')
                    self.assertEqual(sentinel.read_text(), 'retained\n')


if __name__ == '__main__':
    unittest.main()
