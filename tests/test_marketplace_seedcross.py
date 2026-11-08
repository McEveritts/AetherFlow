"""Real SeedCross scripts with synthetic Git/venv tools and real SQLite state.

Django, pip, systemd, and authentication calls are mocked, not vendor execution.
"""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_marketplace_servarr import ArchiveFixture, HOST_COMMAND

MANAGE = '''import os, pathlib, sqlite3, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
assert os.environ['DJANGO_SETTINGS_MODULE'] == 'af_settings'
if sys.argv[1] == 'migrate':
    database = root / 'var/lib/seedcross/db/db.sqlite3'
    assert database.parent.is_dir()
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE IF NOT EXISTS fixture_migration (value TEXT)')
        connection.execute("INSERT INTO fixture_migration VALUES ('migration ran')")
    if os.environ.get('FAIL_STAGE') == 'migration': raise SystemExit(75)
elif sys.argv[1] == 'collectstatic':
    static = root / 'var/lib/seedcross/static'
    static.mkdir(parents=True, exist_ok=True)
    (static / 'fixture.css').write_text('fixture static assets')
elif sys.argv[1] == 'shell':
    (root / 'account-bootstrap.py').write_text(sys.stdin.read())
else: raise RuntimeError(sys.argv)
'''

VENV = '''#!/usr/bin/python3
import os, pathlib, subprocess, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
if sys.argv[1:3] == ['-m', 'pip']:
    if os.environ.get('FAIL_STAGE') == 'pip': raise SystemExit(76)
    raise SystemExit(0)
raise SystemExit(subprocess.run(['/usr/bin/python3', *sys.argv[1:]], input=sys.stdin.read(), text=True).returncode)
'''


class SeedCrossLifecycleTests(ArchiveFixture):
    def setUp(self):
        super().setUp()
        self.file('repository/manage.py', MANAGE)
        self.file('repository/requirements.txt', 'synthetic fixture dependencies\n')
        self.file('repository/csui/__init__.py', '')
        self.file('repository/csui/settings.py',
                  'SECRET_KEY = "django-insecure-fixture-not-a-production-secret"\n'
                  'DEBUG = True\nALLOWED_HOSTS = ["*"]\nMIDDLEWARE = []\nDATABASES = {"default": {"NAME": "db/db.sqlite3"}}\n')
        self.file('bin/fixture-venv-python', VENV).chmod(0o755)
        python = self.file('bin/python3', '''#!/usr/bin/python3
import os, pathlib, subprocess, sys
if sys.argv[1:3] == ['-m', 'venv']:
    directory = pathlib.Path(sys.argv[3]) / 'bin'
    directory.mkdir(parents=True)
    (directory / 'python').symlink_to(pathlib.Path(os.environ['TEST_ROOT']) / 'bin/fixture-venv-python')
    raise SystemExit(0)
raise SystemExit(subprocess.run(['/usr/bin/python3', *sys.argv[1:]], input=sys.stdin.read(), text=True).returncode)
''')
        python.chmod(0o755)
        shim = HOST_COMMAND.replace("elif command == 'getent':", '''elif command == 'git':
    if 'clone' in arguments:
        if failure == 'clone': sys.exit(128)
        shutil.copytree(root / 'repository', pathlib.Path(arguments[-1]), dirs_exist_ok=True)
        (pathlib.Path(arguments[-1]) / '.git').mkdir()
    elif 'rev-parse' in arguments: print('fixture-commit')
    else: raise RuntimeError(arguments)
elif command == 'su':
    call = arguments[arguments.index('-c') + 1]
    assert str(root) in call
    sys.exit(subprocess.run(['bash', '-c', call], input=sys.stdin.read(), text=True).returncode)
elif command == 'getent':''')
        for command in ('git', 'su'):
            self.file('bin/' + command, shim).chmod(0o755)
        common = self.root / 'opt/AetherFlow/packages/common.sh'
        with common.open('a') as output:
            output.write('\nload_master_credentials() { :; }\nget_base_domain() { printf "%s" "${TEST_DOMAIN-fixture.example}"; }\n')

    def legacy(self):
        database = self.root / 'opt/seedcross/db/db.sqlite3'
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE operator_history (value TEXT)')
            connection.execute("INSERT INTO operator_history VALUES ('retain cross-seed history')")
        self.file('opt/seedcross/manage.py', 'old source')
        self.file('opt/seedcross/start-seedcross.sh', '#!/bin/sh\nprintf "old executable"\n').chmod(0o755)
        self.file('opt/seedcross/csui/settings.py',
                  'SECRET_KEY = "retained-operator-fixture-secret"\nDEBUG = True\n'
                  'ALLOWED_HOSTS = ["custom.fixture.example"]\n'
                  'CSRF_TRUSTED_ORIGINS = ["https://custom.fixture.example"]\n'
                  'MIDDLEWARE = []\nDATABASES = {"default": {"NAME": "db/db.sqlite3"}}\n')
        self.file('install/.seedcross.lock', 'old marker')
        self.file('etc/systemd/system/seedcross.service', 'old unit')
        self.file('active-seedcross', '')
        return database

    def history(self, database):
        with sqlite3.connect(database) as connection:
            return connection.execute('SELECT value FROM operator_history').fetchone()[0]

    def test_real_legacy_sqlite_survives_default_removal_and_retained_reinstall(self):
        self.legacy()
        self.assert_success(self.run_script('seedcross', 'remove'))
        retained = self.root / 'var/lib/seedcross/db/db.sqlite3'
        self.assertEqual(self.history(retained), 'retain cross-seed history')
        self.assertFalse((self.root / 'opt/seedcross').exists())
        self.assert_success(self.run_script('seedcross'))
        self.assertEqual(self.history(retained), 'retain cross-seed history')
        self.assertTrue((self.root / 'opt/seedcross/db').is_symlink())
        runtime = json.loads((self.root / 'var/lib/seedcross/runtime.json').read_text())
        self.assertEqual(runtime['secret_key'], 'retained-operator-fixture-secret')
        self.assertIn('custom.fixture.example', runtime['allowed_hosts'])
        self.assertIn('https://custom.fixture.example', runtime['csrf_trusted_origins'])
        self.assert_success(self.run_script('seedcross', 'remove', DELETE_DATA='true'))
        self.assertFalse(retained.exists())

    def test_expression_backed_legacy_settings_preserve_effective_identity_and_policy(self):
        self.legacy()
        settings = self.root / 'opt/seedcross/csui/settings.py'
        source = settings.read_text().replace(
            'SECRET_KEY = "retained-operator-fixture-secret"',
            'import os\nSECRET_KEY = os.environ["TEST_SEEDCROSS_OPERATOR_SECRET"]\nprint(SECRET_KEY)',
        ).replace(
            'ALLOWED_HOSTS = ["custom.fixture.example"]',
            'ALLOWED_HOSTS = ["custom.fixture.example"] + ["dynamic.fixture.example"]',
        ).replace(
            'CSRF_TRUSTED_ORIGINS = ["https://custom.fixture.example"]',
            'CSRF_TRUSTED_ORIGINS = tuple("https://" + host for host in ALLOWED_HOSTS)',
        )
        settings.write_text(source)
        result = self.run_script('seedcross', AF_PACKAGE_ACTION='update',
                                 TEST_SEEDCROSS_OPERATOR_SECRET='retained-operator-fixture-secret')
        self.assert_success(result)
        runtime = json.loads((self.root / 'var/lib/seedcross/runtime.json').read_text())
        self.assertEqual(runtime['secret_key'], 'retained-operator-fixture-secret')
        for host in ('custom.fixture.example', 'dynamic.fixture.example'):
            self.assertIn(host, runtime['allowed_hosts'])
            self.assertIn('https://' + host, runtime['csrf_trusted_origins'])
        commands = (self.root / 'commands.jsonl').read_text()
        self.assertNotIn('retained-operator-fixture-secret', commands)
        self.assertNotIn('retained-operator-fixture-secret', result.stdout + result.stderr)
        calls = [json.loads(line) for line in commands.splitlines()]
        self.assertTrue(any(call[:4] == ['su', '-s', '/bin/bash', 'seedcross'] and call[-1].endswith("/.venv/bin/python' -")
                            for call in calls))

    def test_legacy_settings_evaluation_failure_restores_state_without_rotating_secret(self):
        legacy = self.legacy()
        before = legacy.read_bytes()
        settings = self.root / 'opt/seedcross/csui/settings.py'
        original = settings.read_text() + '\nraise RuntimeError("fixture settings evaluation failure")\n'
        settings.write_text(original)
        result = self.run_script('seedcross', AF_PACKAGE_ACTION='update')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing to replace its runtime identity', result.stdout + result.stderr)
        self.assertEqual(legacy.read_bytes(), before)
        self.assertEqual(settings.read_text(), original)
        self.assertEqual((self.root / 'opt/seedcross/manage.py').read_text(), 'old source')
        self.assertEqual((self.root / 'etc/systemd/system/seedcross.service').read_text(), 'old unit')
        self.assertEqual((self.root / 'install/.seedcross.lock').read_text(), 'old marker')
        self.assertTrue((self.root / 'active-seedcross').exists())
        self.assertFalse((self.root / 'var/lib/seedcross/runtime.json').exists())

    def test_clone_and_dependency_failure_preserve_non_git_legacy_tree(self):
        legacy = self.legacy()
        for failure in ('clone', 'pip'):
            with self.subTest(failure=failure):
                result = self.run_script('seedcross', AF_PACKAGE_ACTION='update', FAIL_STAGE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.history(legacy), 'retain cross-seed history')
                self.assertEqual((self.root / 'opt/seedcross/manage.py').read_text(), 'old source')
                self.assertTrue((self.root / 'active-seedcross').exists())

    def test_migration_failure_restores_real_sqlite_code_unit_and_receipt(self):
        legacy = self.legacy()
        before = legacy.read_bytes()
        result = self.run_script('seedcross', AF_PACKAGE_ACTION='update', FAIL_STAGE='migration')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(legacy.read_bytes(), before)
        self.assertEqual((self.root / 'opt/seedcross/manage.py').read_text(), 'old source')
        self.assertEqual((self.root / 'etc/systemd/system/seedcross.service').read_text(), 'old unit')
        self.assertEqual((self.root / 'install/.seedcross.lock').read_text(), 'old marker')

    def test_conflicting_legacy_and_retained_databases_fail_closed(self):
        legacy = self.legacy()
        retained = self.file('var/lib/seedcross/db/db.sqlite3', 'different retained database')
        result = self.run_script('seedcross')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(retained.read_text(), 'different retained database')
        self.assertEqual(self.history(legacy), 'retain cross-seed history')
        self.assertEqual((self.root / 'install/.seedcross.lock').read_text(), 'old marker')

    def test_fresh_runtime_disables_debug_serves_static_and_retains_secret_on_update(self):
        self.assert_success(self.run_script('seedcross', TEST_DOMAIN=''))
        runtime_path = self.root / 'var/lib/seedcross/runtime.json'
        runtime = json.loads(runtime_path.read_text())
        self.assertNotIn('seedcross.', runtime['allowed_hosts'])
        self.assertNotIn('*', runtime['allowed_hosts'])
        self.assertFalse(runtime['secret_key'].startswith('django-insecure-'))
        settings = self.root / 'opt/seedcross/af_settings.py'
        inspect = subprocess.run(['/usr/bin/python3', '-c',
            'import af_settings; assert af_settings.DEBUG is False; assert "whitenoise.middleware.WhiteNoiseMiddleware" in af_settings.MIDDLEWARE; assert af_settings.DATABASES["default"]["NAME"].endswith("/var/lib/seedcross/db/db.sqlite3")'],
            cwd=settings.parent, capture_output=True, text=True)
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        self.assertTrue((self.root / 'var/lib/seedcross/static/fixture.css').exists())
        start = (self.root / 'opt/seedcross/start-seedcross.sh').read_text()
        self.assertIn('--bind 127.0.0.1:19876', start)
        self.assertNotIn('runserver', start)
        self.assert_success(self.run_script('seedcross', AF_PACKAGE_ACTION='update'))
        self.assertEqual(json.loads(runtime_path.read_text())['secret_key'], runtime['secret_key'])

    def test_removal_preserves_legacy_sqlite_wal_and_shm_sidecars(self):
        self.legacy()
        self.file('opt/seedcross/db/db.sqlite3-wal', 'fixture WAL sidecar bytes')
        self.file('opt/seedcross/db/db.sqlite3-shm', 'fixture SHM sidecar bytes')
        self.assert_success(self.run_script('seedcross', 'remove'))
        for suffix in ('wal', 'shm'):
            self.assertEqual((self.root / f'var/lib/seedcross/db/db.sqlite3-{suffix}').read_text(),
                             f'fixture {suffix.upper()} sidecar bytes')


if __name__ == '__main__':
    unittest.main()
