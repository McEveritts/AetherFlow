#!/usr/bin/env python3
"""Exercise Palate's privileged lifecycle in an isolated filesystem with fake services."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from installer_test_helpers import common_functions


ROOT = Path(__file__).resolve().parents[1]
MOCK_COMMAND = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ['TEST_ROOT'])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
failure = os.environ.get('TEST_FAILURE', '')
with (root / 'commands').open('a') as log:
    log.write(command + ' ' + ' '.join(args) + '\n')
if command in ('apt-get', 'chown', 'id', 'useradd'):
    pass
elif command == 'install':
    path = Path(args[-1])
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(int(args[args.index('-m') + 1], 8))
elif command == 'runuser':
    command_args = args[args.index('--') + 1:]
    os.execvp(command_args[0], command_args)
elif command == 'psql':
    if 'SHOW port' in args:
        print('5432')
    else:
        with (root / 'sql').open('a') as log:
            log.write(sys.stdin.read())
elif command == 'pg_dump':
    print('database-backup')
elif command == 'git':
    if args[0] == 'ls-remote':
        print('a' * 40 + '\trefs/tags/' + os.environ.get('TEST_TAG', 'v1.5.23'))
    else:
        target = Path(args[-1])
        (target / 'package.json').write_text(json.dumps({'version': '1.5.23'}))
        (target / 'vault').mkdir()
        (target / 'vault/recipe.md').write_text('upstream-recipe')
elif command == 'node':
    if args[0] == '-p':
        print('1.5.23')
    elif 'db' in args and failure == 'schema':
        sys.exit(1)
elif command == 'npm':
    action = 'build' if args == ['run', 'build'] else 'dependencies'
    if failure == action:
        sys.exit(1)
    if action == 'build':
        if (root / 'opt/palate').exists():
            assert (root / 'running').exists(), 'service stopped before build completed'
        Path('.next/cache').mkdir(parents=True)
        Path('.next/BUILD_ID').write_text('production-build')
elif command == 'curl':
    if '--output' in args:
        sys.exit(1 if failure == 'health' else 0)
    target = Path(args[args.index('-o') + 1])
    source = root / ('SHASUMS256.txt' if target.name == 'node-shasums.txt' else 'node.tar.xz')
    shutil.copyfile(source, target)
elif command == 'systemctl':
    if 'af-palate.service' in args:
        running = root / 'running'
        if args[0] == 'is-active':
            sys.exit(0 if running.exists() else 3)
        elif args[0] == 'stop':
            running.unlink(missing_ok=True)
        elif args[0] in ('restart', 'start'):
            if args[0] == 'restart' and failure == 'restart':
                sys.exit(1)
            running.touch()
else:
    raise RuntimeError(command)
'''


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Requires Linux Bash')
class PalateInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='af-palate-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('mock-bin', 'opt/AetherFlow/packages', 'etc/systemd/system', 'var/backups'):
            (self.root / directory).mkdir(parents=True)
        common = self.root / 'opt/AetherFlow/packages/common.sh'
        common.write_text(r'''
require_root() { :; }
print_error() { printf '%s\n' "$*" >&2; }
print_info() { printf '%s\n' "$*"; }
report_progress() { printf '[PROGRESS:%s] %s\n' "$1" "$2"; }
get_base_domain() { printf 'example.test\n'; }
write_lock() { touch "$TEST_ROOT/install/.palate.lock"; }
remove_lock() { rm -f "$TEST_ROOT/install/.palate.lock"; }
purge_systemd_unit() {
    systemctl stop af-palate.service
    rm -f "$TEST_ROOT/etc/systemd/system/af-palate.service"
}
purge_system_user() { printf 'purge-user %s\n' "$1" >> "$TEST_ROOT/commands"; }
''')
        with common.open("a") as output:
            output.write(common_functions("node_build"))
        for name in ('apt-get', 'chown', 'id', 'useradd', 'install', 'runuser', 'psql', 'pg_dump', 'git', 'node', 'npm', 'curl', 'systemctl'):
            path = self.root / 'mock-bin' / name
            path.write_text(MOCK_COMMAND)
            path.chmod(0o755)
        arch = 'arm64' if os.uname().machine in ('aarch64', 'arm64') else 'x64'
        archive_name = f'node-v22.23.4-linux-{arch}.tar.xz'
        archive = self.root / 'node.tar.xz'
        with tarfile.open(archive, 'w:xz') as output:
            for name in ('node', 'npm'):
                data = MOCK_COMMAND.encode()
                info = tarfile.TarInfo(f'node-v22.23.4-linux-{arch}/bin/{name}')
                info.size = len(data)
                info.mode = 0o755
                output.addfile(info, io.BytesIO(data))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / 'SHASUMS256.txt').write_text(f'{checksum}  {archive_name}\n')
        self.env = {**os.environ, 'PATH': f"{self.root}/mock-bin:{os.environ['PATH']}", 'TEST_ROOT': str(self.root)}
        self.app = self.root / 'opt/palate'
        self.vault = self.root / 'var/lib/palate/vault'
        self.config = self.root / 'etc/palate/palate.env'
        self.unit = self.root / 'etc/systemd/system/af-palate.service'

    def run_script(self, action='install', **environment):
        source = (ROOT / f'packages/package/{action}/{action}package-palate').read_text()
        for prefix in ('/opt/', '/var/', '/etc/', '/run/', '/install'):
            source = source.replace(prefix, str(self.root) + prefix)
        script = self.root / f'{action}.sh'
        script.write_text(source)
        return subprocess.run(['bash', str(script)], env={**self.env, **environment}, capture_output=True, text=True, timeout=20)

    def install(self, **environment):
        result = self.run_script(**environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def commands(self):
        return (self.root / 'commands').read_text()

    def test_fresh_install_honors_port_and_separates_secrets(self):
        result = self.install(AF_APP_PORT='17008')
        values = dict(line.split('=', 1) for line in self.config.read_text().splitlines())
        self.assertEqual(values['PORT'], '17008')
        self.assertEqual(values['NEXTAUTH_URL'], 'https://palate.example.test')
        self.assertEqual(values['JELLYFIN_INTERNAL_URL'], 'http://jellyfin.aether.local')
        secrets = [values[key] for key in ('NEXTAUTH_SECRET', 'PALATE_ENCRYPTION_SECRET', 'PALATE_RATE_LIMIT_SECRET', 'CRON_SECRET')]
        self.assertEqual(len(set(secrets)), 4)
        for secret in secrets + [values['PALATE_DB_PASSWORD']]:
            self.assertEqual(len(secret), 64)
            self.assertNotIn(secret, result.stdout + result.stderr + self.commands())
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.app / 'vault').resolve(), self.vault)
        self.assertEqual((self.app / '.af-version').read_text(), '1.5.23\n')
        self.assertIn('--hostname 127.0.0.1 --port ${PORT}', self.unit.read_text())
        self.assertTrue((self.root / 'install/.palate.lock').exists())
        self.assertFalse(list((self.root / 'opt').glob('.palate-build.*')))

    def test_reinstall_preserves_vault_and_configuration(self):
        self.install()
        original = self.config.read_text()
        (self.vault / 'recipe.md').write_text('my-recipe')
        with self.config.open('a') as output:
            output.write('USDA_API_KEY=my-custom-value\n')
        self.install(AF_APP_PORT='17009')
        self.assertEqual((self.vault / 'recipe.md').read_text(), 'my-recipe')
        self.assertIn('USDA_API_KEY=my-custom-value', self.config.read_text())
        for line in original.splitlines():
            if not line.startswith('PORT='):
                self.assertIn(line, self.config.read_text())
        self.assertIn('PORT=17009', self.config.read_text())
        backups = list((self.root / 'var/backups').glob('aetherflow-palate.*'))
        self.assertEqual(len(backups), 2)
        self.assertTrue(all((backup / 'database.dump').is_file() for backup in backups))

    def test_upgrade_failures_keep_previous_app_and_data(self):
        self.install()
        (self.app / '.af-version').write_text('previous-version')
        (self.vault / 'recipe.md').write_text('my-recipe')
        previous_unit = self.unit.read_text()
        previous_config = self.config.read_text()
        for failure in ('dependencies', 'build', 'schema', 'restart', 'health'):
            with self.subTest(failure=failure):
                result = self.run_script(TEST_FAILURE=failure, AF_APP_PORT='17010')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.app / '.af-version').read_text(), 'previous-version')
                self.assertEqual((self.vault / 'recipe.md').read_text(), 'my-recipe')
                self.assertEqual(self.unit.read_text(), previous_unit)
                self.assertEqual(self.config.read_text(), previous_config)
                self.assertTrue((self.root / 'running').exists())
                self.assertFalse(list((self.root / 'opt').glob('.palate-build.*')))

    def test_first_install_failure_does_not_mark_installed(self):
        result = self.run_script(TEST_FAILURE='health')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.root / 'install/.palate.lock').exists())
        self.assertTrue(self.vault.exists())
        self.assertTrue(self.config.exists())

    def test_corrupt_runtime_and_unstable_tag_are_rejected(self):
        (self.root / 'node.tar.xz').write_bytes(b'corrupt')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.app.exists())
        result = self.run_script(TEST_TAG='v1.6.0-beta.1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'install/.palate.lock').exists())

    def test_invalid_port_is_rejected_before_package_changes(self):
        for port in ('80', '65536', '28014;touch bad', 'invalid'):
            with self.subTest(port=port):
                result = self.run_script(AF_APP_PORT=port)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'commands').exists())

    def test_removal_preserves_data_and_explicit_purge_is_scoped(self):
        self.install()
        config = self.config.read_text()
        result = self.run_script('remove')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.app.exists())
        self.assertTrue(self.vault.exists())
        self.assertEqual(self.config.read_text(), config)
        self.assertFalse((self.root / 'install/.palate.lock').exists())
        result = self.run_script('remove', DELETE_DATA='true')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.vault.exists())
        self.assertFalse(self.config.exists())
        self.assertIn('DROP DATABASE IF EXISTS af_palate', (self.root / 'sql').read_text())
        self.assertIn('purge-user af-palate', self.commands())
        self.assertNotIn('systemctl stop postgresql', self.commands())


if __name__ == '__main__':
    unittest.main()
