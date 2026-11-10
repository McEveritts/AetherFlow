"""Real archive entry points with synthetic releases and isolated host commands."""
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import hashlib
import subprocess
import tarfile
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions, replace_paths_once

ROOT = Path(__file__).resolve().parents[1]
APPLICATIONS = {
    'sonarr': ('Sonarr', 'v3'),
    'radarr': ('Radarr', 'v3'),
    'lidarr': ('Lidarr', 'v1'),
    'readarr': ('Readarr', 'v1'),
    'prowlarr': ('Prowlarr', 'v1'),
    'ombi': ('Ombi', None),
    'jackett': ('Jackett', None),
    'adguardhome': ('AdGuardHome', None),
    'navidrome': ('navidrome', None),
    'librespeed': ('librespeed', None),
}
EXECUTABLES = {'jackett': 'jackett', 'librespeed': 'speedtest-backend'}
FLAT_ARCHIVES = {'ombi', 'navidrome', 'librespeed'}
HOST_COMMAND = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
command, arguments = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / 'commands.jsonl').open('a') as output:
    output.write(json.dumps([command, *arguments]) + '\n')
failure = os.environ.get('FAIL_STAGE', '')
if command == 'dpkg':
    if '--compare-versions' in arguments:
        sys.exit(subprocess.run(['/usr/bin/dpkg', *arguments]).returncode)
    print(os.environ.get('TEST_ARCH', 'amd64'))
elif command == 'curl':
    if '-o' in arguments:
        if failure == 'download': sys.exit(22)
        target = pathlib.Path(arguments[arguments.index('-o') + 1])
        if failure == 'archive': target.write_text('not a tarball')
        else: shutil.copyfile(root / 'release.tar.gz', target)
    elif failure == 'readiness':
        sys.exit(22)
    else:
        print('{"status":"OK"}')
elif command == 'systemctl':
    active = root / ('active-' + os.environ['TEST_APP'])
    if arguments[0] == 'show':
        print('LoadState=loaded\nActiveState=' + ('active' if active.exists() else 'inactive'))
    if arguments[0] == 'is-active': sys.exit(0 if active.exists() else 3)
    if arguments[0] == 'stop':
        if failure == 'stop': sys.exit(73)
        active.unlink(missing_ok=True)
    executable = pathlib.Path(os.environ['TEST_EXECUTABLE_PATH'])
    if arguments[0] in ('enable', 'restart') and failure in ('activation', 'signal') and executable.exists() and 'fixture executable' in executable.read_text():
        database = pathlib.Path(os.environ['TEST_DATABASE'])
        database.write_text('simulated incomplete migration')
        if failure == 'signal':
            import signal
            os.kill(os.getppid(), signal.SIGTERM)
        sys.exit(73)
    if arguments[0] in ('enable', 'restart'): active.touch()
elif command == 'mv':
    if failure == 'old-move' and arguments[-1].endswith('/app'):
        sys.exit(74)
    sys.exit(subprocess.run(['/usr/bin/mv', *arguments]).returncode)
elif command == 'getent':
    sys.exit(2)
elif command == 'tar':
    if '-C' in arguments:
        destination = pathlib.Path(arguments[arguments.index('-C') + 1]).resolve()
        if not destination.is_relative_to(root.resolve()):
            raise RuntimeError('Extraction destination escaped fixture root')
    sys.exit(subprocess.run(['/usr/bin/tar', *arguments]).returncode)
elif command == 'htpasswd':
    print('fixture-user:fixture-password-hash')
elif command not in ('apt-get', 'id', 'chown', 'useradd', 'userdel', 'groupdel', 'sleep', 'setcap'):
    raise RuntimeError((command, arguments))
'''


class ArchiveFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for directory in ('bin', 'opt/AetherFlow/packages', 'var/log/aetherflow',
                          'etc/systemd/system', 'install', 'tmp', 'opt', 'var/lib'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for command in ('dpkg', 'curl', 'systemctl', 'getent', 'apt-get', 'id',
                        'chown', 'useradd', 'userdel', 'groupdel', 'sleep', 'setcap', 'htpasswd', 'tar', 'mv'):
            executable = self.root / 'bin' / command
            executable.write_text(HOST_COMMAND)
            executable.chmod(0o755)
        python = self.root / 'bin/python3'
        python.write_text('''#!/usr/bin/python3
import os, pathlib, subprocess, sys
source = sys.stdin.read()
if os.environ.get('TEST_LEGACY_TARFILE'):
    source = "import tarfile; del tarfile.data_filter\\n" + source
if 'Identity/Wizard' not in source and 'auth/createAdmin' not in source:
    raise SystemExit(subprocess.run(['/usr/bin/python3', *sys.argv[1:]], input=source, text=True).returncode)
''')
        python.chmod(0o755)
        source = (ROOT / 'packages/common.sh').read_text()
        helpers = source[source.index('command_exists()'):source.index('lock_path()')]
        helpers += common_functions('systemd_unit_inactive', 'stop_systemd_unit',
                                    'purge_systemd_unit', 'purge_system_user',
                                    'verify_systemd_service_active', 'wait_for_service_ready',
                                    'af_write_failure_receipt')
        helpers = self.rebase(helpers)
        stubs = '''set -euo pipefail
AF_ALLOW_VERSION_FALLBACK=1
export AF_ALLOW_VERSION_FALLBACK
MASTER_USER=fixture-user
MASTER_PASS=fixture-password
require_root() { :; }
log_info() { printf '%s\\n' "$*" >> "$LOGFILE"; }
log_warn() { printf '%s\\n' "$*" >> "$LOGFILE"; }
print_error() { printf '%s\\n' "$*" >&2; }
print_warn() { printf '%s\\n' "$*" >&2; }
report_progress() { printf '%s\\n' "$*" >> "$TEST_ROOT/progress"; }
github_latest_tag() { printf 'fixture-2.0\\n'; }
seed_servarr_master_user() { printf '%s\\n' "$*" >> "$TEST_ROOT/credentials-seed"; }
write_lock() { printf 'installed\\n' > "$TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f "$AF_ARCHIVE_BACKUP/.af-archive-pending"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
'''
        (self.root / 'opt/AetherFlow/packages/common.sh').write_text(stubs + helpers)

    def rebase(self, source):
        return replace_paths_once(source, [(prefix, str(self.root) + prefix) for prefix in
            ('/opt', '/etc/', '/var/', '/tmp/', '/install', '/home/', '/usr/local/')])

    def file(self, relative, contents):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
        return target

    def prepare(self, package, existing=False):
        title, _ = APPLICATIONS.get(package, (package, None))
        archive_root = self.root / 'archive' / title
        archive_root.mkdir(parents=True, exist_ok=True)
        executable_name = EXECUTABLES.get(package, title)
        executable = archive_root / executable_name
        executable.write_text('#!/bin/sh\nprintf "fixture executable\\n"\n')
        executable.chmod(0o755)
        (archive_root / 'release').write_text('new code')
        if package == 'readarr':
            (archive_root / 'Readarr.dll').write_text('0.4.12.2738\n')
        with tarfile.open(self.root / 'release.tar.gz', 'w:gz') as archive:
            if package in FLAT_ARCHIVES:
                for entry in archive_root.iterdir():
                    archive.add(entry, arcname=entry.name)
            else:
                archive.add(archive_root, arcname=title)
        if existing:
            self.file(f'opt/{title}/release', 'old code')
            self.file(f'opt/{title}/{executable_name}', 'old executable')
            self.file(f'opt/{title}/.af-version', 'old-version')
            if package == 'readarr':
                self.file(f'opt/{title}/Readarr.dll', '0.4.12.2738\n')
            self.persistent_files(package, 'existing database')
            self.file(f'etc/systemd/system/{package}.service', 'old unit')
            self.file(f'install/.{package}.lock', 'old marker')
            self.file(f'active-{package}', '')

    def persistent_files(self, package, database_contents):
        if package == 'adguardhome':
            database_path, config_path = 'opt/AdGuardHome/data/sessions.db', 'opt/AdGuardHome/AdGuardHome.yaml'
            contents = 'users:\n  - name: operator\n    password: retained-fixture-key\nhttp:\n  address: 127.0.0.1:19876\n'
        elif package == 'librespeed':
            database_path, config_path = 'opt/librespeed/speedtest.db', 'opt/librespeed/settings.toml'
            contents = 'listen_port=19876\npassword="retained-fixture-key"\n'
        elif package == 'navidrome':
            database_path, config_path = 'var/lib/navidrome/navidrome.db', 'var/lib/navidrome/navidrome.toml'
            contents = 'Port = 19876\nMusicFolder = "/operator/music"\nPasswordEncryptionKey = "retained-fixture-key"\n'
        elif package == 'ombi':
            database_path, config_path = 'etc/Ombi/Ombi.db', 'etc/Ombi/appsettings.json'
            contents = '{"operatorSecret":"retained-fixture-key"}\n'
        elif package == 'qui':
            database_path, config_path = 'var/lib/qui/qui.db', 'var/lib/qui/config.toml'
            contents = 'port = 19876\nsessionSecret = "retained-fixture-key"\n'
        else:
            database_path, config_path = f'var/lib/{package}/app.db', f'var/lib/{package}/config.xml'
            contents = '<Config><Port>19876</Port><ApiKey>retained-fixture-key</ApiKey></Config>'
        return self.file(database_path, database_contents), self.file(config_path, contents)

    def database_path(self, package):
        return self.root / {
            'adguardhome': 'opt/AdGuardHome/data/sessions.db',
            'librespeed': 'opt/librespeed/speedtest.db',
            'navidrome': 'var/lib/navidrome/navidrome.db',
            'ombi': 'etc/Ombi/Ombi.db',
            'qui': 'var/lib/qui/qui.db',
        }.get(package, f'var/lib/{package}/app.db')

    def run_script(self, package, action='install', **overrides):
        source = (ROOT / f'packages/package/{action}/{action}package-{package}').read_text()
        script = self.root / 'script'
        rebased = self.rebase(source)
        remaining = rebased.replace(str(self.root), '__FIXTURE__')
        self.assertIsNone(re.search(r'(?<![\w/])/(?:opt|etc|var|tmp|install|home)(?=[/\s\"\'])', remaining))
        script.write_text(rebased)
        title = APPLICATIONS.get(package, (package, None))[0]
        environment = {**os.environ, 'PATH': f'{self.root}/bin:{os.environ["PATH"]}',
                       'TEST_ROOT': str(self.root), 'TEST_APP': package,
                       'TEST_TITLE': title, 'TEST_EXECUTABLE': EXECUTABLES.get(package, title),
                       'TEST_DATABASE': str(self.database_path(package)),
                       'TEST_EXECUTABLE_PATH': str(self.root / ('usr/local/bin/qui' if package == 'qui' else f'opt/{title}/{EXECUTABLES.get(package, title)}')),
                       'AF_APP_PORT': '19876', 'AF_PACKAGE_ACTION': 'install', **overrides}
        archive = self.root / 'release.tar.gz'
        if archive.is_file() and 'AF_DOWNLOAD_SHA256' not in overrides:
            environment['AF_DOWNLOAD_SHA256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        if package == 'readarr' and archive.is_file():
            readarr_archive = self.root / 'tmp/readarr-verified.tar.gz'
            shutil.copyfile(archive, readarr_archive)
            environment.setdefault('AF_READARR_VERIFIED_ARCHIVE', str(readarr_archive))
            environment.setdefault('AF_READARR_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest())
        environment.setdefault('AF_ALLOW_VERSION_FALLBACK', '1')
        result = subprocess.run(['bash', str(script)], env=environment,
                                capture_output=True, text=True, timeout=30)
        if evidence := os.environ.get('AF_LIFECYCLE_FIXTURE_EVIDENCE'):
            with Path(evidence).open('a') as output:
                output.write(json.dumps({'package_id': package, 'action': action,
                    'lifecycle_action': environment['AF_PACKAGE_ACTION'],
                    'architecture': environment.get('TEST_ARCH', 'amd64'),
                    'purge': environment.get('DELETE_DATA', 'false'),
                    'failure_injection': environment.get('FAIL_STAGE', ''),
                    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                    'test': self.id(), 'exit_status': result.returncode}) + '\n')
        return result

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ServarrLifecycleTests(ArchiveFixture):
    def test_each_application_install_update_remove_reinstall_and_purge(self):
        for package, (title, api_version) in APPLICATIONS.items():
            with self.subTest(package=package):
                self.prepare(package)
                self.assert_success(self.run_script(package))
                self.assertEqual((self.root / f'opt/{title}/release').read_text(), 'new code')
                if api_version:
                    self.assertIn(f'{package} 19876 {api_version}',
                                  (self.root / 'credentials-seed').read_text())
                database, config = self.persistent_files(package, 'retained database')
                self.assert_success(self.run_script(package, AF_PACKAGE_ACTION='update'))
                self.assertEqual(database.read_text(), 'retained database')
                self.assertIn('retained-fixture-key', config.read_text())
                self.assert_success(self.run_script(package, 'remove'))
                self.assertFalse((self.root / f'opt/{title}/{EXECUTABLES.get(package, title)}').exists())
                self.assertFalse((self.root / f'install/.{package}.lock').exists())
                self.assertEqual(database.read_text(), 'retained database')
                self.assert_success(self.run_script(package))
                self.assertEqual(database.read_text(), 'retained database')
                self.assertIn('retained-fixture-key', config.read_text())
                self.assert_success(self.run_script(package, 'remove', DELETE_DATA='true'))
                self.assertFalse(database.parent.exists())
                self.assertFalse(list((self.root / 'opt').glob(f'{title}.af-backup.??????')))

    def test_each_failed_activation_restores_previous_code_state_unit_and_marker(self):
        for package, (title, _) in APPLICATIONS.items():
            with self.subTest(package=package):
                self.prepare(package, existing=True)
                result = self.run_script(package, AF_PACKAGE_ACTION='update', FAIL_STAGE='activation')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((self.root / f'opt/{title}/release').read_text(), 'old code')
                self.assertEqual(self.database_path(package).read_text(), 'existing database')
                self.assertEqual((self.root / f'etc/systemd/system/{package}.service').read_text(), 'old unit')
                self.assertEqual((self.root / f'install/.{package}.lock').read_text(), 'old marker')

    def test_each_failed_readiness_cannot_publish_new_installation(self):
        for package, (title, _) in APPLICATIONS.items():
            with self.subTest(package=package):
                self.prepare(package)
                result = self.run_script(package, FAIL_STAGE='readiness')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((self.root / f'install/.{package}.lock').exists())

    def test_each_download_and_archive_failure_preserves_existing_application(self):
        for package, (title, _) in APPLICATIONS.items():
            if package == 'readarr':
                continue
            for failure in ('download', 'archive'):
                with self.subTest(package=package, failure=failure):
                    self.prepare(package, existing=True)
                    result = self.run_script(package, FAIL_STAGE=failure)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((self.root / f'opt/{title}/release').read_text(), 'old code')
                    self.assertEqual(self.database_path(package).read_text(), 'existing database')

    def test_each_application_architecture_mapping_and_unsupported_architecture(self):
        for package in APPLICATIONS:
            for architecture, asset in (('amd64', 'x64'), ('arm64', 'arm64'), ('armhf', 'arm')):
                with self.subTest(package=package, architecture=architecture):
                    self.prepare(package)
                    self.assert_success(self.run_script(package, TEST_ARCH=architecture))
                    commands = [json.loads(line) for line in
                                (self.root / 'commands.jsonl').read_text().splitlines()]
                    expected = f'arch={asset}'
                    if package in ('sonarr', 'ombi'):
                        expected = f'linux-{asset}'
                    elif package in ('adguardhome', 'navidrome', 'librespeed'):
                        expected = {'amd64': 'linux_amd64', 'arm64': 'linux_arm64', 'armhf': 'linux_armv7'}[architecture]
                    elif package == 'jackett':
                        expected = {'amd64': 'AMDx64', 'arm64': 'ARM64', 'armhf': 'ARM32'}[architecture]
                    self.assertTrue(any(command[0] == 'curl' and
                        any(expected in argument for argument in command) for command in commands))
            result = self.run_script(package, TEST_ARCH='riscv64')
            self.assertNotEqual(result.returncode, 0)

    def test_partial_tar_member_cannot_overwrite_any_previous_executable(self):
        for package, (title, _) in APPLICATIONS.items():
            with self.subTest(package=package):
                self.prepare(package, existing=True)
                contents = io.BytesIO()
                with tarfile.open(fileobj=contents, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    executable_name = EXECUTABLES.get(package, title)
                    executable = tarfile.TarInfo(executable_name if package in FLAT_ARCHIVES else f'{title}/{executable_name}')
                    payload = b'new executable from a truncated release'
                    executable.size = len(payload)
                    executable.mode = 0o755
                    archive.addfile(executable, io.BytesIO(payload))
                    incomplete = tarfile.TarInfo('truncated-member')
                    incomplete.size = 8192
                    archive.addfile(incomplete, io.BytesIO(b'x' * incomplete.size))
                (self.root / 'release.tar.gz').write_bytes(gzip.compress(contents.getvalue()[:1552]))
                result = self.run_script(package, AF_PACKAGE_ACTION='update')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / f'opt/{title}/{EXECUTABLES.get(package, title)}').read_text(), 'old executable')
                self.assertEqual(self.database_path(package).read_text(), 'existing database')
                self.assertEqual((self.root / f'install/.{package}.lock').read_text(), 'old marker')

    def test_failed_old_tree_move_does_not_delete_original_application(self):
        self.prepare('sonarr', existing=True)
        result = self.run_script('sonarr', FAIL_STAGE='old-move')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'opt/Sonarr/Sonarr').read_text(), 'old executable')
        self.assertEqual(self.database_path('sonarr').read_text(), 'existing database')

    def test_termination_restores_previous_application_and_database(self):
        self.prepare('navidrome', existing=True)
        media = self.file('var/lib/navidrome/music/precious.flac', 'retained media')
        inode = media.stat().st_ino
        result = self.run_script('navidrome', FAIL_STAGE='signal')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'opt/navidrome/navidrome').read_text(), 'old executable')
        self.assertEqual(self.database_path('navidrome').read_text(), 'existing database')
        self.assertEqual(media.stat().st_ino, inode)
        backup, = (self.root / 'opt').glob('navidrome.af-backup.??????')
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertFalse(any(path.name == 'music' for path in backup.rglob('*')))

    def test_purge_does_not_follow_foreign_or_symlink_backups(self):
        self.prepare('adguardhome', existing=True)
        foreign = self.file('opt/AdGuardHome.af-backup.ABCDEF/.af-archive-owner', 'different-app')
        secret = self.file('foreign-data/secret', 'never purge another application')
        (self.root / 'opt/AdGuardHome.af-backup.GHIJKL').symlink_to(secret.parent, target_is_directory=True)
        self.assert_success(self.run_script('adguardhome', 'remove', DELETE_DATA='true'))
        self.assertTrue(foreign.exists())
        self.assertEqual(secret.read_text(), 'never purge another application')

    def test_interrupted_snapshot_blocks_retry_without_destroying_recovery_files(self):
        self.prepare('radarr', existing=True)
        self.file('opt/Radarr.af-backup.ABCDEF/.af-archive-owner', 'radarr\n')
        pending = self.file('opt/Radarr.af-backup.ABCDEF/.af-archive-pending', '')
        recovered = self.file('opt/Radarr.af-backup.ABCDEF/app/Radarr', 'recovery executable')
        result = self.run_script('radarr', AF_PACKAGE_ACTION='update')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('needs recovery', result.stderr)
        self.assertTrue(pending.exists())
        self.assertEqual(recovered.read_text(), 'recovery executable')
        self.assertEqual((self.root / 'opt/Radarr/Radarr').read_text(), 'old executable')

    def test_invalid_executable_and_escaping_archive_fail_before_service_stop(self):
        for name, mode, link in [('Sonarr/Sonarr', 0o644, None),
                                 ('Sonarr/not-the-executable', 0o755, None),
                                 ('Sonarr/Sonarr', 0o755, '/etc/passwd')]:
            with self.subTest(name=name, mode=mode, link=link):
                self.prepare('sonarr', existing=True)
                with tarfile.open(self.root / 'release.tar.gz', 'w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    member.mode = mode
                    if link:
                        member.type, member.linkname = tarfile.SYMTYPE, link
                    else:
                        member.size = 4
                    archive.addfile(member, None if link else io.BytesIO(b'code'))
                (self.root / 'commands.jsonl').unlink(missing_ok=True)
                result = self.run_script('sonarr')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / 'opt/Sonarr/Sonarr').read_text(), 'old executable')
                commands = [json.loads(line) for line in (self.root / 'commands.jsonl').read_text().splitlines()]
                self.assertFalse(any(command[0] == 'systemctl' and 'stop' in command for command in commands))

    def test_stop_refusal_cannot_replace_live_application(self):
        for package, (title, _) in APPLICATIONS.items():
            with self.subTest(package=package):
                self.prepare(package, existing=True)
                result = self.run_script(package, FAIL_STAGE='stop')
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((self.root / f'active-{package}').exists())
                self.assertEqual((self.root / f'opt/{title}/{EXECUTABLES.get(package, title)}').read_text(), 'old executable')

    def test_conservative_extraction_fallback_without_python_security_backport(self):
        self.prepare('radarr', existing=True)
        self.assert_success(self.run_script('radarr', TEST_LEGACY_TARFILE='1'))
        self.assertIn('fixture executable', (self.root / 'opt/Radarr/Radarr').read_text())


class QuiLifecycleTests(ArchiveFixture):
    def prepare_qui(self):
        self.prepare('qui')
        with tarfile.open(self.root / 'release.tar.gz', 'w:gz') as archive:
            archive.add(self.root / 'archive/qui/qui', arcname='qui')
        self.file('usr/local/bin/qui', '#!/bin/sh\nprintf "old executable\\n"\n').chmod(0o755)
        self.persistent_files('qui', 'retained database')
        self.file('etc/systemd/system/qui.service', 'old unit')
        self.file('install/.qui.lock', 'old marker')
        self.file('active-qui', '')

    def test_acquisition_and_stop_failure_keep_previous_binary_service_and_secrets(self):
        for failure in ('download', 'archive', 'stop'):
            with self.subTest(failure=failure):
                self.prepare_qui()
                result = self.run_script('qui', AF_PACKAGE_ACTION='update', FAIL_STAGE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('old executable', (self.root / 'usr/local/bin/qui').read_text())
                self.assertTrue((self.root / 'active-qui').exists())
                self.assertEqual(self.database_path('qui').read_text(), 'retained database')

    def test_late_activation_failure_restores_binary_unit_database_and_marker(self):
        self.prepare_qui()
        result = self.run_script('qui', AF_PACKAGE_ACTION='update', FAIL_STAGE='activation')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('old executable', (self.root / 'usr/local/bin/qui').read_text())
        self.assertEqual(self.database_path('qui').read_text(), 'retained database')
        self.assertEqual((self.root / 'etc/systemd/system/qui.service').read_text(), 'old unit')
        self.assertEqual((self.root / 'install/.qui.lock').read_text(), 'old marker')
        self.assertTrue((self.root / 'active-qui').exists())

    def test_update_retained_remove_reinstall_and_purge(self):
        self.prepare_qui()
        self.assert_success(self.run_script('qui', AF_PACKAGE_ACTION='update'))
        self.assertIn('fixture executable', (self.root / 'usr/local/bin/qui').read_text())
        self.assert_success(self.run_script('qui', 'remove'))
        self.assertFalse((self.root / 'usr/local/bin/qui').exists())
        self.assertEqual(self.database_path('qui').read_text(), 'retained database')
        self.assert_success(self.run_script('qui'))
        self.assertEqual(self.database_path('qui').read_text(), 'retained database')
        self.assertIn('retained-fixture-key', (self.root / 'var/lib/qui/config.toml').read_text())
        self.assert_success(self.run_script('qui', 'remove', DELETE_DATA='true'))
        self.assertFalse(self.database_path('qui').exists())
        self.assertFalse(list((self.root / 'usr/local/bin').glob('qui.af-backup.??????')))


if __name__ == '__main__':
    unittest.main()
