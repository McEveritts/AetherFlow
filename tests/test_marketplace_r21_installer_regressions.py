"""Exercise Sol L-01 and S-01 with rebased installers and private host mocks."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_marketplace_catalog_lifecycle_matrix import InstallerFixture


APPLICATIONS = ("flood", "n8n", "thelounge", "duplicati", "audiobookshelf")
SNAPSHOT_PREFIXES = ("af-runtime-", "af-flood-runtime-", "af-duplicati-runtime-", "aetherflow-audiobookshelf.")
RUNTIME_PATHS = {
    "flood": ("opt/flood", "usr/local/bin/flood", "usr/bin/flood", "var/lib/flood", "etc/systemd/system/flood.service"),
    "n8n": ("opt/n8n", "var/lib/n8n", "etc/systemd/system/n8n.service", "usr/local/bin/n8n"),
    "thelounge": ("opt/thelounge", "var/lib/thelounge", "etc/systemd/system/thelounge.service", "usr/local/bin/thelounge"),
    "duplicati": (
        "etc/duplicati", "var/lib/duplicati", "etc/systemd/system/duplicati.service", "usr/bin/duplicati-server",
        "usr/lib/duplicati", "usr/share/duplicati", "etc/default/duplicati",
    ),
    "audiobookshelf": (
        "etc/default/audiobookshelf", "etc/systemd/system/audiobookshelf.service", "opt/audiobookshelf",
        "var/lib/audiobookshelf", "var/cache/audiobookshelf", "etc/audiobookshelf",
        "etc/apt/sources.list.d/audiobookshelf.list", "etc/apt/keyrings/audiobookshelf-archive-keyring.gpg",
        "usr/bin/audiobookshelf", "usr/share/audiobookshelf",
    ),
}

COPY_PROBE = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["AF_FIXTURE_ROOT"])
arguments = sys.argv[1:]
source = Path(arguments[-2])
target = Path(arguments[-1])
with (root / "commands.jsonl").open("a") as output:
    output.write(json.dumps(["cp", *arguments]) + "\\n")
if target.parent.name.startswith(("af-runtime-", "af-flood-runtime-", "af-duplicati-runtime-", "aetherflow-audiobookshelf.")):
    journal = root / "r21-snapshot-copies.jsonl"
    completed = len(journal.read_text().splitlines()) if journal.exists() else 0
    with journal.open("a") as output:
        output.write(json.dumps(arguments) + "\\n")
    if completed == int(os.environ.get("AF_R21_FAIL_SNAPSHOT_AFTER", "-1")):
        if source.is_dir():
            target.mkdir()
            (target / "r21-incomplete-snapshot").write_text("partial copy, never restore\\n")
        else:
            target.write_text("partial copy, never restore\\n")
        print("R21: injected partial snapshot copy failure", file=sys.stderr)
        raise SystemExit(87)
os.execv("/usr/bin/cp", ["/usr/bin/cp", *arguments])
'''


class MarketplaceR21InstallerRegressions(unittest.TestCase):
    def fixture(self, app):
        fixture = InstallerFixture(app)
        self.addCleanup(fixture.close)
        if app == "thelounge":
            for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
                command = directory / "node"
                source = command.read_text()
                anchor = "elif command == 'node':\n"
                self.assertIn(anchor, source)
                command.write_text(source.replace(anchor, anchor + "    if '-v' in arguments and any('thelounge' in argument for argument in arguments):\n        print(version)\n        sys.exit(0)\n", 1))
        baseline = fixture.run("install")
        self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
        self.assertTrue(self.active_marker(fixture).exists())
        self.assertTrue(fixture.lock.exists())
        fixture.file(f"var/lib/{app}/r21-retained-state", "unchanged operator state\n")
        return fixture

    def active_marker(self, fixture):
        return fixture.root / f"active-{fixture.app}.service"

    def commands(self, fixture, offset=0):
        return [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()[offset:]]

    def runtime_state(self, fixture, identities=True):
        entries = {}
        for relative in RUNTIME_PATHS[fixture.app]:
            target = fixture.root / relative
            paths = [target]
            if target.is_dir() and not target.is_symlink():
                paths.extend(sorted(target.rglob("*")))
            for path in paths:
                name = str(path.relative_to(fixture.root))
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    entries[name] = None
                    continue
                value = None
                if stat.S_ISLNK(metadata.st_mode):
                    value = os.readlink(path)
                elif stat.S_ISREG(metadata.st_mode):
                    value = hashlib.sha256(path.read_bytes()).hexdigest()
                properties = (stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode), value)
                entries[name] = (*properties, metadata.st_ino) if identities else properties
        return entries

    def backups(self, fixture):
        return sorted(path for directory in ("tmp", "var/backups") for path in (fixture.root / directory).iterdir()
                      if path.is_dir() and path.name.startswith(SNAPSHOT_PREFIXES))

    def copy_probe(self, fixture):
        fixture.file("mock-bin/cp", COPY_PROBE).chmod(0o700)

    def assert_snapshot_failure(self, fixture, was_active, completed_copies, restart_fails=False):
        self.copy_probe(fixture)
        active = self.active_marker(fixture)
        if not was_active:
            active.unlink()
        before = self.runtime_state(fixture)
        enabled = fixture.root / f"enabled-{fixture.app}.service"
        enabled_before = enabled.exists()
        lock_before = fixture.lock.read_bytes()
        offset = len(self.commands(fixture))
        result = fixture.run("update", AF_FIXTURE_VERSION="2.2.0", AF_R21_FAIL_SNAPSHOT_AFTER=str(completed_copies),
                             AF_FIXTURE_FAILURE="service" if restart_fails else "")
        self.assertEqual(result.returncode, 87, result.stdout + result.stderr)
        self.assertEqual(self.runtime_state(fixture), before)
        self.assertEqual(active.exists(), was_active and not restart_fails)
        self.assertEqual(enabled.exists(), enabled_before)
        self.assertEqual(fixture.lock.read_bytes(), lock_before)
        commands = self.commands(fixture, offset)
        copies = [command for command in commands if command[0] == "cp"]
        self.assertEqual(len(copies), completed_copies + 1)
        self.assertTrue(all(Path(command[-1]).parent.name.startswith(SNAPSHOT_PREFIXES) for command in copies))
        systemctl = [command for command in commands if command[0] == "systemctl"]
        starts = [command for command in systemctl if command[1] in ("start", "restart")]
        self.assertEqual(len(starts), int(was_active))
        self.assertFalse(any(command[1] in ("daemon-reload", "enable", "disable") for command in systemctl))
        backups = self.backups(fixture)
        if restart_fails:
            self.assertEqual(len(backups), 1)
            failed_target = Path(copies[-1][-1])
            if failed_target.is_dir():
                failed_target /= "r21-incomplete-snapshot"
            self.assertEqual(failed_target.read_text(), "partial copy, never restore\n")
            if completed_copies:
                self.assertTrue((backups[0] / "0").exists())
            self.assertIn(f"recovery backup preserved at {backups[0]}", result.stderr)
        else:
            self.assertEqual(backups, [])

    def test_first_snapshot_copy_failure_recovers_only_previously_active_services(self):
        for app in APPLICATIONS:
            for was_active in (True, False):
                with self.subTest(app=app, was_active=was_active), self.fixture(app) as fixture:
                    self.assert_snapshot_failure(fixture, was_active, completed_copies=0)

    def test_partial_snapshot_failure_never_restores_incomplete_backups(self):
        for app in APPLICATIONS:
            for was_active in (True, False):
                with self.subTest(app=app, was_active=was_active), self.fixture(app) as fixture:
                    self.assert_snapshot_failure(fixture, was_active, completed_copies=1)

    def test_snapshot_recovery_restart_failure_preserves_original_exit_and_backup(self):
        for app in APPLICATIONS:
            with self.subTest(app=app), self.fixture(app) as fixture:
                self.assert_snapshot_failure(fixture, True, completed_copies=1, restart_fails=True)

    def assert_link_rejected(self, fixture, variant, early=True):
        unit = fixture.root / f"etc/systemd/system/{fixture.app}.service"
        content = unit.read_bytes() + b"\nX-R21-Operator-Sentinel=retained\n"
        if variant in ("symlink", "hardlink"):
            retained = fixture.file("operator-owned-unit.conf", content.decode())
            unit.unlink()
            if variant == "symlink":
                unit.symlink_to(retained)
            else:
                os.link(retained, unit)
        else:
            parent = fixture.root / variant
            retained_parent = fixture.root / "operator-owned-parent"
            parent.rename(retained_parent)
            parent.symlink_to(retained_parent, target_is_directory=True)
            retained = retained_parent / unit.relative_to(parent)
            retained.write_bytes(content)
        before = self.runtime_state(fixture)
        offset = len(self.commands(fixture))
        result = fixture.run("update", AF_FIXTURE_VERSION="2.2.0")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(retained.read_bytes(), content)
        if early:
            self.assertEqual(self.runtime_state(fixture), before)
            self.assertTrue(self.active_marker(fixture).exists())
            commands = self.commands(fixture, offset)
            forbidden = {"apt-get", "systemctl", "node", "npm", "chown", "useradd", "cp", "curl", "wget"}
            self.assertFalse([command for command in commands if command[0] in forbidden], commands)
            self.assertEqual(self.backups(fixture), [])

    def test_n8n_and_thelounge_reject_linked_units_before_mutation(self):
        for app in ("n8n", "thelounge"):
            for variant in ("symlink", "hardlink"):
                with self.subTest(app=app, variant=variant), self.fixture(app) as fixture:
                    self.assert_link_rejected(fixture, variant)

    def test_n8n_and_thelounge_reject_linked_unit_parents_before_mutation(self):
        for app in ("n8n", "thelounge"):
            for parent in ("etc", "etc/systemd", "etc/systemd/system"):
                with self.subTest(app=app, parent=parent), self.fixture(app) as fixture:
                    self.assert_link_rejected(fixture, parent)

    def test_flood_remains_a_link_rejecting_negative_control(self):
        for variant in ("symlink", "hardlink"):
            with self.subTest(variant=variant), self.fixture("flood") as fixture:
                self.assert_link_rejected(fixture, variant, early=False)

    def test_valid_updates_keep_readiness_and_version_receipts(self):
        for app in APPLICATIONS:
            with self.subTest(app=app), self.fixture(app) as fixture:
                version = fixture.root / (f"opt/{app}/.af-version" if app == "audiobookshelf" else f"var/lib/{app}/.af-version")
                self.assertEqual(version.read_text(), "2.1.0\n")
                unit = fixture.root / f"etc/systemd/system/{app}.service"
                unit_inode = unit.stat().st_ino
                offset = len(self.commands(fixture))
                result = fixture.run("update", AF_FIXTURE_VERSION="2.2.0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(version.read_text(), "2.2.0\n")
                self.assertTrue(self.active_marker(fixture).exists())
                self.assertTrue(fixture.lock.exists())
                commands = self.commands(fixture, offset)
                self.assertTrue(any(command[:3] == ["systemctl", "is-active", "--quiet"] for command in commands))
                if app == "audiobookshelf":
                    self.assertTrue(any(command[0] == "python3" and "-" in command for command in commands))
                else:
                    suffix = "/healthz" if app == "n8n" else "/"
                    url = f"http://127.0.0.1:{fixture.metadata['default_port']}{suffix}"
                    self.assertTrue(any(command[0] == "curl" and url in command for command in commands))
                if app in ("n8n", "thelounge"):
                    self.assertEqual(stat.S_IMODE(unit.stat().st_mode), 0o644)
                    self.assertNotEqual(unit.stat().st_ino, unit_inode)
                    self.assertEqual(unit.stat().st_nlink, 1)
                    self.assertFalse(unit.is_symlink())

    def test_post_mutation_failure_restores_complete_snapshot_and_original_active_state(self):
        for app in APPLICATIONS:
            for was_active in (True, False):
                with self.subTest(app=app, was_active=was_active), self.fixture(app) as fixture:
                    if not was_active:
                        self.active_marker(fixture).unlink()
                    before = self.runtime_state(fixture, identities=False)
                    result = fixture.run("update", AF_FIXTURE_VERSION="2.2.0", AF_FIXTURE_FAILURE="service")
                    self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
                    self.assertEqual(self.runtime_state(fixture, identities=False), before)
                    self.assertEqual(self.active_marker(fixture).exists(), was_active)
                    self.assertEqual(self.backups(fixture), [])

    def test_post_mutation_stop_failure_keeps_backup_and_skips_restoration(self):
        for app in APPLICATIONS:
            with self.subTest(app=app), self.fixture(app) as fixture:
                self.copy_probe(fixture)
                for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
                    executable = directory / "systemctl"
                    source = executable.read_text()
                    anchor = "if command == 'systemctl':\n"
                    self.assertIn(anchor, source)
                    replacement = '''if command == 'systemctl':
    if arguments[0] == 'stop' and (root / 'service-failed').exists():
        sys.exit(78)
    if arguments[0] in ('start', 'restart', 'enable'):
        (root / 'var/lib' / app / 'r21-retained-state').write_text('mutated runtime state\\n')
'''
                    executable.write_text(source.replace(anchor, replacement, 1))
                offset = len(self.commands(fixture))
                result = fixture.run("update", AF_FIXTURE_VERSION="2.2.0", AF_FIXTURE_FAILURE="service")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual((fixture.root / f"var/lib/{app}/r21-retained-state").read_text(), "mutated runtime state\n")
                backups = self.backups(fixture)
                self.assertEqual(len(backups), 1)
                self.assertIn(f"recovery backup preserved at {backups[0]}", result.stderr)
                copies = [command for command in self.commands(fixture, offset) if command[0] == "cp"]
                self.assertFalse([command for command in copies if Path(command[-2]).parent == backups[0]])


if __name__ == "__main__":
    unittest.main()
