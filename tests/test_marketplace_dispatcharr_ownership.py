"""Rebased Dispatcharr scripts with fake services, SQL, downloads and identities."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, common_functions, replace_paths_once
from test_marketplace_dispatcharr import UPGRADE_MOCK
from test_marketplace_teardown import FAKE_COMMAND

COMMON_DIRECTORIES = ("logos", "recordings", "uploads", "m3us", "epgs", "plugins", "backups", "logs", "cache")
MARKER = ".aetherflow-data-owner"
SCRIPT_ROOT = ROOT


class DispatcharrOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "var/lib/dispatcharr"
        self.config = self.root / "etc/dispatcharr"
        self.link = self.root / "data"
        self.bin = self.root / "fake-bin"
        for directory in ("fake-bin", "opt/AetherFlow/packages", "etc/systemd/system", "var/log/aetherflow", "install", "upstream/frontend"):
            (self.root / directory).mkdir(parents=True)
        for relative in ("pyproject.toml", "manage.py", "frontend/package.json"):
            self.file("upstream/" + relative, "vendor fixture")
        mock = UPGRADE_MOCK.replace('sys.exit(subprocess.run(["/usr/bin/git", *args]).returncode)', 'shutil.copytree(root / "upstream", pathlib.Path(args[-1]), dirs_exist_ok=True)')
        mock = mock.replace('if args[:2] == ["-", "postgres"]:', 'if os.environ.get("FAIL_SQL") and os.environ["FAIL_SQL"] in args[-1]:\n        sys.exit(42)\n    if args[:2] == ["-", "postgres"]:')
        mock = mock.replace('"chown", "id", "useradd"):', '"chown", "id", "useradd", "getent", "userdel", "groupdel"):')
        for command in ("git", "python3.13", "su", "runuser", "npm", "systemctl", "apt-get", "chown", "id", "useradd", "getent", "userdel", "groupdel"):
            self.file("fake-bin/" + command, mock).chmod(0o755)
        self.file("fake-bin/rm", FAKE_COMMAND).chmod(0o755)
        self.file("database", "old-schema")
        self.file("install/.dispatcharr.lock", "installed")
        self.file("opt/dispatcharr/old-code", "old-runtime")
        self.file("etc/dispatcharr/db_pass", "a" * 32)
        self.file("etc/dispatcharr/secret_key", "b" * 64)
        self.file("etc/dispatcharr/dispatcharr.env", "CUSTOM_SETTING=keep-me\nDISPATCHARR_PORT=19491\nDISPATCHARR_LOG_LEVEL=DEBUG\n")
        for unit in ("dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat"):
            self.file(f"etc/systemd/system/{unit}.service", "old-unit")
            self.file(f"active-{unit}.service", "active")
        common = """set -euo pipefail
require_root() { :; }
load_master_credentials() { MASTER_USER=admin; MASTER_PASS=testpass; }
log_info() { printf '%s\\n' "$*"; }
log_warn() { printf '%s\\n' "$*" >&2; }
log_error() { printf '%s\\n' "$*" >&2; }
print_error() { printf '%s\\n' "$*" >&2; }
report_progress() { printf '[PROGRESS:%s] %s\\n' "$1" "$2"; }
ensure_node() { :; }
write_lock() { touch "$TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f "$AF_ARCHIVE_BACKUP/.af-archive-pending"; }
lock_path() { printf '%s/install/.%s.lock\\n' "$TEST_ROOT" "$1"; }
remove_lock() { rm -f "$TEST_ROOT/install/.$1.lock"; }
"""
        names = ("node_build", "queue_app_version", "commit_app_versions", "safe_restore_path_from_backup", "write_app_version", "safe_config_python", "validate_config_paths", "write_config_file", "purge_systemd_unit", "purge_system_user", "command_exists", "safe_rm_rf")
        source = (ROOT / "packages/common.sh").read_text()
        names += tuple(name for name in ("purge_systemd_units", "stop_systemd_unit", "systemd_unit_inactive", "backup_postgresql_database", "restore_postgresql_database") if f"\n{name}() " in source)
        common += self.rebase(common_functions(*names))
        self.file("opt/AetherFlow/packages/common.sh", common)

    def file(self, relative, body):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        return target

    def rebase(self, source):
        return replace_paths_once(source, [(prefix, str(self.root) + prefix) for prefix in ("/opt/", "/var/", "/etc/", "/install", "/home/", "/data")])

    def run_script(self, action="install", **environment):
        source = (SCRIPT_ROOT / f"packages/package/{action}/{action}package-dispatcharr").read_text()
        script = self.file(f"{action}.sh", self.rebase(source))
        return subprocess.run(["bash", str(script)], env={
            **os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "TEST_ROOT": str(self.root),
            "AF_TARGET_VERSION": "0.33.0", **environment,
        }, text=True, capture_output=True, timeout=30)

    def seed_owned(self, compatibility=False):
        self.file(f"var/lib/dispatcharr/{MARKER}", f"aetherflow-dispatcharr-data-v1:{self.data}\n").chmod(0o600)
        self.data.chmod(0o755)
        for directory in COMMON_DIRECTORIES:
            (self.data / directory).mkdir(exist_ok=True)
        if compatibility:
            self.link.symlink_to(self.data)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_recovery(self):
        self.assertEqual((self.config / "db_pass").read_text().strip(), "a" * 32)
        self.assertEqual((self.config / "secret_key").read_text().strip(), "b" * 64)
        self.assertTrue((self.root / "install/.dispatcharr.lock").is_file())

    def test_fresh_install_establishes_owned_storage(self):
        self.assert_success(self.run_script())
        self.assertTrue((self.data / MARKER).is_file())
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(self.link.resolve(), self.data)
        for directory in COMMON_DIRECTORIES:
            self.assertTrue((self.data / directory).is_dir())
            self.assertFalse((self.data / directory).is_symlink())

    def test_empty_dedicated_directory_can_be_initialized(self):
        self.data.mkdir(parents=True)
        self.assert_success(self.run_script())
        self.assertTrue((self.data / MARKER).is_file())

    def test_nonempty_unmarked_directory_is_not_adopted(self):
        retained = self.file("var/lib/dispatcharr/logos/other-app/keep", "unowned bytes")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(retained.read_bytes(), b"unowned bytes")
        self.assertFalse((self.data / MARKER).exists())
        self.assert_recovery()
        self.assertNotIn("ALTER USER", self.commands())

    def commands(self):
        log = self.root / "commands"
        return log.read_text() if log.exists() else ""

    def test_shared_real_data_install_rejects_every_common_name_before_mutation(self):
        for directory in COMMON_DIRECTORIES:
            with self.subTest(directory=directory):
                retained = self.file(f"data/{directory}/other-app/nested.bin", "foreign\x00bytes")
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(retained.read_bytes(), b"foreign\x00bytes")
                self.assert_recovery()
                self.assertNotIn("ALTER USER", self.commands())
                self.assertNotIn("chown -R dispatcharr:dispatcharr", self.commands())

    def test_legacy_link_without_marker_is_not_adopted_or_purged(self):
        retained = self.file("var/lib/dispatcharr/logos/legacy", "legacy retained")
        self.link.symlink_to(self.data)
        for action in ("install", "remove"):
            with self.subTest(action=action):
                result = self.run_script(action, DELETE_DATA="true")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(retained.read_bytes(), b"legacy retained")
                self.assertTrue(self.link.is_symlink())
                self.assert_recovery()
                self.assertNotIn("PROGRESS:100", result.stdout)

    def test_normal_remove_retains_data_link_config_and_account(self):
        self.seed_owned(compatibility=True)
        retained = self.file("var/lib/dispatcharr/uploads/keep", "retained data")
        self.assert_success(self.run_script("remove"))
        self.assertEqual(retained.read_bytes(), b"retained data")
        self.assertTrue(self.link.is_symlink())
        self.assertTrue((self.data / MARKER).is_file())
        self.assertEqual((self.config / "db_pass").read_text(), "a" * 32)
        self.assertNotIn("DROP DATABASE", self.commands())
        self.assertNotIn("userdel", self.commands())
        self.assertFalse((self.root / "opt/dispatcharr").exists())

    def test_explicit_purge_removes_owned_data_and_link(self):
        self.seed_owned(compatibility=True)
        self.file("var/lib/dispatcharr/uploads/keep", "owned data")
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertFalse(self.data.exists())
        self.assertFalse(self.link.is_symlink())
        self.assertFalse(self.config.exists())
        self.assertFalse((self.root / "install/.dispatcharr.lock").exists())

    def test_foreign_compatibility_link_is_preserved(self):
        retained = self.file("foreign/logos/keep", "foreign data")
        self.link.symlink_to(self.root / "foreign")
        self.assertNotEqual(self.run_script().returncode, 0)
        self.seed_owned()
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(retained.read_bytes(), b"foreign data")

    def test_reinstall_update_preserve_data_secrets_custom_config_and_port(self):
        self.assert_success(self.run_script(AF_APP_PORT="19492"))
        retained = self.file("var/lib/dispatcharr/uploads/keep", "existing data")
        for action in ("install", "update"):
            with self.subTest(action=action):
                self.assert_success(self.run_script(AF_PACKAGE_ACTION=action))
                self.assertEqual(retained.read_bytes(), b"existing data")
                environment = (self.config / "dispatcharr.env").read_text()
                for expected in ("CUSTOM_SETTING=keep-me\n", "DISPATCHARR_PORT=19492\n", "DISPATCHARR_LOG_LEVEL=DEBUG\n"):
                    self.assertIn(expected, environment)
                self.assert_recovery()

    def test_remove_then_reinstall_accepts_retained_relative_compatibility_link(self):
        self.assert_success(self.run_script(AF_APP_PORT="19494"))
        retained = self.file("var/lib/dispatcharr/uploads/keep", "retained through uninstall")
        self.assertTrue(self.link.is_symlink())
        self.link.unlink()
        self.link.symlink_to(os.path.relpath(self.data, self.root))
        self.assert_success(self.run_script("remove"))
        self.assert_success(self.run_script())
        self.assertEqual(retained.read_bytes(), b"retained through uninstall")
        self.assertEqual(self.link.resolve(), self.data)
        self.assertIn("DISPATCHARR_PORT=19494\n", (self.config / "dispatcharr.env").read_text())

    def test_first_install_activation_failure_retains_owned_retryable_storage(self):
        (self.root / "opt/dispatcharr/old-code").unlink()
        (self.root / "opt/dispatcharr").rmdir()
        (self.root / "install/.dispatcharr.lock").unlink()
        for unit in ("dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat"):
            (self.root / f"etc/systemd/system/{unit}.service").unlink()
            (self.root / f"active-{unit}.service").unlink()
        before = (self.config / "dispatcharr.env").read_bytes()
        result = self.run_script(FAIL_STAGE="systemctl")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.data / MARKER).is_file())
        self.assertTrue(self.link.is_symlink())
        self.assertEqual((self.config / "dispatcharr.env").read_bytes(), before)
        self.assertFalse((self.root / "install/.dispatcharr.lock").exists())
        self.assertFalse((self.root / "opt/dispatcharr").exists())
        self.assertNotIn("PROGRESS:100", result.stdout)
        self.assert_success(self.run_script())

    def test_runtime_writable_directories_survive_remove_reinstall_and_purge(self):
        self.assert_success(self.run_script())
        retained = []
        for directory in ("media", "logo_cache"):
            relative = self.root / "opt/dispatcharr" / directory
            self.assertTrue(relative.is_symlink())
            self.assertEqual(relative.resolve(), self.data / directory)
            retained.append(self.file(f"opt/dispatcharr/{directory}/keep", "writable runtime state"))
        self.assert_success(self.run_script("remove"))
        for directory in ("media", "logo_cache"):
            self.assertEqual((self.data / directory / "keep").read_bytes(), b"writable runtime state")
        self.assert_success(self.run_script())
        for target in retained:
            self.assertEqual(target.read_bytes(), b"writable runtime state")
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertFalse(self.data.exists())

    def test_update_preserves_prior_real_runtime_media_without_shared_adoption(self):
        for directory in ("media", "logo_cache"):
            self.file(f"opt/dispatcharr/{directory}/keep", "prior runtime data")
        self.assert_success(self.run_script())
        for directory in ("media", "logo_cache"):
            self.assertTrue((self.root / "opt/dispatcharr" / directory).is_symlink())
            self.assertEqual((self.data / directory / "keep").read_bytes(), b"prior runtime data")

    def test_prior_runtime_media_symlink_never_adopts_foreign_contents(self):
        retained = self.file("foreign/keep", "unowned bytes")
        (self.root / "opt/dispatcharr/media").symlink_to(retained.parent)
        self.assert_success(self.run_script())
        self.assertTrue((self.root / "opt/dispatcharr/media").is_symlink())
        self.assertEqual((self.root / "opt/dispatcharr/media").resolve(), self.data / "media")
        self.assertFalse((self.data / "media/keep").exists())
        self.assertEqual(retained.read_bytes(), b"unowned bytes")

    def test_activation_failure_restores_runtime_units_config_and_database(self):
        self.seed_owned(compatibility=True)
        retained = self.file("var/lib/dispatcharr/uploads/keep", "existing data")
        before = (self.config / "dispatcharr.env").read_bytes()
        result = self.run_script(FAIL_STAGE="systemctl")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(retained.read_bytes(), b"existing data")
        self.assertEqual((self.config / "dispatcharr.env").read_bytes(), before)
        self.assertEqual((self.root / "opt/dispatcharr/old-code").read_text(), "old-runtime")
        self.assertEqual((self.root / "database").read_text(), "old-schema")
        for unit in ("dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat"):
            self.assertEqual((self.root / f"etc/systemd/system/{unit}.service").read_text(), "old-unit")
            self.assertTrue((self.root / f"active-{unit}.service").exists())
        self.assertNotIn("PROGRESS:100", result.stdout)

    def test_sql_failures_retain_owned_recovery_material(self):
        self.seed_owned(compatibility=True)
        retained = self.file("var/lib/dispatcharr/backups/keep", "database-dependent data")
        for statement in ("DROP DATABASE", "DROP USER"):
            with self.subTest(statement=statement):
                result = self.run_script("remove", DELETE_DATA="true", FAIL_SQL=statement)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(retained.read_bytes(), b"database-dependent data")
                self.assertTrue(self.link.is_symlink())
                self.assert_recovery()
                self.assertNotIn("PROGRESS:100", result.stdout)

    def test_purge_never_traverses_nested_symlinks(self):
        self.seed_owned(compatibility=True)
        retained = self.file("foreign/nested/keep", "foreign bytes")
        (self.data / "uploads/foreign").symlink_to(retained.parent)
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertEqual(retained.read_bytes(), b"foreign bytes")

    def test_install_never_recursively_chowns_nested_symlinks(self):
        self.seed_owned(compatibility=True)
        retained = self.file("foreign/nested/keep", "foreign bytes")
        (self.data / "uploads/foreign").symlink_to(retained.parent)
        self.assert_success(self.run_script())
        self.assertEqual(retained.read_bytes(), b"foreign bytes")
        self.assertNotIn(f"chown -R dispatcharr:dispatcharr {self.data}", self.commands())
        self.assertNotIn(f"chown -R dispatcharr:dispatcharr {self.link}", self.commands())

    def test_managed_subdirectory_symlink_collision_is_rejected(self):
        self.seed_owned(compatibility=True)
        retained = self.file("foreign/keep", "foreign bytes")
        (self.data / "uploads").rmdir()
        (self.data / "uploads").symlink_to(retained.parent)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(retained.read_bytes(), b"foreign bytes")
        self.assert_recovery()

    def test_root_and_ancestor_symlinks_are_rejected(self):
        retained = self.file("foreign/keep", "foreign bytes")
        self.data.parent.mkdir(parents=True, exist_ok=True)
        self.data.symlink_to(retained.parent)
        for action in ("install", "remove"):
            with self.subTest(action=action):
                self.assertNotEqual(self.run_script(action, DELETE_DATA="true").returncode, 0)
                self.assertEqual(retained.read_bytes(), b"foreign bytes")
                self.assert_recovery()
        self.assertTrue(self.data.is_symlink())
        self.data.unlink()
        self.data.parent.rmdir()
        self.data.parent.symlink_to(retained.parent)
        self.assertNotEqual(self.run_script("remove", DELETE_DATA="true").returncode, 0)
        self.assertEqual(retained.read_bytes(), b"foreign bytes")
        self.assert_recovery()

    def test_symlink_marker_cannot_authorize_purge(self):
        self.seed_owned()
        marker = self.data / MARKER
        marker.rename(self.root / "foreign-marker")
        marker.symlink_to(self.root / "foreign-marker")
        self.assertNotEqual(self.run_script("remove", DELETE_DATA="true").returncode, 0)
        self.assert_recovery()
        self.assertTrue((self.root / "foreign-marker").is_file())

    def test_invalid_marker_contents_or_permissions_cannot_authorize_purge(self):
        marker = self.data / MARKER
        for invalid in ("contents", "marker-writable", "root-writable", "hardlink"):
            with self.subTest(invalid=invalid):
                self.seed_owned()
                marker.write_text(f"aetherflow-dispatcharr-data-v1:{self.data}\n")
                marker.chmod(0o600)
                self.data.chmod(0o755)
                if invalid == "contents":
                    marker.write_text("not Dispatcharr provenance")
                elif invalid == "marker-writable":
                    marker.chmod(0o666)
                elif invalid == "root-writable":
                    self.data.chmod(0o777)
                else:
                    os.link(marker, self.root / "linked-marker")
                result = self.run_script("remove", DELETE_DATA="true")
                self.assertNotEqual(result.returncode, 0)
                self.assert_recovery()
                self.assertNotIn("DROP DATABASE", self.commands())

    def test_quoted_retained_allocated_port_is_not_reset(self):
        self.file("etc/dispatcharr/dispatcharr.env", 'export DISPATCHARR_PORT="19493" # retained allocation\nCUSTOM_SETTING=keep-me\n')
        self.assert_success(self.run_script())
        self.assertIn("DISPATCHARR_PORT=19493\n", (self.config / "dispatcharr.env").read_text())

    def test_owned_purge_never_removes_unproven_home_directory(self):
        self.seed_owned(compatibility=True)
        retained = self.file("home/dispatcharr/other-app/keep", "unowned home data")
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertTrue(retained.is_file())
        self.assertEqual(retained.read_bytes(), b"unowned home data")

    def test_dangling_foreign_compatibility_link_is_not_replaced_or_unlinked(self):
        self.link.symlink_to(self.root / "missing-foreign-data")
        self.assertNotEqual(self.run_script().returncode, 0)
        self.seed_owned()
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(os.readlink(self.link), str(self.root / "missing-foreign-data"))

    def test_owned_cleanup_failure_retains_credentials_and_marker(self):
        self.seed_owned(compatibility=True)
        result = self.run_script("remove", DELETE_DATA="true", FAIL_PATH=str(self.data))
        self.assertNotEqual(result.returncode, 0)
        self.assert_recovery()
        self.assertTrue(self.data.exists())
        self.assertNotIn("PROGRESS:100", result.stdout)


def shared_name_regression(directory):
    def test_shared_name(self):
        self.seed_owned()
        retained = self.file(f"data/{directory}/other-app/nested.bin", "foreign\x00bytes")
        self.assert_success(self.run_script("remove", DELETE_DATA="true"))
        self.assertTrue(retained.is_file())
        self.assertEqual(retained.read_bytes(), b"foreign\x00bytes")
    return test_shared_name


for directory in COMMON_DIRECTORIES:
    setattr(DispatcharrOwnershipTests, f"test_purge_preserves_shared_{directory}_foreign_bytes", shared_name_regression(directory))


if __name__ == "__main__":
    unittest.main()
