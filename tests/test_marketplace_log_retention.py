"""Fixture-only coverage for shipped marketplace lifecycle log retention."""

import fcntl
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/log-retention.py"
SPEC = importlib.util.spec_from_file_location("marketplace_log_retention", HELPER)
retention = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retention)


def shell_function(path, name):
    source = path.read_text()
    start = re.search(rf"^(?:function )?{re.escape(name)}\(\) \{{\n", source, re.MULTILINE)
    if start is None:
        raise AssertionError(f"Missing shell function {name}")
    return source[start.start():source.index("\n}\n", start.end()) + 3]


class LogRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-log-retention-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir(mode=0o750)

    def write(self, name, content, mode=0o600):
        path = self.logs / name
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def rotate(self, max_bytes=64, keep=3):
        return retention.retain_logs(self.logs, max_bytes=max_bytes, keep=keep)

    def archive(self, name="install-sonarr.log", generation=1):
        return self.logs / f"{name}.af-retention.{generation}"

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-B", str(HELPER), "--log-dir", str(self.logs),
                               *arguments], capture_output=True, text=True, timeout=10)

    def test_default_policy_is_ten_mib_and_three_archives(self):
        self.assertEqual(retention.DEFAULT_MAX_BYTES, 10485760)
        self.assertEqual(retention.DEFAULT_KEEP, 3)

    def test_native_and_bash_names_share_the_shipped_policy(self):
        names = ["install.log", "install-sonarr.log", "remove-sonarr.log", "install-seedcross.log",
                 "remove-xrdp.log", "install-native.v2_test.log", "install-native..log",
                 "install-" + "a" * 64 + ".log"]
        for name in names:
            self.write(name, b"x" * 65)
        self.assertEqual(self.rotate(), (len(names), []))
        for name in names:
            self.assertEqual((self.logs / name).read_bytes(), b"")
            self.assertEqual(self.archive(name).read_bytes(), b"x" * 64)

    def test_below_and_at_threshold_keep_content_and_inode(self):
        for size in (0, 20, 64):
            path = self.write("install-sonarr.log", b"x" * size)
            inode = path.stat().st_ino
            self.assertEqual(self.rotate(), (0, []))
            self.assertEqual(path.read_bytes(), b"x" * size)
            self.assertEqual(path.stat().st_ino, inode)
            self.assertFalse(self.archive().exists())

    def test_already_enormous_log_copies_only_a_bounded_tail(self):
        path = self.write("install-sonarr.log", b"")
        with path.open("wb") as writer:
            writer.truncate(128 * 1024 * 1024)
            writer.seek(-64, os.SEEK_END)
            writer.write(b"tail" * 16)
        inode = path.stat().st_ino
        with mock.patch.object(retention.os, "pread", wraps=os.pread) as reads:
            self.assertEqual(self.rotate(), (1, []))
        self.assertEqual(sum(call.args[1] for call in reads.call_args_list), 64)
        self.assertEqual(self.archive().read_bytes(), b"tail" * 16)
        self.assertEqual(path.stat().st_size, 0)
        self.assertEqual(path.stat().st_ino, inode)

    def test_native_style_open_append_descriptor_survives_rotation(self):
        path = self.write("remove-sonarr.log", b"before\n" * 30)
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            inode = os.fstat(descriptor).st_ino
            self.assertEqual(self.rotate(), (1, []))
            os.write(descriptor, b"native-after\n")
            self.assertEqual(os.fstat(descriptor).st_ino, inode)
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(path.read_bytes(), b"native-after\n")
        finally:
            os.close(descriptor)

    def test_bash_external_append_redirect_remains_on_visible_inode(self):
        path = self.write("install-seedcross.log", b"")
        inode = path.stat().st_ino
        result = subprocess.run(["bash", "-euc", r'''
exec 3>>"$1"
printf '%s' "$4" >&3
"$2" -B "$3" --log-dir "${1%/*}" --max-bytes 64 --keep 3
printf 'bash-after\n' >&3
''', "--", str(path), sys.executable, str(HELPER), "before" * 30],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.read_bytes(), b"bash-after\n")
        self.assertEqual(self.archive(path.name).stat().st_size, 64)

    def test_busy_writer_does_not_expand_the_snapshot_copy_budget(self):
        path = self.write("install-sonarr.log", b"x" * 128)
        real_read = os.pread
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)

        def append_during_read(source, size, offset):
            os.write(descriptor, b"concurrent" * 100)
            return real_read(source, size, offset)

        try:
            with mock.patch.object(retention.os, "pread", side_effect=append_during_read) as reads:
                self.assertEqual(self.rotate(), (1, []))
            self.assertEqual(reads.call_count, 1)
            self.assertEqual(self.archive().stat().st_size, 64)
            os.write(descriptor, b"after\n")
            self.assertEqual(path.read_bytes(), b"after\n")
        finally:
            os.close(descriptor)

    def test_retention_count_and_generation_order(self):
        for generation in range(6):
            self.write("install-sonarr.log", str(generation).encode() * 100)
            self.assertEqual(self.rotate(keep=2), (1, []))
        self.assertEqual(self.archive(generation=1).read_bytes(), b"5" * 64)
        self.assertEqual(self.archive(generation=2).read_bytes(), b"4" * 64)
        self.assertEqual(len(list(self.logs.glob("install-sonarr.log.af-retention.*"))), 2)

    def test_lowered_limits_trim_and_prune_archives_without_rotating_active(self):
        active = self.write("install-sonarr.log", b"small")
        for generation in range(1, 5):
            self.write(self.archive(generation=generation).name, b"older" * 40)
        self.assertEqual(self.rotate(max_bytes=20, keep=2), (0, []))
        self.assertEqual(active.read_bytes(), b"small")
        self.assertEqual(self.archive(generation=1).read_bytes(), b"older" * 4)
        self.assertEqual(self.archive(generation=2).read_bytes(), b"older" * 4)
        self.assertFalse(self.archive(generation=3).exists())
        self.assertFalse(self.archive(generation=4).exists())

    def test_interrupted_pending_copy_is_reclaimed_before_trimming(self):
        self.write("install-sonarr.log", b"small")
        self.write(self.archive().name, b"a" * 128)
        pending = self.write("install-sonarr.log.af-retention.pending", b"incomplete")
        self.assertEqual(self.rotate(), (0, []))
        self.assertEqual(self.archive().read_bytes(), b"a" * 64)
        self.assertFalse(pending.exists())

    def test_unrelated_files_directories_and_nonmanaged_archives_are_untouched(self):
        names = ["setup.log", "release-manager.log", "quasselcore.log", "operator.log",
                 "install-sonarr.log.1", "install-sonarr.log.gz", "install-sonarr.log.af-retention.01",
                 "install-sonarr.log.af-retention.other",
                 "install-..bad.log", "install-a..bad.log", "install--bad.log",
                 "install-" + "a" * 65 + ".log"]
        paths = [self.write(name, b"untouched" * 20, 0o644) for name in names]
        nested = self.logs / "nested"
        nested.mkdir()
        paths.append(nested / "install-sonarr.log")
        paths[-1].write_bytes(b"nested" * 20)
        snapshots = [(path, path.read_bytes(), path.stat().st_mode, path.stat().st_ino) for path in paths]
        self.assertEqual(self.rotate(), (0, []))
        for path, content, mode, inode in snapshots:
            self.assertEqual((path.read_bytes(), path.stat().st_mode, path.stat().st_ino),
                             (content, mode, inode))

    def test_active_symlink_is_rejected_and_other_safe_log_is_retained(self):
        victim = self.root / "victim"
        victim.write_bytes(b"private")
        (self.logs / "install-sonarr.log").symlink_to(victim)
        self.write("remove-sonarr.log", b"safe" * 40)
        rotated, errors = self.rotate()
        self.assertEqual(rotated, 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(victim.read_bytes(), b"private")
        self.assertTrue((self.logs / "install-sonarr.log").is_symlink())

    def test_archive_and_pending_symlinks_prevent_active_truncation(self):
        for suffix in ("1", "pending"):
            with self.subTest(suffix=suffix):
                active = self.write("install-sonarr.log", b"active" * 30)
                victim = self.root / "victim"
                victim.write_bytes(b"private")
                link = self.logs / f"install-sonarr.log.af-retention.{suffix}"
                link.symlink_to(victim)
                rotated, errors = self.rotate()
                self.assertEqual((rotated, len(errors)), (0, 1))
                self.assertEqual(active.read_bytes(), b"active" * 30)
                self.assertEqual(victim.read_bytes(), b"private")
                self.assertTrue(link.is_symlink())
                link.unlink()

    def test_log_directory_and_ancestor_symlinks_are_rejected(self):
        self.write("install-sonarr.log", b"active" * 30)
        link = self.root / "linked"
        link.symlink_to(self.logs, target_is_directory=True)
        ancestor = self.root / "ancestor"
        ancestor.symlink_to(self.root, target_is_directory=True)
        for path in (link, ancestor / "logs"):
            with self.subTest(path=path), self.assertRaises(OSError):
                retention.retain_logs(path, max_bytes=64)
        self.assertEqual((self.logs / "install-sonarr.log").read_bytes(), b"active" * 30)
        self.assertFalse((self.logs / ".af-retention.lock").exists())

    def test_root_relative_and_traversal_directories_are_rejected(self):
        for path in ("/", "relative", str(self.logs) + "/../logs"):
            with self.subTest(path=path), self.assertRaises(retention.UnsafeLogError):
                retention.retain_logs(path, max_bytes=64)
        self.assertEqual(list(self.logs.iterdir()), [])

    def test_active_hardlink_and_archive_hardlink_are_rejected(self):
        active = self.write("install-sonarr.log", b"active" * 30)
        outside = self.root / "outside"
        os.link(active, outside)
        rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(outside.read_bytes(), b"active" * 30)
        outside.unlink()
        archive = self.write(self.archive().name, b"archive")
        os.link(archive, outside)
        rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(active.read_bytes(), b"active" * 30)
        self.assertEqual(outside.read_bytes(), b"archive")

    def test_fifo_and_directory_named_as_log_do_not_block(self):
        os.mkfifo(self.logs / "install-fifo.log", 0o600)
        (self.logs / "remove-directory.log").mkdir()
        rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 2))

    def test_foreign_file_owner_is_rejected_without_chmod(self):
        active = self.write("install-sonarr.log", b"active" * 30, 0o644)
        inode = active.stat().st_ino
        real_stat = os.fstat

        def foreign_owner(descriptor):
            metadata = real_stat(descriptor)
            values = list(metadata)
            if metadata.st_ino == inode:
                values[4] += 123
                return os.stat_result(values)
            return metadata

        with mock.patch.object(retention.os, "fstat", side_effect=foreign_owner):
            rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(stat.S_IMODE(active.stat().st_mode), 0o644)
        self.assertEqual(active.read_bytes(), b"active" * 30)

    def test_legacy_directory_migration_uses_only_the_pinned_descriptor(self):
        inode = self.logs.stat().st_ino
        real_stat = os.fstat
        legacy_uid = os.geteuid() + 123

        def legacy_directory(descriptor):
            metadata = real_stat(descriptor)
            if metadata.st_ino != inode:
                return metadata
            values = list(metadata)
            values[4] = legacy_uid
            return os.stat_result(values)

        with mock.patch.object(retention.os, "fstat", side_effect=legacy_directory):
            with self.assertRaises(retention.UnsafeLogError):
                self.rotate()
            with mock.patch.object(retention.os, "fchown") as ownership:
                self.assertEqual(retention.retain_logs(self.logs, max_bytes=64, legacy_uid=legacy_uid), (0, []))
        ownership.assert_called_once()
        self.assertEqual(ownership.call_args.args[1:], (os.geteuid(), os.getegid()))

    def test_writable_archive_rejects_rotation_without_touching_active(self):
        active = self.write("install-sonarr.log", b"active" * 30)
        archive = self.write(self.archive().name, b"older", 0o666)
        rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(active.read_bytes(), b"active" * 30)
        self.assertEqual((archive.read_bytes(), stat.S_IMODE(archive.stat().st_mode)), (b"older", 0o666))

    def test_unsafe_writable_files_and_directory_fail_closed(self):
        active = self.write("install-sonarr.log", b"active" * 30, 0o666)
        rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(stat.S_IMODE(active.stat().st_mode), 0o666)
        self.logs.chmod(0o777)
        with self.assertRaises(retention.UnsafeLogError):
            self.rotate()
        self.assertEqual(active.read_bytes(), b"active" * 30)

    def test_trusted_log_permissions_and_lock_are_restricted(self):
        active = self.write("install-sonarr.log", b"active" * 30, 0o644)
        self.assertEqual(self.rotate(), (1, []))
        for path in (active, self.archive()):
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.geteuid(), os.getegid()))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.logs / ".af-retention.lock").stat().st_mode), 0o600)

    def test_second_retainer_rejects_locked_directory(self):
        self.write("install-sonarr.log", b"active" * 30)
        with (self.logs / ".af-retention.lock").open("wb") as lock:
            lock_path = self.logs / ".af-retention.lock"
            lock_path.chmod(0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.rotate()
        self.assertEqual((self.logs / "install-sonarr.log").read_bytes(), b"active" * 30)

    def test_lock_symlink_is_never_followed(self):
        victim = self.root / "victim"
        victim.write_bytes(b"private")
        (self.logs / ".af-retention.lock").symlink_to(victim)
        with self.assertRaises(OSError):
            self.rotate()
        self.assertEqual(victim.read_bytes(), b"private")

    def test_lock_hardlink_is_rejected_without_touching_other_path(self):
        victim = self.root / "victim"
        victim.write_bytes(b"private")
        victim.chmod(0o644)
        os.link(victim, self.logs / ".af-retention.lock")
        with self.assertRaises(retention.UnsafeLogError):
            self.rotate()
        self.assertEqual((victim.read_bytes(), stat.S_IMODE(victim.stat().st_mode)), (b"private", 0o644))

    def test_archive_copy_failure_never_truncates_active_and_next_run_recovers(self):
        active = self.write("install-sonarr.log", b"active" * 30)
        with mock.patch.object(retention.os, "pread", side_effect=OSError("fixture disk error")):
            rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(active.read_bytes(), b"active" * 30)
        self.assertFalse(self.archive().exists())
        self.assertEqual(self.rotate(), (1, []))
        self.assertEqual(self.archive().stat().st_size, 64)
        self.assertFalse((self.logs / "install-sonarr.log.af-retention.pending").exists())

    def test_active_path_replacement_cannot_truncate_a_symlink_target(self):
        active = self.write("install-sonarr.log", b"active" * 30)
        victim = self.root / "victim"
        victim.write_bytes(b"private")
        moved = self.logs / "operator-held.log"
        copy = retention._copy_tail

        def replace_during_copy(*arguments):
            copy(*arguments)
            active.rename(moved)
            active.symlink_to(victim)

        with mock.patch.object(retention, "_copy_tail", side_effect=replace_during_copy):
            rotated, errors = self.rotate()
        self.assertEqual((rotated, len(errors)), (0, 1))
        self.assertEqual(victim.read_bytes(), b"private")
        self.assertEqual(moved.read_bytes(), b"active" * 30)
        self.assertTrue(active.is_symlink())

    def test_new_log_directory_is_created_safely(self):
        self.logs.rmdir()
        self.assertEqual(self.rotate(), (0, []))
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o750)

    def test_invalid_limits_fail_before_creating_directory(self):
        self.logs.rmdir()
        for arguments in (("--max-bytes", "0"), ("--keep", "0"),
                          ("--max-bytes", "67108865"), ("--keep", "21")):
            with self.subTest(arguments=arguments):
                result = self.cli(*arguments)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("must be", result.stderr)
                self.assertFalse(self.logs.exists())

    def test_cli_reports_rejected_entries_as_failure(self):
        (self.logs / "install-sonarr.log").symlink_to(self.root / "missing")
        result = self.cli("--max-bytes", "64")
        self.assertEqual(result.returncode, 1)
        self.assertIn("rejected 1", result.stdout)
        self.assertIn("install-sonarr.log", result.stderr)


class LogRetentionDeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-log-retention-delivery-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.current = self.root / "current"
        copied_deploy = self.current / "deploy"
        shutil.copytree(ROOT / "deploy", copied_deploy)
        copied_deploy.chmod(copied_deploy.stat().st_mode | stat.S_IWUSR)
        self.units = self.root / "units"
        self.commands = self.root / "commands.log"

    def restart(self, fail_start=False):
        body = shell_function(ROOT / "deploy/release-manager.sh", "install_packaged_unit")
        body += shell_function(ROOT / "deploy/release-manager.sh", "restart_systemd_units")
        body += "\nrestart_systemd_units\n"
        preamble = r'''
CURRENT_LINK="$1"
SYSTEMD_UNITS_DST="$2"
LOG_FILE="$3"
verify_isolated_systemd_lifecycle_authorized() { :; }
log_info() { :; }
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$LOG_FILE"
    [[ "$*" != 'start aetherflow-log-retention.service' || "${FAIL_START}" != fail ]]
}
pm2() { printf 'stubbed pm2 %s\n' "$*" >> "$LOG_FILE"; }
'''
        return subprocess.run(["bash", "-euc", preamble + body, "--", str(self.current),
                               str(self.units), str(self.commands)], capture_output=True, text=True,
                              timeout=10, env={**os.environ, "FAIL_START": "fail" if fail_start else "pass"})

    def test_release_installs_and_activates_packaged_retention_units(self):
        result = self.restart()
        self.assertEqual(result.returncode, 0, result.stderr)
        for suffix in ("service", "timer"):
            name = "aetherflow-log-retention." + suffix
            self.assertEqual((self.units / name).read_bytes(), (ROOT / "deploy/systemd" / name).read_bytes())
        commands = self.commands.read_text()
        self.assertLess(commands.index("systemctl daemon-reload"),
                        commands.index("systemctl start aetherflow-log-retention.service"))
        self.assertLess(commands.index("systemctl enable --now aetherflow-log-retention.timer"),
                        commands.index("systemctl restart aetherflow-runner.service"))

    def test_release_retention_failure_is_not_silently_ignored(self):
        result = self.restart(fail_start=True)
        self.assertNotEqual(result.returncode, 0)
        commands = self.commands.read_text()
        self.assertIn("systemctl start aetherflow-log-retention.service", commands)
        self.assertNotIn("systemctl enable --now aetherflow-log-retention.timer", commands)
        self.assertNotIn("systemctl restart aetherflow-runner.service", commands)

    def test_pre_feature_release_does_not_enable_an_absent_helper(self):
        (self.current / "deploy/log-retention.py").unlink()
        result = self.restart()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("log-retention", self.commands.read_text())

    def test_release_preserves_operator_units(self):
        self.units.mkdir()
        installed = self.units / "aetherflow-log-retention.timer"
        installed.write_text("operator timer\n")
        result = self.restart()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(installed.read_text(), "operator timer\n")

    def test_binary_and_source_delivery_copy_deploy_and_setup_activates_policy(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn('cp -R deploy "${STAGE_DIR}/deploy"', workflow)
        source_build = (ROOT / "setup/modules/modern_stack.sh").read_text()
        self.assertIn('cp -R "${af_root}/deploy" "${release_dir}/deploy"', source_build)
        boot = shell_function(ROOT / "setup/modules/05-finalize.sh", "_boot")
        for suffix in ("service", "timer"):
            self.assertIn(f"/opt/AetherFlow/current/deploy/systemd/aetherflow-log-retention.{suffix}", boot)
        self.assertLess(boot.index("_harden_permissions"), boot.index("systemctl start aetherflow-log-retention.service"))
        self.assertLess(boot.index("systemctl enable --now aetherflow-log-retention.timer"),
                        boot.index("systemctl enable aetherflow-runner.service"))
        self.assertIn("systemctl start aetherflow-log-retention.service || return 1", boot)

    def test_shipped_unit_references_delivered_helper_and_explicit_policy(self):
        service = (self.current / "deploy/systemd/aetherflow-log-retention.service").read_text()
        self.assertIn("ExecStart=/usr/bin/python3 -B /opt/AetherFlow/current/deploy/log-retention.py", service)
        self.assertTrue((self.current / "deploy/log-retention.py").is_file())
        self.assertIn("Environment=AF_LOG_RETENTION_MAX_BYTES=10485760", service)
        self.assertIn("Environment=AF_LOG_RETENTION_KEEP=3", service)
        self.assertIn("--group aetherflow --legacy-owner aetherflow", service)
        self.assertIn("PrivateNetwork=yes", service)
        timer = (self.current / "deploy/systemd/aetherflow-log-retention.timer").read_text()
        self.assertIn("OnBootSec=1min", timer)
        self.assertIn("OnUnitInactiveSec=1min", timer)
        self.assertIn("Unit=aetherflow-log-retention.service", timer)
        self.assertIn("WantedBy=timers.target", timer)


if __name__ == "__main__":
    unittest.main()
