"""Verify durable recovery storage for privileged updates and shell installers."""
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions, installer_common_functions
from test_marketplace_catalog_lifecycle_matrix import InstallerFixture


ROOT = Path(__file__).resolve().parents[1]
INSTALLERS_DIR = ROOT / "packages/package/install"

EXPECTED_VAR_BACKUPS_INSTALLERS = (
    "audiobookshelf",
    "bazarr",
    "calibreweb",
    "cloudplow",
    "flaresolverr",
    "homeassistant",
    "jellyseerr",
    "listenarr",
    "maintainerr",
    "overseerr",
    "palate",
    "paperless-ngx",
    "pihole",
    "sabnzbd",
    "tautulli",
)


class DurableRecoveryStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-durable-rec-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "tmp").mkdir(mode=0o700, parents=True)

    def _run_shell(self, body, extra_env=None, helpers=None):
        helper_src = common_functions(*(helpers or ()))
        script = f"set -euo pipefail\n{helper_src}\n{body}\n"
        env = dict(
            os.environ,
            TEST_ROOT=str(self.root),
            TMPDIR=str(self.root / "tmp"),
        )
        for key in (
            "AF_RECOVERY_ROOT",
            "AETHERFLOW_RECOVERY_ROOT",
            "AF_TRANSACTION_ROOT",
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_INSTALL_ROOT",
            "AF_FIXTURE_ROOT",
        ):
            env.pop(key, None)
        if extra_env:
            for key, value in extra_env.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = str(value)
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

    def test_static_audit_no_installer_uses_ephemeral_tmp_for_recovery_and_privatetmp_preserved(self):
        # 1. Sandbox isolation (PrivateTmp=yes) must remain intact everywhere.
        for rel in (
            "deploy/systemd/aetherflow-runner.service",
            "backend-rs/crates/af-release/src/health.rs",
            "deploy/release-manager.sh",
        ):
            text = (ROOT / rel).read_text()
            self.assertIn("PrivateTmp=yes", text, f"{rel} must preserve PrivateTmp=yes")

        # 2. common.sh begin_state_transaction must use persistent recovery helpers, never /tmp or /var/tmp.
        common_text = (ROOT / "packages/common.sh").read_text()
        start = common_text.index("\nbegin_state_transaction() ")
        end = common_text.index("\n}\n", start)
        begin_tx = common_text[start:end]
        self.assertIn("af_prepare_recovery_root", begin_tx)
        self.assertIn('af_create_recovery_backup_dir "af-state-"', begin_tx)
        self.assertNotIn("${TMPDIR:-/var/tmp}", begin_tx)

        # 3. No installer may create recovery/rollback backup dirs under /tmp, /var/tmp, TMPDIR, or AF_JOB_SCRATCH_DIR.
        ephemeral_backup_re = re.compile(
            r'(?:BACKUP_DIR|RUNTIME_BACKUP|AF_STATE_BACKUP)\s*=\s*"\$\(mktemp\s+-d\s+[^)]*(?:/tmp|TMPDIR|AF_JOB_SCRATCH)'
        )
        installers = sorted(INSTALLERS_DIR.glob("installpackage-*"))
        self.assertGreaterEqual(len(installers), 70)
        for installer in installers:
            text = installer.read_text()
            match = ephemeral_backup_re.search(text)
            self.assertIsNone(
                match,
                f"{installer.name} must not create recovery backup under ephemeral tmp/scratch: {match.group(0) if match else ''}",
            )

        # 4. Every /var/backups/aetherflow-* installer must validate /var/backups and enforce chmod 700.
        for pkg in EXPECTED_VAR_BACKUPS_INSTALLERS:
            text = (INSTALLERS_DIR / f"installpackage-{pkg}").read_text()
            self.assertIn(
                "/var/backups/.af-backup-root",
                text,
                f"installpackage-{pkg} must validate /var/backups against symlink traversal",
            )
            self.assertRegex(
                text,
                r'chmod\s+700\s+"?\$(?:BACKUP_DIR|ABS_BACKUP_DIR|PIHOLE_BACKUP_DIR)"?',
                f"installpackage-{pkg} must enforce private 0700 permissions on backup dir",
            )

    def test_shell_recovery_helpers_validate_paths_symlinks_permissions_and_ephemeral_roots(self):
        # 1. Default resolves under <TEST_ROOT>/var/backups/aetherflow-recovery and ignores installer DATA_DIR.
        res = self._run_shell(
            'DATA_DIR="/var/lib/sonarr"\n'
            'created="$(af_create_recovery_backup_dir "af-runtime-")"\n'
            'printf "%s\\n" "$created"\n'
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        created = Path(res.stdout.strip())
        recovery_root = self.root / "var/backups/aetherflow-recovery"
        self.assertEqual(created.parent, recovery_root)
        self.assertTrue(created.name.startswith("af-runtime-"))
        self.assertEqual(stat.S_IMODE(recovery_root.lstat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(created.lstat().st_mode), 0o700)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

        # 2. Reject ephemeral tmp/var-tmp/dev-shm/run overrides, protected roots, traversal, and relative paths.
        bad_roots = [
            str(self.root / "tmp/bad-rec"),
            str(self.root / "var/tmp/bad-rec"),
            str(self.root / "dev/shm/bad-rec"),
            str(self.root / "run/bad-rec"),
            "/tmp/bad-rec",
            "/var/tmp/bad-rec",
            str(self.root / "var/backups"),
            str(self.root / "var"),
            str(self.root / "var/backups/../tmp/bad-rec"),
            "relative/recovery",
        ]
        for bad in bad_roots:
            with self.subTest(bad_root=bad):
                bad_res = self._run_shell(
                    f'af_prepare_recovery_root "{bad}"',
                )
                self.assertNotEqual(bad_res.returncode, 0, f"Should reject {bad}")
                self.assertEqual(bad_res.stdout.strip(), "")

        # 3. Reject invalid backup prefixes.
        for bad_prefix in ("../escape", "bad/prefix", "..", "."):
            with self.subTest(bad_prefix=bad_prefix):
                bad_res = self._run_shell(f'af_create_recovery_backup_dir "{bad_prefix}"')
                self.assertNotEqual(bad_res.returncode, 0, f"Should reject prefix {bad_prefix}")

        # 4. Reject insecure recovery root permissions (0755, 0777).
        for bad_mode in (0o755, 0o777):
            recovery_root.chmod(bad_mode)
            bad_res = self._run_shell('af_create_recovery_backup_dir "af-runtime-"')
            self.assertNotEqual(bad_res.returncode, 0, f"Should reject mode {oct(bad_mode)}")
            self.assertIn("0o700", bad_res.stderr)
        recovery_root.chmod(0o700)

        # 5. Reject world-writable ancestor directory.
        var_backups = self.root / "var/backups"
        var_backups.chmod(0o777)
        anc_res = self._run_shell('af_create_recovery_backup_dir "af-runtime-"')
        self.assertNotEqual(anc_res.returncode, 0)
        self.assertIn("unsafe writable permissions", anc_res.stderr)
        var_backups.chmod(0o755)

        # 6. Reject symlinked recovery root and symlinked ancestor.
        decoy = self.root / "decoy"
        decoy.mkdir(mode=0o700)
        created.rmdir()
        recovery_root.rmdir()
        recovery_root.symlink_to(decoy)
        sym_leaf = self._run_shell('af_create_recovery_backup_dir "af-runtime-"')
        self.assertNotEqual(sym_leaf.returncode, 0)
        self.assertIn("symlink", sym_leaf.stderr.lower())

        recovery_root.unlink()
        var_backups.rmdir()
        var_backups.symlink_to(decoy)
        sym_anc = self._run_shell('af_create_recovery_backup_dir "af-runtime-"')
        self.assertNotEqual(sym_anc.returncode, 0)
        self.assertIn("symlink", sym_anc.stderr.lower())

    def test_begin_state_transaction_cleanup_and_incomplete_rollback_preservation(self):
        app_dir = self.root / "var/lib/demoapp"
        app_dir.mkdir(parents=True)
        sentinel = app_dir / "state.db"
        sentinel.write_text("v1-original")
        (self.root / "install").mkdir(exist_ok=True)

        common_stub = f"""
LOGFILE="{self.root}/test.log"
PACKAGE_NAME="demoapp"
print_error() {{ printf '%s\\n' "$*" >&2; }}
print_warn() {{ printf '%s\\n' "$*" >&2; }}
log_warn() {{ printf '%s\\n' "$*" >&2; }}
lock_path() {{ printf '%s/install/.%s.lock\\n' "{self.root}" "$1"; }}
af_logged() {{ "$@"; }}
systemctl() {{
    case "${{1:-}}" in
        is-active) return 3 ;;
        show) printf 'LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\n' ;;
        stop|daemon-reload|start) return 0 ;;
        *) return 0 ;;
    esac
}}
"""
        helpers = (
            "begin_state_transaction",
            "cleanup_state_transaction",
            "snapshot_state_dirs",
            "restore_state_snapshot",
            "snapshot_app_state",
            "restore_app_state",
            "safe_restore_path_from_backup",
            "stop_systemd_unit",
            "quiesce_services_for_rollback",
            "systemd_unit_inactive",
            "validate_config_paths",
            "safe_config_python",
            "safe_rm_rf",
        )

        # 1. Successful commit removes AF_STATE_BACKUP cleanly.
        ok_res = self._run_shell(
            common_stub
            + f'begin_state_transaction demoapp.service 0 / "{app_dir}"\n'
            + 'INSTALL_COMMITTED=true\n',
            helpers=helpers,
        )
        self.assertEqual(ok_res.returncode, 0, ok_res.stderr)
        recovery_root = self.root / "var/backups/aetherflow-recovery"
        self.assertEqual(stat.S_IMODE(recovery_root.lstat().st_mode), 0o700)
        self.assertEqual(list(recovery_root.glob("af-state-*")), [])
        self.assertEqual(list((self.root / "tmp").glob("af-state-*")), [])

        # 2. Clean rollback restores live file and cleans up AF_STATE_BACKUP.
        for units in ("demoapp.service", "", "  "):
            with self.subTest(units=units):
                rb_res = self._run_shell(
                    common_stub
                    + f'begin_state_transaction "{units}" 0 / "{app_dir}"\n'
                    + f'printf "v2-corrupted" > "{sentinel}"\n'
                    + 'exit 42\n',
                    helpers=helpers,
                )
                self.assertEqual(rb_res.returncode, 42, rb_res.stderr)
                self.assertEqual(sentinel.read_text(), "v1-original")
                self.assertEqual(list(recovery_root.glob("af-state-*")), [])
                self.assertEqual(list((self.root / "tmp").glob("af-state-*")), [])

        # 3. Incomplete rollback (quiesce fails) preserves backup under persistent recovery root (0700).
        inc_res = self._run_shell(
            common_stub
            + f'begin_state_transaction demoapp.service 0 / "{app_dir}"\n'
            + f'printf "v2-live-mutated" > "{sentinel}"\n'
            + 'systemctl() { [[ "${1:-}" == stop ]] && return 73; [[ "${1:-}" == is-active ]] && return 0; return 0; }\n'
            + 'exit 1\n',
            helpers=helpers,
        )
        self.assertEqual(inc_res.returncode, 1, inc_res.stderr)
        self.assertEqual(sentinel.read_text(), "v2-live-mutated")
        preserved = list(recovery_root.glob("af-state-*"))
        self.assertEqual(len(preserved), 1)
        self.assertEqual(stat.S_IMODE(preserved[0].lstat().st_mode), 0o700)
        self.assertEqual((preserved[0] / "state/0/state.db").read_text(), "v1-original")
        self.assertIn(f"recovery backup preserved at {preserved[0]}", inc_res.stderr)
        self.assertEqual(list((self.root / "tmp").glob("af-state-*")), [])

    def test_invidious_and_piped_preserve_durable_recovery_while_cleaning_disposable_scratch(self):
        for app, func_name, completed_vars, extra_setup in (
            (
                "invidious",
                "cleanup_invidious_install",
                "INVIDIOUS_INSTALL_COMPLETED=0",
                "PREVIOUS_UNITS=(af-invidious.service)\nTMP_DIR=''\n",
            ),
            (
                "piped",
                "cleanup_piped_install",
                "PIPED_INSTALL_COMPLETED=0\nPIPED_CERTIFIED=0",
                "RUNTIME_HAD_PREVIOUS=true\nSERVICE_STOPPED=true\nBUILD_DIR=''\n",
            ),
        ):
            with self.subTest(app=app):
                installer_text = (INSTALLERS_DIR / f"installpackage-{app}").read_text()
                start = installer_text.index(f"{func_name}() {{")
                end = installer_text.index("\n}\n", start) + 3
                cleanup_fn = installer_text[start:end]

                scratch_dir = self.root / f"tmp/{app}-disposable-scratch"
                scratch_dir.mkdir(mode=0o700, parents=True)
                (scratch_dir / "downloaded.tar.gz").write_text("disposable-download")

                script_body = f"""
set +e
LOGFILE="{self.root}/test.log"
af_write_failure_receipt() {{ :; }}
print_error() {{ printf '%s\\n' "$*" >&2; }}
print_warn() {{ printf '%s\\n' "$*" >&2; }}
systemctl() {{ return 1; }}
{cleanup_fn}

AF_JOB_SCRATCH_DIR="{scratch_dir}"
RUNTIME_BACKUP="$(af_create_recovery_backup_dir "af-{app}-runtime-")"
backup_dir="$RUNTIME_BACKUP"
printf 'saved-db-%s' "{app}" > "$RUNTIME_BACKUP/state.sql"
{completed_vars}
{extra_setup}
RUNTIME_CHANGED=false
INSTALL_COMMITTED=false

{func_name}
rc=$?
printf 'BACKUP=%s\\nRC=%d\\n' "$RUNTIME_BACKUP" "$rc"
"""
                res = self._run_shell(script_body, helpers=("af_cleanup_job_scratch",))
                self.assertIn("RC=1", res.stdout, res.stderr)
                match = re.search(r"^BACKUP=(.+)$", res.stdout, re.MULTILINE)
                self.assertIsNotNone(match, res.stdout + res.stderr)
                backup_path = Path(match.group(1))
                self.assertEqual(backup_path.parent, self.root / "var/backups/aetherflow-recovery")
                self.assertTrue(backup_path.is_dir(), "Durable recovery backup must be preserved")
                self.assertEqual((backup_path / "state.sql").read_text(), f"saved-db-{app}")
                self.assertFalse(
                    scratch_dir.exists(),
                    "Disposable build scratch must be cleaned up when durable recovery lives outside scratch",
                )
                self.assertIn(f"recovery backup preserved at {backup_path}", res.stderr)

    def test_migrated_installers_preserve_incomplete_rollback_under_recovery_root(self):
        for app, prefix in (("fail2ban", "af-fail2ban-runtime-"), ("prometheus", "af-runtime-")):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                baseline = fixture.run("install")
                self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)
                recovery_root = fixture.root / "var/backups/aetherflow-recovery"
                self.assertEqual(list(recovery_root.glob(f"{prefix}*")), [])
                self.assertEqual(list((fixture.root / "tmp").glob(f"{prefix}*")), [])

                # Force restore copy failure during failed update to trigger incomplete rollback preservation.
                fixture.file(
                    "mock-bin/cp",
                    """#!/usr/bin/python3
import os, sys
source = next(arg for arg in sys.argv[1:] if not arg.startswith('-'))
needle = os.environ.get('AF_FAIL_RESTORE_SUBSTR', '')
if needle and needle in source:
    sys.exit(75)
os.execv('/usr/bin/cp', ['/usr/bin/cp', *sys.argv[1:]])
""",
                ).chmod(0o755)
                failed = fixture.run(
                    "update",
                    AF_FIXTURE_FAILURE="service",
                    AF_FAIL_RESTORE_SUBSTR=str(recovery_root / prefix),
                )
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(list((fixture.root / "tmp").glob(f"{prefix}*")), [])
                self.assertEqual(stat.S_IMODE(recovery_root.lstat().st_mode), 0o700)
                preserved = list(recovery_root.glob(f"{prefix}*"))
                self.assertEqual(len(preserved), 1, failed.stdout + failed.stderr)
                self.assertEqual(stat.S_IMODE(preserved[0].lstat().st_mode), 0o700)
                self.assertIn(f"recovery backup preserved at {preserved[0]}", failed.stderr)


if __name__ == "__main__":
    unittest.main()
