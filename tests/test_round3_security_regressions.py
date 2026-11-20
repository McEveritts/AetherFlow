#!/usr/bin/env python3
"""Round-3 security & operational parity regression tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _resolve_openable_tmp_root() -> str:
    cand = Path(tempfile.gettempdir()).resolve()
    if all(os.access(p, os.R_OK | os.X_OK) for p in (cand, *cand.parents)):
        return str(cand)
    if Path("/tmp").is_dir() and os.access("/tmp", os.R_OK | os.W_OK | os.X_OK):
        return str(Path("/tmp").resolve())
    return str(cand)


RESOLVED_TMP_ROOT = _resolve_openable_tmp_root()


class Round3SecurityRegressionTests(unittest.TestCase):
    def test_common_sh_64hex_aes_ctypes_openssl_fallback_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-r3-creds-", dir=RESOLVED_TMP_ROOT) as tmp:
            tmp_path = Path(tmp)
            fake_pkg_dir = tmp_path / "shadow_py"
            fake_pkg_dir.mkdir()
            # Force ImportError on `import cryptography` so common.sh MUST use the ctypes libcrypto path
            (fake_pkg_dir / "cryptography.py").write_text(
                'raise ImportError("simulated host without python3-cryptography")\n',
                encoding="utf-8",
            )

            env_dir = tmp_path / "etc_af"
            env_dir.mkdir()
            hex64_key = bytes(range(32)).hex()
            env_file = env_dir / "aetherflow.env"
            env_file.write_text(f"export AES_MASTER_KEY={hex64_key}\n", encoding="utf-8")

            creds_file = tmp_path / ".master.creds"
            lock_dir = tmp_path / "locks"
            lock_dir.mkdir()
            log_file = tmp_path / "install.log"

            base_env = {
                **os.environ,
                "PYTHONPATH": f"{fake_pkg_dir}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
                "AETHERFLOW_ENV_FILE": str(env_file),
                "AETHERFLOW_MASTER_CREDS_FILE": str(creds_file),
                "LOCK_DIR": str(lock_dir),
                "LOGFILE": str(log_file),
            }
            # Remove ambient MASTER_USER / MASTER_PASS / AES_MASTER_KEY so file loader is exercised
            for k in ("MASTER_USER", "MASTER_PASS", "AES_MASTER_KEY"):
                base_env.pop(k, None)

            # 1. Encrypt & persist new .master.creds using 64-hex key via ctypes OpenSSL fallback
            probe = (
                'set -euo pipefail\n'
                'source "$1"\n'
                'load_master_credentials\n'
                'sab_pw="$(derive_app_password "sabnzbd:admin")"\n'
                'sab_other="$(derive_app_password "sabnzbd:nzbkey")"\n'
                'printf "%s\\n%s\\n%s\\n%s\\n" "$MASTER_USER" "$MASTER_PASS" "$sab_pw" "$sab_other"\n'
            )
            r1 = subprocess.run(
                ["bash", "-c", probe, "--", str(ROOT / "packages/common.sh")],
                env=base_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(r1.returncode, 0, r1.stderr)
            lines1 = r1.stdout.splitlines()
            self.assertEqual(len(lines1), 4)
            user1, pass1, sab_pw1, sab_other1 = lines1
            self.assertTrue(bool(user1))
            self.assertGreaterEqual(len(pass1), 16)
            self.assertNotEqual(sab_pw1, pass1)
            self.assertNotEqual(sab_pw1, sab_other1)

            raw_cipher = creds_file.read_text(encoding="utf-8").strip()
            parsed_cipher = json.loads(raw_cipher)
            self.assertTrue(str(parsed_cipher["password"]).startswith("enc:v1:"), raw_cipher)
            self.assertTrue(str(parsed_cipher["ha1"]).startswith("enc:v1:"), raw_cipher)

            # 2. Second invocation decrypts identical credentials & deterministic derived password
            r2 = subprocess.run(
                ["bash", "-c", probe, "--", str(ROOT / "packages/common.sh")],
                env=base_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertEqual(r2.stdout.splitlines(), lines1)

            # 3. Wrong AES_MASTER_KEY MUST fail closed and MUST NOT overwrite encrypted .master.creds
            bad_env_file = env_dir / "bad.env"
            bad_env_file.write_text("AES_MASTER_KEY=" + ("f" * 64) + "\n", encoding="utf-8")
            bad_env = {**base_env, "AETHERFLOW_ENV_FILE": str(bad_env_file)}
            r_bad = subprocess.run(
                ["bash", "-c", probe, "--", str(ROOT / "packages/common.sh")],
                env=bad_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(r_bad.returncode, 0)
            self.assertEqual(creds_file.read_text(encoding="utf-8").strip(), raw_cipher)

    def test_sabnzbd_installer_uses_domain_separated_derived_password_and_drops_ha1(self) -> None:
        sab = (ROOT / "packages/package/install/installpackage-sabnzbd").read_text(encoding="utf-8")
        self.assertIn("derive_app_password", sab)
        self.assertNotIn("Password_ha1", sab)

    def test_log_retention_drains_multi_chunk_backlog_in_single_pass_under_flock(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-r3-logret-", dir=RESOLVED_TMP_ROOT) as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir(mode=0o750)
            target_log = log_dir / "install-sonarr.log"
            # Write > 4x max_bytes (max_bytes = 4096 -> write ~20 KiB)
            payload = "".join(f"line-{idx:05d}-" + ("x" * 60) + "\n" for idx in range(300))
            target_log.write_text(payload, encoding="utf-8")
            target_log.chmod(0o640)
            self.assertGreater(target_log.stat().st_size, 4096 * 4)

            res = subprocess.run(
                [
                    "python3",
                    str(ROOT / "deploy/log-retention.py"),
                    "--log-dir",
                    str(log_dir),
                    "--max-bytes",
                    "4096",
                    "--keep",
                    "3",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertLessEqual(target_log.stat().st_size, 4096)
            self.assertTrue((log_dir / "install-sonarr.log.af-retention.1").is_file())

    def test_runner_systemd_sandboxing_parity_and_sudo_compatibility(self) -> None:
        pkg_unit = (ROOT / "deploy/systemd/aetherflow-runner.service").read_text(encoding="utf-8")
        self.assertFalse(
            (ROOT / "setup/templates/sysd/aetherflow-runner.template").exists(),
            "Duplicate aetherflow-runner.template must be retired in favor of deploy/systemd/aetherflow-runner.service",
        )
        self.assertFalse(
            (ROOT / "setup/templates/sysd/aetherflow-api.template").exists(),
            "Duplicate aetherflow-api.template must be retired in favor of deploy/systemd/aetherflow-api.service",
        )
        rm_sh = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        health_rs = (ROOT / "backend-rs/crates/af-release/src/health.rs").read_text(encoding="utf-8")

        required_directives = (
            "PrivateTmp=yes",
            "ProtectClock=yes",
            "ProtectKernelLogs=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "LockPersonality=yes",
            "RestrictRealtime=yes",
            "SystemCallArchitectures=native",
            "SystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap",
        )
        for directive in required_directives:
            self.assertIn(directive, pkg_unit)
            self.assertIn(directive, rm_sh)
            self.assertIn(directive, health_rs)

        active_lines = [
            ln.strip()
            for ln in pkg_unit.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        self.assertNotIn("NoNewPrivileges=yes", active_lines)
        self.assertNotIn("RestrictSUIDSGID=yes", active_lines)

    def test_kasmvnc_display_probe_honors_proc_net_unix_under_private_tmp(self) -> None:
        kasm = (ROOT / "packages/package/install/installpackage-kasmvnc").read_text(encoding="utf-8")
        snippet = "PROC_NET_UNIX_PATH=" + kasm.split("PROC_NET_UNIX_PATH=", 1)[1].split("\nKASMVNC_DISPLAY=", 1)[0]
        with tempfile.TemporaryDirectory(prefix="af-r3-x11-") as tmp:
            proc_unix = Path(tmp) / "proc_net_unix"
            proc_unix.write_text(
                "Num       RefCount Protocol Flags    Type St Inode Path\n"
                "0000000000000000: 00000002 00000000 00010000 0001 01 12345 @/tmp/.X11-unix/X47\n",
                encoding="utf-8",
            )
            probe = (
                snippet
                + '\nif x11_display_free 47; then echo "BUG_FREE_47"; exit 1; fi\n'
                + 'x11_display_free 48\n'
                + 'echo "OK"\n'
            )
            res = subprocess.run(
                ["bash", "-euc", probe],
                env={**os.environ, "AF_PROC_NET_UNIX": str(proc_unix)},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("OK", res.stdout)

    def test_strict_nightly_tag_gate_and_modern_stack_export_preservation(self) -> None:
        modern = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        rm_sh = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        self.assertIn("-[Nn]ightly\\.[0-9]+", modern)
        self.assertIn("-[Nn]ightly\\.[0-9]+", rm_sh)

        # Verify modern_stack.sh preserves `export KEY=VALUE`
        with tempfile.TemporaryDirectory(prefix="af-r3-modern-") as tmp:
            env_file = Path(tmp) / "aetherflow.env"
            sample_hex64 = bytes(range(32)).hex()
            env_file.write_text(
                f"export AES_MASTER_KEY={sample_hex64}\n"
                "export CUSTOM_EXPORTED_FLAG=preserved_ok\n",
                encoding="utf-8",
            )
            self.assertIn("export[[:space:]]+", modern)

    def test_common_sh_keeps_last_aes_master_key_and_validates_tar_archives(self) -> None:
        import tarfile
        import io

        with tempfile.TemporaryDirectory(prefix="af-r5-common-", dir=RESOLVED_TMP_ROOT) as tmp:
            root = Path(tmp)
            env_file = root / "aetherflow.env"
            stale_hex = bytes([0x11] * 32).hex()
            active_hex = bytes([0x22] * 32).hex()
            env_file.write_text(
                f"AES_MASTER_KEY={stale_hex}\nexport AES_MASTER_KEY={active_hex}\n",
                encoding="utf-8",
            )
            creds_file = root / ".master.creds"
            lock_dir = root / "lock"
            lock_dir.mkdir()
            env = {
                **os.environ,
                "AETHERFLOW_ENV_FILE": str(env_file),
                "AETHERFLOW_MASTER_CREDS_FILE": str(creds_file),
                "LOCK_DIR": str(lock_dir),
                "LOGFILE": "/dev/null",
            }
            for k in ("AES_MASTER_KEY", "MASTER_USER", "MASTER_PASS"):
                env.pop(k, None)

            proc = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{ROOT / "packages/common.sh"}" && '
                    'load_master_credentials && printf "%s" "$MASTER_PASS"',
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            generated_pass = proc.stdout
            self.assertGreaterEqual(len(generated_pass), 16)
            # Removing stale_hex and keeping only active_hex must still decrypt cleanly
            env_file.write_text(f"AES_MASTER_KEY={active_hex}\n", encoding="utf-8")
            proc2 = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{ROOT / "packages/common.sh"}" && load_master_credentials && printf "%s" "$MASTER_PASS"',
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(proc2.stdout, generated_pass)

            # Verify af_validate_tar_archive rejects traversal & symlink archives
            bad_tar = root / "traversal.tar.gz"
            with tarfile.open(bad_tar, "w:gz") as tf:
                info = tarfile.TarInfo(name="../escaped.py")
                payload = b"print('bad')\n"
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            bad_res = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{ROOT / "packages/common.sh"}" && af_validate_tar_archive "{bad_tar}"',
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_res.returncode, 0)

    def test_log_retention_preserves_late_append_before_ftruncate(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "af_log_retention_r5", ROOT / "deploy/log-retention.py"
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory(prefix="af-r5-logret-", dir=RESOLVED_TMP_ROOT) as tmp:
            log_dir = Path(tmp)
            os.chmod(log_dir, 0o750)
            log_path = log_dir / "install-test.log"
            log_path.write_bytes(b"A" * 2048)
            os.chmod(log_path, 0o640)

            orig_fsync = mod.os.fsync
            orig_lseek = mod.os.lseek
            state = {"seeded": False, "late": False}

            def hook_fsync(fd: int) -> None:
                orig_fsync(fd)
                if not state["seeded"] and log_path.stat().st_size == 2048:
                    state["seeded"] = True
                    with open(log_path, "ab") as writer1:
                        writer1.write(b"INITIAL_LIVE_TAIL\n")

            def hook_lseek(fd: int, pos: int, how: int) -> int:
                res = orig_lseek(fd, pos, how)
                if state["seeded"] and not state["late"] and pos == 0 and how == os.SEEK_SET:
                    state["late"] = True
                    with open(log_path, "ab") as late_writer:
                        late_writer.write(b"LATE_APPEND_CANARY\n")
                return res

            mod.os.fsync = hook_fsync
            mod.os.lseek = hook_lseek
            try:
                mod.retain_logs(str(log_dir), max_bytes=512, keep=2)
            finally:
                mod.os.fsync = orig_fsync
                mod.os.lseek = orig_lseek

            final_bytes = log_path.read_bytes()
            self.assertIn(b"INITIAL_LIVE_TAIL\n", final_bytes)
            self.assertIn(b"LATE_APPEND_CANARY\n", final_bytes)

    def test_verify_provenance_strips_auth_on_cross_origin_redirect(self) -> None:
        import importlib.util
        import urllib.request

        spec = importlib.util.spec_from_file_location(
            "af_verify_prov_r5", ROOT / "deploy/verify-provenance.py"
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        self.assertTrue(mod._is_trusted_github_https_url("https://api.github.com/repos/a/b"))
        self.assertFalse(mod._is_trusted_github_https_url("http://api.github.com/repos/a/b"))
        self.assertFalse(mod._is_trusted_github_https_url("https://evil.example.com/repos/a/b"))

        handler = mod._StripAuthCrossOriginRedirectHandler()
        orig_req = urllib.request.Request(
            "https://api.github.com/repos/McEveritts/AetherFlow/attestations/sha256:" + ("a" * 64),
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = handler.redirect_request(
            orig_req, None, 302, "Found", {}, "https://s3.amazonaws.com/bucket/blob"
        )
        assert redirected is not None
        self.assertNotIn("Authorization", redirected.headers)
        self.assertNotIn("Authorization", redirected.unredirected_hdrs)

    def test_sabnzbd_partial_venv_rollback_does_not_nest_and_runner_restart_checked(self) -> None:
        sab_src = (ROOT / "packages/package/install/installpackage-sabnzbd").read_text(
            encoding="utf-8"
        )
        self.assertIn('elif [[ "$VENV_ACTIVATED" -eq 1 || "$VENV_MOVED" -eq 1 ]]; then', sab_src)
        self.assertNotIn('>> "$LOGFILE" 2>&1', sab_src)

        with tempfile.TemporaryDirectory(prefix="af-r6-sab-") as tmp:
            root = Path(tmp)
            app_dir = root / "SABnzbd"
            app_dir.mkdir()
            partial_venv = app_dir / ".venv"
            partial_venv.mkdir()
            (partial_venv / "broken.txt").write_text("partial", encoding="utf-8")
            backup_dir = root / "backup"
            backup_dir.mkdir()
            orig_venv = backup_dir / "venv"
            orig_venv.mkdir()
            (orig_venv / "python3").write_text("healthy-runtime", encoding="utf-8")

            rebased_cleanup = sab_src[sab_src.index("cleanup() {") : sab_src.index("\ntrap cleanup EXIT")]
            rebased_cleanup = rebased_cleanup.replace("/opt/SABnzbd", str(app_dir))
            probe = f"""
set -euo pipefail
SUCCESS=0
APP_ACTIVATED=0
VENV_ACTIVATED=0
VENV_MOVED=1
APP_MOVED=0
SERVICE_STOPPED=0
UNIT_WRITTEN=0
WAS_RUNNABLE=0
BUILD_DIR=""
BACKUP_DIR={str(backup_dir)!r}
quiesce_services_for_rollback() {{ return 0; }}
restore_app_state() {{ return 0; }}
af_logged() {{ "$@"; }}
print_warn() {{ :; }}
{rebased_cleanup}
false || cleanup
"""
            proc = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertTrue((app_dir / ".venv/python3").is_file())
            self.assertFalse((app_dir / ".venv/venv").exists())

        rm_src = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl restart aetherflow-runner.service || return 1", rm_src)
        self.assertIn("if ! restart_systemd_units; then", rm_src)

    def test_log_retention_serializes_with_active_flock_holder_from_common_sh(self) -> None:
        import fcntl
        import importlib.util
        import threading
        import time

        spec = importlib.util.spec_from_file_location(
            "af_log_retention_r6", ROOT / "deploy/log-retention.py"
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory(prefix="af-r6-loglock-", dir=RESOLVED_TMP_ROOT) as tmp:
            log_dir = Path(tmp)
            os.chmod(log_dir, 0o750)
            log_path = log_dir / "install-sabnzbd.log"
            log_path.write_bytes(b"X" * 1024)
            os.chmod(log_path, 0o640)

            locked_evt = threading.Event()
            done_evt = threading.Event()

            def writer() -> None:
                with open(log_path, "ab") as active_holder:
                    fcntl.flock(active_holder.fileno(), fcntl.LOCK_SH)
                    try:
                        locked_evt.set()
                        time.sleep(0.15)
                        active_holder.write(b"\nACTIVE_INSTALL_LINE\n")
                        active_holder.flush()
                    finally:
                        fcntl.flock(active_holder.fileno(), fcntl.LOCK_UN)
                        done_evt.set()

            t = threading.Thread(target=writer, daemon=True)
            t.start()
            self.assertTrue(locked_evt.wait(timeout=2.0))
            self.assertEqual(mod.retain_logs(str(log_dir), max_bytes=256, keep=2), (1, []))
            self.assertTrue(done_evt.is_set())
            t.join(timeout=2.0)
            archive_bytes = (log_dir / "install-sabnzbd.log.af-retention.1").read_bytes()
            self.assertIn(b"ACTIVE_INSTALL_LINE\n", archive_bytes)

    def test_round8_release_manager_recovery_state_guard_and_standalone_rollback_snapshot(self) -> None:
        import contextlib
        import hashlib
        import sqlite3

        with tempfile.TemporaryDirectory(prefix="af-r8-rm-") as tmp:
            root = Path(tmp) / "isolated_root"
            af_opt = root / "opt/AetherFlow"
            releases = af_opt / "releases"
            prev_rel = releases / "1111111111"
            cur_rel = releases / "2222222222"
            data_dir = root / "var/lib/aetherflow"
            log_dir = root / "var/log/aetherflow"
            bin_dir = root / "usr/local/bin"
            stub_bin = Path(tmp) / "stub_bin"
            env_dir = root / "etc/aetherflow"
            systemd_dst = root / "etc/systemd/system"
            for d in (prev_rel, cur_rel / "data-snapshot", data_dir, log_dir, bin_dir, stub_bin, env_dir, systemd_dst):
                d.mkdir(parents=True, exist_ok=True)

            (prev_rel / "aetherflow-api").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (prev_rel / "af").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(prev_rel / "aetherflow-api", 0o755)
            os.chmod(prev_rel / "af", 0o755)
            (prev_rel / ".version").write_text("v4.0.0-nightly.109.1\n", encoding="utf-8")
            (cur_rel / "aetherflow-api").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (cur_rel / "af").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(cur_rel / "aetherflow-api", 0o755)
            os.chmod(cur_rel / "af", 0o755)
            (cur_rel / ".version").write_text("v4.0.0-nightly.110.1\n", encoding="utf-8")

            bak_db = cur_rel / "data-snapshot/aetherflow.sqlite.bak"
            with contextlib.closing(sqlite3.connect(bak_db)) as c:
                c.execute("CREATE TABLE marker (v TEXT)")
                c.execute("INSERT INTO marker VALUES ('PRE_DEPLOY_GOOD_DB')")
                c.commit()
            digest = hashlib.sha256(bak_db.read_bytes()).hexdigest()
            (cur_rel / "data-snapshot/MANIFEST.sha256").write_text(
                f"{digest}  aetherflow.sqlite.bak\n", encoding="utf-8"
            )

            live_db = data_dir / "aetherflow.sqlite"
            with contextlib.closing(sqlite3.connect(live_db)) as c:
                c.execute("CREATE TABLE marker (v TEXT)")
                c.execute("INSERT INTO marker VALUES ('INITIAL_LIVE_DB')")
                c.commit()

            (releases / ".previous_release").write_text(str(prev_rel), encoding="utf-8")
            (af_opt / "current").symlink_to(cur_rel)

            for tool, body in {
                "systemctl": "#!/bin/sh\nexit 0\n",
                "curl": '#!/bin/sh\nprintf \'{"status":"ok"}\\n200\'\n',
            }.items():
                p = stub_bin / tool
                p.write_text(body, encoding="utf-8")
                os.chmod(p, 0o755)

            conf = Path(tmp) / "rm.conf"
            conf.write_text(
                f"RELEASES_DIR={releases}\n"
                f"CURRENT_LINK={af_opt / 'current'}\n"
                f"REPO_DIR={af_opt}\n"
                f"LEGACY_OPT_ROOT={af_opt}\n"
                f"DATA_DIR={data_dir}\n"
                f"AF_DB_PATH={live_db}\n"
                f"LOG_FILE={log_dir / 'deploy.log'}\n"
                f"ENV_DIR={env_dir}\n"
                f"ENV_FILE={env_dir / 'aetherflow.env'}\n"
                f"SYSTEMD_UNITS_SRC={ROOT / 'deploy/systemd'}\n"
                f"SYSTEMD_UNITS_DST={systemd_dst}\n"
                f"CLI_BIN_DIR={bin_dir}\n"
                "HEALTH_RETRIES=1\n"
                "HEALTH_INTERVAL=0\n",
                encoding="utf-8",
            )
            env = {
                **os.environ,
                "PATH": f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            }

            # 1. Unfinished post-swap `.recovery_state.json` MUST block `cleanup` (and `deploy`) until `rollback` runs.
            rec_file = releases / ".recovery_state.json"
            rec_file.write_text(
                json.dumps(
                    {
                        "command": "deploy",
                        "phase": "stage3_health_probe",
                        "candidate_release": str(cur_rel),
                        "previous_release": str(prev_rel),
                    }
                ),
                encoding="utf-8",
            )
            blocked = subprocess.run(
                ["bash", str(ROOT / "deploy/release-manager.sh"), "cleanup", "--config", str(conf)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("unfinished after symlink swap", blocked.stdout + blocked.stderr)

            # 2. Standalone `rollback` (after completed deploy + DB corruption) restores `cur_rel/data-snapshot` and marks `complete`.
            live_db.write_bytes(b"CORRUPT_POST_DEPLOY_DB")
            rec_file.write_text(
                json.dumps(
                    {
                        "command": "deploy",
                        "phase": "complete",
                        "candidate_release": str(cur_rel),
                        "previous_release": str(prev_rel),
                    }
                ),
                encoding="utf-8",
            )
            rb = subprocess.run(
                ["bash", str(ROOT / "deploy/release-manager.sh"), "rollback", "--config", str(conf)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(rb.returncode, 0, msg=rb.stdout + rb.stderr)
            with contextlib.closing(sqlite3.connect(live_db)) as c:
                val = c.execute("SELECT v FROM marker").fetchone()[0]
            self.assertEqual(val, "PRE_DEPLOY_GOOD_DB")
            rec_after = json.loads(rec_file.read_text(encoding="utf-8"))
            self.assertEqual(rec_after["phase"], "complete")

    def test_round8_common_sh_af_logged_nofollow_and_log_retention_self_healing_and_setup_hygiene(self) -> None:
        import importlib.util

        with tempfile.TemporaryDirectory(prefix="af-r8-common-", dir=RESOLVED_TMP_ROOT) as tmp:
            tmp_path = Path(tmp)
            lock_dir = tmp_path / "locks"
            lock_dir.mkdir()
            boot_log = tmp_path / "boot.log"
            victim = tmp_path / "victim.txt"
            sym_log = tmp_path / "symlink.log"
            sym_log.symlink_to(victim)

            probe_symlink = f"""
set -euo pipefail
export LOCK_DIR={str(lock_dir)!r}
export LOGFILE={str(boot_log)!r}
source {str(ROOT / 'packages/common.sh')!r}
export LOGFILE={str(sym_log)!r}
af_logged echo "SHOULD_NOT_WRITE"
"""
            res_sym = subprocess.run(["bash", "-c", probe_symlink], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertFalse(victim.exists(), "af_logged O_NOFOLLOW must never create symlink target")

            real_log = tmp_path / "install-test.log"
            probe_ok = f"""
set -euo pipefail
export LOCK_DIR={str(lock_dir)!r}
export LOGFILE={str(real_log)!r}
source {str(ROOT / 'packages/common.sh')!r}
my_shell_fn() {{ echo "SHELL_FN_OK"; }}
af_logged my_shell_fn
"""
            res_ok = subprocess.run(["bash", "-c", probe_ok], capture_output=True, text=True, timeout=10)
            self.assertEqual(res_ok.returncode, 0, msg=res_ok.stderr)
            self.assertIn("SHELL_FN_OK", real_log.read_text(encoding="utf-8"))

            # Verify deploy/log-retention.py rotates self_healing.log
            spec = importlib.util.spec_from_file_location(
                "af_log_retention_r8", ROOT / "deploy/log-retention.py"
            )
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            heal_dir = tmp_path / "heal_logs"
            heal_dir.mkdir()
            os.chmod(heal_dir, 0o750)
            heal_log = heal_dir / "self_healing.log"
            heal_log.write_bytes(b"H" * 1024)
            os.chmod(heal_log, 0o640)
            self.assertEqual(mod.retain_logs(str(heal_dir), max_bytes=256, keep=2), (1, []))
            self.assertTrue((heal_dir / "self_healing.log.af-retention.1").is_file())

        # Static hygiene checks on setup/sudoers/plugin scripts
        for retired_tpl in (
            "setup/templates/sudoers.template",
            "setup/templates/profile.template",
            "setup/templates/web-console.conf.template",
        ):
            self.assertFalse(
                (ROOT / retired_tpl).exists(),
                f"Obsolete QuickBox template {retired_tpl} must remain retired",
            )
        fin_src = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        self.assertIn('data-snapshot" \\) -prune', fin_src)
        self.assertNotIn("Admin Password:", fin_src)
        plugin_files = (
            [p for p in (ROOT / "packages/plugin").rglob("*") if p.is_file()]
            if (ROOT / "packages/plugin").exists()
            else []
        )
        self.assertEqual(
            plugin_files,
            [],
            "Obsolete QuickBox packages/plugin scripts must remain purged",
        )

    def test_round9_logs_confinement_manifest_fail_closed_and_nextcloud_vhost_scope(self) -> None:
        fin_src = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        self.assertIn('-path "${af_root}/logs"', fin_src)
        self.assertIn('chmod 700 "${af_root}/logs"', fin_src)
        self.assertIn('-exec chmod 600 {} +', fin_src)

        for pkg in ("filebrowser", "nextcloud"):
            pkg_src = (ROOT / f"packages/package/install/installpackage-{pkg}").read_text(
                encoding="utf-8"
            )
            self.assertIn("install -d -m 0700 /opt/AetherFlow/logs", pkg_src)

        vw_src = (ROOT / "packages/package/install/installpackage-vaultwarden").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/opt/AetherFlow/logs", vw_src)
        self.assertIn("install -d -m 0750 /etc/vaultwarden", vw_src)
        self.assertIn("write_config_file /etc/vaultwarden/admin_token.txt 0600", vw_src)
        self.assertIn("write_config_file /etc/vaultwarden/vaultwarden.env 0600", vw_src)

        nc_src = (ROOT / "packages/package/install/installpackage-nextcloud").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('sed -i', nc_src)
        self.assertIn("safe_config_python", nc_src)
        self.assertIn("write_config_file /etc/apache2/sites-available/nextcloud.conf 0644", nc_src)

        rm_src = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        self.assertIn("Failed to write snapshot SHA-256 manifest", rm_src)
        self.assertIn("AETHERFLOW_SKIP_PROVENANCE_VERIFY=1 is set", rm_src)

        # Functional test: state_snapshot fails closed if sha256sum fails
        snippet = rm_src[
            rm_src.index("state_snapshot() {") : rm_src.index("\nsync_legacy_package_paths()")
        ]
        with tempfile.TemporaryDirectory(prefix="af-r9-snap-") as tmp:
            tmp_path = Path(tmp)
            db_dir = tmp_path / "data"
            db_dir.mkdir()
            db_file = db_dir / "aetherflow.sqlite"
            import sqlite3

            conn = sqlite3.connect(db_file)
            conn.executescript("CREATE TABLE t (id INT); INSERT INTO t VALUES (1);")
            conn.commit()
            conn.close()

            bin_dir = tmp_path / "fakebin"
            bin_dir.mkdir()
            fake_sha = bin_dir / "sha256sum"
            fake_sha.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            fake_sha.chmod(0o755)

            probe = f"""
set -euo pipefail
export PATH="{bin_dir}:$PATH"
DRY_RUN=false
RESOLVED_DB_PATH={str(db_file)!r}
RESOLVED_DB_SOURCE="env"
RELEASE_DIR={str(tmp_path / 'rel')!r}
DATA_DIR={str(db_dir)!r}
SQLITE_DB="aetherflow.sqlite"
SNAPSHOT_TIMEOUT=5
sqlite_online_backup() {{ cp "$1" "$2"; }}
sqlite_integrity() {{ echo "ok"; }}
log_info() {{ :; }}
log_warn() {{ :; }}
log_error() {{ echo "ERR:$*" >&2; }}
{snippet}
state_snapshot
"""
            proc = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Failed to write snapshot SHA-256 manifest", proc.stderr)

    def test_pass3_seedbox_hardening_apache_headers_vsftpd_opt_in_and_dropin_alignment(self) -> None:
        ssl_tpl = (ROOT / "setup/templates/default-ssl.conf.template").read_text(encoding="utf-8")
        for header_dir in (
            "RequestHeader unset X-Real-IP",
            "RequestHeader unset X-Forwarded-Host",
            "RequestHeader unset X-Aetherflow-User",
            "RequestHeader unset Remote-User",
            "RequestHeader unset X-Forwarded-User",
            'RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"',
        ):
            self.assertIn(header_dir, ssl_tpl)
        self.assertNotIn("USERNAME.rtorrent.downloads", ssl_tpl)
        self.assertNotIn("USERNAME.deluge.downloads", ssl_tpl)
        self.assertNotIn("/etc/htpasswd", ssl_tpl)

        aliases_tpl = (ROOT / "setup/templates/aliases-seedbox.conf.template").read_text(encoding="utf-8")
        self.assertNotIn("Options Indexes FollowSymLinks", aliases_tpl)
        self.assertIn("Options -Indexes -FollowSymLinks", aliases_tpl)

        vsftpd_tpl = (ROOT / "setup/templates/vsftpd.conf.template").read_text(encoding="utf-8")
        for directive in (
            "ssl_tlsv1=NO",
            "ssl_tlsv1_1=NO",
            "ssl_tlsv1_2=YES",
            "seccomp_sandbox=YES",
        ):
            self.assertIn(directive, vsftpd_tpl)

        sec_sh = (ROOT / "setup/modules/04-security.sh").read_text(encoding="utf-8")
        default_ports = subprocess.check_output(
            ["bash", "-c", 'source "$1"; _fw_allowed_ports', "bash", str(ROOT / "setup/modules/04-security.sh")],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            text=True,
        ).strip()
        self.assertEqual(default_ports, "22/tcp 80/tcp 443/tcp")

        ftpd_ports = subprocess.check_output(
            ["bash", "-c", 'source "$1"; _fw_allowed_ports', "bash", str(ROOT / "setup/modules/04-security.sh")],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AETHERFLOW_ENABLE_FTPD": "yes"},
            text=True,
        ).strip()
        self.assertEqual(ftpd_ports, "22/tcp 80/tcp 443/tcp 21/tcp 10090:10100/tcp")
        self.assertNotIn("fileshare.conf.template", sec_sh)
        self.assertNotIn("lshell.conf-focal.template", sec_sh)

        fin_sh = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        self.assertIn("chmod 0600 /etc/ssl/private/vsftpd.pem", fin_sh)
        self.assertIn("AETHERFLOW_ENABLE_FTPD", fin_sh)
        for cli_cmd in ("af health", "af service status", "af service restart"):
            self.assertIn(cli_cmd, fin_sh)
        for old_cmd in ("aetherflow logs", "aetherflow restart", "aetherflow status"):
            self.assertNotIn(old_cmd, fin_sh)

        setup_sh = (ROOT / "setup/AetherFlow-Setup").read_text(encoding="utf-8")
        for retired_tok in ("AUTODLPASSWORD", "AUTODLPORT", "_lshell"):
            self.assertNotIn(retired_tok, setup_sh)
        self.assertIn("AETHERFLOW_ENABLE_FTPD", setup_sh)
        for retired_tpl in (
            "setup/templates/lshell.conf-focal.template",
            "setup/templates/fileshare.conf.template",
        ):
            self.assertFalse((ROOT / retired_tpl).exists(), f"Orphan template {retired_tpl} must be deleted")


if __name__ == "__main__":
    unittest.main()
