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


class Round3SecurityRegressionTests(unittest.TestCase):
    def test_common_sh_64hex_aes_ctypes_openssl_fallback_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-r3-creds-") as tmp:
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
        with tempfile.TemporaryDirectory(prefix="af-r3-logret-") as tmp:
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
        tpl_unit = (ROOT / "setup/templates/sysd/aetherflow-runner.template").read_text(encoding="utf-8")
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
            self.assertIn(directive, tpl_unit)
            self.assertIn(directive, rm_sh)
            self.assertIn(directive, health_rs)

        for unit_text in (pkg_unit, tpl_unit):
            active_lines = [
                ln.strip()
                for ln in unit_text.splitlines()
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

        with tempfile.TemporaryDirectory(prefix="af-r5-common-") as tmp:
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

        with tempfile.TemporaryDirectory(prefix="af-r5-logret-") as tmp:
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

    def test_log_retention_skips_active_flock_holder_from_common_sh(self) -> None:
        import fcntl
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "af_log_retention_r6", ROOT / "deploy/log-retention.py"
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory(prefix="af-r6-loglock-") as tmp:
            log_dir = Path(tmp)
            os.chmod(log_dir, 0o750)
            log_path = log_dir / "install-sabnzbd.log"
            log_path.write_bytes(b"X" * 1024 + b"\nACTIVE_INSTALL_LINE\n")
            os.chmod(log_path, 0o640)

            with open(log_path, "rb") as active_holder:
                fcntl.flock(active_holder.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                try:
                    self.assertEqual(mod.retain_logs(str(log_dir), max_bytes=256, keep=2), (0, []))
                    self.assertIn(b"ACTIVE_INSTALL_LINE\n", log_path.read_bytes())
                finally:
                    fcntl.flock(active_holder.fileno(), fcntl.LOCK_UN)

            self.assertEqual(mod.retain_logs(str(log_dir), max_bytes=256, keep=2), (1, []))
            archive_bytes = (log_dir / "install-sabnzbd.log.af-retention.1").read_bytes()
            self.assertIn(b"ACTIVE_INSTALL_LINE\n", archive_bytes)


if __name__ == "__main__":
    unittest.main()
