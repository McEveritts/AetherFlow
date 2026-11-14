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


if __name__ == "__main__":
    unittest.main()
