"""Regression tests for setup Apache MD5 Digest gating and snakeoil certificate subject hygiene."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROMPTS_SH = ROOT / "setup/modules/01-prompts.sh"
SECURITY_SH = ROOT / "setup/modules/04-security.sh"


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX bash")
class SetupApacheHygieneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-setup-hygiene-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mock_bin = self.root / "mock-bin"
        self.mock_bin.mkdir(parents=True)
        self.cmd_log = self.root / "commands.log"
        self.apache_etc = self.root / "etc/apache2"
        (self.apache_etc / "sites-enabled").mkdir(parents=True)
        (self.apache_etc / "conf-enabled").mkdir(parents=True)
        (self.apache_etc / "conf-enabled/security.conf").write_text(
            "ServerTokens OS\nServerSignature On\n", encoding="utf-8"
        )
        self.default_docroot = self.root / "var/www/aetherflow-default"
        self.digest_file = self.root / "etc/htpasswd"
        self.basic_file = self.apache_etc / "AetherFlow/htpasswd"
        self._install_mock_tools()

    def _install_mock_tools(self):
        for tool in ("a2enmod", "a2dismod", "a2enconf", "phpenmod"):
            script = self.mock_bin / tool
            script.write_text(
                f'#!/bin/bash\nprintf "%s %s\\n" "{tool}" "$*" >> "$CMD_LOG"\nexit 0\n',
                encoding="utf-8",
            )
            script.chmod(0o755)
        chown = self.mock_bin / "chown"
        chown.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        chown.chmod(0o755)
        htpasswd = self.mock_bin / "htpasswd"
        htpasswd.write_text(
            '#!/bin/bash\nprintf "%s:\\$2y\\$10\\$mockedbcrypthashvalue012345678901234567890123456\\n" "$2"\n',
            encoding="utf-8",
        )
        htpasswd.chmod(0o755)
        openssl = self.mock_bin / "openssl"
        openssl.write_text(
            '#!/bin/bash\nprintf "openssl %s\\n" "$*" >> "$CMD_LOG"\n'
            'out_path=""\n'
            'while [[ $# -gt 0 ]]; do\n'
            '  if [[ "$1" == "-out" ]]; then out_path="$2"; shift 2; continue; fi\n'
            '  shift\n'
            'done\n'
            'if [[ -n "$out_path" ]]; then mkdir -p "$(dirname "$out_path")"; printf "CERT\\n" > "$out_path"; fi\n'
            'exit 0\n',
            encoding="utf-8",
        )
        openssl.chmod(0o755)

    def _run_setup_snippet(self, snippet: str, extra_env=None) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "PATH": f"{self.mock_bin}:/usr/bin:/bin",
            "CMD_LOG": str(self.cmd_log),
            "OUTTO": str(self.root / "setup.log"),
            "HTPASSWD": str(self.digest_file),
            "AF_APACHE_HTPASSWD": str(self.basic_file),
            "AF_APACHE_ETC_DIR": str(self.apache_etc),
            "AF_LEGACY_SEEDBOX_ALIASES_CONF": str(self.apache_etc / "sites-enabled/aliases-seedbox.conf"),
            "AF_DEFAULT_DOCROOT": str(self.default_docroot),
            "AF_LEGACY_SRV_LINK": str(self.root / "srv/aetherflow"),
            "AF_PHP_ETC_DIR": str(self.root / "etc/php"),
            "local_setup": f"{ROOT / 'setup'}/",
            "username": "alice",
            "passwd": "StrongPassword123!",
            "REALM": "Welcome to AetherFlow",
        }
        env.pop("AF_ENABLE_LEGACY_SEEDBOX_ALIASES", None)
        env.pop("FQDN", None)
        if extra_env:
            for k, v in extra_env.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        script = (
            f'set -euo pipefail\n'
            f'source "{PROMPTS_SH}"\n'
            f'source "{SECURITY_SH}"\n'
            f"{snippet}\n"
        )
        return subprocess.run(
            ["bash", "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_fresh_setup_skips_md5_digest_and_legacy_seedbox_aliases_by_default(self):
        res = self._run_setup_snippet(
            '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf'
        )
        self.assertEqual(res.returncode, 0, res.stderr)

        self.assertTrue(self.basic_file.is_file())
        self.assertTrue(self.basic_file.read_text(encoding="utf-8").startswith("alice:$2y$"))
        self.assertFalse(self.digest_file.exists(), "fresh setup must not create MD5 /etc/htpasswd by default")
        self.assertFalse(
            (self.apache_etc / "sites-enabled/aliases-seedbox.conf").exists(),
            "fresh setup must not provision aliases-seedbox.conf by default",
        )
        self.assertTrue((self.apache_etc / "sites-enabled/default-ssl.conf").is_file())
        cmds = self.cmd_log.read_text(encoding="utf-8") if self.cmd_log.exists() else ""
        self.assertNotIn("a2enmod auth_digest", cmds)
        self.assertIn("a2enmod ssl", cmds)

    def test_explicit_opt_in_enables_legacy_seedbox_aliases_and_digest_htpasswd(self):
        res = self._run_setup_snippet(
            '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf',
            extra_env={"AF_ENABLE_LEGACY_SEEDBOX_ALIASES": "1"},
        )
        self.assertEqual(res.returncode, 0, res.stderr)

        self.assertTrue(self.basic_file.is_file())
        self.assertTrue(self.digest_file.is_file())
        self.assertIn("alice:Welcome to AetherFlow:", self.digest_file.read_text(encoding="utf-8"))
        aliases_conf = self.apache_etc / "sites-enabled/aliases-seedbox.conf"
        self.assertTrue(aliases_conf.is_file())
        self.assertIn("/alice.rtorrent.downloads", aliases_conf.read_text(encoding="utf-8"))
        self.assertIn("a2enmod auth_digest", self.cmd_log.read_text(encoding="utf-8"))

    def test_existing_upgraded_hosts_preserve_legacy_aliases_and_digest_automatically(self):
        # Case A: upgraded host already has aliases-seedbox.conf
        aliases_conf = self.apache_etc / "sites-enabled/aliases-seedbox.conf"
        aliases_conf.write_text("# pre-existing upgraded host\n", encoding="utf-8")
        res = self._run_setup_snippet(
            '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf'
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(self.basic_file.is_file())
        self.assertTrue(self.digest_file.is_file())
        self.assertIn("/alice.rtorrent.downloads", aliases_conf.read_text(encoding="utf-8"))
        self.assertIn("a2enmod auth_digest", self.cmd_log.read_text(encoding="utf-8"))

        # Case B: upgraded host has pre-existing /etc/htpasswd only
        aliases_conf.unlink()
        self.cmd_log.unlink()
        self.digest_file.write_text("legacy:Welcome to AetherFlow:0000\n", encoding="utf-8")
        res2 = self._run_setup_snippet(
            '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf'
        )
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertIn("alice:Welcome to AetherFlow:", self.digest_file.read_text(encoding="utf-8"))
        self.assertTrue(aliases_conf.is_file())
        self.assertIn("a2enmod auth_digest", self.cmd_log.read_text(encoding="utf-8"))

    def test_snakeoil_cert_uses_neutral_local_subject_and_sanitizes_fqdn(self):
        sec_src = SECURITY_SH.read_text(encoding="utf-8")
        self.assertNotIn("/C=CN/ST=BJ/L=PRC/O=IT/CN=www.example.com", sec_src)
        self.assertNotIn("www.example.com", sec_src)

        cases = [
            (None, "/CN=aetherflow.local"),
            ("", "/CN=aetherflow.local"),
            ("box.example.net", "/CN=box.example.net"),
            ("box.example.net.", "/CN=box.example.net"),
            ("evil/O=Injected", "/CN=aetherflow.local"),
            ("../traversal", "/CN=aetherflow.local"),
            ("bad host name", "/CN=aetherflow.local"),
        ]
        for idx, (fqdn_val, expected_subj) in enumerate(cases):
            with self.subTest(fqdn=fqdn_val):
                self.cmd_log.unlink(missing_ok=True)
                cert_path = self.root / f"certs/snakeoil-{idx}.pem"
                key_path = self.root / f"certs/snakeoil-{idx}.key"
                res = self._run_setup_snippet(
                    "_fix_cert",
                    extra_env={
                        "FQDN": fqdn_val,
                        "AF_SNAKEOIL_CERT": str(cert_path),
                        "AF_SNAKEOIL_KEY": str(key_path),
                    },
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertTrue(cert_path.is_file())
                logged = self.cmd_log.read_text(encoding="utf-8")
                self.assertIn(f"-subj {expected_subj}", logged)

    def test_apacheconf_sets_default_ssl_server_name_when_fqdn_configured(self):
        res = self._run_setup_snippet(
            '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf',
            extra_env={"FQDN": "Example.org."},
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        default_ssl = (self.apache_etc / "sites-enabled/default-ssl.conf").read_text(encoding="utf-8")
        self.assertNotIn("ServerName _", default_ssl)
        self.assertEqual(default_ssl.count("ServerName example.org"), 2)
        self.assertEqual(
            default_ssl.count(
                "ServerAlias www.example.org direct.example.org *.example.org"
            ),
            2,
        )

    def test_apacheconf_keeps_placeholder_for_local_or_invalid_fqdn(self):
        for bad_fqdn in (None, "", "localhost", "box.local", "evil/host", "bad host"):
            with self.subTest(fqdn=bad_fqdn):
                res = self._run_setup_snippet(
                    '_write_apache_htpasswd_files "$username" "$passwd" "$REALM"\n_apacheconf',
                    extra_env={"FQDN": bad_fqdn},
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                default_ssl = (self.apache_etc / "sites-enabled/default-ssl.conf").read_text(
                    encoding="utf-8"
                )
                self.assertEqual(default_ssl.count("ServerName _"), 2)


if __name__ == "__main__":
    unittest.main()
