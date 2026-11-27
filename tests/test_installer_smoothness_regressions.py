#!/usr/bin/env python3
"""Regression tests for fresh-install smoothness findings on Debian 13 (Trixie):
1. FTP opt-in (AETHERFLOW_ENABLE_FTPD=yes): vsftpd 3.0.5/3.0.3 TLS directives, port 21 alignment,
   no raw iptables pre-injection that tricks _setup_firewall into skipping UFW, surfaced
   systemctl start failures, case-insensitive truthiness, and _installftpd behavior.
2. Interactive & unattended fresh-install OUTTO logging prompt (not short-circuited to /dev/null
   at module source time), plus --resume, --fresh, interactive 'n', and set -u safety with OUTTO unset.
3. _hostname() in-memory domain/hostname_value/FQDN propagation, symlink fail-closed guards,
   _finished() banner domain, /root 0700 parent-dir preservation, direct-interface/offline IPv4
   detection, bootstrap-token onboarding wording, and valid af CLI commands.
4. Debian _depends() omits virtual dstat package so pcp (pmcd + pmlogger) is not pulled in.
5. _apacheconf() guards optional legacy scgi/fastcgi modules (enabling fcgid when present) and
   AetherFlow-Setup describes ffmpeg as an APT package install rather than a source build.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPT = ROOT / "setup/AetherFlow-Setup"
CORE_SH = ROOT / "setup/modules/00-core.sh"
PACKAGES_SH = ROOT / "setup/modules/02-packages.sh"
SERVICES_SH = ROOT / "setup/modules/03-services.sh"
SECURITY_SH = ROOT / "setup/modules/04-security.sh"
FINALIZE_SH = ROOT / "setup/modules/05-finalize.sh"
STATE_SH = ROOT / "setup/modules/06-state.sh"
VSFTPD_TPL = ROOT / "setup/templates/vsftpd.conf.template"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _extract_seed_helpers_from_setup() -> str:
    src = SETUP_SCRIPT.read_text(encoding="utf-8")
    truthy_block = src[src.index("af_truthy() {") : src.index("af_resolve_seed_path() {")]
    seed_block = src[src.index("_save_seed_value() {") : src.index("# Export for use in 06-state.sh")]
    return truthy_block + "\n" + seed_block


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX bash")
class InstallerSmoothnessRegressionTests(unittest.TestCase):
    def test_vsftpd_template_tls_adaptation_port_21_and_ufw_preservation(self) -> None:
        tpl_text = VSFTPD_TPL.read_text(encoding="utf-8")
        self.assertIn("ssl_tlsv1=NO", tpl_text)
        self.assertIn("ssl_tlsv11=NO", tpl_text)
        self.assertIn("ssl_tlsv12=YES", tpl_text)
        self.assertIn("ssl_tlsv13=YES", tpl_text)
        self.assertIn("listen_port=21", tpl_text)
        self.assertNotIn("ssl_tlsv1_1=", tpl_text)
        self.assertNotIn("ssl_tlsv1_2=", tpl_text)
        self.assertNotIn("listen_port=5757", tpl_text)

        with tempfile.TemporaryDirectory(prefix="af-smooth-ftpd-") as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()

            ipt_log = root / "iptables.log"
            ufw_log = root / "ufw.log"
            systemctl_log = root / "systemctl.log"
            openssl_log = root / "openssl.log"
            apt_log = root / "apt.log"

            _write_executable(
                stub_bin / "openssl",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(openssl_log)!r}
out_path=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-out" ]; then out_path="$2"; shift 2; continue; fi
    shift
done
if [ -n "$out_path" ]; then
    mkdir -p "$(dirname "$out_path")"
    printf 'MOCK-CERT\\n' > "$out_path"
fi
exit 0
""",
            )
            _write_executable(stub_bin / "chown", "#!/bin/sh\nexit 0\n")
            _write_executable(
                stub_bin / "apt-get",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(apt_log)!r}
if [ "$1" = "purge" ]; then exit 100; fi
exit 0
""",
            )
            _write_executable(
                stub_bin / "iptables",
                f"""#!/bin/sh
printf 'iptables %s\\n' "$*" >> {str(ipt_log)!r}
if [ "$1" = "-S" ]; then
    printf -- '-P %s ACCEPT\\n' "$2"
    exit 0
fi
exit 0
""",
            )
            _write_executable(
                stub_bin / "ip6tables",
                f"""#!/bin/sh
printf 'ip6tables %s\\n' "$*" >> {str(ipt_log)!r}
if [ "$1" = "-S" ]; then
    printf -- '-P %s ACCEPT\\n' "$2"
    exit 0
fi
exit 0
""",
            )
            _write_executable(
                stub_bin / "ufw",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(ufw_log)!r}
if [ "$1" = "status" ]; then
    echo "Status: inactive"
    exit 0
fi
exit 0
""",
            )
            _write_executable(
                stub_bin / "systemctl",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(systemctl_log)!r}
if [ "${{MOCK_VSFTPD_FAIL:-0}}" = "1" ] && [ "$1" = "restart" ] && [ "$2" = "vsftpd" ]; then
    echo "Job for vsftpd.service failed" >&2
    exit 1
fi
exit 0
""",
            )
            _write_executable(
                stub_bin / "ip",
                """#!/bin/sh
if [ "${MOCK_IP_MODE:-direct}" = "offline" ]; then
    echo "RTNETLINK answers: Network is unreachable" >&2
    exit 2
fi
echo "8.8.8.8 dev eth0 src 198.51.100.77 uid 0"
exit 0
""",
            )

            # 1. Mock vsftpd 3.0.5 binary (no underscores, supports ssl_tlsv11/12/13) with mixed-case AETHERFLOW_ENABLE_FTPD=Yes
            bin_305 = root / "vsftpd-305"
            bin_305.write_bytes(b"\x00ssl_tlsv1\x00ssl_tlsv11\x00ssl_tlsv12\x00ssl_tlsv13\x00")

            conf_305 = root / "etc/vsftpd.conf"
            chroot_list = root / "etc/vsftpd.chroot_list"
            cert_file = root / "etc/ssl/private/vsftpd.pem"
            openssl_cnf = root / "root/.openssl.cnf"
            out_log = root / "setup.log"

            env = {
                **os.environ,
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "AETHERFLOW_ENABLE_FTPD": "Yes",
                "IP": "203.0.113.42",
                "AF_SYS_ROOT": str(root / "sysroot"),
                "AF_SSH_PORTS": "22",
                "AF_OPENSSL_CNF": str(openssl_cnf),
                "AF_VSFTPD_CERT": str(cert_file),
                "AF_VSFTPD_CONF": str(conf_305),
                "AF_VSFTPD_CHROOT_LIST": str(chroot_list),
                "AF_VSFTPD_BIN": str(bin_305),
                "OUTTO": str(out_log),
                "INSTALL_LOG": str(root / "install.log"),
                "local_setup": f"{ROOT / 'setup'}/",
            }
            (root / "sysroot/etc/ssh").mkdir(parents=True)
            (root / "sysroot/etc/ssh/sshd_config").write_text("Port 22\n", encoding="utf-8")

            probe = (
                'set -euo pipefail\n'
                f'source "{CORE_SH}"\n'
                f'source "{SERVICES_SH}"\n'
                f'source "{SECURITY_SH}"\n'
                f'source "{FINALIZE_SH}"\n'
                '_installftpd\n'
                '_ftpdconfig\n'
                '_setup_firewall\n'
            )
            res = subprocess.run(["bash", "-c", probe], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            # _installftpd ignores purge non-zero and installs vsftpd via _af_apt_install
            apt_lines = apt_log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(any("install" in ln and "vsftpd" in ln for ln in apt_lines), apt_lines)

            rendered = conf_305.read_text(encoding="utf-8")
            self.assertIn("ssl_tlsv1=NO\n", rendered)
            self.assertIn("ssl_tlsv11=NO\n", rendered)
            self.assertIn("ssl_tlsv12=YES\n", rendered)
            self.assertIn("ssl_tlsv13=YES\n", rendered)
            self.assertIn("listen_port=21\n", rendered)
            self.assertIn("pasv_min_port=10090\n", rendered)
            self.assertIn("pasv_max_port=10100\n", rendered)
            self.assertIn("pasv_address=203.0.113.42\n", rendered)
            self.assertEqual(cert_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(cert_file.parent.stat().st_mode & 0o777, 0o710)
            self.assertEqual(openssl_cnf.parent.stat().st_mode & 0o777, 0o700)

            # _ftpdconfig must NOT invoke iptables -I/-A, so _setup_firewall selects UFW on a clean host
            ipt_lines = ipt_log.read_text(encoding="utf-8").splitlines() if ipt_log.exists() else []
            self.assertFalse(
                any("-I INPUT" in ln or "-A INPUT" in ln for ln in ipt_lines),
                f"_ftpdconfig must not inject raw iptables rules: {ipt_lines}",
            )
            ufw_cmds = ufw_log.read_text(encoding="utf-8").splitlines()
            self.assertIn("allow 21/tcp", ufw_cmds)
            self.assertIn("allow 10090:10100/tcp", ufw_cmds)
            self.assertIn("--force enable", ufw_cmds)
            self.assertIn("enable vsftpd", systemctl_log.read_text(encoding="utf-8").splitlines())
            self.assertIn("restart vsftpd", systemctl_log.read_text(encoding="utf-8").splitlines())

            # 1b. Direct-interface /32 route extracts src IP (198.51.100.77, NOT uid 0) when IP is unset;
            # offline route (exit 2) succeeds cleanly under set -euo pipefail without writing empty pasv_address
            env_no_ip = {k: v for k, v in env.items() if k != "IP"}
            env_no_ip["AF_SKIP_SYSTEMCTL"] = "1"
            res_direct = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env_no_ip, "MOCK_IP_MODE": "direct"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_direct.returncode, 0, res_direct.stderr)
            self.assertIn("pasv_address=198.51.100.77\n", conf_305.read_text(encoding="utf-8"))

            res_offline = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env_no_ip, "MOCK_IP_MODE": "offline"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_offline.returncode, 0, res_offline.stderr)
            self.assertNotIn("pasv_address=", conf_305.read_text(encoding="utf-8"))

            # 2. If host has real /usr/sbin/vsftpd (e.g., Debian 13) and we are non-root, prove it
            # parses every rendered directive cleanly. vsftpd writes `500 OOPS:` messages to fd 0
            # (VSFTP_COMMAND_FD), so capture via a socketpair connected to stdin/stdout/stderr.
            real_vsftpd = Path("/usr/sbin/vsftpd")
            if os.geteuid() != 0 and real_vsftpd.is_file() and os.access(real_vsftpd, os.X_OK):
                def _probe_vsftpd_config(cfg_path: Path) -> str:
                    parent_sock, child_sock = socket.socketpair()
                    try:
                        proc = subprocess.Popen(
                            [str(real_vsftpd), str(cfg_path)],
                            stdin=child_sock,
                            stdout=child_sock,
                            stderr=child_sock,
                            close_fds=True,
                        )
                        child_sock.close()
                        proc.wait(timeout=10)
                        parent_sock.settimeout(1.0)
                        chunks: list[bytes] = []
                        while True:
                            try:
                                data = parent_sock.recv(4096)
                            except OSError:
                                break
                            if not data:
                                break
                            chunks.append(data)
                        return b"".join(chunks).decode("utf-8", errors="replace")
                    finally:
                        child_sock.close()
                        parent_sock.close()

                env_real = {**env, "AF_VSFTPD_BIN": str(real_vsftpd), "AF_SKIP_SYSTEMCTL": "1"}
                res_real = subprocess.run(
                    ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                    env=env_real,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res_real.returncode, 0, res_real.stderr)
                ok_msg = _probe_vsftpd_config(conf_305)
                self.assertIn("must be started as root", ok_msg, f"Unexpected vsftpd parser output: {ok_msg!r}")
                self.assertNotIn("unrecognised variable", ok_msg)

                bad_conf = root / "etc/vsftpd-bad.conf"
                bad_conf.write_text("listen=YES\nssl_enable=YES\nssl_tlsv1_1=NO\n", encoding="utf-8")
                bad_msg = _probe_vsftpd_config(bad_conf)
                self.assertIn("unrecognised variable in config file: ssl_tlsv1_1", bad_msg)

            # 3. vsftpd 3.0.5 without ssl_tlsv13 drops ssl_tlsv13 while keeping ssl_tlsv11/12
            bin_305_no13 = root / "vsftpd-305-no13"
            bin_305_no13.write_bytes(b"\x00ssl_tlsv1\x00ssl_tlsv11\x00ssl_tlsv12\x00")
            res_no13 = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env, "AF_VSFTPD_BIN": str(bin_305_no13), "AF_SKIP_SYSTEMCTL": "1"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_no13.returncode, 0, res_no13.stderr)
            t_no13 = conf_305.read_text(encoding="utf-8")
            self.assertIn("ssl_tlsv11=NO\n", t_no13)
            self.assertIn("ssl_tlsv12=YES\n", t_no13)
            self.assertNotIn("ssl_tlsv13=", t_no13)

            # 4. Underscored build with and without ssl_tlsv1_3
            bin_u_no13 = root / "vsftpd-underscored-no13"
            bin_u_no13.write_bytes(b"\x00ssl_tlsv1\x00ssl_tlsv1_1\x00ssl_tlsv1_2\x00")
            res_u = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env, "AF_VSFTPD_BIN": str(bin_u_no13), "AF_SKIP_SYSTEMCTL": "1"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_u.returncode, 0, res_u.stderr)
            u_text = conf_305.read_text(encoding="utf-8")
            self.assertIn("ssl_tlsv1_1=NO\n", u_text)
            self.assertIn("ssl_tlsv1_2=YES\n", u_text)
            self.assertNotIn("ssl_tlsv11=", u_text)
            self.assertNotIn("ssl_tlsv13=", u_text)
            self.assertNotIn("ssl_tlsv1_3=", u_text)

            bin_u_13 = root / "vsftpd-underscored-13"
            bin_u_13.write_bytes(b"\x00ssl_tlsv1\x00ssl_tlsv1_1\x00ssl_tlsv1_2\x00ssl_tlsv1_3\x00")
            res_u13 = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env, "AF_VSFTPD_BIN": str(bin_u_13), "AF_SKIP_SYSTEMCTL": "1"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_u13.returncode, 0, res_u13.stderr)
            self.assertIn("ssl_tlsv1_3=YES\n", conf_305.read_text(encoding="utf-8"))

            # 5. Legacy vsftpd 3.0.3 (only ssl_tlsv1) drops ssl_tlsv11/12/13 cleanly
            bin_303 = root / "vsftpd-303"
            bin_303.write_bytes(b"\x00ssl_tlsv1\x00ssl_sslv2\x00ssl_sslv3\x00")
            res_303 = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env, "AF_VSFTPD_BIN": str(bin_303), "AF_SKIP_SYSTEMCTL": "1"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_303.returncode, 0, res_303.stderr)
            t303 = conf_305.read_text(encoding="utf-8")
            self.assertIn("ssl_tlsv1=NO\n", t303)
            self.assertNotIn("ssl_tlsv11=", t303)
            self.assertNotIn("ssl_tlsv12=", t303)
            self.assertNotIn("ssl_tlsv13=", t303)

            # 6. Failing `systemctl restart vsftpd` MUST fail _ftpdconfig AND emit [ WARN ] in _finished
            res_fail = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**env, "MOCK_VSFTPD_FAIL": "1"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_fail.returncode, 0)

            info_file = root / "priv-root/information.info"
            res_fin_warn = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'set -euo pipefail; source "{CORE_SH}"; source "{STATE_SH}"; source "{FINALIZE_SH}"; '
                    'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""; _init_state; _finished',
                ],
                input="n\n",
                env={
                    **env,
                    "STATE_FILE": str(root / "state"),
                    "CONFIG_FILE": str(root / "config"),
                    "AF_INFO_FILE": str(info_file),
                    "AF_SKIP_SELF_DELETE": "1",
                    "MOCK_VSFTPD_FAIL": "1",
                    "UNATTENDED": "false",
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_fin_warn.returncode, 0, res_fin_warn.stdout + res_fin_warn.stderr)
            self.assertIn("vsftpd failed to start", res_fin_warn.stdout)

    def test_fresh_interactive_unattended_resume_and_fresh_flag_outto_flow(self) -> None:
        seed_helpers = _extract_seed_helpers_from_setup()
        with tempfile.TemporaryDirectory(prefix="af-smooth-outto-") as tmp:
            root = Path(tmp)
            state_file = root / "state"
            config_file = root / "config"
            install_log = root / "install.log"

            base_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "STATE_FILE": str(state_file),
                "CONFIG_FILE": str(config_file),
                "INSTALL_LOG": str(install_log),
            }

            # 1. Sourcing all modules must leave OUTTO unset
            src_probe = (
                'set -e\n'
                f'for m in "{ROOT / "setup/modules"}"/*.sh; do source "$m"; done\n'
                'printf "OUTTO=[%s]\\n" "${OUTTO:-}"\n'
            )
            r_src = subprocess.run(["bash", "-c", src_probe], env=base_env, capture_output=True, text=True, timeout=15)
            self.assertEqual(r_src.returncode, 0, r_src.stderr)
            self.assertEqual(r_src.stdout.strip(), "OUTTO=[]")

            # Mirrors setup/AetherFlow-Setup lines 2145-2185 + _logcheck
            def run_flow(
                *,
                unattended: bool = False,
                fresh: bool = False,
                stdin_text: str = "",
                extra_env: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[str]:
                probe = (
                    'set +e\n'
                    f'for m in "{ROOT / "setup/modules"}"/*.sh; do source "$m"; done\n'
                    'set +e\n'
                    f'UNATTENDED={"true" if unattended else "false"}\n'
                    f'FRESH_INSTALL={"true" if fresh else "false"}\n'
                    'BUILD_FROM_SOURCE=false; CLI_USERNAME=""; CLI_PASSWORD=""; CLI_DOMAIN=""; RELEASE_CHANNEL="stable"\n'
                    'af_detect_default_channel() { echo stable; }\n'
                    f'{seed_helpers}\n'
                    '_init_state\n'
                    'if [[ "${FRESH_INSTALL}" == "true" ]]; then _cleanup_state; fi\n'
                    'if [[ -f "${CONFIG_FILE}" ]]; then _load_config_into_vars; fi\n'
                    '_apply_seed_config\n'
                    'if [[ -f "${CONFIG_FILE}" ]]; then _load_config_into_vars; fi\n'
                    'OUTTO="${OUTTO:-/dev/null}"\n'
                    '_logcheck\n'
                    'printf "\\nFINAL_OUTTO=%s\\n" "$OUTTO"\n'
                )
                return subprocess.run(
                    ["bash", "-c", probe],
                    input=stdin_text,
                    env={**base_env, **(extra_env or {})},
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            # 2. Fresh interactive install ("y"): prompts and saves /root/AetherFlow.<PPID>.log
            r_int = run_flow(stdin_text="y\n")
            self.assertEqual(r_int.returncode, 0, r_int.stdout + r_int.stderr)
            self.assertIn("Do you wish to write to a log file?", r_int.stdout)
            m = re.search(r"FINAL_OUTTO=(/root/AetherFlow\.\d+\.log)", r_int.stdout)
            self.assertIsNotNone(m, r_int.stdout)
            assert m is not None
            saved_log_path = m.group(1)
            self.assertIn(f"OUTTO={saved_log_path}", config_file.read_text(encoding="utf-8"))

            # 3. Resumed install preserves saved OUTTO without re-prompting
            r_resume = run_flow()
            self.assertEqual(r_resume.returncode, 0, r_resume.stdout + r_resume.stderr)
            self.assertNotIn("Do you wish to write to a log file?", r_resume.stdout)
            self.assertIn(f"FINAL_OUTTO={saved_log_path}", r_resume.stdout)

            # 4. Interactive "n" selects /dev/null explicitly; subsequent --fresh clears it and re-prompts
            config_file.unlink(missing_ok=True)
            r_no = run_flow(stdin_text="n\n")
            self.assertEqual(r_no.returncode, 0, r_no.stdout + r_no.stderr)
            self.assertIn("Do you wish to write to a log file?", r_no.stdout)
            self.assertIn("FINAL_OUTTO=/dev/null", r_no.stdout)
            self.assertIn("OUTTO=/dev/null", config_file.read_text(encoding="utf-8"))

            r_fresh = run_flow(fresh=True, stdin_text="y\n")
            self.assertEqual(r_fresh.returncode, 0, r_fresh.stdout + r_fresh.stderr)
            self.assertIn("Do you wish to write to a log file?", r_fresh.stdout)
            self.assertRegex(r_fresh.stdout, r"FINAL_OUTTO=/root/AetherFlow\.\d+\.log")

            # 5. Fresh unattended install without AETHERFLOW_LOG_FILE saves /root/AetherFlow.<PPID>.log
            config_file.unlink(missing_ok=True)
            r_unatt = run_flow(unattended=True)
            self.assertEqual(r_unatt.returncode, 0, r_unatt.stdout + r_unatt.stderr)
            self.assertNotIn("Do you wish to write to a log file?", r_unatt.stdout)
            self.assertRegex(r_unatt.stdout, r"FINAL_OUTTO=/root/AetherFlow\.\d+\.log")

            # 6. Explicit AETHERFLOW_LOG_FILE skips prompt and preserves custom path
            config_file.unlink(missing_ok=True)
            r_custom = run_flow(extra_env={"AETHERFLOW_LOG_FILE": "/root/AetherFlow.install.log"})
            self.assertEqual(r_custom.returncode, 0, r_custom.stdout + r_custom.stderr)
            self.assertNotIn("Do you wish to write to a log file?", r_custom.stdout)
            self.assertIn("FINAL_OUTTO=/root/AetherFlow.install.log", r_custom.stdout)

    def test_hostname_propagates_to_finished_banner_preserves_root_mode_and_blocks_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-smooth-host-") as tmp:
            root = Path(tmp)
            state_file = root / "state"
            config_file = root / "config"
            install_log = root / "install.log"
            etc_hostname = root / "hostname"
            etc_hosts = root / "hosts"
            etc_hosts.write_text("127.0.0.1 localhost\n127.0.1.1 old.local old\n", encoding="utf-8")

            # Simulate /root with strict 0700 permissions — _finished() must NOT weaken it to 0755
            fake_root_dir = root / "root-home"
            fake_root_dir.mkdir(mode=0o700)
            fake_root_dir.chmod(0o700)
            info_file = fake_root_dir / "information.info"

            stub_bin = root / "bin"
            stub_bin.mkdir()
            _write_executable(
                stub_bin / "ip",
                """#!/bin/sh
if [ "${MOCK_IP_MODE:-direct}" = "offline" ]; then
    exit 2
fi
echo "8.8.8.8 dev eth0 src 203.0.113.99 uid 0"
exit 0
""",
            )

            base_env = {
                "PATH": f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "STATE_FILE": str(state_file),
                "CONFIG_FILE": str(config_file),
                "INSTALL_LOG": str(install_log),
                "AF_HOSTNAME_FILE": str(etc_hostname),
                "AF_HOSTS_FILE": str(etc_hosts),
                "AF_SKIP_HOSTNAME_CMD": "1",
                "AF_INFO_FILE": str(info_file),
                "AF_SKIP_SELF_DELETE": "1",
                "AF_SKIP_SYSTEMCTL": "1",
                "UNATTENDED": "false",
                "username": "operator",
                "FIN": "3",
            }

            # 1. Same-shell interactive _hostname -> _finished (fresh interactive flow)
            probe = (
                'set -euo pipefail\n'
                f'source "{CORE_SH}"\n'
                f'source "{STATE_SH}"\n'
                f'source "{FINALIZE_SH}"\n'
                'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""\n'
                '_init_state\n'
                '_hostname\n'
                'printf "MEM_VARS=%s|%s|%s\\n" "$hostname_value" "$domain" "$FQDN"\n'
                '_finished\n'
            )
            res = subprocess.run(
                ["bash", "-c", probe],
                input="example.org\nn\n",
                env=base_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("MEM_VARS=example.org|example.org|example.org", res.stdout)
            self.assertEqual(etc_hostname.read_text(encoding="utf-8").strip(), "example.org")
            self.assertIn("127.0.1.1 example.org example", etc_hosts.read_text(encoding="utf-8"))
            self.assertEqual(
                fake_root_dir.stat().st_mode & 0o777,
                0o700,
                "_finished() must never weaken an existing 0700 parent directory (e.g. /root)",
            )
            self.assertEqual(info_file.stat().st_mode & 0o777, 0o600)

            self.assertIn("https://example.org/", res.stdout)
            self.assertIn("/var/lib/aetherflow/.setup-bootstrap-token", res.stdout)
            self.assertNotIn("Log in using the administrator credentials you created", res.stdout)
            self.assertIn("af health", res.stdout)
            self.assertIn("af service status aetherflow-api", res.stdout)
            self.assertIn("af service restart aetherflow-api", res.stdout)
            self.assertNotRegex(res.stdout, r"af service status\s+-")
            self.assertNotRegex(res.stdout, r"af service restart\s+-")

            info_text = info_file.read_text(encoding="utf-8")
            self.assertIn("Dashboard Onboarding: https://example.org/", info_text)
            self.assertIn("/var/lib/aetherflow/.setup-bootstrap-token", info_text)

            # 2. Resumed-shell _finished without in-memory domain/hostname_value still reads saved config
            resume_probe = (
                'set -euo pipefail\n'
                f'source "{CORE_SH}"\n'
                f'source "{STATE_SH}"\n'
                f'source "{FINALIZE_SH}"\n'
                'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""\n'
                'unset domain hostname_value username\n'
                '_finished\n'
            )
            res_resume = subprocess.run(
                ["bash", "-c", resume_probe],
                input="n\n",
                env={
                    **{k: v for k, v in base_env.items() if k != "username"},
                    "AETHERFLOW_WEB_ADMIN_PASSWORD": "ExplicitSeedPassword123!",
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_resume.returncode, 0, res_resume.stdout + res_resume.stderr)
            self.assertIn("https://example.org/", res_resume.stdout)
            self.assertIn("Sign in with the web administrator account seeded during setup.", res_resume.stdout)

            # 3. Direct-interface route without domain uses src IP (203.0.113.99, NOT 0),
            #    and offline route falls back to 127.0.0.1 under set -euo pipefail
            config_file.unlink(missing_ok=True)
            res_no_domain = subprocess.run(
                ["bash", "-c", resume_probe],
                input="n\n",
                env={**base_env, "MOCK_IP_MODE": "direct"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_no_domain.returncode, 0, res_no_domain.stdout + res_no_domain.stderr)
            self.assertIn("https://203.0.113.99/", res_no_domain.stdout)
            self.assertNotIn("https://0/", res_no_domain.stdout)

            res_offline = subprocess.run(
                ["bash", "-c", resume_probe],
                input="n\n",
                env={**base_env, "MOCK_IP_MODE": "offline"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_offline.returncode, 0, res_offline.stdout + res_offline.stderr)
            self.assertIn("https://127.0.0.1/", res_offline.stdout)

            # 4. _hostname and _finished fail closed on symlinked /etc/hosts, /etc/hostname, and info file
            victim = root / "victim.txt"
            victim.write_text("UNTOUCHED\n", encoding="utf-8")
            sym_hosts = root / "hosts.symlink"
            sym_hosts.symlink_to(victim)
            res_sym = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'set -euo pipefail; source "{CORE_SH}"; source "{STATE_SH}"; '
                    'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""; _init_state; _hostname',
                ],
                input="evil.example.org\n",
                env={**base_env, "AF_HOSTS_FILE": str(sym_hosts)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "UNTOUCHED\n")

            sym_hostname = root / "hostname.symlink"
            sym_hostname.symlink_to(victim)
            res_sym_hn = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'set -euo pipefail; source "{CORE_SH}"; source "{STATE_SH}"; '
                    'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""; _init_state; _hostname',
                ],
                input="evil.example.org\n",
                env={**base_env, "AF_HOSTNAME_FILE": str(sym_hostname)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_sym_hn.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "UNTOUCHED\n")

            sym_info = root / "information.symlink"
            sym_info.symlink_to(victim)
            res_sym_info = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'set -euo pipefail; source "{CORE_SH}"; source "{STATE_SH}"; source "{FINALIZE_SH}"; '
                    'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""; _finished',
                ],
                input="n\n",
                env={**base_env, "AF_INFO_FILE": str(sym_info)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_sym_info.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "UNTOUCHED\n")

            # 5. AetherFlow-Setup restores FQDN from saved hostname_value/domain on resume for _fix_cert
            setup_src = SETUP_SCRIPT.read_text(encoding="utf-8")
            self.assertIn('if [[ -z "${FQDN:-}" ]]; then\n    FQDN="${domain:-${hostname_value:-}}"\nfi', setup_src)
            config_file.write_text("hostname_value=resume.example.org\n", encoding="utf-8")
            fqdn_probe = (
                'set -euo pipefail\n'
                f'source "{STATE_SH}"\n'
                f'source "{SECURITY_SH}"\n'
                'unset FQDN domain hostname_value\n'
                '_load_config_into_vars\n'
                'if [[ -z "${FQDN:-}" ]]; then FQDN="${domain:-${hostname_value:-}}"; fi\n'
                '_af_snakeoil_cert_subject "${FQDN:-}"\n'
            )
            res_fqdn = subprocess.run(["bash", "-c", fqdn_probe], env=base_env, capture_output=True, text=True, timeout=15)
            self.assertEqual(res_fqdn.returncode, 0, res_fqdn.stderr)
            self.assertEqual(res_fqdn.stdout.strip(), "/CN=resume.example.org")

    def test_debian13_depends_omits_dstat_and_survives_unset_outto_under_set_u(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-smooth-deb13-deps-") as tmp:
            root = Path(tmp)
            apt_log = root / "apt-args.jsonl"
            probe = (
                'set -euo pipefail\n'
                'unset OUTTO\n'
                f'source "{CORE_SH}"\n'
                f'source "{PACKAGES_SH}"\n'
                f'apt-get() {{ python3 -c \'import json, sys; open(sys.argv[1], "a").write(json.dumps(sys.argv[2:]) + "\\n")\' "{apt_log}" "$@"; return 0; }}\n'
                '_depends\n'
            )
            res = subprocess.run(
                ["bash", "-c", probe],
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "DISTRO": "Debian",
                    "CODENAME": "trixie",
                    "PHP_VER": "8.4",
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            calls = [json.loads(ln) for ln in apt_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
            flat = [arg for call in calls for arg in call]
            self.assertNotIn("dstat", flat, "Debian _depends must not install virtual dstat package (pulls in pcp)")
            self.assertNotIn("pcp", flat)
            self.assertIn("dool", flat)

    def test_apacheconf_guards_missing_scgi_fastcgi_and_ffmpeg_label_matches_apt(self) -> None:
        setup_src = SETUP_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Installing ffmpeg package for screenshots", setup_src)
        self.assertNotIn("Building ffmpeg from source", setup_src)

        with tempfile.TemporaryDirectory(prefix="af-smooth-apache-") as tmp:
            root = Path(tmp)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            cmd_log = root / "cmds.log"
            apache_etc = root / "etc/apache2"
            (apache_etc / "sites-enabled").mkdir(parents=True)
            (apache_etc / "conf-enabled").mkdir(parents=True)
            (apache_etc / "mods-available").mkdir(parents=True)
            (apache_etc / "mods-available/fcgid.load").write_text("# fcgid\n", encoding="utf-8")
            (apache_etc / "conf-enabled/security.conf").write_text("ServerTokens OS\nServerSignature On\n", encoding="utf-8")

            for tool in ("a2enmod", "a2dismod", "a2enconf", "phpenmod"):
                _write_executable(
                    mock_bin / tool,
                    f'#!/bin/bash\nprintf "%s %s\\n" "{tool}" "$*" >> "{cmd_log}"\nexit 0\n',
                )
            _write_executable(mock_bin / "chown", "#!/bin/bash\nexit 0\n")

            env = {
                **os.environ,
                "PATH": f"{mock_bin}:/usr/bin:/bin",
                "AF_APACHE_ETC_DIR": str(apache_etc),
                "AF_LEGACY_SEEDBOX_ALIASES_CONF": str(apache_etc / "sites-enabled/aliases-seedbox.conf"),
                "HTPASSWD": str(root / "etc/htpasswd"),
                "AF_APACHE_HTPASSWD": str(apache_etc / "AetherFlow/htpasswd"),
                "AF_DEFAULT_DOCROOT": str(root / "var/www/aetherflow-default"),
                "AF_LEGACY_SRV_LINK": str(root / "srv/aetherflow"),
                "AF_PHP_ETC_DIR": str(root / "etc/php"),
                "local_setup": f"{ROOT / 'setup'}/",
                "username": "operator",
            }
            env.pop("OUTTO", None)
            res = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{SECURITY_SH}"; _apacheconf'],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            cmds = cmd_log.read_text(encoding="utf-8").splitlines()
            self.assertNotIn("a2enmod scgi", cmds)
            self.assertNotIn("a2enmod fastcgi", cmds)
            self.assertIn("a2enmod fcgid", cmds)
            self.assertIn("a2enmod proxy_fcgi setenvif", cmds)

            # When scgi.load and fastcgi.load exist, both are enabled cleanly
            (apache_etc / "mods-available/scgi.load").write_text("# scgi\n", encoding="utf-8")
            (apache_etc / "mods-available/fastcgi.load").write_text("# fastcgi\n", encoding="utf-8")
            cmd_log.unlink()
            res2 = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{SECURITY_SH}"; _apacheconf'],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            cmds2 = cmd_log.read_text(encoding="utf-8").splitlines()
            self.assertIn("a2enmod scgi", cmds2)
            self.assertIn("a2enmod fastcgi", cmds2)

    def test_mcsurgeon_autofixes_injection_symlinks_ubuntu_noble_and_modern_stack_ipv4(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-smooth-surgeon-") as tmp:
            root = Path(tmp)
            stub_bin = root / "bin"
            stub_bin.mkdir()
            _write_executable(
                stub_bin / "openssl",
                """#!/bin/sh
out_path=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-out" ]; then out_path="$2"; shift 2; continue; fi
    shift
done
if [ -n "$out_path" ]; then printf 'MOCK-KEY-AND-CERT\\n' > "$out_path"; fi
exit 0
""",
            )
            _write_executable(stub_bin / "chown", "#!/bin/sh\nexit 0\n")

            # S-01: _ftpdconfig rejects newline/directive injection and invalid IPv4 in IP
            vsftpd_conf = root / "etc/vsftpd.conf"
            vsftpd_cert = root / "etc/ssl/private/vsftpd.pem"
            vsftpd_bin = root / "vsftpd-305"
            vsftpd_bin.write_bytes(b"\x00ssl_tlsv1\x00ssl_tlsv11\x00ssl_tlsv12\x00ssl_tlsv13\x00")
            ftpd_env = {
                **os.environ,
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "AETHERFLOW_ENABLE_FTPD": "yes",
                "AF_SKIP_SYSTEMCTL": "1",
                "AF_OPENSSL_CNF": str(root / "root/.openssl.cnf"),
                "AF_VSFTPD_CERT": str(vsftpd_cert),
                "AF_VSFTPD_CONF": str(vsftpd_conf),
                "AF_VSFTPD_CHROOT_LIST": str(root / "etc/vsftpd.chroot_list"),
                "AF_VSFTPD_BIN": str(vsftpd_bin),
                "local_setup": f"{ROOT / 'setup'}/",
            }
            for bad_ip in ("203.0.113.10\nssl_enable=NO", "999.1.1.1", "010.0.0.1", "not-an-ip"):
                with self.subTest(bad_ip=bad_ip):
                    res_ip = subprocess.run(
                        ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                        env={**ftpd_env, "IP": bad_ip},
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertNotEqual(res_ip.returncode, 0)

            # S-03: _ftpdconfig rejects symlinked targets and atomically replaces permissive pre-existing vsftpd.pem with 0600
            victim = root / "victim.txt"
            victim.write_text("KEEP\n", encoding="utf-8")
            sym_cert = root / "sym-vsftpd.pem"
            sym_cert.symlink_to(victim)
            res_sym = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**ftpd_env, "IP": "203.0.113.10", "AF_VSFTPD_CERT": str(sym_cert)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "KEEP\n")

            vsftpd_cert.parent.mkdir(parents=True, exist_ok=True)
            vsftpd_cert.write_text("OLD-PERMISSIVE\n", encoding="utf-8")
            vsftpd_cert.chmod(0o644)
            old_inode = vsftpd_cert.stat().st_ino
            res_cert = subprocess.run(
                ["bash", "-c", f'set -euo pipefail; source "{FINALIZE_SH}"; _ftpdconfig'],
                env={**ftpd_env, "IP": "203.0.113.10"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_cert.returncode, 0, res_cert.stderr)
            self.assertEqual(vsftpd_cert.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(vsftpd_cert.stat().st_ino, old_inode, "vsftpd.pem must be replaced atomically, not overwritten in-place")

            # S-02: _hostname rejects awk \n escape injection, whitespace host injection, and leading-hyphen option injection
            hosts_file = root / "hosts"
            hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            hostname_file = root / "hostname"
            hn_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "STATE_FILE": str(root / "state"),
                "CONFIG_FILE": str(root / "config"),
                "INSTALL_LOG": str(root / "install.log"),
                "AF_HOSTNAME_FILE": str(hostname_file),
                "AF_HOSTS_FILE": str(hosts_file),
                "AF_SKIP_HOSTNAME_CMD": "1",
                "UNATTENDED": "false",
            }
            for bad_host in (r"box.example.org\n1.2.3.4 github.com", "-F", "box.example.org evil.local", "-bad.org"):
                with self.subTest(bad_host=bad_host):
                    res_hn = subprocess.run(
                        [
                            "bash",
                            "-c",
                            f'set -euo pipefail; source "{CORE_SH}"; source "{STATE_SH}"; '
                            'bold=""; green=""; normal=""; cyan=""; magenta=""; yellow=""; _init_state; _hostname',
                        ],
                        input=f"{bad_host}\n",
                        env=hn_env,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertNotEqual(res_hn.returncode, 0)
            self.assertEqual(hosts_file.read_text(encoding="utf-8"), "127.0.0.1 localhost\n")

            # P-01: Ubuntu 24.04 (noble) _depends omits mandatory dstat/dool and skips missing dool cleanly
            ubuntu_log = root / "ubuntu-apt.jsonl"
            ubuntu_probe = (
                'set -euo pipefail\n'
                'unset OUTTO\n'
                f'source "{CORE_SH}"\n'
                f'source "{PACKAGES_SH}"\n'
                'apt-cache() { return 1; }\n'
                f'apt-get() {{ python3 -c \'import json, sys; open(sys.argv[1], "a").write(json.dumps(sys.argv[2:]) + "\\n")\' "{ubuntu_log}" "$@"; return 0; }}\n'
                '_depends\n'
            )
            res_ub = subprocess.run(
                ["bash", "-c", ubuntu_probe],
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "DISTRO": "Ubuntu",
                    "CODENAME": "noble",
                    "PHP_VER": "8.3",
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_ub.returncode, 0, res_ub.stdout + res_ub.stderr)
            ub_flat = [arg for ln in ubuntu_log.read_text(encoding="utf-8").splitlines() if ln.strip() for arg in json.loads(ln)]
            self.assertNotIn("dool", ub_flat)
            self.assertNotIn("dstat", ub_flat)

            # P-02: modern_stack.sh extracts src IP on direct /32 routes (not uid 0) and survives offline ip exit 2
            _write_executable(
                stub_bin / "ip",
                """#!/bin/sh
if [ "${MOCK_IP_MODE:-direct}" = "offline" ]; then exit 2; fi
echo "8.8.8.8 dev eth0 src 198.51.100.88 uid 0"
exit 0
""",
            )
            ms_root = root / "ms_install"
            ms_env_dir = root / "ms_env"
            ms_data_dir = root / "ms_data"
            ms_sysd_dir = root / "ms_sysd"
            for d in (ms_root / "deploy/systemd", ms_root / "setup/templates/sysd", ms_env_dir, ms_data_dir, ms_sysd_dir):
                d.mkdir(parents=True, exist_ok=True)
            ms_probe = (
                'set -euo pipefail\n'
                f'source "{ROOT / "setup/modules/modern_stack.sh"}"\n'
                '_af_modern_from_source_enabled() { return 1; }\n'
                '_pull_prebuilt_v4_release() { return 0; }\n'
                '_af_resolve_release_channel() { echo stable; }\n'
                '_safe_overlay_config() { cp "$1" "$2"; }\n'
                '_build_modern_stack\n'
            )
            ms_base_env = {
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "AF_INSTALL_ROOT": str(ms_root),
                "AF_ENV_DIR": str(ms_env_dir),
                "AF_DATA_DIR": str(ms_data_dir),
                "AF_SYSTEMD_DIR": str(ms_sysd_dir),
                "AF_RUN_DIR": str(root / "ms_run"),
                "AF_LOG_DIR": str(root / "ms_log"),
                "AF_SKIP_SYSTEMCTL": "1",
                "AF_OFFLINE": "1",
            }
            res_ms_direct = subprocess.run(
                ["bash", "-c", ms_probe],
                env={**ms_base_env, "MOCK_IP_MODE": "direct"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_ms_direct.returncode, 0, res_ms_direct.stderr)
            ms_env_text = (ms_env_dir / "aetherflow.env").read_text(encoding="utf-8")
            self.assertIn("198.51.100.88", ms_env_text)
            self.assertNotIn("https://0", ms_env_text)

            (ms_env_dir / "aetherflow.env").unlink()
            res_ms_offline = subprocess.run(
                ["bash", "-c", ms_probe],
                env={**ms_base_env, "MOCK_IP_MODE": "offline"},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res_ms_offline.returncode, 0, res_ms_offline.stderr)
            self.assertIn("ALLOWED_HOSTS=localhost,localhost:8080,127.0.0.1,127.0.0.1:8080", (ms_env_dir / "aetherflow.env").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
