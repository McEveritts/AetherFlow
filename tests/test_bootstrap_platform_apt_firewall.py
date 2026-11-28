#!/usr/bin/env python3
"""Scoped isolated fixture tests for AetherFlow bootstrap platform behavior:
- Normal setup/AetherFlow-Setup entry & OS detection (Debian 12/13, Ubuntu 22.04/24.04)
- APT legacy (.list) and deb822 (.sources) preservation across AMD64/ARM64
- Architecture-aware signed fallback generation and distro keyring selection
- Fail-closed APT/keyring/symlink guards
- Firewall SSH listener discovery, operator rule preservation, and netfilter-persistent save
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPT = ROOT / "setup/AetherFlow-Setup"
CORE_MODULE = ROOT / "setup/modules/00-core.sh"
PACKAGES_MODULE = ROOT / "setup/modules/02-packages.sh"
SECURITY_MODULE = ROOT / "setup/modules/04-security.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _host_path_snapshot() -> dict[str, tuple[bool, int | None, int | None]]:
    targets = (
        Path("/etc/apt/sources.list"),
        Path("/etc/apt/sources.list.d"),
        Path("/etc/iptables"),
        Path("/etc/iptables/rules.v4"),
        Path("/etc/iptables/rules.v6"),
        Path("/etc/iptables.rules"),
    )
    snap: dict[str, tuple[bool, int | None, int | None]] = {}
    for p in targets:
        try:
            st = p.lstat()
            snap[str(p)] = (True, st.st_mtime_ns, st.st_size)
        except OSError:
            snap[str(p)] = (False, None, None)
    return snap


def _make_stateful_iptables_stub(bin_dir: Path, state_file: Path, log_file: Path, fail_on_substring: str = "") -> None:
    """Create stateful mock iptables, ip6tables, iptables-save, ip6tables-save binaries."""
    py = sys.executable
    common_script = f"""#!{py}
import json, os, sys

TOOL = os.path.basename(sys.argv[0])
FAMILY = "v6" if TOOL.startswith("ip6") else "v4"
STATE_FILE = {str(state_file)!r}
LOG_FILE = {str(log_file)!r}
FAIL_SUB = {fail_on_substring!r}
ARGS = sys.argv[1:]

with open(LOG_FILE, "a", encoding="utf-8") as lf:
    lf.write(json.dumps({{"tool": TOOL, "args": ARGS}}) + "\\n")

with open(STATE_FILE, "r", encoding="utf-8") as sf:
    state = json.load(sf)

fam = state[FAMILY]

if TOOL.endswith("-save"):
    lines = ["*filter"]
    for chain in ("INPUT", "FORWARD", "OUTPUT"):
        lines.append(f":{{chain}} {{fam['policies'][chain]}} [0:0]")
    for chain in ("INPUT", "FORWARD", "OUTPUT"):
        for rule in fam["chains"][chain]:
            lines.append(f"-A {{chain}} {{rule}}")
    lines.append("COMMIT")
    sys.stdout.write("\\n".join(lines) + "\\n")
    sys.exit(0)

if FAIL_SUB and FAIL_SUB in " ".join(ARGS):
    sys.stderr.write(f"simulated failure on {{FAIL_SUB}}\\n")
    sys.exit(1)

if not ARGS:
    sys.exit(2)

op = ARGS[0]
if op == "-S":
    chain = ARGS[1]
    sys.stdout.write(f"-P {{chain}} {{fam['policies'][chain]}}\\n")
    for rule in fam["chains"][chain]:
        sys.stdout.write(f"-A {{chain}} {{rule}}\\n")
    sys.exit(0)

if op == "-F":
    chain = ARGS[1]
    fam["chains"][chain] = []
    with open(STATE_FILE, "w", encoding="utf-8") as sf:
        json.dump(state, sf)
    sys.exit(0)

if op == "-P":
    chain, policy = ARGS[1], ARGS[2]
    fam["policies"][chain] = policy
    with open(STATE_FILE, "w", encoding="utf-8") as sf:
        json.dump(state, sf)
    sys.exit(0)

if op == "-C":
    chain = ARGS[1]
    rule = " ".join(ARGS[2:])
    sys.exit(0 if rule in fam["chains"][chain] else 1)

if op == "-A":
    chain = ARGS[1]
    rule = " ".join(ARGS[2:])
    fam["chains"][chain].append(rule)
    with open(STATE_FILE, "w", encoding="utf-8") as sf:
        json.dump(state, sf)
    sys.exit(0)

if op == "-I":
    chain = ARGS[1]
    if len(ARGS) >= 3 and ARGS[2].isdigit():
        idx = int(ARGS[2]) - 1
        rule = " ".join(ARGS[3:])
    else:
        idx = 0
        rule = " ".join(ARGS[2:])
    fam["chains"][chain].insert(idx, rule)
    with open(STATE_FILE, "w", encoding="utf-8") as sf:
        json.dump(state, sf)
    sys.exit(0)

sys.exit(1)
"""
    for name in ("iptables", "ip6tables", "iptables-save", "ip6tables-save"):
        _write_executable(bin_dir / name, common_script)


class BootstrapPlatformAptFirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._before_host_snap = _host_path_snapshot()

    def tearDown(self) -> None:
        after_host_snap = _host_path_snapshot()
        self.assertEqual(
            self._before_host_snap,
            after_host_snap,
            "Isolated fixture tests must never mutate live host APT or firewall files",
        )

    def test_setup_preserves_system_skeleton_and_existing_user_dotfiles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-skeleton-") as tmp:
            root = Path(tmp)
            skeleton = root / "etc/skel"
            user_home = root / "home/operator"
            skeleton.mkdir(parents=True)
            user_home.mkdir(parents=True)
            (skeleton / ".bashrc").write_text("system profile\n")
            (user_home / ".bashrc").write_text("operator profile\n")

            packages = root / "packages.sh"
            packages.write_text(PACKAGES_MODULE.read_text().replace("/etc/skel", str(skeleton)))
            services = root / "services.sh"
            services.write_text(
                (ROOT / "setup/modules/03-services.sh").read_text().replace("/home/", f"{root}/home/")
            )
            command = """
            runuser() {
                [[ "$1 $2 $3" == "-u operator --" ]] || return 1
                shift 3
                "$@"
            }
            source "$1"
            source "$2"
            username=operator
            _skel
            _makedirs
            _skel
            _makedirs
            """
            result = subprocess.run(
                ["bash", "-ec", command, "af-skeleton-test", str(packages), str(services)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((skeleton / ".bashrc").read_text(), "system profile\n")
            self.assertEqual((user_home / ".bashrc").read_text(), "operator profile\n")
            for relative in ("Media", "torrents/rtorrent", "torrents/deluge", "torrents/qbittorrent"):
                self.assertTrue((skeleton / relative).is_dir(), relative)
                self.assertTrue((user_home / relative).is_dir(), relative)
            self.assertTrue((user_home / ".sessions").is_dir())
            self.assertTrue((user_home / "rwatch").is_dir())

    def test_normal_setup_entry_lists_steps_and_detects_all_supported_os_fixtures(self) -> None:
        os_fixtures = (
            ("debian12", 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n', "Debian", "bookworm", "12", "8.2"),
            ("debian13", 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n', "Debian", "trixie", "13", "8.4"),
            ("debian13_rolling", 'ID=debian\nPRETTY_NAME="Debian GNU/Linux trixie/sid"\nVERSION_CODENAME=trixie\n', "Debian", "trixie", "13", "8.4"),
            ("ubuntu2204", 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n', "Ubuntu", "jammy", "22.04", "8.1"),
            ("ubuntu2404", 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', "Ubuntu", "noble", "24.04", "8.3"),
        )
        with tempfile.TemporaryDirectory(prefix="af-entry-") as tmp:
            root = Path(tmp)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            os_rel = root / "os-release"
            os_rel.write_text('ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n', encoding="utf-8")
            env = {
                **os.environ,
                "STATE_FILE": str(root / "state"),
                "CONFIG_FILE": str(root / "config"),
                "INSTALL_LOG": str(root / "install.log"),
                "LOCKFILE": str(root / "setup.lock"),
                "AF_SETUP_SCRATCH_DIR": str(scratch),
                "AF_OS_RELEASE_FILE": str(os_rel),
            }
            res = subprocess.run(
                ["bash", str(SETUP_SCRIPT), "--list-steps"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            for step in ("repos", "updates", "depends", "firewall"):
                self.assertIn(f"[ ] {step}", res.stdout)

            for label, content, exp_distro, exp_code, exp_ver, exp_php in os_fixtures:
                with self.subTest(os=label):
                    os_rel.write_text(content, encoding="utf-8")
                    probe = (
                        'set -euo pipefail\n'
                        'unset DISTRO OS_ID CODENAME VERSION_ID SETNAME PHP_VER\n'
                        'source "$1"\n'
                        '_ensure_distro_vars\n'
                        'printf "%s|%s|%s|%s" "$DISTRO" "$CODENAME" "$VERSION_ID" "$PHP_VER"\n'
                    )
                    out = subprocess.run(
                        ["bash", "-c", probe, "fixture", str(CORE_MODULE)],
                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AF_OS_RELEASE_FILE": str(os_rel)},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assertEqual(out.stdout, f"{exp_distro}|{exp_code}|{exp_ver}|{exp_php}")

    def _run_updates_fixture(
        self,
        *,
        distro: str,
        os_id: str,
        codename: str,
        arch: str,
        sources_list: str | None = None,
        sources_list_symlink: bool = False,
        dropins: dict[str, str] | None = None,
        keyrings: tuple[str, ...] | None = None,
        apt_update_rc: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], Path, list[list[str]]]:
        tmp = Path(tempfile.mkdtemp(prefix=f"af-apt-{os_id}-{codename}-{arch}-"))
        self.addCleanup(shutil.rmtree, tmp, True)

        apt_etc = tmp / "etc/apt"
        sources_d = apt_etc / "sources.list.d"
        keyrings_dir = tmp / "usr/share/keyrings"
        install_dir = tmp / "install"
        stub_bin = tmp / "bin"
        apt_log = tmp / "apt-calls.jsonl"
        outto = tmp / "setup.log"

        for d in (sources_d, keyrings_dir, stub_bin):
            d.mkdir(parents=True, exist_ok=True)

        if sources_list_symlink:
            victim = tmp / "victim.txt"
            victim.write_text("UNTOUCHED\n", encoding="utf-8")
            (apt_etc / "sources.list").symlink_to(victim)
        elif sources_list is not None:
            (apt_etc / "sources.list").write_text(sources_list, encoding="utf-8")

        for name, body in (dropins or {}).items():
            (sources_d / name).write_text(body, encoding="utf-8")

        if keyrings is None:
            default_kr = "ubuntu-archive-keyring.gpg" if distro == "Ubuntu" else "debian-archive-keyring.gpg"
            keyrings = (default_kr,)
        for kr in keyrings:
            (keyrings_dir / kr).write_bytes(b"FAKE-OPENPGP-KEYRING-BYTES")

        _write_executable(
            stub_bin / "dpkg",
            f"#!/bin/sh\nif [ \"$1\" = \"--print-architecture\" ]; then printf '%s\\n' {arch!r}; exit 0; fi\nexit 1\n",
        )
        _write_executable(
            stub_bin / "apt-get",
            f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open({str(apt_log)!r}, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")
if "--print-uris" in args:
    os.execv("/usr/bin/apt-get", ["/usr/bin/apt-get", *args])
if "update" in args and {apt_update_rc} != 0:
    sys.stderr.write("E: The repository is not signed / signature verification failed\\n")
    sys.exit({apt_update_rc})
sys.exit(0)
""",
        )

        probe = (
            'set -euo pipefail\n'
            'source "$1"\n'
            'source "$2"\n'
            'local_setup="$3"\n'
            '_updates\n'
        )
        env = {
            "PATH": f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "DISTRO": distro,
            "OS_ID": os_id,
            "CODENAME": codename,
            "PHP_VER": "8.1" if codename == "jammy" else ("8.3" if codename == "noble" else ("8.4" if codename == "trixie" else "8.2")),
            "OUTTO": str(outto),
            "AF_APT_ETC_DIR": str(apt_etc),
            "AF_KEYRINGS_DIR": str(keyrings_dir),
            "AF_INSTALL_DIR": str(install_dir),
        }
        proc = subprocess.run(
            ["bash", "-c", probe, "apt-fixture", str(CORE_MODULE), str(PACKAGES_MODULE), f"{ROOT / 'setup'}/"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        calls: list[list[str]] = []
        if apt_log.exists():
            calls = [json.loads(ln) for ln in apt_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return proc, tmp, calls

    def test_ubuntu_2204_arm64_legacy_ports_sources_preserved_and_ubuntu_keyring_selected(self) -> None:
        original_sources = (
            "# Official Ubuntu 22.04 ARM64 cloud image sources\n"
            "deb http://ports.ubuntu.com/ubuntu-ports jammy main restricted\n"
            "deb http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted\n"
            "deb http://ports.ubuntu.com/ubuntu-ports jammy universe\n"
            "deb http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted\n"
        )
        proc, tmp, calls = self._run_updates_fixture(
            distro="Ubuntu",
            os_id="ubuntu",
            codename="jammy",
            arch="arm64",
            sources_list=original_sources,
            dropins={},  # Explicitly NO ubuntu.sources
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        after = (tmp / "etc/apt/sources.list").read_text(encoding="utf-8")
        self.assertEqual(after, original_sources, "Ubuntu 22.04 ARM64 legacy ports.ubuntu.com sources.list must be preserved verbatim")
        self.assertNotIn("archive.ubuntu.com", after)

        install_calls = [c for c in calls if "install" in c]
        self.assertEqual(len(install_calls), 1)
        self.assertIn("ubuntu-keyring", install_calls[0])
        self.assertNotIn("debian-archive-keyring", install_calls[0])

    def test_preserves_valid_operator_and_vendor_sources_across_debian_and_ubuntu_matrix(self) -> None:
        cases = (
            (
                "debian12_amd64_legacy_list",
                "Debian",
                "debian",
                "bookworm",
                "amd64",
                "deb https://mirror.example.org/debian bookworm main contrib non-free-firmware\n",
                {},
                "debian-archive-keyring",
            ),
            (
                "debian12_arm64_vendor_deb822",
                "Debian",
                "debian",
                "bookworm",
                "arm64",
                None,
                {
                    "hetzner-mirror.sources": (
                        "Types: deb\n"
                        "URIs: https://mirror.hetzner.com/debian/packages\n"
                        "Suites: bookworm bookworm-updates\n"
                        "Components: main contrib non-free-firmware\n"
                        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
                    )
                },
                "debian-archive-keyring",
            ),
            (
                "debian13_arm64_debian_sources",
                "Debian",
                "debian",
                "trixie",
                "arm64",
                "",
                {
                    "debian.sources": (
                        "Types: deb deb-src\n"
                        "URIs: https://deb.debian.org/debian/\n"
                        "Suites: trixie trixie-updates\n"
                        "Components: main contrib non-free non-free-firmware\n"
                        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
                    )
                },
                "debian-archive-keyring",
            ),
            (
                "ubuntu2404_arm64_ubuntu_sources",
                "Ubuntu",
                "ubuntu",
                "noble",
                "arm64",
                "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources\n",
                {
                    "ubuntu.sources": (
                        "Types: deb\n"
                        "URIs: http://ports.ubuntu.com/ubuntu-ports/\n"
                        "Suites: noble noble-updates noble-backports\n"
                        "Components: main restricted universe multiverse\n"
                        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
                    )
                },
                "ubuntu-keyring",
            ),
            (
                "ubuntu2404_amd64_vendor_list_dropin",
                "Ubuntu",
                "ubuntu",
                "noble",
                "amd64",
                "# comment only\n",
                {
                    "cloud-vendor.list": (
                        "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                        "http://eu-central-1.ec2.archive.ubuntu.com/ubuntu noble main universe\n"
                    )
                },
                "ubuntu-keyring",
            ),
        )
        for label, distro, os_id, codename, arch, slist, dropins, exp_keyring_pkg in cases:
            with self.subTest(case=label):
                proc, tmp, calls = self._run_updates_fixture(
                    distro=distro,
                    os_id=os_id,
                    codename=codename,
                    arch=arch,
                    sources_list=slist,
                    dropins=dropins,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                slist_path = tmp / "etc/apt/sources.list"
                if slist is None:
                    self.assertFalse(slist_path.exists(), "Missing sources.list should not be created when valid drop-in exists")
                else:
                    self.assertEqual(slist_path.read_text(encoding="utf-8"), slist)
                install_calls = [c for c in calls if "install" in c]
                self.assertEqual(len(install_calls), 1)
                self.assertIn(exp_keyring_pkg, install_calls[0])

    def test_missing_apt_config_generates_arch_defaults_with_release_signatures_and_real_apt_parses_uris(self) -> None:
        matrix = (
            ("ubuntu2204_arm64", "Ubuntu", "ubuntu", "jammy", "arm64", "http://ports.ubuntu.com/ubuntu-ports/", "archive.ubuntu.com", ("ubuntu-archive-keyring.gpg",), "ubuntu-archive-keyring.gpg"),
            ("ubuntu2204_amd64", "Ubuntu", "ubuntu", "jammy", "amd64", "http://archive.ubuntu.com/ubuntu/", "ports.ubuntu.com", ("ubuntu-archive-keyring.gpg",), "ubuntu-archive-keyring.gpg"),
            ("ubuntu2404_arm64", "Ubuntu", "ubuntu", "noble", "arm64", "http://ports.ubuntu.com/ubuntu-ports/", "archive.ubuntu.com", ("ubuntu-archive-keyring.gpg",), "ubuntu-archive-keyring.gpg"),
            ("ubuntu2404_amd64", "Ubuntu", "ubuntu", "noble", "amd64", "http://archive.ubuntu.com/ubuntu/", "ports.ubuntu.com", ("ubuntu-archive-keyring.gpg",), "ubuntu-archive-keyring.gpg"),
            ("debian12_amd64", "Debian", "debian", "bookworm", "amd64", "https://deb.debian.org/debian/", "ubuntu.com", ("debian-archive-keyring.gpg",), "debian-archive-keyring.gpg"),
            ("debian12_arm64", "Debian", "debian", "bookworm", "arm64", "https://deb.debian.org/debian/", "ubuntu.com", ("debian-archive-keyring.gpg",), "debian-archive-keyring.gpg"),
            ("debian13_amd64_pgp", "Debian", "debian", "trixie", "amd64", "https://deb.debian.org/debian/", "ubuntu.com", ("debian-archive-keyring.pgp",), "debian-archive-keyring.pgp"),
            ("debian13_arm64", "Debian", "debian", "trixie", "arm64", "https://deb.debian.org/debian/", "ubuntu.com", ("debian-archive-keyring.gpg",), "debian-archive-keyring.gpg"),
        )
        real_apt_get = shutil.which("apt-get")

        for label, distro, os_id, codename, arch, must_have_uri, must_not_have, keyrings, exp_kr in matrix:
            with self.subTest(case=label):
                # Include a disabled .sources stanza, a cdrom-only sources.list, and a third-party php.list
                # to prove none of them mask missing base OS sources.
                proc, tmp, _calls = self._run_updates_fixture(
                    distro=distro,
                    os_id=os_id,
                    codename=codename,
                    arch=arch,
                    sources_list="# only cdrom\ndeb cdrom:[ISO]/ " + codename + " main\n",
                    dropins={
                        "disabled.sources": (
                            "Types: deb\n"
                            "URIs: http://example.invalid/repo\n"
                            f"Suites: {codename}\n"
                            "Components: main\n"
                            "Enabled: no\n"
                        ),
                        "php.list": f"deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ {codename} main\n",
                    },
                    keyrings=keyrings,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                managed = tmp / "etc/apt/sources.list.d/aetherflow-base.list"
                rendered = managed.read_text(encoding="utf-8")
                self.assertTrue((tmp / "etc/apt/sources.list").read_text(encoding="utf-8").startswith("# only cdrom\n"))
                self.assertIn(must_have_uri, rendered)
                self.assertNotIn(must_not_have, rendered)
                self.assertIn(f" {codename} ", rendered)
                self.assertIn(f"signed-by={tmp / 'usr/share/keyrings' / exp_kr}", rendered)
                self.assertNotIn("trusted=yes", rendered)
                self.assertNotIn("RELEASE", rendered)

                if real_apt_get:
                    # Verify real apt-get parses the generated file in a 100% isolated state/cache dir (no network).
                    apt_state = tmp / "apt-state"
                    apt_cache = tmp / "apt-cache"
                    empty_parts = tmp / "empty-parts"
                    for d in (apt_state / "lists/partial", apt_cache / "archives/partial", empty_parts):
                        d.mkdir(parents=True, exist_ok=True)
                    (apt_state / "status").write_text("", encoding="utf-8")
                    uri_res = subprocess.run(
                        [
                            real_apt_get,
                            "-o", f"APT::Architecture={arch}",
                            "-o", "APT::Architectures=",
                            "-o", f"Dir::Etc::sourcelist={managed}",
                            "-o", f"Dir::Etc::sourceparts={empty_parts}",
                            "-o", f"Dir::State={apt_state}",
                            "-o", f"Dir::State::status={apt_state / 'status'}",
                            "-o", f"Dir::Cache={apt_cache}",
                            "update",
                            "--print-uris",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertEqual(uri_res.returncode, 0, uri_res.stdout + uri_res.stderr)
                    self.assertIn(f"{must_have_uri}dists/{codename}/InRelease", uri_res.stdout)

    def test_apt_fail_closed_on_unsupported_arch_missing_keyring_symlink_and_signature_failure(self) -> None:
        # 1. Unsupported architecture with missing config fails closed
        proc, tmp, _ = self._run_updates_fixture(
            distro="Ubuntu", os_id="ubuntu", codename="jammy", arch="riscv64", sources_list="# empty\n"
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((tmp / "etc/apt/sources.list").read_text(encoding="utf-8"), "# empty\n")

        # 2. Missing release signing keyring with missing config fails closed
        proc, tmp, _ = self._run_updates_fixture(
            distro="Ubuntu", os_id="ubuntu", codename="jammy", arch="arm64", sources_list="# empty\n", keyrings=()
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((tmp / "etc/apt/sources.list").read_text(encoding="utf-8"), "# empty\n")

        # 3. Symlinked /etc/apt/sources.list with missing config fails closed and leaves target untouched
        proc, tmp, _ = self._run_updates_fixture(
            distro="Debian", os_id="debian", codename="bookworm", arch="amd64", sources_list_symlink=True
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((tmp / "victim.txt").read_text(encoding="utf-8"), "UNTOUCHED\n")

        # 4. Signature/update failure fails closed and never uses --allow-unauthenticated
        proc, _tmp, calls = self._run_updates_fixture(
            distro="Ubuntu",
            os_id="ubuntu",
            codename="noble",
            arch="arm64",
            sources_list="deb http://ports.ubuntu.com/ubuntu-ports noble main\n",
            apt_update_rc=100,
        )
        self.assertNotEqual(proc.returncode, 0)
        flat_args = [arg for call in calls for arg in call]
        self.assertNotIn("--allow-unauthenticated", flat_args)
        self.assertFalse(any("AllowInsecureRepositories" in arg for arg in flat_args))

        # 5. Ubuntu _depends selects ubuntu-keyring instead of debian-archive-keyring
        with tempfile.TemporaryDirectory(prefix="af-dep-ubuntu-") as tmp_dir:
            scratch = Path(tmp_dir)
            probe = (
                'set -euo pipefail\n'
                'source "$1"\n'
                'source "$2"\n'
                'apt-cache() { return 1; }\n'
                'apt-get() { printf "%s\\n" "$@" >> apt-args; return 0; }\n'
                '_depends\n'
            )
            res = subprocess.run(
                ["bash", "-c", probe, "dep-fixture", str(CORE_MODULE), str(PACKAGES_MODULE)],
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "DISTRO": "Ubuntu",
                    "CODENAME": "jammy",
                    "PHP_VER": "8.1",
                    "OUTTO": str(scratch / "out.log"),
                },
                cwd=scratch,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            apt_args = (scratch / "apt-args").read_text(encoding="utf-8").splitlines()
            self.assertIn("ubuntu-keyring", apt_args)
            self.assertNotIn("debian-archive-keyring", apt_args)

    def test_firewall_uses_effective_ssh_daemon_socket_and_session_ports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-ssh-detect-") as tmp:
            root = Path(tmp)
            commands = root / "bin"
            commands.mkdir()
            config = root / "etc/ssh/sshd_config"
            config.parent.mkdir(parents=True)
            config.touch()
            env = {
                "PATH": f"{commands}:/usr/bin:/bin",
                "AF_SYS_ROOT": str(root),
            }

            def ports(**overrides: str) -> str:
                return subprocess.check_output(
                    ["bash", "-c", 'source "$1"; _fw_allowed_ports', "fw-probe", str(SECURITY_MODULE)],
                    env={**env, **overrides},
                    text=True,
                    timeout=10,
                ).strip()

            self.assertEqual(ports(), "22/tcp 80/tcp 443/tcp")
            _write_executable(
                commands / "sshd",
                f"#!/bin/sh\ntest \"$*\" = \"-T -f {config}\" || exit 1\n"
                "printf 'port 22022\\nlistenaddress [::]:2244\\n'",
            )
            session = "203.0.113.5 51234 198.51.100.2 22"
            self.assertEqual(ports(SSH_CONNECTION=session), "22022/tcp 2244/tcp 22/tcp 80/tcp 443/tcp")

            _write_executable(
                commands / "systemctl",
                '#!/bin/sh\ncase "$1:$*" in\n'
                '    is-active:*ssh.socket) exit 0 ;;\n'
                '    show:*ssh.socket) printf "[::]:2299 (Stream)\\n" ;;\n'
                '    *) exit 1 ;;\nesac\n',
            )
            _write_executable(
                commands / "ss",
                '#!/bin/sh\nprintf \'LISTEN 0 128 0.0.0.0:2288 0.0.0.0:* users:(("sshd",pid=412,fd=3))\\n\'\n',
            )
            self.assertEqual(ports(AF_FW_USE_SYSTEMCTL="1", AF_FW_USE_SS="1"), "2299/tcp 2288/tcp 80/tcp 443/tcp")
            self.assertEqual(ports(AF_SSH_PORTS="2299,2299,invalid", SSH_CONNECTION=session), "2299/tcp 22/tcp 80/tcp 443/tcp")

    def test_firewall_ufw_allows_custom_ssh_before_enable_and_falls_back_on_ufw_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-fw-ufw-") as tmp:
            root = Path(tmp)
            sys_root = root / "sysroot"
            (sys_root / "etc/ssh").mkdir(parents=True)
            (sys_root / "etc/ssh/sshd_config").write_text("Port 2222\n", encoding="utf-8")

            stub_bin = root / "bin"
            stub_bin.mkdir()
            ufw_log = root / "ufw.log"
            systemctl_log = root / "systemctl.log"
            ipt_state = root / "ipt-state.json"
            ipt_log = root / "ipt.log"
            ipt_state.write_text(
                json.dumps(
                    {
                        "v4": {"policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}, "chains": {"INPUT": [], "FORWARD": [], "OUTPUT": []}},
                        "v6": {"policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}, "chains": {"INPUT": [], "FORWARD": [], "OUTPUT": []}},
                    }
                ),
                encoding="utf-8",
            )
            _make_stateful_iptables_stub(stub_bin, ipt_state, ipt_log)
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
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {str(systemctl_log)!r}\nexit 0\n",
            )

            env = {
                "PATH": f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "AF_SYS_ROOT": str(sys_root),
                "AF_SSH_PORTS": "2222",
                "OUTTO": str(root / "out.log"),
                "INSTALL_LOG": str(root / "install.log"),
            }
            res = subprocess.run(
                ["bash", "-c", 'source "$1"; _setup_firewall', "fw-ufw", str(SECURITY_MODULE)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            ufw_cmds = ufw_log.read_text(encoding="utf-8").splitlines()
            self.assertNotIn("reset", ufw_cmds)
            self.assertIn("allow 2222/tcp", ufw_cmds)
            self.assertNotIn("allow 22/tcp", ufw_cmds)
            self.assertLess(ufw_cmds.index("allow 2222/tcp"), ufw_cmds.index("default deny incoming"))
            self.assertLess(ufw_cmds.index("default deny incoming"), ufw_cmds.index("--force enable"))
            self.assertIn("enable ufw", systemctl_log.read_text(encoding="utf-8").splitlines())

            # Now simulate ufw allow failure: must NOT run --force enable and must fall back cleanly to iptables!
            ufw_log.unlink()
            _write_executable(
                stub_bin / "ufw",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(ufw_log)!r}
if [ "$1" = "status" ]; then
    echo "Status: inactive"
    exit 0
fi
if [ "$1" = "allow" ]; then
    exit 1
fi
exit 0
""",
            )
            np_log = root / "np.log"
            _write_executable(
                stub_bin / "netfilter-persistent",
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {str(np_log)!r}\nexit 0\n",
            )
            res2 = subprocess.run(
                ["bash", "-c", 'source "$1"; _setup_firewall', "fw-ufw-fail", str(SECURITY_MODULE)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            ufw_cmds2 = ufw_log.read_text(encoding="utf-8").splitlines()
            self.assertNotIn("--force enable", ufw_cmds2)
            self.assertEqual(np_log.read_text(encoding="utf-8").splitlines(), ["save"])
            saved_state = json.loads(ipt_state.read_text(encoding="utf-8"))
            self.assertEqual(saved_state["v4"]["policies"]["INPUT"], "DROP")
            self.assertIn("-p tcp --dport 2222 -j ACCEPT", saved_state["v4"]["chains"]["INPUT"])

    def test_firewall_preserves_operator_iptables_rules_idempotently_and_persists_consistently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-fw-ipt-") as tmp:
            root = Path(tmp)
            sys_root = root / "sysroot"
            (sys_root / "etc/ssh").mkdir(parents=True)
            (sys_root / "etc/ssh/sshd_config").write_text("Port 2222\n", encoding="utf-8")

            stub_bin = root / "bin"
            stub_bin.mkdir()
            ufw_log = root / "ufw.log"
            systemctl_log = root / "systemctl.log"
            ipt_state = root / "ipt-state.json"
            ipt_log = root / "ipt.log"

            initial_state = {
                "v4": {
                    "policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                    "chains": {
                        "INPUT": [
                            "-p tcp --dport 2222 -j f2b-sshd",
                            "-i wg0 -j ACCEPT",
                            "-s 10.0.0.0/8 -p tcp --dport 9100 -j ACCEPT",
                            "-j REJECT --reject-with icmp-host-prohibited",
                        ],
                        "FORWARD": ["-i wg0 -j ACCEPT"],
                        "OUTPUT": [],
                    },
                },
                "v6": {
                    "policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                    "chains": {
                        "INPUT": ["-i wg0 -j ACCEPT"],
                        "FORWARD": [],
                        "OUTPUT": [],
                    },
                },
            }
            ipt_state.write_text(json.dumps(initial_state), encoding="utf-8")
            _make_stateful_iptables_stub(stub_bin, ipt_state, ipt_log)

            # UFW is installed but INACTIVE; operator manages raw iptables directly!
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
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {str(systemctl_log)!r}\nexit 0\n",
            )
            np_log = root / "np.log"
            _write_executable(
                stub_bin / "netfilter-persistent",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> {str(np_log)!r}
mkdir -p {str(sys_root / 'etc/iptables')!r}
iptables-save > {str(sys_root / 'etc/iptables/rules.v4')!r}
ip6tables-save > {str(sys_root / 'etc/iptables/rules.v6')!r}
exit 0
""",
            )

            env = {
                "PATH": f"{stub_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
                "AF_SYS_ROOT": str(sys_root),
                "AF_SSH_PORTS": "2222",
                "OUTTO": str(root / "out.log"),
                "INSTALL_LOG": str(root / "install.log"),
            }

            # Run twice to verify full idempotency!
            for run_idx in (1, 2):
                res = subprocess.run(
                    ["bash", "-c", 'source "$1"; _setup_firewall', f"fw-ipt-{run_idx}", str(SECURITY_MODULE)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            # UFW must ONLY have been queried for status, NEVER enabled over operator iptables rules!
            ufw_cmds = ufw_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(set(ufw_cmds), {"status"})

            # iptables -F must NEVER have been invoked!
            ipt_calls = [json.loads(ln) for ln in ipt_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertFalse(any(c["args"] and c["args"][0] == "-F" for c in ipt_calls), "Must never flush INPUT")

            final_state = json.loads(ipt_state.read_text(encoding="utf-8"))
            v4_in = final_state["v4"]["chains"]["INPUT"]
            # Operator rules preserved intact & catch-all REJECT remains LAST!
            self.assertEqual(v4_in[0], "-p tcp --dport 2222 -j f2b-sshd")
            self.assertEqual(v4_in[1], "-i wg0 -j ACCEPT")
            self.assertEqual(v4_in[2], "-s 10.0.0.0/8 -p tcp --dport 9100 -j ACCEPT")
            self.assertEqual(v4_in[-1], "-j REJECT --reject-with icmp-host-prohibited")
            # Required rules inserted before catch-all, with zero duplicates across two runs
            for req in (
                "-i lo -j ACCEPT",
                "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                "-p tcp --dport 2222 -j ACCEPT",
                "-p tcp --dport 80 -j ACCEPT",
                "-p tcp --dport 443 -j ACCEPT",
                "-p udp --dport 1900 -j DROP",
            ):
                self.assertEqual(v4_in.count(req), 1, f"Expected exactly 1 occurrence of {req} in {v4_in}")
            # Operator FORWARD rule & ACCEPT policy preserved on v4; empty v6 FORWARD restricted to DROP
            self.assertEqual(final_state["v4"]["policies"]["INPUT"], "DROP")
            self.assertEqual(final_state["v4"]["policies"]["FORWARD"], "ACCEPT")
            self.assertEqual(final_state["v4"]["chains"]["FORWARD"], ["-i wg0 -j ACCEPT"])
            self.assertEqual(final_state["v6"]["policies"]["INPUT"], "DROP")
            self.assertEqual(final_state["v6"]["policies"]["FORWARD"], "DROP")
            self.assertIn("-p ipv6-icmp -j ACCEPT", final_state["v6"]["chains"]["INPUT"])
            self.assertIn("-i wg0 -j ACCEPT", final_state["v6"]["chains"]["INPUT"])

            # Persistence used netfilter-persistent save -> /etc/iptables/rules.v4 & rules.v6 (never /etc/iptables.rules)
            self.assertEqual(np_log.read_text(encoding="utf-8").splitlines(), ["save", "save"])
            self.assertIn("enable netfilter-persistent.service", systemctl_log.read_text(encoding="utf-8").splitlines())
            self.assertTrue((sys_root / "etc/iptables/rules.v4").is_file())
            self.assertTrue((sys_root / "etc/iptables/rules.v6").is_file())
            self.assertFalse((sys_root / "etc/iptables.rules").exists())

    def test_firewall_iptables_fallback_atomic_rules_v4_v6_symlink_guard_and_no_lockout_on_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-fw-persist-") as tmp:
            root = Path(tmp)
            sys_root = root / "sysroot"
            (sys_root / "etc/ssh").mkdir(parents=True)
            (sys_root / "etc/ssh/sshd_config").write_text("Port 2222\n", encoding="utf-8")

            stub_bin = root / "bin"
            stub_bin.mkdir()
            ipt_state = root / "ipt-state.json"
            ipt_log = root / "ipt.log"
            clean_state = {
                "v4": {"policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}, "chains": {"INPUT": [], "FORWARD": [], "OUTPUT": []}},
                "v6": {"policies": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}, "chains": {"INPUT": [], "FORWARD": [], "OUTPUT": []}},
            }
            ipt_state.write_text(json.dumps(clean_state), encoding="utf-8")
            _make_stateful_iptables_stub(stub_bin, ipt_state, ipt_log)

            # Build a minimal PATH without netfilter-persistent and without ufw so atomic rules.v4/v6 path runs
            iso_bin = root / "iso_bin"
            iso_bin.mkdir()
            for tool in ("bash", "awk", "grep", "mktemp", "chmod", "mv", "rm", "install", "date", "sed"):
                resolved = shutil.which(tool)
                if resolved:
                    (iso_bin / tool).symlink_to(resolved)
            for tool in ("iptables", "ip6tables", "iptables-save", "ip6tables-save"):
                (iso_bin / tool).symlink_to(stub_bin / tool)

            env = {
                "PATH": str(iso_bin),
                "AF_SYS_ROOT": str(sys_root),
                "OUTTO": str(root / "out.log"),
                "INSTALL_LOG": str(root / "install.log"),
            }
            res = subprocess.run(
                ["bash", "-c", 'source "$1"; _setup_firewall_iptables "2222/tcp 80/tcp 443/tcp"', "fw-atomic", str(SECURITY_MODULE)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            v4_rules = sys_root / "etc/iptables/rules.v4"
            v6_rules = sys_root / "etc/iptables/rules.v6"
            self.assertTrue(v4_rules.is_file())
            self.assertTrue(v6_rules.is_file())
            self.assertEqual(stat.S_IMODE(v4_rules.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(v6_rules.stat().st_mode), 0o640)
            self.assertIn("--dport 2222 -j ACCEPT", v4_rules.read_text(encoding="utf-8"))
            self.assertFalse((sys_root / "etc/iptables.rules").exists())

            # Symlinked rules.v4 must fail closed without touching symlink target
            victim = root / "victim-rules"
            victim.write_text("KEEP\n", encoding="utf-8")
            v4_rules.unlink()
            v4_rules.symlink_to(victim)
            res_sym = subprocess.run(
                ["bash", "-c", 'source "$1"; _fw_persist_iptables', "fw-sym", str(SECURITY_MODULE)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "KEEP\n")

            # Simulated failure adding SSH allow rule MUST fail BEFORE setting INPUT policy to DROP
            ipt_state.write_text(json.dumps(clean_state), encoding="utf-8")
            _make_stateful_iptables_stub(stub_bin, ipt_state, ipt_log, fail_on_substring="--dport 2222")
            v4_rules.unlink()
            res_fail = subprocess.run(
                ["bash", "-c", 'source "$1"; _setup_firewall_iptables "2222/tcp 80/tcp 443/tcp"', "fw-nolockout", str(SECURITY_MODULE)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(res_fail.returncode, 0)
            post_fail_state = json.loads(ipt_state.read_text(encoding="utf-8"))
            self.assertEqual(post_fail_state["v4"]["policies"]["INPUT"], "ACCEPT", "Must never flip INPUT to DROP if SSH allow failed")

    def test_state_acquire_lock_defaults_to_run_normalizes_var_run_and_rejects_custom_symlink_dirs(self) -> None:
        state_module = ROOT / "setup/modules/06-state.sh"
        with tempfile.TemporaryDirectory(prefix="af-lock-") as tmp:
            root = Path(tmp)
            # 1. Default LOCKFILE points to /run/aetherflow-setup.lock (not legacy /var/run symlink)
            default_probe = subprocess.run(
                ["bash", "-c", 'unset LOCKFILE; source "$1"; printf "%s" "$LOCKFILE"', "lock-default", str(state_module)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(default_probe.returncode, 0, default_probe.stderr)
            self.assertEqual(default_probe.stdout, "/run/aetherflow-setup.lock")

            # 2. Custom symlinked lock directory MUST fail closed without creating any target file
            real_dir = root / "real-lock-dir"
            real_dir.mkdir()
            sym_dir = root / "sym-lock-dir"
            sym_dir.symlink_to(real_dir)
            sym_res = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; _acquire_lock',
                    "lock-symdir",
                    str(state_module),
                ],
                env={**os.environ, "LOCKFILE": str(sym_dir / "aetherflow-setup.lock")},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(sym_res.returncode, 0)
            self.assertIn("Refusing symlinked lockfile directory", sym_res.stderr)
            self.assertFalse((real_dir / "aetherflow-setup.lock").exists())

            # 2b. Nested lock path beneath a symlinked ancestor MUST fail closed BEFORE mkdir -p
            nested_sym_res = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; _acquire_lock',
                    "lock-nested-symdir",
                    str(state_module),
                ],
                env={**os.environ, "LOCKFILE": str(sym_dir / "nested" / "sub" / "aetherflow-setup.lock")},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(nested_sym_res.returncode, 0)
            self.assertIn("Refusing symlinked lockfile directory", nested_sym_res.stderr)
            self.assertFalse((real_dir / "nested").exists())

            # 3. Direct non-symlink directory acquires and releases flock cleanly even under
            #    noclobber and if LOCKFILE is mutated after acquisition (AF_LOCK_PATH preserved)
            direct_lock = real_dir / "aetherflow-setup.lock"
            decoy_lock = real_dir / "decoy.lock"
            decoy_lock.write_text("KEEP-DECOY\n", encoding="utf-8")
            ok_res = subprocess.run(
                [
                    "bash",
                    "-c",
                    'set -o noclobber; source "$1"; _acquire_lock; '
                    'printf "%s" "$LOCKFILE"; '
                    'LOCKFILE="$2"; '
                    '_release_lock',
                    "lock-ok",
                    str(state_module),
                    str(decoy_lock),
                ],
                env={**os.environ, "LOCKFILE": str(direct_lock)},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(ok_res.returncode, 0, ok_res.stdout + ok_res.stderr)
            self.assertEqual(ok_res.stdout, str(direct_lock))
            self.assertEqual(direct_lock.read_text(encoding="utf-8"), "")
            self.assertEqual(decoy_lock.read_text(encoding="utf-8"), "KEEP-DECOY\n")

            # 3b. Contended lock reads holder PID via locked FD without clobbering
            contended_lock = real_dir / "contended.lock"
            holder = subprocess.Popen(
                [
                    "bash",
                    "-c",
                    'source "$1"; _acquire_lock; printf "LOCKED:%s\\n" "${BASHPID:-$$}"; sleep 5; _release_lock',
                    "lock-holder",
                    str(state_module),
                ],
                env={**os.environ, "LOCKFILE": str(contended_lock)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert holder.stdout is not None
                ready_line = holder.stdout.readline().strip()
                self.assertTrue(ready_line.startswith("LOCKED:"), ready_line)
                holder_pid = ready_line.split(":", 1)[1]
                contender = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; _acquire_lock',
                        "lock-contender",
                        str(state_module),
                    ],
                    env={**os.environ, "LOCKFILE": str(contended_lock)},
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(contender.returncode, 0)
                self.assertIn(f"PID: {holder_pid}", contender.stdout)
            finally:
                holder.terminate()
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)

            # 3c. Trailing slash on AF_INSTALL_ROOT in 05-finalize.sh self-delete guard preserves repo script
            finalize_module = ROOT / "setup/modules/05-finalize.sh"
            fake_root = root / "af-root"
            fake_setup_dir = fake_root / "setup"
            fake_setup_dir.mkdir(parents=True)
            fake_script = fake_setup_dir / "AetherFlow-Setup"
            fake_script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            guard_probe = subprocess.run(
                [
                    "bash",
                    "-c",
                    'af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"; '
                    'af_root="$(realpath -m "${af_root}" 2>/dev/null || printf \'%s\' "${af_root%/}")"; '
                    'af_root="${af_root%/}"; '
                    'if [[ "${AF_SKIP_SELF_DELETE:-0}" != "1" ]] && [[ -n "${af_root}" ]] && [[ "$(realpath "$0" 2>/dev/null || echo "$0")" != "${af_root}"/* ]]; then '
                    'printf "WOULD_DELETE"; else printf "KEPT"; fi',
                    str(fake_script),
                ],
                env={**os.environ, "AF_INSTALL_ROOT": f"{fake_root}/"},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(guard_probe.returncode, 0, guard_probe.stderr)
            self.assertEqual(guard_probe.stdout, "KEPT")
            self.assertIn('af_root="${af_root%/}"', finalize_module.read_text(encoding="utf-8"))

            # 4. Legacy /var/run/* normalizes to /run/* when /var/run is a root-owned symlink to /run or ../run
            var_run = Path("/var/run")
            run_dir = Path("/run")
            if (
                var_run.is_symlink()
                and var_run.lstat().st_uid == 0
                and os.readlink(var_run) in ("/run", "../run")
                and not run_dir.is_symlink()
                and run_dir.is_dir()
                and run_dir.lstat().st_uid == 0
            ):
                run_user_dir = Path(f"/run/user/{os.getuid()}")
                if run_user_dir.is_dir() and os.access(run_user_dir, os.W_OK):
                    lock_name = f"af-setup-lock-test-{os.getpid()}.lock"
                    expected_norm = f"/run/user/{os.getuid()}/{lock_name}"
                    try:
                        norm_res = subprocess.run(
                            [
                                "bash",
                                "-c",
                                'source "$1"; _acquire_lock; printf "%s" "$LOCKFILE"; _release_lock',
                                "lock-varrun",
                                str(state_module),
                            ],
                            env={**os.environ, "LOCKFILE": f"/var/run/user/{os.getuid()}/{lock_name}"},
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        self.assertEqual(norm_res.returncode, 0, norm_res.stdout + norm_res.stderr)
                        self.assertEqual(norm_res.stdout, expected_norm)
                    finally:
                        Path(expected_norm).unlink(missing_ok=True)
                else:
                    # Non-writable /run: still verify /var/run/* normalized to /run/* and did NOT fail symlink check
                    norm_res = subprocess.run(
                        [
                            "bash",
                            "-c",
                            'source "$1"; _acquire_lock',
                            "lock-varrun-ro",
                            str(state_module),
                        ],
                        env={**os.environ, "LOCKFILE": "/var/run/aetherflow-setup.lock"},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertNotIn("Refusing symlinked lockfile directory", norm_res.stderr)
                    if norm_res.returncode != 0:
                        self.assertIn("/run/aetherflow-setup.lock", norm_res.stderr)


if __name__ == "__main__":
    unittest.main()
