"""Synthetic regression tests for exact APT version pinning, receipts, and rollback."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.installer_test_helpers import ROOT, replace_paths_once


APT_AUTOMATION_PATH = ROOT / "config/package_automation.json"
INSTALL_DIR = ROOT / "packages/package/install"


class SyntheticAptEnvironment:
    """Isolated temp filesystem with synthetic apt-get, dpkg-query, dpkg, and systemctl shims.

    Never touches host APT or dpkg state.
    """

    def __init__(self, repo_versions, installed=None, apt_behavior=None):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-apt-exact-")
        self.root = Path(self._tmp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "dpkg-state.json"
        self.repo_path = self.root / "apt-repo.json"
        self.log_path = self.root / "commands.jsonl"
        self.behavior_path = self.root / "apt-behavior.json"

        for rel in (
            "install",
            "etc/apt/sources.list.d",
            "etc/apt/keyrings",
            "etc/default",
            "etc/jellyfin",
            "etc/netdata",
            "etc/novnc",
            "etc/systemd/system",
            "etc/wireguard",
            "opt/emby-server",
            "var/lib/aetherflow/apt-reinstall-required",
            "var/lib/grafana",
            "var/lib/jellyfin",
            "var/lib/kasmvnc",
            "var/lib/quassel",
            "var/lib/transmission-daemon",
            "var/log/aetherflow",
            "var/log/quassel",
            "usr/bin",
            "usr/sbin",
            "usr/lib/jellyfin",
            "usr/share/jellyfin",
            "usr/lib/quassel",
            "usr/share/quassel",
            "tmp/tx-root",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)

        (self.root / "tmp/tx-root").chmod(0o700)
        (self.root / "etc/aetherflow").mkdir(parents=True, exist_ok=True)

        # Normalize installed dict: pkg -> {"status": "installed", "version": "..."}
        norm_installed = {}
        for pkg, val in (installed or {}).items():
            if isinstance(val, str):
                norm_installed[pkg] = {"status": "installed", "version": val}
            else:
                norm_installed[pkg] = dict(val)
        self.state_path.write_text(json.dumps(norm_installed))
        self.repo_path.write_text(json.dumps(repo_versions))
        self.behavior_path.write_text(json.dumps(apt_behavior or {}))

        # Rebase common.sh into isolated root and keep synthetic bin_dir ahead of system PATH
        self.common_sh = self.root / "packages/common.sh"
        self.common_sh.parent.mkdir(parents=True, exist_ok=True)
        common_text = self.rebase((ROOT / "packages/common.sh").read_text())
        common_text = common_text.replace(
            'export PATH="/usr/local/nodejs/bin:',
            f'export PATH="{self.bin_dir}:{self.root / "usr/sbin"}:{self.root / "usr/bin"}:/usr/local/nodejs/bin:',
            1,
        )
        self.common_sh.write_text(common_text)

        self._install_shims()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._tmp.cleanup()

    def rebase(self, text):
        root_str = str(self.root)
        replacements = {
            "/var/lib/aetherflow/apt-reinstall-required": f"{root_str}/var/lib/aetherflow/apt-reinstall-required",
            "/var/lib/aetherflow": f"{root_str}/var/lib/aetherflow",
            "/var/log/aetherflow": f"{root_str}/var/log/aetherflow",
            "/var/lib/quassel": f"{root_str}/var/lib/quassel",
            "/var/log/quassel": f"{root_str}/var/log/quassel",
            "/var/lib/jellyfin": f"{root_str}/var/lib/jellyfin",
            "/var/lib/grafana": f"{root_str}/var/lib/grafana",
            "/var/lib/kasmvnc": f"{root_str}/var/lib/kasmvnc",
            "/var/lib/transmission-daemon": f"{root_str}/var/lib/transmission-daemon",
            "/var/lib/netdata": f"{root_str}/var/lib/netdata",
            "/etc/netdata": f"{root_str}/etc/netdata",
            "/etc/jellyfin": f"{root_str}/etc/jellyfin",
            "/etc/default/quasselcore": f"{root_str}/etc/default/quasselcore",
            "/etc/wireguard": f"{root_str}/etc/wireguard",
            "/etc/novnc": f"{root_str}/etc/novnc",
            "/etc/apt/sources.list.d": f"{root_str}/etc/apt/sources.list.d",
            "/etc/apt/keyrings": f"{root_str}/etc/apt/keyrings",
            "/etc/aetherflow": f"{root_str}/etc/aetherflow",
            "/etc/systemd/system": f"{root_str}/etc/systemd/system",
            "/opt/emby-server": f"{root_str}/opt/emby-server",
            "/opt/netdata": f"{root_str}/opt/netdata",
            "/usr/bin/quasselcore": f"{root_str}/usr/bin/quasselcore",
            "/usr/lib/quassel": f"{root_str}/usr/lib/quassel",
            "/usr/share/quassel": f"{root_str}/usr/share/quassel",
            "/usr/bin/jellyfin": f"{root_str}/usr/bin/jellyfin",
            "/usr/lib/jellyfin": f"{root_str}/usr/lib/jellyfin",
            "/usr/share/jellyfin": f"{root_str}/usr/share/jellyfin",
            "/usr/sbin/netdata": f"{root_str}/usr/sbin/netdata",
            "/usr/local/sbin/netdata": f"{root_str}/usr/local/sbin/netdata",
            "/usr/lib/netdata": f"{root_str}/usr/lib/netdata",
            "/usr/libexec/netdata": f"{root_str}/usr/libexec/netdata",
            "/usr/share/netdata": f"{root_str}/usr/share/netdata",
            "/install": f"{root_str}/install",
        }
        return replace_paths_once(text, replacements)

    def write_executable(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        path.chmod(0o755)
        return path

    def _install_shims(self):
        self.write_executable(
            self.bin_dir / "dpkg-query",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

state = json.loads(Path(os.environ["AF_SYNTH_DPKG_STATE"]).read_text())
fmt = ""
pkg = None
args = sys.argv[1:]
i = 0
while i < len(args):
    a = args[i]
    if a.startswith("-f="):
        fmt = a[3:]
    elif a in ("-f", "--showformat") and i + 1 < len(args):
        fmt = args[i + 1]
        i += 1
    elif not a.startswith("-"):
        pkg = a
    i += 1

if not pkg or pkg not in state:
    sys.stderr.write(f"dpkg-query: no packages found matching {pkg}\n")
    sys.exit(1)

entry = state[pkg]
status = entry.get("status", "installed")
version = entry.get("version", "")
out = fmt.replace("${db:Status-Status}", status).replace("${Version}", version).replace("\\n", "\n")
sys.stdout.write(out)
""",
        )

        self.write_executable(
            self.bin_dir / "apt-get",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

log_path = Path(os.environ["AF_SYNTH_LOG"])
with log_path.open("a") as fh:
    fh.write(json.dumps(["apt-get", *sys.argv[1:]]) + "\n")

state_path = Path(os.environ["AF_SYNTH_DPKG_STATE"])
repo = json.loads(Path(os.environ["AF_SYNTH_APT_REPO"]).read_text())
behavior = json.loads(Path(os.environ["AF_SYNTH_APT_BEHAVIOR"]).read_text())
state = json.loads(state_path.read_text())

args = sys.argv[1:]
subcmd = None
allow_downgrades = "--allow-downgrades" in args
specs = []
i = 0
while i < len(args):
    a = args[i]
    if a == "-o" and i + 1 < len(args):
        i += 2
        continue
    if a.startswith("-"):
        i += 1
        continue
    if subcmd is None:
        subcmd = a
    else:
        specs.append(a)
    i += 1

if subcmd == "update":
    sys.exit(0)

if subcmd == "remove":
    for spec in specs:
        pkg = spec.split("=", 1)[0]
        state.pop(pkg, None)
    state_path.write_text(json.dumps(state))
    sys.exit(0)

if subcmd == "install":
    if behavior.get("fail_install_for"):
        for spec in specs:
            pkg = spec.split("=", 1)[0]
            if pkg in behavior["fail_install_for"]:
                sys.stderr.write(f"E: Simulated APT failure for {spec}\n")
                sys.exit(100)

    pending = {}
    for spec in specs:
        if spec.endswith(".deb"):
            continue
        if "=" in spec:
            pkg, req_ver = spec.split("=", 1)
            versions = repo.get(pkg, [])
            if req_ver not in versions:
                sys.stderr.write(f"E: Version '{req_ver}' for '{pkg}' was not found\n")
                sys.exit(100)
            chosen = req_ver
            # Simulate a buggy repo/apt returning wrong version or non-installed status if configured
            override = behavior.get("install_override", {}).get(pkg)
            if override and not allow_downgrades:
                pending[pkg] = dict(override)
            else:
                pending[pkg] = {"status": "installed", "version": chosen}
        else:
            pkg = spec
            versions = repo.get(pkg)
            if versions:
                # Candidate is always the last version in the list
                chosen = versions[-1]
                override = behavior.get("install_override", {}).get(pkg)
                if override and not allow_downgrades:
                    pending[pkg] = dict(override)
                else:
                    pending[pkg] = {"status": "installed", "version": chosen}
            else:
                # Auxiliary packages like curl/openssl/ca-certificates
                pending[pkg] = {"status": "installed", "version": "1.0-1"}

    # Optional lockstep companion simulation (e.g., jellyfin pulls jellyfin-server & jellyfin-web)
    for parent_pkg, companions in behavior.get("lockstep_companions", {}).items():
        if parent_pkg in pending:
            ver = pending[parent_pkg]["version"]
            for comp in companions:
                if comp not in pending:
                    pending[comp] = {"status": "installed", "version": ver}

    state.update(pending)
    state_path.write_text(json.dumps(state))
    sys.exit(0)

sys.exit(0)
""",
        )

        self.write_executable(
            self.bin_dir / "systemctl",
            r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

log_path = Path(os.environ["AF_SYNTH_LOG"])
with log_path.open("a") as fh:
    fh.write(json.dumps(["systemctl", *sys.argv[1:]]) + "\n")

svc_path = Path(os.environ["AF_SYNTH_DPKG_STATE"]).with_name("svc-state.json")
svc = json.loads(svc_path.read_text()) if svc_path.exists() else {}
args = sys.argv[1:]
behavior = json.loads(Path(os.environ["AF_SYNTH_APT_BEHAVIOR"]).read_text())

cmd = args[0] if args else ""
units = [a for a in args[1:] if not a.startswith("-") and a != "--"]

if cmd == "is-active":
    active = bool(units) and all(svc.get(u, False) for u in units) and not behavior.get("fail_service")
    if "--quiet" not in args:
        print("active" if active else "inactive")
    sys.exit(0 if active else 3)

if cmd == "show":
    active = bool(units) and all(svc.get(u, False) for u in units) and not behavior.get("fail_service")
    joined = " ".join(args)
    if "LoadState" in joined:
        print("loaded")
    elif "SubState" in joined:
        print("running" if active else "dead")
    else:
        print("active" if active else "inactive")
    sys.exit(0)

if cmd == "stop":
    for u in units:
        svc[u] = False
    svc_path.write_text(json.dumps(svc))
    sys.exit(0)

if cmd in ("restart", "start") or (cmd == "enable" and "--now" in args):
    if behavior.get("fail_service"):
        sys.stderr.write("Simulated systemd activation failure\n")
        sys.exit(1)
    for u in units:
        svc[u] = True
    svc_path.write_text(json.dumps(svc))
    sys.exit(0)

sys.exit(0)
""",
        )

        self.write_executable(
            self.bin_dir / "dpkg",
            r"""#!/usr/bin/env python3
import os, subprocess, sys
if len(sys.argv) >= 2 and sys.argv[1] == "--print-architecture":
    print("amd64")
    sys.exit(0)
if os.path.exists("/usr/bin/dpkg"):
    sys.exit(subprocess.run(["/usr/bin/dpkg", *sys.argv[1:]]).returncode)
sys.exit(0)
""",
        )

        for noop in ("chown", "chmod", "useradd", "lsb_release"):
            self.write_executable(self.bin_dir / noop, "#!/bin/bash\nexit 0\n")

        self.write_executable(
            self.bin_dir / "id",
            r"""#!/bin/bash
if [[ "${1:-}" == "-u" ]]; then
    echo 0
    exit 0
fi
exit 0
""",
        )

        self.write_executable(
            self.bin_dir / "openssl",
            r"""#!/usr/bin/env python3
import sys
from pathlib import Path
args = sys.argv[1:]
for flag in ("-out", "-keyout"):
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            p = Path(args[idx + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("SYNTH-CERT\n")
""",
        )

    def env(self, extra=None):
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}:{self.root / 'usr/sbin'}:{self.root / 'usr/bin'}:/usr/bin:/bin",
            "AF_SYNTH_DPKG_STATE": str(self.state_path),
            "AF_SYNTH_APT_REPO": str(self.repo_path),
            "AF_SYNTH_APT_BEHAVIOR": str(self.behavior_path),
            "AF_SYNTH_LOG": str(self.log_path),
            "AF_TRANSACTION_ROOT": str(self.root / "tmp/tx-root"),
            "DEBIAN_FRONTEND": "noninteractive",
        }
        env.pop("AF_TARGET_VERSION", None)
        env.pop("AF_ALLOW_DOWNGRADE", None)
        if extra:
            env.update(extra)
        return env

    def commands(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]

    def dpkg_state(self):
        return json.loads(self.state_path.read_text())

    def run_bash(self, body, extra_env=None):
        script = f"""
set -euo pipefail
source "{self.common_sh}"
require_root() {{ :; }}
wait_for_service_ready() {{ :; }}
{body}
"""
        return subprocess.run(
            ["bash", "-c", script],
            env=self.env(extra_env),
            text=True,
            capture_output=True,
            timeout=20,
        )

    def run_install_script(self, app_name, extra_env=None, prelude=""):
        raw = (INSTALL_DIR / f"installpackage-{app_name}").read_text()
        rebased = self.rebase(raw)
        script_path = self.root / "packages/package/install" / f"installpackage-{app_name}"
        script_path.parent.mkdir(parents=True, exist_ok=True)
        # Inject non-root test stubs right before require_root (after common.sh is sourced)
        inject = f"""
require_root() {{ :; }}
wait_for_service_ready() {{ :; }}
install_apt_signing_key() {{ mkdir -p "$(dirname "$2")"; printf 'synth-key\\n' > "$2"; }}
seed_jellyfin_master_user() {{ :; }}
{prelude}
"""
        if "\nrequire_root\n" in rebased:
            rebased = rebased.replace("\nrequire_root\n", "\n" + inject + "\nrequire_root\n", 1)
        else:
            rebased = inject + "\n" + rebased
        script_path.write_text(rebased)
        script_path.chmod(0o755)
        return subprocess.run(
            ["bash", str(script_path)],
            env=self.env(extra_env),
            text=True,
            capture_output=True,
            timeout=20,
        )


class AptExactVersionTests(unittest.TestCase):
    def test_all_18_apt_entries_match_package_automation_and_use_shared_helpers(self):
        automation = json.loads(APT_AUTOMATION_PATH.read_text())
        apt_entries = {
            name: cfg for name, cfg in automation.items() if cfg.get("update_source") == "apt"
        }
        self.assertEqual(len(apt_entries), 18, f"Expected 18 apt entries, found {sorted(apt_entries)}")

        prep_re = re.compile(
            r"^\s*prepare_apt_package_transaction\s+(--local-deb\s+)?(\S+)\s+(.+?)\s*$",
            re.MULTILINE,
        )
        resolve_re = re.compile(r"resolve_installed_apt_package_version\s+([a-z0-9][a-z0-9+.-]*)")

        for name, cfg in sorted(apt_entries.items()):
            expected_pkg = cfg["update_package"]
            script_path = INSTALL_DIR / f"installpackage-{name}"
            self.assertTrue(script_path.is_file(), f"Missing install script for {name}")
            content = script_path.read_text()

            prep_match = prep_re.search(content)
            self.assertIsNotNone(prep_match, f"{name}: missing prepare_apt_package_transaction")
            self.assertIsNone(
                prep_match.group(1),
                f"{name}: update_source=apt installer must not pass --local-deb",
            )
            pkgs = prep_match.group(3).split()
            self.assertEqual(
                pkgs[0],
                expected_pkg,
                f"{name}: primary APT package '{pkgs[0]}' does not match package_automation.json update_package '{expected_pkg}'",
            )

            resolve_matches = resolve_re.findall(content)
            self.assertIn(
                expected_pkg,
                resolve_matches,
                f"{name}: receipt must resolve installed version for primary package '{expected_pkg}' via resolve_installed_apt_package_version",
            )

            # Ensure no revision/epoch stripping remains on APT receipts
            self.assertNotIn("%%-*", content, f"{name}: must not strip Debian revision with %%-*")

        # Verify the two non-APT .deb workflows preserve --local-deb mode
        for deb_app, deb_pkg in (("emby", "emby-server"), ("kasmvnc", "kasmvncserver")):
            content = (INSTALL_DIR / f"installpackage-{deb_app}").read_text()
            prep_match = prep_re.search(content)
            self.assertIsNotNone(prep_match, f"{deb_app}: missing prepare_apt_package_transaction")
            self.assertIsNotNone(
                prep_match.group(1),
                f"{deb_app}: local .deb installer must pass --local-deb",
            )
            self.assertEqual(prep_match.group(3).split()[0], deb_pkg)

    def test_non_candidate_exact_selection_epochs_revisions_and_primary_scoping(self):
        repo = {
            "quassel-core": ["1:0.13.1-1", "1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"],
            "openssl": ["3.0.11-1~deb12u2", "3.0.15-1~deb12u1"],
        }
        with SyntheticAptEnvironment(repo) as env:
            # Select non-candidate version 1:0.14.0-1+deb12u1 (Candidate is 1:0.14.0-2+deb12u1)
            res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            apt_installs = [c for c in env.commands() if c[:2] == ["apt-get", "install"]]
            self.assertTrue(apt_installs, "expected apt-get install invocation")
            install_cmd = apt_installs[-1]
            self.assertIn("quassel-core=1:0.14.0-1+deb12u1", install_cmd)
            self.assertIn("openssl", install_cmd)
            self.assertFalse(
                any(arg.startswith("openssl=") for arg in install_cmd),
                f"companion package openssl must remain unpinned: {install_cmd}",
            )

            self.assertEqual(env.dpkg_state()["quassel-core"]["version"], "1:0.14.0-1+deb12u1")
            receipt = (env.root / "var/lib/quassel/.af-version").read_text().strip()
            self.assertEqual(receipt, "1:0.14.0-1+deb12u1")

    def test_jellyfin_pins_jellyfin_and_receipts_jellyfin_not_jellyfin_server(self):
        repo = {
            "jellyfin": ["10.10.2+deb12", "10.10.3+deb12", "10.10.4+deb12"],
            "jellyfin-server": ["10.10.2+deb12", "10.10.3+deb12", "10.10.99+deb12"],
            "jellyfin-web": ["10.10.2+deb12", "10.10.3+deb12", "10.10.4+deb12"],
        }
        # Deliberately set jellyfin-server to a distinct version to prove receipt reads `jellyfin`
        installed = {
            "jellyfin": "10.10.2+deb12",
            "jellyfin-server": "10.10.99+deb12",
            "jellyfin-web": "10.10.2+deb12",
        }
        with SyntheticAptEnvironment(repo, installed=installed) as env:
            (env.root / "var/lib/jellyfin/.af-version").write_text("10.10.2+deb12\n")
            res = env.run_install_script("jellyfin", extra_env={"AF_TARGET_VERSION": "10.10.3+deb12"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            apt_installs = [c for c in env.commands() if c[:2] == ["apt-get", "install"]]
            jellyfin_cmd = [c for c in apt_installs if any("jellyfin" in a for a in c)][-1]
            self.assertIn("jellyfin=10.10.3+deb12", jellyfin_cmd)
            self.assertNotIn("jellyfin-server", jellyfin_cmd)
            self.assertEqual((env.root / "var/lib/jellyfin/.af-version").read_text().strip(), "10.10.3+deb12")

    def test_wireguard_pins_wireguard_tools_and_leaves_wireguard_metapackage_unpinned(self):
        repo = {
            "wireguard-tools": ["1.0.20210914-1.1+b1", "1.0.20210914-2"],
            "wireguard": ["1.0.20210914-1"],
            "qrencode": ["4.1.1-1"],
        }
        with SyntheticAptEnvironment(repo) as env:
            res = env.run_bash(
                f"""
                PACKAGE_NAME="wireguard"
                begin_state_transaction "wg-quick@wg0" 0 "/" "{env.root}/etc/wireguard"
                prepare_apt_package_transaction "{env.root}/etc/wireguard/.af-version" wireguard-tools wireguard
                apt-get install --no-remove -y -qq wireguard wireguard-tools qrencode
                WG_VER="$(resolve_installed_apt_package_version wireguard-tools "1.0.20210914")"
                systemctl start wg-quick@wg0
                queue_app_version "{env.root}/etc/wireguard/.af-version" "$WG_VER"
                commit_app_versions
                INSTALL_COMMITTED=true
                """,
                extra_env={"AF_TARGET_VERSION": "1.0.20210914-1.1+b1"},
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            self.assertIn("wireguard-tools=1.0.20210914-1.1+b1", install_cmd)
            self.assertIn("wireguard", install_cmd)
            self.assertFalse(any(a.startswith("wireguard=") for a in install_cmd))
            self.assertEqual(
                (env.root / "etc/wireguard/.af-version").read_text().strip(),
                "1.0.20210914-1.1+b1",
            )

    def test_invalid_exact_apt_tokens_rejected_before_apt_get(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1"]}
        bad_tokens = [
            "latest",
            "v1.2.3",
            "V1.2.3",
            "1.2.*",
            "1.2.3-",
            "1.2_3",
            "deadbeef",
            "quassel-core=1:0.14.0-1",
            "1:0.14.0-1/bookworm",
            "1::0.14.0-1",
            "epoch:1.0-1",
            "1.0..2",
        ]
        for bad in bad_tokens:
            with self.subTest(token=bad), SyntheticAptEnvironment(repo) as env:
                res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": bad})
                self.assertNotEqual(res.returncode, 0, f"expected rejection for token {bad!r}")
                self.assertEqual(
                    [c for c in env.commands() if c[0] == "apt-get"],
                    [],
                    f"apt-get must not run for invalid token {bad!r}",
                )

    def test_unavailable_exact_target_fails_cleanly_and_preserves_prior_state(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]}
        installed = {"quassel-core": "1:0.14.0-1+deb12u1", "openssl": "3.0.15-1~deb12u1"}
        with SyntheticAptEnvironment(repo, installed=installed) as env:
            receipt = env.root / "var/lib/quassel/.af-version"
            receipt.write_text("1:0.14.0-1+deb12u1\n")
            cfg = env.root / "etc/default/quasselcore"
            cfg.write_text('LISTEN="0.0.0.0"\nPORT="4242"\n')

            res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.99-1"})
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual(env.dpkg_state()["quassel-core"]["version"], "1:0.14.0-1+deb12u1")
            self.assertEqual(receipt.read_text().strip(), "1:0.14.0-1+deb12u1")
            self.assertFalse(
                any(c[:2] == ["systemctl", "restart"] for c in env.commands()),
                "service must not be activated when exact target is unavailable",
            )

    def test_post_install_version_mismatch_and_non_installed_status_reject_and_rollback_before_activation(self):
        for case_name, override in (
            ("wrong-version", {"status": "installed", "version": "1:0.14.0-2+deb12u1"}),
            ("half-installed", {"status": "half-installed", "version": "1:0.14.0-1+deb12u1"}),
            ("config-files", {"status": "config-files", "version": "1:0.14.0-1+deb12u1"}),
        ):
            with self.subTest(case=case_name), SyntheticAptEnvironment(
                repo_versions={"quassel-core": ["1:0.13.1-1", "1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]},
                installed={"quassel-core": "1:0.13.1-1"},
                apt_behavior={"install_override": {"quassel-core": override}},
            ) as env:
                receipt = env.root / "var/lib/quassel/.af-version"
                receipt.write_text("1:0.13.1-1\n")

                res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1"})
                self.assertNotEqual(res.returncode, 0, f"{case_name} must fail")
                self.assertFalse(
                    any(c[:2] == ["systemctl", "restart"] for c in env.commands()),
                    f"{case_name}: service activation must not run after dpkg verification failure",
                )
                self.assertEqual(
                    env.dpkg_state()["quassel-core"],
                    {"status": "installed", "version": "1:0.13.1-1"},
                    f"{case_name}: rollback must restore prior dpkg package version",
                )
                self.assertEqual(receipt.read_text().strip(), "1:0.13.1-1")

    def test_multi_package_lockstep_rollback_batches_downgrade_specs(self):
        repo = {
            "jellyfin": ["10.10.2+deb12", "10.10.3+deb12"],
            "jellyfin-server": ["10.10.2+deb12", "10.10.3+deb12"],
            "jellyfin-web": ["10.10.2+deb12", "10.10.3+deb12"],
        }
        installed = {
            "jellyfin": "10.10.2+deb12",
            "jellyfin-server": "10.10.2+deb12",
            "jellyfin-web": "10.10.2+deb12",
        }
        behavior = {
            "fail_service": True,
            "lockstep_companions": {"jellyfin": ["jellyfin-server", "jellyfin-web"]},
        }
        with SyntheticAptEnvironment(repo, installed=installed, apt_behavior=behavior) as env:
            receipt = env.root / "var/lib/jellyfin/.af-version"
            receipt.write_text("10.10.2+deb12\n")
            res = env.run_install_script("jellyfin", extra_env={"AF_TARGET_VERSION": "10.10.3+deb12"})
            self.assertNotEqual(res.returncode, 0)
            batch_rollbacks = [
                c
                for c in env.commands()
                if c[:2] == ["apt-get", "install"]
                and "--allow-downgrades" in c
                and "jellyfin=10.10.2+deb12" in c
                and "jellyfin-server=10.10.2+deb12" in c
                and "jellyfin-web=10.10.2+deb12" in c
            ]
            self.assertTrue(batch_rollbacks, f"expected batched multi-package rollback in {env.commands()}")
            for pkg in ("jellyfin", "jellyfin-server", "jellyfin-web"):
                self.assertEqual(env.dpkg_state()[pkg]["version"], "10.10.2+deb12")
            self.assertEqual(receipt.read_text().strip(), "10.10.2+deb12")

    def test_downgrade_policy_blocks_without_flag_and_allows_with_flag(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]}
        installed = {"quassel-core": "1:0.14.0-2+deb12u1"}

        with SyntheticAptEnvironment(repo, installed=installed) as env:
            # Even with a legacy stripped receipt (0.14.0), dpkg is at 1:0.14.0-2+deb12u1 -> downgrade must be refused
            (env.root / "var/lib/quassel/.af-version").write_text("0.14.0\n")
            res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1"})
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual([c for c in env.commands() if c[:2] == ["apt-get", "install"]], [])
            self.assertEqual(env.dpkg_state()["quassel-core"]["version"], "1:0.14.0-2+deb12u1")

        with SyntheticAptEnvironment(repo, installed=installed) as env:
            (env.root / "var/lib/quassel/.af-version").write_text("1:0.14.0-2+deb12u1\n")
            res = env.run_install_script(
                "quassel",
                extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1", "AF_ALLOW_DOWNGRADE": "1"},
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            self.assertIn("--allow-downgrades", install_cmd)
            self.assertIn("quassel-core=1:0.14.0-1+deb12u1", install_cmd)
            self.assertEqual(env.dpkg_state()["quassel-core"]["version"], "1:0.14.0-1+deb12u1")
            self.assertEqual(
                (env.root / "var/lib/quassel/.af-version").read_text().strip(),
                "1:0.14.0-1+deb12u1",
            )

    def test_already_shipped_stripped_receipt_upgrades_cleanly_to_full_debian_version(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]}
        installed = {"quassel-core": "1:0.14.0-1+deb12u1"}
        with SyntheticAptEnvironment(repo, installed=installed) as env:
            (env.root / "var/lib/quassel/.af-version").write_text("0.14.0\n")
            res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-2+deb12u1"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(
                (env.root / "var/lib/quassel/.af-version").read_text().strip(),
                "1:0.14.0-2+deb12u1",
            )

    def test_netdata_exact_target_blocks_bootstrap_fallback_while_unpinned_retains_it(self):
        valid_sha = "a" * 64
        marker_file_name = "kickstart-called"

        # 1. Exact target when APT fails: MUST NOT call fetch_and_run / kickstart.sh
        with SyntheticAptEnvironment(
            repo_versions={"netdata": ["1.45.3-1"]},
            apt_behavior={"fail_install_for": ["netdata"]},
        ) as env:
            marker = env.root / marker_file_name
            prelude = f"""
fetch_and_run() {{ touch "{marker}"; return 0; }}
"""
            res = env.run_install_script(
                "netdata",
                extra_env={"AF_TARGET_VERSION": "1.45.3-1", "NETDATA_KICKSTART_SHA256": valid_sha},
                prelude=prelude,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(marker.exists(), "exact Netdata target must never invoke kickstart bootstrap")

        # 2. Unpinned when APT fails + valid NETDATA_KICKSTART_SHA256: retains existing bootstrap fallback
        with SyntheticAptEnvironment(
            repo_versions={"netdata": ["1.45.3-1"]},
            apt_behavior={"fail_install_for": ["netdata"]},
        ) as env:
            marker = env.root / marker_file_name
            netdata_bin = env.write_executable(
                env.root / "usr/sbin/netdata",
                "#!/bin/bash\necho 'netdata v1.47.1'\n",
            )
            prelude = f"""
fetch_and_run() {{ touch "{marker}"; return 0; }}
"""
            res = env.run_install_script(
                "netdata",
                extra_env={"NETDATA_KICKSTART_SHA256": valid_sha},
                prelude=prelude,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue(marker.exists(), "unpinned Netdata must retain bootstrap fallback")
            self.assertEqual((env.root / "etc/netdata/.af-version").read_text().strip(), "1.47.1")
            self.assertTrue(netdata_bin.exists())

    def test_unpinned_install_and_local_deb_workflows_preserved(self):
        repo = {
            "quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"],
            "curl": ["7.88.1-10"],
            "ca-certificates": ["20230311"],
        }
        # 1. Unpinned APT install selects candidate without `=` pin and writes full Debian receipt
        with SyntheticAptEnvironment(repo) as env:
            res = env.run_install_script("quassel")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            self.assertIn("quassel-core", install_cmd)
            self.assertFalse(any(a.startswith("quassel-core=") for a in install_cmd))
            self.assertEqual(
                (env.root / "var/lib/quassel/.af-version").read_text().strip(),
                "1:0.14.0-2+deb12u1",
            )

        # 2. --local-deb transaction (emby/kasmvnc) accepts non-Debian GitHub target tokens without pinning apt-get
        with SyntheticAptEnvironment(repo) as env:
            fake_deb = env.root / "tmp/emby.deb"
            fake_deb.write_text("placeholder")
            res = env.run_bash(
                f"""
                PACKAGE_NAME="emby"
                begin_state_transaction "emby-server" 8096 "/health" "{env.root}/opt/emby-server"
                prepare_apt_package_transaction --local-deb "{env.root}/opt/emby-server/.af-version" emby-server
                apt-get install -y -qq curl ca-certificates
                apt-get install --no-remove -y "{fake_deb}"
                systemctl start emby-server
                queue_app_version "{env.root}/opt/emby-server/.af-version" "4.8.10.0"
                commit_app_versions
                INSTALL_COMMITTED=true
                """,
                extra_env={"AF_TARGET_VERSION": "v4.8.10.0"},
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            apt_installs = [c for c in env.commands() if c[:2] == ["apt-get", "install"]]
            self.assertEqual(len(apt_installs), 2)
            self.assertFalse(any("=" in arg for cmd in apt_installs for arg in cmd))
            self.assertEqual(
                (env.root / "opt/emby-server/.af-version").read_text().strip(),
                "4.8.10.0",
            )


if __name__ == "__main__":
    unittest.main()
