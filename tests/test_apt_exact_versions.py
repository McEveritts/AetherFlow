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
            "etc/deluge",
            "etc/jellyfin",
            "etc/netdata",
            "etc/novnc",
            "etc/systemd/system",
            "etc/transmission-daemon",
            "etc/wireguard",
            "opt/emby-server",
            "var/lib/aetherflow/apt-reinstall-required",
            "var/lib/deluge",
            "var/lib/grafana",
            "var/lib/jellyfin",
            "var/lib/kasmvnc",
            "var/lib/quassel",
            "var/lib/transmission",
            "var/lib/transmission-daemon",
            "var/log/aetherflow",
            "var/log/deluge",
            "var/log/quassel",
            "usr/bin",
            "usr/sbin",
            "usr/lib/jellyfin",
            "usr/lib/python3/dist-packages/deluge",
            "usr/lib/quassel",
            "usr/lib/transmission",
            "usr/share/deluge",
            "usr/share/jellyfin",
            "usr/share/quassel",
            "usr/share/transmission/web",
            "tmp/tx-root",
            "tmp/scratch",
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
            "/var/lib/deluge": f"{root_str}/var/lib/deluge",
            "/var/log/deluge": f"{root_str}/var/log/deluge",
            "/var/lib/quassel": f"{root_str}/var/lib/quassel",
            "/var/log/quassel": f"{root_str}/var/log/quassel",
            "/var/lib/jellyfin": f"{root_str}/var/lib/jellyfin",
            "/var/lib/grafana": f"{root_str}/var/lib/grafana",
            "/var/lib/kasmvnc": f"{root_str}/var/lib/kasmvnc",
            "/var/lib/transmission-daemon": f"{root_str}/var/lib/transmission-daemon",
            "/var/lib/transmission": f"{root_str}/var/lib/transmission",
            "/var/lib/netdata": f"{root_str}/var/lib/netdata",
            "/etc/deluge": f"{root_str}/etc/deluge",
            "/etc/netdata": f"{root_str}/etc/netdata",
            "/etc/jellyfin": f"{root_str}/etc/jellyfin",
            "/etc/default/quasselcore": f"{root_str}/etc/default/quasselcore",
            "/etc/transmission-daemon": f"{root_str}/etc/transmission-daemon",
            "/etc/wireguard": f"{root_str}/etc/wireguard",
            "/etc/novnc": f"{root_str}/etc/novnc",
            "/etc/apt/sources.list.d": f"{root_str}/etc/apt/sources.list.d",
            "/etc/apt/keyrings": f"{root_str}/etc/apt/keyrings",
            "/etc/aetherflow": f"{root_str}/etc/aetherflow",
            "/etc/systemd/system": f"{root_str}/etc/systemd/system",
            "/opt/emby-server": f"{root_str}/opt/emby-server",
            "/opt/netdata": f"{root_str}/opt/netdata",
            "/usr/bin/deluged": f"{root_str}/usr/bin/deluged",
            "/usr/bin/deluge-web": f"{root_str}/usr/bin/deluge-web",
            "/usr/bin/deluge-console": f"{root_str}/usr/bin/deluge-console",
            "/usr/lib/python3/dist-packages/deluge": f"{root_str}/usr/lib/python3/dist-packages/deluge",
            "/usr/share/deluge": f"{root_str}/usr/share/deluge",
            "/usr/bin/quasselcore": f"{root_str}/usr/bin/quasselcore",
            "/usr/lib/quassel": f"{root_str}/usr/lib/quassel",
            "/usr/share/quassel": f"{root_str}/usr/share/quassel",
            "/usr/bin/jellyfin": f"{root_str}/usr/bin/jellyfin",
            "/usr/lib/jellyfin": f"{root_str}/usr/lib/jellyfin",
            "/usr/share/jellyfin": f"{root_str}/usr/share/jellyfin",
            "/usr/bin/transmission-daemon": f"{root_str}/usr/bin/transmission-daemon",
            "/usr/bin/transmission-remote": f"{root_str}/usr/bin/transmission-remote",
            "/usr/share/transmission/web": f"{root_str}/usr/share/transmission/web",
            "/usr/share/transmission": f"{root_str}/usr/share/transmission",
            "/usr/lib/transmission": f"{root_str}/usr/lib/transmission",
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
    fail_remove = set(behavior.get("fail_remove_for", []))
    remove_override = behavior.get("remove_override", {})
    remove_pkgs = [spec.split("=", 1)[0] for spec in specs]
    if len(remove_pkgs) > 1 and behavior.get("batch_remove_override"):
        for pkg, entry in behavior["batch_remove_override"].items():
            if pkg in remove_pkgs:
                if entry is None:
                    state.pop(pkg, None)
                else:
                    state[pkg] = dict(entry)
        state_path.write_text(json.dumps(state))
        if behavior.get("fail_batch_remove"):
            sys.stderr.write("E: Simulated batch APT remove failure\n")
            sys.exit(100)
        sys.exit(0)
    for pkg in remove_pkgs:
        if pkg in fail_remove:
            sys.stderr.write(f"E: Simulated APT remove failure for {pkg}\n")
            sys.exit(100)
    for pkg in remove_pkgs:
        if pkg in remove_override:
            override = remove_override[pkg]
            if override is None:
                state.pop(pkg, None)
            else:
                state[pkg] = dict(override)
        else:
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
    pinned_pkgs = set()
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
            pinned_pkgs.add(pkg)
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

    # Enforce strict Debian exact-version Depends (`dep (= ver)`):
    # - Fails if dep resolves to a different version than pkg
    # - Fails if dep is not explicitly pinned and its Candidate != ver (real APT non-candidate boundary)
    exact_depends = behavior.get("exact_depends", {})
    for pkg, entry in list(pending.items()):
        ver = entry["version"]
        for dep in exact_depends.get(pkg, []):
            dep_versions = repo.get(dep, [])
            dep_candidate = dep_versions[-1] if dep_versions else None
            if dep in pending:
                if pending[dep]["version"] != ver:
                    sys.stderr.write(
                        f"E: Unmet dependencies: {pkg} : Depends: {dep} (= {ver}) "
                        f"but {pending[dep]['version']} is to be installed\n"
                    )
                    sys.exit(100)
            else:
                if dep_candidate != ver and dep not in pinned_pkgs:
                    sys.stderr.write(
                        f"E: Unmet dependencies: {pkg} : Depends: {dep} (= {ver}) "
                        f"but {dep_candidate} is to be installed\n"
                    )
                    sys.exit(100)
                if ver not in dep_versions:
                    sys.stderr.write(f"E: Version '{ver}' for '{dep}' was not found\n")
                    sys.exit(100)
                override = behavior.get("install_override", {}).get(dep)
                if override and not allow_downgrades:
                    pending[dep] = dict(override)
                else:
                    pending[dep] = {"status": "installed", "version": ver}

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
            self.bin_dir / "git",
            "#!/bin/bash\nexit 1\n",
        )

        self.write_executable(
            self.bin_dir / "curl",
            r"""#!/usr/bin/env python3
import sys
args = sys.argv[1:]
joined = " ".join(args)
if "127.0.0.1" in joined or "localhost" in joined:
    if "-w" in args:
        sys.stdout.write("200")
    sys.exit(0)
if "api.github.com/repos/ronggang/transmission-web-control" in joined:
    sys.stdout.write('{"tag_name":"v1.6.1-update1"}\n')
    sys.exit(0)
sys.exit(1)
""",
        )

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
            "AF_JOB_SCRATCH_ROOT": str(self.root / "tmp/scratch"),
            "MASTER_USER": "admin",
            "MASTER_PASS": "test-pass-1234",
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
            r"^\s*prepare_apt_package_transaction\s+((?:--(?:local-deb|lockstep)\s+)*)(\S+)\s+(.+?)\s*$",
            re.MULTILINE,
        )
        resolve_re = re.compile(r"resolve_installed_apt_package_version\s+([a-z0-9][a-z0-9+.-]*)")
        expected_lockstep = {
            "deluge": ["deluged", "deluge-web", "deluge-console", "deluge-common"],
            "transmission": ["transmission-daemon", "transmission-common", "transmission-cli"],
        }

        for name, cfg in sorted(apt_entries.items()):
            expected_pkg = cfg["update_package"]
            script_path = INSTALL_DIR / f"installpackage-{name}"
            self.assertTrue(script_path.is_file(), f"Missing install script for {name}")
            content = script_path.read_text()

            prep_match = prep_re.search(content)
            self.assertIsNotNone(prep_match, f"{name}: missing prepare_apt_package_transaction")
            flags = prep_match.group(1).split()
            self.assertNotIn(
                "--local-deb",
                flags,
                f"{name}: update_source=apt installer must not pass --local-deb",
            )
            pkgs = prep_match.group(3).split()
            self.assertEqual(
                pkgs[0],
                expected_pkg,
                f"{name}: primary APT package '{pkgs[0]}' does not match package_automation.json update_package '{expected_pkg}'",
            )
            if name in expected_lockstep:
                self.assertIn("--lockstep", flags, f"{name}: lockstep APT installer must pass --lockstep")
                self.assertEqual(pkgs, expected_lockstep[name], f"{name}: lockstep package set mismatch")
            else:
                self.assertNotIn("--lockstep", flags, f"{name}: non-lockstep APT installer must not pass --lockstep")

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
            self.assertIn(
                "--local-deb",
                prep_match.group(1).split(),
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

    def test_fresh_install_transitional_dpkg_states_invoke_individual_removal_and_clean_up(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]}
        cases = (
            ("half-installed->removed", "half-installed", None),
            ("unpacked->removed", "unpacked", None),
            ("half-configured->config-files", "half-configured", {"status": "config-files", "version": "1:0.14.0-1+deb12u1"}),
            ("triggers-awaited->removed", "triggers-awaited", None),
            ("triggers-pending->config-files", "triggers-pending", {"status": "config-files", "version": "1:0.14.0-1+deb12u1"}),
        )
        for label, bad_status, post_remove_entry in cases:
            behavior = {
                "install_override": {"quassel-core": {"status": bad_status, "version": "1:0.14.0-1+deb12u1"}},
            }
            if post_remove_entry is not None:
                behavior["remove_override"] = {"quassel-core": post_remove_entry}
            with self.subTest(case=label), SyntheticAptEnvironment(repo, apt_behavior=behavior) as env:
                res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1"})
                self.assertNotEqual(res.returncode, 0, f"{label}: install must fail on {bad_status}")
                self.assertIn(
                    ["apt-get", "remove", "-y", "--no-auto-remove", "quassel-core"],
                    env.commands(),
                    f"{label}: rollback must run individual apt-get remove for fresh {bad_status} package",
                )
                if post_remove_entry is None:
                    self.assertNotIn("quassel-core", env.dpkg_state())
                else:
                    self.assertEqual(env.dpkg_state()["quassel-core"]["status"], "config-files")
                marker = env.root / "var/lib/aetherflow/apt-reinstall-required/quassel-core"
                self.assertFalse(marker.exists(), f"{label}: clean removal must not leave reinstall marker")
                self.assertNotIn("incomplete_rollback", res.stdout + res.stderr)
                self.assertEqual(list((env.root / "tmp/tx-root").glob("af-state-*")), [])

    def test_fresh_install_transitional_removal_failure_or_residual_state_marks_incomplete_rollback(self):
        repo = {"quassel-core": ["1:0.14.0-1+deb12u1", "1:0.14.0-2+deb12u1"]}
        failure_cases = (
            (
                "remove-command-fails",
                {
                    "install_override": {"quassel-core": {"status": "half-installed", "version": "1:0.14.0-1+deb12u1"}},
                    "fail_remove_for": ["quassel-core"],
                },
                "half-installed",
            ),
            (
                "remove-exits-0-but-leaves-unpacked",
                {
                    "install_override": {"quassel-core": {"status": "unpacked", "version": "1:0.14.0-1+deb12u1"}},
                    "remove_override": {"quassel-core": {"status": "unpacked", "version": "1:0.14.0-1+deb12u1"}},
                },
                "unpacked",
            ),
            (
                "remove-exits-0-but-leaves-half-installed",
                {
                    "install_override": {"quassel-core": {"status": "installed", "version": "1:0.14.0-2+deb12u1"}},
                    "remove_override": {"quassel-core": {"status": "half-installed", "version": "1:0.14.0-2+deb12u1"}},
                },
                "half-installed",
            ),
        )
        for label, behavior, residual_status in failure_cases:
            with self.subTest(case=label), SyntheticAptEnvironment(repo, apt_behavior=behavior) as env:
                res = env.run_install_script("quassel", extra_env={"AF_TARGET_VERSION": "1:0.14.0-1+deb12u1"})
                self.assertNotEqual(res.returncode, 0)
                self.assertIn(
                    ["apt-get", "remove", "-y", "--no-auto-remove", "quassel-core"],
                    env.commands(),
                    f"{label}: rollback must attempt individual apt-get remove",
                )
                self.assertEqual(env.dpkg_state()["quassel-core"]["status"], residual_status)
                marker = env.root / "var/lib/aetherflow/apt-reinstall-required/quassel-core"
                self.assertTrue(marker.is_file(), f"{label}: residual {residual_status} must write reinstall marker")
                self.assertEqual(marker.read_text().strip(), "<none>")
                self.assertIn("incomplete_rollback", res.stdout + res.stderr)
                self.assertTrue(
                    list((env.root / "tmp/tx-root").glob("af-state-*")),
                    f"{label}: incomplete rollback must preserve recovery backup",
                )

        # Multi-package fresh-install batch removal partially leaves one package unpacked -> individual fallback runs
        deluge_repo = {
            "deluged": ["2.1.1-1", "2.2.0-1"],
            "deluge-web": ["2.1.1-1", "2.2.0-1"],
            "deluge-console": ["2.1.1-1", "2.2.0-1"],
            "deluge-common": ["2.1.1-1", "2.2.0-1"],
            "python3-libtorrent": ["2.0.11-1"],
        }
        deluge_behavior = {
            "exact_depends": {
                "deluged": ["deluge-common"],
                "deluge-web": ["deluge-common"],
                "deluge-console": ["deluge-common"],
            },
            "install_override": {
                "deluged": {"status": "half-installed", "version": "2.1.1-1"},
                "deluge-common": {"status": "unpacked", "version": "2.1.1-1"},
            },
            "fail_batch_remove": True,
            "batch_remove_override": {
                "deluged": None,
                "deluge-web": None,
                "deluge-console": None,
                "deluge-common": {"status": "unpacked", "version": "2.1.1-1"},
            },
        }
        with SyntheticAptEnvironment(deluge_repo, apt_behavior=deluge_behavior) as env:
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.1.1-1"})
            self.assertNotEqual(res.returncode, 0)
            remove_cmds = [c for c in env.commands() if c[:2] == ["apt-get", "remove"]]
            self.assertTrue(any(len(c) > 5 for c in remove_cmds), f"expected batch remove in {remove_cmds}")
            self.assertIn(
                ["apt-get", "remove", "-y", "--no-auto-remove", "deluge-common"],
                remove_cmds,
                f"expected individual fallback remove for unpacked deluge-common in {remove_cmds}",
            )
            self.assertNotIn("deluge-common", env.dpkg_state())
            self.assertNotIn("incomplete_rollback", res.stdout + res.stderr)

    def test_deluge_lockstep_non_candidate_target_pins_companions_preserves_auxiliary_and_snapshots_common(self):
        repo = {
            "deluged": ["2.1.1-1", "2.2.0-1"],
            "deluge-web": ["2.1.1-1", "2.2.0-1"],
            "deluge-console": ["2.1.1-1", "2.2.0-1"],
            "deluge-common": ["2.1.1-1", "2.2.0-1"],
            "python3-libtorrent": ["2.0.10-1", "2.0.11-1"],
        }
        strict_deps = {
            "exact_depends": {
                "deluged": ["deluge-common"],
                "deluge-web": ["deluge-common"],
                "deluge-console": ["deluge-common"],
            }
        }

        # 1. Fresh install with exact non-candidate 2.1.1-1 pins all 4 lockstep pkgs and leaves python3-libtorrent unpinned
        with SyntheticAptEnvironment(repo, apt_behavior=strict_deps) as env:
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.1.1-1"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            for pkg in ("deluged", "deluge-web", "deluge-console", "deluge-common"):
                self.assertIn(f"{pkg}=2.1.1-1", install_cmd, f"missing lockstep pin for {pkg} in {install_cmd}")
                self.assertEqual(env.dpkg_state()[pkg], {"status": "installed", "version": "2.1.1-1"})
            self.assertIn("python3-libtorrent", install_cmd)
            self.assertFalse(any(a.startswith("python3-libtorrent=") for a in install_cmd))
            self.assertEqual(env.dpkg_state()["python3-libtorrent"]["version"], "2.0.11-1")
            self.assertEqual((env.root / "var/lib/deluge/.af-version").read_text().strip(), "2.1.1-1")

        # 2. Failed upgrade rolls back all 4 packages (including transitive deluge-common) atomically in one batch
        installed = {
            "deluged": "2.1.1-1",
            "deluge-web": "2.1.1-1",
            "deluge-console": "2.1.1-1",
            "deluge-common": "2.1.1-1",
            "python3-libtorrent": "2.0.11-1",
        }
        with SyntheticAptEnvironment(
            repo,
            installed=installed,
            apt_behavior={**strict_deps, "fail_service": True},
        ) as env:
            (env.root / "var/lib/deluge/.af-version").write_text("2.1.1-1\n")
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.2.0-1"})
            self.assertNotEqual(res.returncode, 0)
            batch_rollbacks = [
                c
                for c in env.commands()
                if c[:2] == ["apt-get", "install"]
                and "--allow-downgrades" in c
                and all(f"{pkg}=2.1.1-1" in c for pkg in ("deluged", "deluge-web", "deluge-console", "deluge-common"))
            ]
            self.assertTrue(batch_rollbacks, f"expected batched 4-package deluge rollback in {env.commands()}")
            for pkg in ("deluged", "deluge-web", "deluge-console", "deluge-common"):
                self.assertEqual(env.dpkg_state()[pkg], {"status": "installed", "version": "2.1.1-1"})
            self.assertEqual((env.root / "var/lib/deluge/.af-version").read_text().strip(), "2.1.1-1")

        # 3. Pre-installed newer transitive deluge-common blocks downgrade without AF_ALLOW_DOWNGRADE=1
        with SyntheticAptEnvironment(
            repo,
            installed={"deluge-common": "2.2.0-1"},
            apt_behavior=strict_deps,
        ) as env:
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.1.1-1"})
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual([c for c in env.commands() if c[:2] == ["apt-get", "install"]], [])
            self.assertEqual(env.dpkg_state()["deluge-common"]["version"], "2.2.0-1")

        # 4. Reinstall marker on transitive deluge-common keeps it pinned once with --reinstall
        with SyntheticAptEnvironment(repo, apt_behavior=strict_deps) as env:
            marker = env.root / "var/lib/aetherflow/apt-reinstall-required/deluge-common"
            marker.write_text("<none>\n")
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.1.1-1"})
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            self.assertIn("--reinstall", install_cmd)
            self.assertEqual(install_cmd.count("deluge-common=2.1.1-1"), 1, install_cmd)
            self.assertNotIn("deluge-common", install_cmd)
            self.assertFalse(marker.exists())

        # 5. Post-install verification catches half-installed transitive deluge-common and cleans all 4 packages
        with SyntheticAptEnvironment(
            repo,
            apt_behavior={
                **strict_deps,
                "install_override": {"deluge-common": {"status": "half-installed", "version": "2.1.1-1"}},
            },
        ) as env:
            res = env.run_install_script("deluge", extra_env={"AF_TARGET_VERSION": "2.1.1-1"})
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in env.commands()))
            for pkg in ("deluged", "deluge-web", "deluge-console", "deluge-common"):
                self.assertNotIn(pkg, env.dpkg_state(), f"{pkg} must be removed on fresh rollback")
            self.assertNotIn("incomplete_rollback", res.stdout + res.stderr)

    def test_transmission_lockstep_non_candidate_target_pins_companions_preserves_auxiliary_and_rolls_back(self):
        repo = {
            "transmission-daemon": ["4.1.0~beta2+dfsg-3+deb13u2", "4.1.4+dfsg-1~bpo13+1"],
            "transmission-common": ["4.1.0~beta2+dfsg-3+deb13u2", "4.1.4+dfsg-1~bpo13+1"],
            "transmission-cli": ["4.1.0~beta2+dfsg-3+deb13u2", "4.1.4+dfsg-1~bpo13+1"],
            "curl": ["8.14.1-2+deb13u7"],
            "git": ["1:2.47.3-0+deb13u1"],
            "ca-certificates": ["20250419+deb13u1"],
        }
        strict_deps = {
            "exact_depends": {
                "transmission-daemon": ["transmission-common"],
                "transmission-cli": ["transmission-common"],
            }
        }

        # 1. Fresh install with exact non-candidate pins all 3 lockstep packages and keeps curl/git/ca-certificates unpinned
        with SyntheticAptEnvironment(repo, apt_behavior=strict_deps) as env:
            res = env.run_install_script(
                "transmission",
                extra_env={"AF_TARGET_VERSION": "4.1.0~beta2+dfsg-3+deb13u2"},
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            install_cmd = [c for c in env.commands() if c[:2] == ["apt-get", "install"]][-1]
            for pkg in ("transmission-daemon", "transmission-common", "transmission-cli"):
                self.assertIn(f"{pkg}=4.1.0~beta2+dfsg-3+deb13u2", install_cmd)
                self.assertEqual(
                    env.dpkg_state()[pkg],
                    {"status": "installed", "version": "4.1.0~beta2+dfsg-3+deb13u2"},
                )
            for aux in ("curl", "git", "ca-certificates"):
                self.assertIn(aux, install_cmd)
                self.assertFalse(any(a.startswith(f"{aux}=") for a in install_cmd))
            self.assertEqual(
                (env.root / "var/lib/transmission-daemon/.af-version").read_text().strip(),
                "4.1.0~beta2+dfsg-3+deb13u2",
            )

        # 2. Failed upgrade rolls back all 3 lockstep packages atomically
        installed = {
            "transmission-daemon": "4.1.0~beta2+dfsg-3+deb13u2",
            "transmission-common": "4.1.0~beta2+dfsg-3+deb13u2",
            "transmission-cli": "4.1.0~beta2+dfsg-3+deb13u2",
        }
        with SyntheticAptEnvironment(
            repo,
            installed=installed,
            apt_behavior={**strict_deps, "fail_service": True},
        ) as env:
            (env.root / "var/lib/transmission-daemon/.af-version").write_text("4.1.0~beta2+dfsg-3+deb13u2\n")
            res = env.run_install_script(
                "transmission",
                extra_env={"AF_TARGET_VERSION": "4.1.4+dfsg-1~bpo13+1"},
            )
            self.assertNotEqual(res.returncode, 0)
            batch_rollbacks = [
                c
                for c in env.commands()
                if c[:2] == ["apt-get", "install"]
                and "--allow-downgrades" in c
                and all(
                    f"{pkg}=4.1.0~beta2+dfsg-3+deb13u2" in c
                    for pkg in ("transmission-daemon", "transmission-common", "transmission-cli")
                )
            ]
            self.assertTrue(batch_rollbacks, f"expected batched 3-package transmission rollback in {env.commands()}")
            for pkg in ("transmission-daemon", "transmission-common", "transmission-cli"):
                self.assertEqual(
                    env.dpkg_state()[pkg],
                    {"status": "installed", "version": "4.1.0~beta2+dfsg-3+deb13u2"},
                )
            self.assertEqual(
                (env.root / "var/lib/transmission-daemon/.af-version").read_text().strip(),
                "4.1.0~beta2+dfsg-3+deb13u2",
            )

    def test_readonly_apt_simulate_verifies_real_debian_lockstep_and_jellyfin_solver_constraints(self):
        if not (Path("/usr/bin/apt-get").exists() and Path("/usr/bin/apt-cache").exists()):
            self.skipTest("Debian apt-get/apt-cache not available on host")

        def parse_policy(pkg_name):
            out = subprocess.run(
                ["/usr/bin/apt-cache", "policy", pkg_name],
                text=True,
                capture_output=True,
                timeout=15,
            )
            if out.returncode != 0:
                return None, []
            candidate = None
            versions = []
            in_table = False
            for line in out.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Candidate:"):
                    candidate = stripped.split(":", 1)[1].strip()
                elif stripped.startswith("Version table:"):
                    in_table = True
                elif in_table:
                    m = re.match(r"^(?:\*\*\*\s+)?(\S+)\s+\d+$", stripped)
                    if m:
                        versions.append(m.group(1))
            return candidate, versions

        # Read-only verification of real Transmission lockstep solver constraints when a non-candidate exists
        tx_cand, tx_vers = parse_policy("transmission-daemon")
        non_cands = [v for v in tx_vers if v != tx_cand]
        if tx_cand and non_cands:
            target = non_cands[0]
            # 1. Pinning only transmission-daemon without lockstep companions MUST fail real apt-get -s
            broken = subprocess.run(
                [
                    "/usr/bin/apt-get", "-s", "-q=2",
                    "-o", "Dir::State::status=/dev/null",
                    "install",
                    "transmission-cli", "transmission-common", f"transmission-daemon={target}",
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertNotEqual(
                broken.returncode,
                0,
                f"expected unpinned transmission companions to fail real apt-get -s for {target}",
            )

            # 2. Pinning all 3 lockstep packages (as installpackage-transmission --lockstep produces) MUST succeed
            fixed = subprocess.run(
                [
                    "/usr/bin/apt-get", "-s", "-q=2",
                    "-o", "Dir::State::status=/dev/null",
                    "install",
                    f"transmission-cli={target}",
                    f"transmission-common={target}",
                    f"transmission-daemon={target}",
                    "curl", "git", "ca-certificates",
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
            self.assertIn(f"Inst transmission-common ({target} ", fixed.stdout)
            self.assertIn(f"Inst transmission-daemon ({target} ", fixed.stdout)
            self.assertIn(f"Inst transmission-cli ({target} ", fixed.stdout)

        # Read-only verification that Jellyfin metapackage resolves cleanly on both normal & marker reinstall
        jf_cand, jf_vers = parse_policy("jellyfin")
        jf_non_cands = [v for v in jf_vers if v != jf_cand]
        if jf_cand and jf_non_cands:
            jf_target = jf_non_cands[0]
            jf_normal = subprocess.run(
                [
                    "/usr/bin/apt-get", "-s", "-q=2",
                    "-o", "Dir::State::status=/dev/null",
                    "install",
                    f"jellyfin={jf_target}",
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(jf_normal.returncode, 0, jf_normal.stdout + jf_normal.stderr)
            self.assertIn(f"Inst jellyfin ({jf_target} ", jf_normal.stdout)

            jf_marker = subprocess.run(
                [
                    "/usr/bin/apt-get", "-s", "-q=2",
                    "-o", "Dir::State::status=/dev/null",
                    "install", "--reinstall",
                    f"jellyfin={jf_target}", "jellyfin-server",
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(jf_marker.returncode, 0, jf_marker.stdout + jf_marker.stderr)
            self.assertIn(f"Inst jellyfin ({jf_target} ", jf_marker.stdout)


if __name__ == "__main__":
    unittest.main()
