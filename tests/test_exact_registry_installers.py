#!/usr/bin/env python3
"""Focused local sandbox regressions for exact-version npm and pip registry installers."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, common_functions, installer_common_functions

REAL_NODE = shutil.which("node")
REAL_NPM = shutil.which("npm")

REBASE_PREFIXES = (
    "/usr/local",
    "/usr/bin/flood",
    "/opt",
    "/var",
    "/etc",
    "/install",
    "/tmp",
)
REBASE_PATTERN = re.compile(
    r"(?<![\w/.-])("
    + "|".join(re.escape(prefix) for prefix in REBASE_PREFIXES)
    + r")(?=/|[^\w.-]|$)"
)


def rebase_installer(source: str, root: Path) -> str:
    return REBASE_PATTERN.sub(lambda match: str(root) + match.group(0), source)


def make_npm_tarball(name: str, version: str, bin_name: str, reported_version: str | None = None) -> bytes:
    cli_version = reported_version or version
    pkg = {
        "name": name,
        "version": version,
        "bin": {bin_name: "cli.js"},
    }
    cli = (
        "#!/usr/bin/env node\n"
        f"console.log({json.dumps(cli_version)});\n"
    )
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, text, mode in (
            ("package/package.json", json.dumps(pkg), 0o644),
            ("package/cli.js", cli, 0o755),
        ):
            payload = text.encode("utf-8")
            info = tarfile.TarInfo(rel)
            info.size = len(payload)
            info.mode = mode
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class _LocalNpmRegistry:
    """Minimal offline loopback npm registry serving exact tarballs and packuments."""

    def __init__(self, packages: dict[str, dict[str, tuple[bytes, str]]]):
        # packages[pkg_name][advertised_ver] = (tarball_bytes, dist_tag_or_empty)
        self.packages = packages
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                host = f"http://127.0.0.1:{self.server.server_port}"
                path = self.path.split("?", 1)[0]
                if path.startswith("/tarballs/"):
                    key = path[len("/tarballs/"):]
                    for pkg_name, versions in registry.packages.items():
                        for ver, (blob, _, _) in versions.items():
                            slug = f"{pkg_name.replace('/', '_')}-{ver}.tgz"
                            if key == slug:
                                self.send_response(200)
                                self.send_header("Content-Type", "application/octet-stream")
                                self.send_header("Content-Length", str(len(blob)))
                                self.end_headers()
                                self.wfile.write(blob)
                                return
                    self.send_response(404)
                    self.end_headers()
                    return

                decoded = path.lstrip("/").replace("%2f", "/").replace("%2F", "/")
                if decoded in registry.packages:
                    versions = registry.packages[decoded]
                    dist_tags = {}
                    ver_meta = {}
                    for ver, (_, tag, bin_name) in versions.items():
                        slug = f"{decoded.replace('/', '_')}-{ver}.tgz"
                        ver_meta[ver] = {
                            "name": decoded,
                            "version": ver,
                            "bin": {bin_name: "cli.js"},
                            "dist": {"tarball": f"{host}/tarballs/{slug}"},
                        }
                        if tag:
                            dist_tags[tag] = ver
                    body = json.dumps({
                        "name": decoded,
                        "dist-tags": dist_tags,
                        "versions": ver_meta,
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                self.send_response(404)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def __exit__(self, exc_type, exc, tb):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


class SharedRegistryVersionGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-reg-guards-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.helpers = self.root / "helpers.sh"
        self.helpers.write_text(
            common_functions(
                "queue_app_version",
                "commit_app_versions",
                "write_app_version",
            )
        )

    def run_bash(self, body: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        script = f'set -euo pipefail\nsource "{self.helpers}"\nprint_error() {{ printf "%s\\n" "$*" >&2; }}\n{body}\n'
        merged = {**os.environ, **(env or {})}
        return subprocess.run(["bash", "-c", script], env=merged, capture_output=True, text=True, timeout=15)

    def test_normalize_exact_registry_version_accepts_supported_tags_and_rejects_invalid(self):
        npm_valid = {
            "4.7.0": "4.7.0",
            "v4.7.0": "4.7.0",
            "V4.4.3": "4.4.3",
            "release-4.5.2": "4.5.2",
            "Release-v4.5.2": "4.5.2",
            "version-4.7.0": "4.7.0",
            "rel-4.7.0": "4.7.0",
            "ver-v4.7.0": "4.7.0",
            " 4.7.0 ": "4.7.0",
            "4.5.2-rc.1": "4.5.2-rc.1",
            "4.5.2-beta.0+build.1": "4.5.2-beta.0+build.1",
        }
        for raw, expected in npm_valid.items():
            with self.subTest(ecosystem="npm", raw=raw):
                res = self.run_bash(f'af_normalize_exact_registry_version npm {json.dumps(raw)}')
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(res.stdout.strip(), expected)

        npm_invalid = [
            "", "   ", "latest", "next", "canary", "stable", "v", "release-",
            "4.7", "^4.7.0", "~4.7.0", ">=4.7.0", "4.7.x", "4.7.*",
            "4.7.0 || 4.8.0", "4.7.0;id", "../4.7.0", "@jesec/flood@4.7.0",
            "https://evil.test/pkg.tgz", "--registry=https://evil.test",
        ]
        for raw in npm_invalid:
            with self.subTest(ecosystem="npm_invalid", raw=raw):
                res = self.run_bash(f'af_normalize_exact_registry_version npm {json.dumps(raw)}')
                self.assertNotEqual(res.returncode, 0, f"Should reject npm target {raw!r}")

        pypi_valid = {
            "0.2.7": "0.2.7",
            "v0.2.7": "0.2.7",
            "V0.2.7": "0.2.7",
            "release-0.2.7": "0.2.7",
            "Release-v0.2.7": "0.2.7",
            "version-0.2.7": "0.2.7",
            "0.2.7.1": "0.2.7.1",
            "0.3.0rc1": "0.3.0rc1",
            "0.3.0a1": "0.3.0a1",
            "0.3.0b2": "0.3.0b2",
            "0.2.7.post1": "0.2.7.post1",
            "0.2.7.dev0": "0.2.7.dev0",
            "1!0.2.7": "1!0.2.7",
        }
        for raw, expected in pypi_valid.items():
            with self.subTest(ecosystem="pypi", raw=raw):
                res = self.run_bash(f'af_normalize_exact_registry_version pypi {json.dumps(raw)}')
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(res.stdout.strip(), expected)

        pypi_invalid = [
            "", "   ", "latest", "stable", "v", "release-", "0.2.*",
            ">=0.2.7", "==0.2.7", "~=0.2.7", "0.2.7,<=0.3.0",
            "0.2.7;id", "../0.2.7", "https://evil.test/unmanic.whl",
            "--index-url=https://evil.test", "0.2.7[extra]",
        ]
        for raw in pypi_invalid:
            with self.subTest(ecosystem="pypi_invalid", raw=raw):
                res = self.run_bash(f'af_normalize_exact_registry_version pypi {json.dumps(raw)}')
                self.assertNotEqual(res.returncode, 0, f"Should reject pypi target {raw!r}")

    def test_commit_app_versions_guards_missing_receipts_and_normalizes_prefixes(self):
        ver_file = self.root / ".af-version"
        # Missing receipt when AF_TARGET_VERSION is set must fail closed.
        missing = self.run_bash("commit_app_versions", env={"AF_TARGET_VERSION": "4.7.0"})
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("No application version receipt queued", missing.stderr)

        # Bare prefix target must never match a receipt.
        bare = self.run_bash(
            f'queue_app_version "{ver_file}" "v"\ncommit_app_versions',
            env={"AF_TARGET_VERSION": "release-"},
        )
        self.assertNotEqual(bare.returncode, 0)
        self.assertFalse(ver_file.exists())

        # Supported prefix normalization matches cleanly.
        matched = self.run_bash(
            f'queue_app_version "{ver_file}" "4.7.0"\ncommit_app_versions',
            env={"AF_TARGET_VERSION": "Release-v4.7.0"},
        )
        self.assertEqual(matched.returncode, 0, matched.stderr)
        self.assertEqual(ver_file.read_text().strip(), "4.7.0")


@unittest.skipUnless(REAL_NODE and REAL_NPM and shutil.which("bash"), "Requires Bash, Node.js, and npm")
class RealLocalNpmRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-local-npm-reg-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.helpers = self.root / "helpers.sh"
        self.helpers.write_text(common_functions("node_build", "install_npm_app", "replace_app_tree"))
        self.log = self.root / "install.log"

    def run_install_npm(self, registry_url: str, package: str, app_dir: Path, exe: Path, **extra_env):
        script = '''set -euo pipefail
source "$1"
print_error() { printf '%s\\n' "$*" >&2; }
log_info() { printf '%s\\n' "$*"; }
install_npm_app "$2" "$3" "$4"
'''
        env = {
            **os.environ,
            "LOGFILE": str(self.log),
            "npm_config_cache": str(self.root / "npm-cache"),
            "npm_config_registry": registry_url,
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            **extra_env,
        }
        return subprocess.run(
            ["bash", "-c", script, "test", str(self.helpers), package, str(app_dir), str(exe)],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_install_npm_app_pins_exact_version_and_rejects_unavailable_or_tampered_package(self):
        packages = {
            "flood": {
                "4.16.3": (make_npm_tarball("flood", "4.16.3", "flood"), "", "flood"),
                "4.16.4": (make_npm_tarball("flood", "4.16.4", "flood"), "latest", "flood"),
                # Advertised as 4.16.2 in registry metadata, but tarball carries 4.16.4 in package.json.
                "4.16.2": (make_npm_tarball("flood", "4.16.4", "flood"), "", "flood"),
            },
            "@jesec/flood": {
                "0.0.0-master.01f5a4a": (
                    make_npm_tarball("@jesec/flood", "0.0.0-master.01f5a4a", "flood"),
                    "latest",
                    "flood",
                ),
            },
            "thelounge": {
                "4.4.3": (make_npm_tarball("thelounge", "4.4.3", "thelounge"), "", "thelounge"),
                "4.5.2": (make_npm_tarball("thelounge", "4.5.2", "thelounge"), "latest", "thelounge"),
            },
        }
        with _LocalNpmRegistry(packages) as registry_url:
            flood_dir = self.root / "opt/flood"
            flood_bin = self.root / "usr/local/bin/flood"
            res = self.run_install_npm(registry_url, "flood@4.16.3", flood_dir, flood_bin)
            self.assertEqual(res.returncode, 0, res.stderr + (self.log.read_text() if self.log.exists() else ""))
            self.assertEqual(subprocess.check_output([str(flood_bin)], text=True).strip(), "4.16.3")
            self.assertEqual(
                json.loads((flood_dir / "node_modules/flood/package.json").read_text())["version"],
                "4.16.3",
            )

            # Unavailable version fails cleanly and preserves prior 4.16.3 runtime.
            missing = self.run_install_npm(registry_url, "flood@9.9.9", flood_dir, flood_bin)
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(subprocess.check_output([str(flood_bin)], text=True).strip(), "4.16.3")
            self.assertFalse(list((self.root / "opt").glob("flood.af-build.*")))
            self.assertFalse(list((self.root / "opt").glob("flood.af-backup.*")))

            # Tampered tarball whose package.json mismatches requested 4.16.2 is rejected before swap.
            tampered = self.run_install_npm(registry_url, "flood@4.16.2", flood_dir, flood_bin)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("does not match requested version", tampered.stderr)
            self.assertEqual(subprocess.check_output([str(flood_bin)], text=True).strip(), "4.16.3")
            self.assertFalse(list((self.root / "opt").glob("flood.af-build.*")))
            self.assertFalse(list((self.root / "opt").glob("flood.af-backup.*")))

            # Non-exact semver range is rejected before invoking npm.
            ranged = self.run_install_npm(registry_url, "flood@^4.16.3", flood_dir, flood_bin)
            self.assertNotEqual(ranged.returncode, 0)
            self.assertEqual(subprocess.check_output([str(flood_bin)], text=True).strip(), "4.16.3")

            # Legacy scoped recovery spec still verifies exact scoped package metadata.
            scoped_dir = self.root / "opt/flood-legacy"
            scoped_bin = self.root / "usr/local/bin/flood-legacy"
            scoped_res = self.run_install_npm(
                registry_url, "@jesec/flood@0.0.0-master.01f5a4a", scoped_dir, self.root / "usr/local/bin/flood"
            )
            self.assertEqual(scoped_res.returncode, 0, scoped_res.stderr)
            self.assertEqual(
                json.loads((scoped_dir / "node_modules/@jesec/flood/package.json").read_text())["version"],
                "0.0.0-master.01f5a4a",
            )
            self.assertFalse(scoped_bin.exists())

            # Bare package name with AF_TARGET_VERSION automatically pins exact version.
            lounge_dir = self.root / "opt/thelounge"
            lounge_bin = self.root / "usr/local/bin/thelounge"
            pinned_env = self.run_install_npm(
                registry_url, "thelounge", lounge_dir, lounge_bin, AF_TARGET_VERSION="Release-v4.4.3"
            )
            self.assertEqual(pinned_env.returncode, 0, pinned_env.stderr)
            self.assertEqual(subprocess.check_output([str(lounge_bin)], text=True).strip(), "4.4.3")

            # Unpinned install still resolves latest cleanly.
            unpinned = self.run_install_npm(registry_url, "flood", flood_dir, flood_bin)
            self.assertEqual(unpinned.returncode, 0, unpinned.stderr)
            self.assertEqual(subprocess.check_output([str(flood_bin)], text=True).strip(), "4.16.4")


MOCK_SANDBOX_BIN = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

root = Path(os.environ["AF_SANDBOX_ROOT"])
cmd = Path(sys.argv[0]).name
args = sys.argv[1:]

with (root / "commands.jsonl").open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([cmd, *args]) + "\n")

if cmd in ("apt-get", "chown", "id", "useradd", "usermod", "getent"):
    sys.exit(0)

if cmd == "curl":
    sys.exit(0)

if cmd == "sudo":
    # Support `sudo -u thelounge THELOUNGE_HOME=... node ...`
    if args[:2] == ["-u", "thelounge"]:
        args = args[2:]
        env = dict(os.environ)
        while args and "=" in args[0]:
            k, v = args.pop(0).split("=", 1)
            env[k] = v
        os.execvpe(args[0], args, env)
    sys.exit(0)

if cmd == "node":
    if any("thelounge" in a for a in args) and "-v" in args:
        bin_path = next(a for a in args if "thelounge" in a)
        os.execv(bin_path, [bin_path, "-v"])
    if "-v" in args or "--version" in args:
        print(os.environ.get("MOCK_NODE_VER", "v22.12.0"))
        sys.exit(0)
    if "-e" in args and "DatabaseSync" in args[args.index("-e") + 1]:
        sys.exit(0)
    if "-e" in args and "process.argv" in args[args.index("-e") + 1]:
        username = args[-1]
        home = Path(os.environ["THELOUNGE_HOME"])
        users_dir = home / "users"
        users_dir.mkdir(parents=True, exist_ok=True)
        (users_dir / f"{username}.json").write_text('{"password":"fixture-hash"}\n')
        sys.exit(0)
    sys.exit(0)

if cmd == "npm":
    if os.environ.get("MOCK_NPM_FAIL") == "1":
        sys.stderr.write("npm error ETARGET No matching version found\n")
        sys.exit(1)
    prefix = Path(args[args.index("--prefix") + 1])
    spec = args[-1]
    if spec.startswith("@"):
        parts = spec.rsplit("@", 1)
        if parts[0]:
            pkg_name, req_ver = parts[0], parts[1]
        else:
            pkg_name, req_ver = spec, ""
    elif "@" in spec:
        pkg_name, req_ver = spec.rsplit("@", 1)
    else:
        pkg_name, req_ver = spec, ""

    default_ver = os.environ.get("MOCK_DEFAULT_VER", "4.16.4")
    pkg_ver = os.environ.get("MOCK_PKG_VER") or req_ver or default_ver
    cli_ver = os.environ.get("MOCK_CLI_VER") or pkg_ver
    bin_name = "flood" if pkg_name in ("flood", "@jesec/flood") else pkg_name

    pkg_dir = prefix / "node_modules" / pkg_name
    if os.environ.get("MOCK_OMIT_PKG_JSON") != "1":
        pkg_dir.mkdir(parents=True, exist_ok=True)
        if os.environ.get("MOCK_SYMLINK_PKG_JSON") == "1":
            target = root / "external-pkg.json"
            target.write_text(json.dumps({"name": pkg_name, "version": pkg_ver}))
            (pkg_dir / "package.json").symlink_to(target)
        else:
            (pkg_dir / "package.json").write_text(json.dumps({"name": pkg_name, "version": pkg_ver}))
    bin_dir = prefix / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_file = bin_dir / bin_name
    bin_file.write_text(f"#!/bin/sh\nprintf '%s\\n' {json.dumps(cli_ver)}\n")
    bin_file.chmod(0o755)
    sys.exit(0)

if cmd == "python3":
    if args[:2] == ["-m", "venv"]:
        venv_dir = Path(args[-1])
        bin_dir = venv_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for name in ("python", "python3", "pip", "pip3"):
            target = bin_dir / name
            target.write_text(f"#!/bin/sh\nexec {json.dumps(str(root / 'mock-bin' / name))} \"$@\"\n")
            target.chmod(0o755)
        sys.exit(0)
    if args and args[0] == "-c" and "importlib.metadata" in args[1]:
        state_file = root / "opt/unmanic/.venv/.mock-meta-version"
        ver = state_file.read_text().strip() if state_file.exists() else ""
        if ver:
            print(ver)
        sys.exit(0)
    real_py = os.environ["AF_REAL_PYTHON"]
    os.execv(real_py, [real_py, *args])

if cmd == "python":
    if args and args[0] == "-c" and "importlib.metadata" in args[1]:
        state_file = root / "opt/unmanic/.venv/.mock-meta-version"
        ver = state_file.read_text().strip() if state_file.exists() else ""
        if ver:
            print(ver)
        sys.exit(0)
    real_py = os.environ["AF_REAL_PYTHON"]
    os.execv(real_py, [real_py, *args])

if cmd in ("pip", "pip3"):
    if "unmanic" in " ".join(args):
        if os.environ.get("MOCK_PIP_FAIL") == "1":
            sys.stderr.write("ERROR: Could not find a version that satisfies the requirement unmanic\n")
            sys.exit(1)
        spec = next((a for a in args if a.startswith("unmanic")), "unmanic")
        req_ver = spec.split("==", 1)[1] if "==" in spec else ""
        default_ver = os.environ.get("MOCK_DEFAULT_VER", "0.2.6")
        meta_ver = os.environ.get("MOCK_META_VER", req_ver or default_ver)
        cli_ver = os.environ.get("MOCK_CLI_VER", meta_ver)
        venv_dir = root / "opt/unmanic/.venv"
        (venv_dir / ".mock-meta-version").write_text(meta_ver + "\n")
        unmanic_bin = venv_dir / "bin/unmanic"
        unmanic_bin.write_text(f"#!/bin/sh\nprintf '%s\\n' {json.dumps(cli_ver)}\n")
        unmanic_bin.chmod(0o755)
    sys.exit(0)

if cmd == "systemctl":
    sub = args[0] if args else ""
    units = [a.removesuffix(".service") for a in args[1:] if not a.startswith("-")]
    if sub == "is-active":
        active = all((root / f"active-{u}").exists() for u in units)
        sys.exit(0 if active else 3)
    if sub == "show":
        unit = units[0] if units else ""
        active = (root / f"active-{unit}").exists()
        unit_file = root / f"etc/systemd/system/{unit}.service"
        print("LoadState=" + ("loaded" if unit_file.exists() or active else "not-found"))
        print("ActiveState=" + ("active" if active else "inactive"))
        print("MainPID=" + ("1234" if active else "0"))
        print("UnitFileState=disabled")
        sys.exit(0)
    if sub == "stop":
        for u in units:
            (root / f"active-{u}").unlink(missing_ok=True)
        sys.exit(0)
    if sub in ("start", "restart"):
        for u in units:
            (root / f"active-{u}").touch()
        sys.exit(0)
    if sub == "enable":
        for u in units:
            (root / f"enabled-{u}").touch()
            if "--now" in args:
                (root / f"active-{u}").touch()
        sys.exit(0)
    if sub == "disable":
        for u in units:
            (root / f"enabled-{u}").unlink(missing_ok=True)
        sys.exit(0)
    sys.exit(0)

raise RuntimeError(f"Unexpected mock command: {cmd} {args}")
'''


class RegistryInstallerSandboxTests(unittest.TestCase):
    def make_sandbox(self, app: str) -> tuple[Path, Path]:
        tmp = tempfile.TemporaryDirectory(prefix=f"af-{app}-sandbox-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel in (
            "mock-bin",
            "opt/AetherFlow/packages",
            "var/log/aetherflow",
            "var/backups/aetherflow-recovery",
            "etc/systemd/system",
            "usr/local/bin",
            "usr/bin",
            "install",
            "tmp",
        ):
            (root / rel).mkdir(parents=True, exist_ok=True)
        (root / "var/backups/aetherflow-recovery").chmod(0o700)

        common = root / "opt/AetherFlow/packages/common.sh"
        common.write_text(
            f'''MASTER_USER=operator
MASTER_PASS="fixture-pass"
require_root() {{ :; }}
load_master_credentials() {{ :; }}
log_info() {{ printf '%s\\n' "$*" >> "$LOGFILE"; }}
log_error() {{ printf '%s\\n' "$*" >&2; }}
print_error() {{ printf '%s\\n' "$*" >&2; }}
print_warn() {{ printf '%s\\n' "$*" >&2; }}
report_progress() {{ :; }}
ensure_node() {{ printf '["ensure_node", "%s"]\\n' "$1" >> "{root}/commands.jsonl"; }}
write_lock() {{ touch "{root}/install/.$1.lock"; INSTALL_COMMITTED=true; }}
'''
            + installer_common_functions(
                "node_build",
                "install_npm_app",
                "replace_app_tree",
                "set_config_value",
                "write_config_file",
                "retained_bind_address",
            )
        )

        for name in (
            "apt-get", "chown", "id", "useradd", "usermod", "getent",
            "curl", "sudo", "node", "npm", "python", "python3", "pip", "pip3", "systemctl",
        ):
            exe = root / "mock-bin" / name
            exe.write_text(MOCK_SANDBOX_BIN)
            exe.chmod(0o755)

        installer_src = (ROOT / f"packages/package/install/installpackage-{app}").read_text()
        rebased = rebase_installer(installer_src, root)
        script = root / f"installpackage-{app}.sh"
        script.write_text(rebased)
        return root, script

    def run_sandbox(self, root: Path, script: Path, **extra_env) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{root}/mock-bin:/usr/bin:/bin",
            "TMPDIR": str(root / "tmp"),
            "AF_SANDBOX_ROOT": str(root),
            "AF_REAL_PYTHON": sys.executable,
            "AF_RECOVERY_ROOT": str(root / "var/backups/aetherflow-recovery"),
            "AF_TRANSACTION_ROOT": str(root / "var/backups/aetherflow-recovery"),
            **extra_env,
        }
        env.pop("AF_TARGET_VERSION", None)
        if "AF_TARGET_VERSION" in extra_env:
            if extra_env["AF_TARGET_VERSION"] is None:
                env.pop("AF_TARGET_VERSION", None)
            else:
                env["AF_TARGET_VERSION"] = extra_env["AF_TARGET_VERSION"]
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=20)

    def read_commands(self, root: Path, start: int = 0) -> list[list[str]]:
        path = root / "commands.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()[start:]]

    def test_flood_pinned_unpinned_mismatch_and_clean_rollback(self):
        root, script = self.make_sandbox("flood")

        # 1. No-target install uses unscoped stable `flood` with Node 22 and managed service flags.
        res = self.run_sandbox(root, script, MOCK_DEFAULT_VER="4.16.3")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        cmds = self.read_commands(root)
        self.assertIn(["ensure_node", "22"], cmds)
        npm_calls = [c for c in cmds if c[0] == "npm"]
        self.assertEqual(len(npm_calls), 1)
        self.assertEqual(npm_calls[0][-1], "flood")
        self.assertNotIn("--save-exact", npm_calls[0])
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.3")
        self.assertTrue((root / "active-flood").exists())
        unit_text = (root / "etc/systemd/system/flood.service").read_text()
        self.assertIn("--host 127.0.0.1 --port 3001 --rundir", unit_text)

        state = root / "var/lib/flood/db/users.db"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text("retained-flood-state\n")

        # 2. Incompatible Node (<22) fails before stopping service or calling npm.
        mark = len(self.read_commands(root))
        old_node = self.run_sandbox(root, script, MOCK_NODE_VER="v20.18.0", AF_TARGET_VERSION="4.16.4")
        self.assertNotEqual(old_node.returncode, 0)
        self.assertIn("Node.js >= 22", old_node.stderr)
        delta = self.read_commands(root, mark)
        self.assertFalse(any(c[0] in ("npm", "systemctl") for c in delta), delta)
        self.assertTrue((root / "active-flood").exists())
        self.assertEqual(state.read_text(), "retained-flood-state\n")

        # 3. Invalid targets fail before stopping service or calling npm.
        for bad in ("latest", "^4.16.4", "4.16.x", "@jesec/flood@4.16.4"):
            mark = len(self.read_commands(root))
            bad_res = self.run_sandbox(root, script, AF_TARGET_VERSION=bad)
            self.assertNotEqual(bad_res.returncode, 0)
            delta = self.read_commands(root, mark)
            self.assertFalse(any(c[0] in ("npm", "systemctl") for c in delta), delta)
            self.assertTrue((root / "active-flood").exists())
            self.assertEqual(state.read_text(), "retained-flood-state\n")

        # 4. Pinned update with tag prefix passes exact `flood@4.16.4` and commits normalized version.
        mark = len(self.read_commands(root))
        pinned = self.run_sandbox(root, script, AF_TARGET_VERSION="v4.16.4")
        self.assertEqual(pinned.returncode, 0, pinned.stdout + pinned.stderr)
        delta = self.read_commands(root, mark)
        npm_pinned = [c for c in delta if c[0] == "npm"]
        self.assertEqual(len(npm_pinned), 1)
        self.assertIn("--save-exact", npm_pinned[0])
        self.assertEqual(npm_pinned[0][-1], "flood@4.16.4")
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
        self.assertEqual(state.read_text(), "retained-flood-state\n")

        # 5. Missing or symlinked package.json on a pinned install fails BEFORE activation and rolls back.
        for label, extra in (
            ("missing-pkg-json", {"AF_TARGET_VERSION": "4.16.5", "MOCK_OMIT_PKG_JSON": "1"}),
            ("symlink-pkg-json", {"AF_TARGET_VERSION": "4.16.5", "MOCK_SYMLINK_PKG_JSON": "1"}),
        ):
            with self.subTest(case=label):
                mark = len(self.read_commands(root))
                bad_meta = self.run_sandbox(root, script, **extra)
                self.assertNotEqual(bad_meta.returncode, 0, bad_meta.stdout + bad_meta.stderr)
                self.assertIn("missing valid package.json metadata", bad_meta.stderr)
                delta = self.read_commands(root, mark)
                self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in delta), delta)
                self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
                self.assertEqual(state.read_text(), "retained-flood-state\n")
                self.assertTrue((root / "active-flood").exists())
                self.assertEqual(
                    subprocess.check_output([str(root / "usr/local/bin/flood"), "--version"], text=True).strip(),
                    "4.16.4",
                )

        # 6. Unavailable version fails without silent fallback and rolls back cleanly.
        lock_mtime = (root / "install/.flood.lock").stat().st_mtime_ns
        mark = len(self.read_commands(root))
        unavail = self.run_sandbox(root, script, AF_TARGET_VERSION="9.9.9", MOCK_NPM_FAIL="1")
        self.assertNotEqual(unavail.returncode, 0)
        npm_unavail = [c for c in self.read_commands(root, mark) if c[0] == "npm"]
        self.assertEqual(len(npm_unavail), 1)
        self.assertEqual(npm_unavail[0][-1], "flood@9.9.9")
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
        self.assertEqual(state.read_text(), "retained-flood-state\n")
        self.assertEqual((root / "install/.flood.lock").stat().st_mtime_ns, lock_mtime)
        self.assertTrue((root / "active-flood").exists())
        self.assertEqual(
            subprocess.check_output([str(root / "usr/local/bin/flood"), "--version"], text=True).strip(),
            "4.16.4",
        )

        # 7. CLI version mismatch fails BEFORE service activation and rolls back cleanly.
        mark = len(self.read_commands(root))
        mismatch = self.run_sandbox(
            root, script, AF_TARGET_VERSION="4.16.5", MOCK_PKG_VER="4.16.5", MOCK_CLI_VER="4.17.0"
        )
        self.assertNotEqual(mismatch.returncode, 0)
        delta = self.read_commands(root, mark)
        self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in delta), delta)
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
        self.assertEqual(state.read_text(), "retained-flood-state\n")
        self.assertTrue((root / "active-flood").exists())
        self.assertEqual(
            subprocess.check_output([str(root / "usr/local/bin/flood"), "--version"], text=True).strip(),
            "4.16.4",
        )

    def test_flood_legacy_scoped_migration_rollback_and_exact_recovery(self):
        root, script = self.make_sandbox("flood")

        # 1. Seed a retained legacy `@jesec/flood` install (`0.0.0-master.01f5a4a`) with custom host & db state.
        legacy_res = self.run_sandbox(root, script, AF_TARGET_VERSION="0.0.0-master.01f5a4a")
        self.assertEqual(legacy_res.returncode, 0, legacy_res.stdout + legacy_res.stderr)
        npm_legacy = [c for c in self.read_commands(root) if c[0] == "npm"]
        self.assertEqual(len(npm_legacy), 1)
        self.assertIn("--save-exact", npm_legacy[0])
        self.assertEqual(npm_legacy[0][-1], "@jesec/flood@0.0.0-master.01f5a4a")
        self.assertTrue((root / "opt/flood/node_modules/@jesec/flood/package.json").exists())
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "0.0.0-master.01f5a4a")

        unit_file = root / "etc/systemd/system/flood.service"
        unit_file.write_text(unit_file.read_text().replace("--host 127.0.0.1", "--host 10.0.0.5"))
        users_db = root / "var/lib/flood/db/users.db"
        users_db.parent.mkdir(parents=True, exist_ok=True)
        users_db.write_text('{"username":"operator"}\n')

        # 2. Unavailable legacy recovery target fails closed without falling back to unscoped `flood`.
        mark = len(self.read_commands(root))
        legacy_fail = self.run_sandbox(root, script, AF_TARGET_VERSION="0.0.0-master.deadbee", MOCK_NPM_FAIL="1")
        self.assertNotEqual(legacy_fail.returncode, 0)
        npm_legacy_fail = [c for c in self.read_commands(root, mark) if c[0] == "npm"]
        self.assertEqual(len(npm_legacy_fail), 1)
        self.assertEqual(npm_legacy_fail[0][-1], "@jesec/flood@0.0.0-master.deadbee")
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "0.0.0-master.01f5a4a")
        self.assertTrue((root / "opt/flood/node_modules/@jesec/flood/package.json").exists())
        self.assertEqual(users_db.read_text(), '{"username":"operator"}\n')
        self.assertTrue((root / "active-flood").exists())

        # 3. Failed migration from legacy `@jesec/flood` to stable `flood@4.16.4` rolls back cleanly.
        mark = len(self.read_commands(root))
        mig_fail = self.run_sandbox(root, script, AF_TARGET_VERSION="4.16.4", MOCK_NPM_FAIL="1")
        self.assertNotEqual(mig_fail.returncode, 0)
        npm_mig_fail = [c for c in self.read_commands(root, mark) if c[0] == "npm"]
        self.assertEqual(len(npm_mig_fail), 1)
        self.assertEqual(npm_mig_fail[0][-1], "flood@4.16.4")
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "0.0.0-master.01f5a4a")
        self.assertTrue((root / "opt/flood/node_modules/@jesec/flood/package.json").exists())
        self.assertIn("--host 10.0.0.5", unit_file.read_text())
        self.assertEqual(users_db.read_text(), '{"username":"operator"}\n')
        self.assertTrue((root / "active-flood").exists())

        # 4. Successful migration from legacy `@jesec/flood` to stable `flood@4.16.4` preserves state, host, and port.
        mark = len(self.read_commands(root))
        migrated = self.run_sandbox(root, script, AF_TARGET_VERSION="v4.16.4", AF_APP_PORT="3015")
        self.assertEqual(migrated.returncode, 0, migrated.stdout + migrated.stderr)
        npm_mig = [c for c in self.read_commands(root, mark) if c[0] == "npm"]
        self.assertEqual(len(npm_mig), 1)
        self.assertIn("--save-exact", npm_mig[0])
        self.assertEqual(npm_mig[0][-1], "flood@4.16.4")
        self.assertTrue((root / "opt/flood/node_modules/flood/package.json").exists())
        self.assertFalse((root / "opt/flood/node_modules/@jesec/flood").exists())
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
        self.assertEqual(users_db.read_text(), '{"username":"operator"}\n')
        self.assertIn("--host 10.0.0.5 --port 3015 --rundir", unit_file.read_text())
        self.assertTrue((root / "active-flood").exists())

        # 5. Downgrading from stable 4.16.4 back to legacy 0.0.0-master.01f5a4a is refused without AF_ALLOW_DOWNGRADE=1,
        #    and succeeds when AF_ALLOW_DOWNGRADE=1 is explicitly set for recovery.
        refused = self.run_sandbox(root, script, AF_TARGET_VERSION="0.0.0-master.01f5a4a")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "4.16.4")
        self.assertTrue((root / "opt/flood/node_modules/flood/package.json").exists())

        recovered = self.run_sandbox(
            root, script, AF_TARGET_VERSION="0.0.0-master.01f5a4a", AF_ALLOW_DOWNGRADE="1"
        )
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertEqual((root / "var/lib/flood/.af-version").read_text().strip(), "0.0.0-master.01f5a4a")
        self.assertTrue((root / "opt/flood/node_modules/@jesec/flood/package.json").exists())
        self.assertEqual(users_db.read_text(), '{"username":"operator"}\n')

    def test_thelounge_pinned_unpinned_mismatch_and_clean_rollback(self):
        root, script = self.make_sandbox("thelounge")

        # 1. No-target install passes bare `thelounge`.
        res = self.run_sandbox(root, script, MOCK_DEFAULT_VER="4.4.3")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        npm_calls = [c for c in self.read_commands(root) if c[0] == "npm"]
        self.assertEqual(npm_calls[0][-1], "thelounge")
        self.assertNotIn("--save-exact", npm_calls[0])
        self.assertEqual((root / "var/lib/thelounge/.af-version").read_text().strip(), "4.4.3")
        self.assertTrue((root / "active-thelounge").exists())

        user_state = root / "var/lib/thelounge/users/operator.json"
        user_state.write_text('{"password":"retained-hash"}\n')

        # 2. Invalid target fails before stopping service or invoking npm.
        mark = len(self.read_commands(root))
        bad = self.run_sandbox(root, script, AF_TARGET_VERSION="latest")
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse(any(c[0] in ("npm", "systemctl") for c in self.read_commands(root, mark)))
        self.assertTrue((root / "active-thelounge").exists())

        # 3. Pinned update with tag prefix passes exact `thelounge@4.5.2`.
        mark = len(self.read_commands(root))
        pinned = self.run_sandbox(root, script, AF_TARGET_VERSION="Release-v4.5.2")
        self.assertEqual(pinned.returncode, 0, pinned.stdout + pinned.stderr)
        npm_pinned = [c for c in self.read_commands(root, mark) if c[0] == "npm"]
        self.assertIn("--save-exact", npm_pinned[0])
        self.assertEqual(npm_pinned[0][-1], "thelounge@4.5.2")
        self.assertEqual((root / "var/lib/thelounge/.af-version").read_text().strip(), "4.5.2")
        self.assertEqual(user_state.read_text(), '{"password":"retained-hash"}\n')

        # 4. Missing package.json on a pinned install fails BEFORE activation and rolls back cleanly.
        mark = len(self.read_commands(root))
        missing_meta = self.run_sandbox(root, script, AF_TARGET_VERSION="4.6.0", MOCK_OMIT_PKG_JSON="1")
        self.assertNotEqual(missing_meta.returncode, 0)
        self.assertIn("missing valid package.json metadata", missing_meta.stderr)
        delta = self.read_commands(root, mark)
        self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in delta), delta)
        self.assertEqual((root / "var/lib/thelounge/.af-version").read_text().strip(), "4.5.2")
        self.assertEqual(user_state.read_text(), '{"password":"retained-hash"}\n')
        self.assertTrue((root / "active-thelounge").exists())

        # 5. Version mismatch rejects before activation and rolls back runtime + retained state.
        mark = len(self.read_commands(root))
        mismatch = self.run_sandbox(
            root, script, AF_TARGET_VERSION="4.6.0", MOCK_PKG_VER="4.6.0", MOCK_CLI_VER="v4.9.9"
        )
        self.assertNotEqual(mismatch.returncode, 0)
        delta = self.read_commands(root, mark)
        self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in delta), delta)
        self.assertEqual((root / "var/lib/thelounge/.af-version").read_text().strip(), "4.5.2")
        self.assertEqual(user_state.read_text(), '{"password":"retained-hash"}\n')
        self.assertTrue((root / "active-thelounge").exists())
        self.assertEqual(
            subprocess.check_output([str(root / "usr/local/bin/thelounge"), "-v"], text=True).strip(),
            "4.5.2",
        )

    def test_unmanic_pinned_unpinned_mismatch_and_clean_rollback(self):
        root, script = self.make_sandbox("unmanic")

        # 1. Fresh install failure with unavailable target does not leave /opt/unmanic or restart service.
        fresh_fail = self.run_sandbox(root, script, AF_TARGET_VERSION="9.9.9", MOCK_PIP_FAIL="1")
        self.assertNotEqual(fresh_fail.returncode, 0)
        self.assertFalse((root / "opt/unmanic").exists())
        self.assertFalse((root / "install/.unmanic.lock").exists())
        self.assertFalse((root / "active-unmanic").exists())

        # 2. No-target install preserves `--upgrade --no-cache-dir unmanic`.
        mark = len(self.read_commands(root))
        res = self.run_sandbox(root, script, MOCK_DEFAULT_VER="0.2.6")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        pip_calls = [c for c in self.read_commands(root, mark) if c[0] == "pip" and "unmanic" in " ".join(c)]
        self.assertEqual(pip_calls[0], ["pip", "install", "--upgrade", "--no-cache-dir", "unmanic"])
        self.assertEqual((root / "opt/unmanic/.af-version").read_text().strip(), "0.2.6")
        self.assertTrue((root / "active-unmanic").exists())

        retained = root / "var/lib/unmanic/.unmanic/userdata/library.db"
        retained.write_text("retained-unmanic-state\n")

        # 3. Invalid targets fail before stopping service or running pip.
        for bad in ("latest", ">=0.2.7", "0.2.*"):
            mark = len(self.read_commands(root))
            bad_res = self.run_sandbox(root, script, AF_TARGET_VERSION=bad)
            self.assertNotEqual(bad_res.returncode, 0)
            self.assertFalse(any(c[0] in ("pip", "systemctl") for c in self.read_commands(root, mark)))
            self.assertTrue((root / "active-unmanic").exists())

        # 4. Pinned update passes exact `unmanic==0.2.7` without `--upgrade`.
        mark = len(self.read_commands(root))
        pinned = self.run_sandbox(root, script, AF_TARGET_VERSION="v0.2.7")
        self.assertEqual(pinned.returncode, 0, pinned.stdout + pinned.stderr)
        pip_pinned = [c for c in self.read_commands(root, mark) if c[0] == "pip" and "unmanic" in " ".join(c)]
        self.assertEqual(pip_pinned[0], ["pip", "install", "--no-cache-dir", "unmanic==0.2.7"])
        self.assertEqual((root / "opt/unmanic/.af-version").read_text().strip(), "0.2.7")
        self.assertEqual(retained.read_text(), "retained-unmanic-state\n")

        # 5. Unavailable version rolls back runtime, state, receipt, and active service.
        unavail = self.run_sandbox(root, script, AF_TARGET_VERSION="0.9.9", MOCK_PIP_FAIL="1")
        self.assertNotEqual(unavail.returncode, 0)
        self.assertEqual((root / "opt/unmanic/.af-version").read_text().strip(), "0.2.7")
        self.assertEqual(retained.read_text(), "retained-unmanic-state\n")
        self.assertTrue((root / "active-unmanic").exists())

        # 6. Metadata mismatch and CLI runtime mismatch both fail BEFORE activation and roll back cleanly.
        for label, extra in (
            ("metadata-mismatch", {"AF_TARGET_VERSION": "0.3.0", "MOCK_META_VER": "0.2.7", "MOCK_CLI_VER": "0.3.0"}),
            ("runtime-mismatch", {"AF_TARGET_VERSION": "0.3.0", "MOCK_META_VER": "0.3.0", "MOCK_CLI_VER": "Unmanic 0.2.7"}),
            ("runtime-empty", {"AF_TARGET_VERSION": "0.3.0", "MOCK_META_VER": "0.3.0", "MOCK_CLI_VER": ""}),
            ("no-fallback-on-pinned", {"AF_TARGET_VERSION": "0.3.0", "MOCK_META_VER": "", "AF_ALLOW_RELEASE_FALLBACK": "1"}),
        ):
            with self.subTest(case=label):
                mark = len(self.read_commands(root))
                res = self.run_sandbox(root, script, **extra)
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                delta = self.read_commands(root, mark)
                self.assertFalse(any(c[:2] == ["systemctl", "enable"] for c in delta), delta)
                self.assertEqual((root / "opt/unmanic/.af-version").read_text().strip(), "0.2.7")
                self.assertEqual(retained.read_text(), "retained-unmanic-state\n")
                self.assertTrue((root / "active-unmanic").exists())

    def test_discovery_metadata_aligns_unmanic_to_pypi(self):
        automation = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        self.assertEqual(automation["unmanic"]["update_source"], "pypi")
        self.assertEqual(automation["unmanic"]["update_package"], "unmanic")
        self.assertNotIn("update_repo", automation["unmanic"])
        self.assertEqual(automation["flood"]["update_source"], "github")
        self.assertEqual(automation["flood"]["update_repo"], "jesec/flood")
        self.assertNotIn("update_package", automation["flood"])
        self.assertEqual(automation["thelounge"]["update_source"], "github")
        self.assertEqual(automation["thelounge"]["update_repo"], "thelounge/thelounge")


if __name__ == "__main__":
    unittest.main()
